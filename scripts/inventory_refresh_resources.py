"""Read-only current aggregate/cache admission, not full readiness or target fit.

The trusted unit must enter the aggregate BEFORE Python/imports/policy/cache
allocation. Current membership cannot prove where earlier allocations happened.
No command/path/options interface, mount/limit writes or pressure workloads.
"""
import os
import re
import stat
import sys

CACHE='/var/cache/command-center-inventory-refresh'
AGGREGATE='/command.slice/command-center.slice/command-center-inventory.slice'
UNIT='command-center-inventory-coordinator.service'
SELF_CGROUP=AGGREGATE+'/'+UNIT
MEMORY=256*1024*1024
CACHE_BYTES=128*1024*1024
INODES=32768
TASKS=64
MAX_SAFE=2**63-1


class ResourceError(ValueError):
    def __init__(self,reason='policy_unsupported'):
        self.reason=reason
        super().__init__('Inventory resource admission unavailable: '+reason)


def _require(condition,reason='policy_unsupported'):
    if not condition:raise ResourceError(reason)


def mount_path(raw):
    _require(type(raw) is bytes and raw.startswith(b'/'))
    escapes={b'040':32,b'011':9,b'012':10,b'134':92}
    result=bytearray();index=0
    while index<len(raw):
        if raw[index]==92:
            sequence=raw[index+1:index+4]
            _require(len(sequence)==3 and sequence in escapes)
            result.append(escapes[sequence]);index+=4
        else:result.append(raw[index]);index+=1
    return result.decode('utf-8','surrogateescape')


def mount_rows(raw):
    _require(type(raw) is bytes and 0<len(raw)<=1024*1024)
    result={}
    for line in raw.splitlines():
        fields=line.split(b' ')
        _require(len(fields)>=10 and b'-' in fields)
        split=fields.index(b'-');_require(split>=6 and len(fields)==split+4)
        _require(all(re.fullmatch(rb'[1-9][0-9]{0,9}',value) for value in fields[:2]))
        identifier=int(fields[0]);_require(identifier not in result)
        _require(re.fullmatch(rb'[0-9]{1,10}:[0-9]{1,10}',fields[2]) is not None)
        device=tuple(int(value) for value in fields[2].split(b':'))
        options=set(fields[5].split(b','))
        _require(bool(options) and (b'rw' in options) != (b'ro' in options))
        result[identifier]={'id':identifier,'parent':int(fields[1]),'device':device,
            'root':mount_path(fields[3]),'path':mount_path(fields[4]),'options':options,'fs':fields[split+1]}
    _require(bool(result));return result


def validate_mounts(raw,*,cache_device,cache_mount_id,cgroup_device,cgroup_mount_id):
    rows=mount_rows(raw)
    cache=[row for row in rows.values() if row['path']==CACHE]
    groups=[row for row in rows.values() if row['path']=='/sys/fs/cgroup']
    _require(len(cache)==len(groups)==1)
    cache=cache[0];groups=groups[0]
    _require(cache['fs']==b'tmpfs' and cache['root']=='/' and cache['device']==cache_device and cache['id']==cache_mount_id and
             {b'rw',b'nodev',b'nosuid',b'noexec'}<=cache['options'])
    _require(groups['fs']==b'cgroup2' and groups['root']=='/' and groups['device']==cgroup_device and groups['id']==cgroup_mount_id)
    _require(not any(row['path'].startswith(CACHE+'/') for row in rows.values()))
    _require(sum(row['device']==cache_device for row in rows.values())==1)
    return cache['id'],groups['id']


def limit(raw):
    _require(type(raw) is bytes and len(raw)<=64)
    if raw in (b'max',b'max\n'):return None
    _require(re.fullmatch(rb'(0|[1-9][0-9]{0,18})\n?',raw) is not None)
    number=int(raw);_require(number<=MAX_SAFE);return number


def validate_profile(parent,ancestors):
    wanted={'memory.max':MEMORY,'memory.swap.max':0,'pids.max':TASKS}
    _require(set(parent)==set(wanted))
    _require(all(limit(parent[key])==value for key,value in wanted.items()),'resource_limit')
    for ancestor in ancestors:
        _require(set(ancestor)==set(wanted))
        for key,value in wanted.items():
            maximum=limit(ancestor[key])
            _require(maximum is None or maximum>=value,'resource_limit')


def validate_membership(raw):
    _require(type(raw) is bytes and raw==('0::'+SELF_CGROUP+'\n').encode('ascii'))


def _read(parent,name,maximum=4096):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    try:
        info=os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022)
        raw=b''
        while True:
            chunk=os.read(fd,min(65536,maximum+1-len(raw)))
            if not chunk:break
            raw+=chunk;_require(len(raw)<=maximum)
        return raw
    finally:os.close(fd)


def _proc(name,maximum):
    # Literal self-only proc files; the kernel's self magic link is intentional.
    _require(name in ('mountinfo','cgroup') or re.fullmatch(r'fdinfo/[0-9]{1,10}',name) is not None)
    with open('/proc/self/'+name,'rb') as source:
        raw=source.read(maximum+1)
    _require(len(raw)<=maximum);return raw


def _mount_id(fd):
    raw=_proc('fdinfo/'+str(fd),4096)
    found=[line.partition(b':')[2].strip() for line in raw.splitlines() if line.startswith(b'mnt_id:')]
    _require(len(found)==1 and re.fullmatch(rb'[1-9][0-9]{0,9}',found[0]) is not None)
    return int(found[0])


class _Chain:
    def __init__(self,parts):
        self.fds=[];self.refs=[]
        try:
            self.fds.append(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
            for part in parts:
                _require(type(part) is str and re.fullmatch('[A-Za-z0-9_.-]{1,255}',part) is not None and part not in ('.','..'))
                parent=self.fds[-1]
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                self.fds.append(child);info=os.fstat(child)
                self.refs.append((parent,part,child,(info.st_dev,info.st_ino)))
            self.verify()
        except BaseException:
            self.close();raise

    def verify(self):
        _require(bool(self.fds))
        for fd in self.fds:
            info=os.fstat(fd)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022)
        for parent,name,child,identity in self.refs:
            named=os.stat(name,dir_fd=parent,follow_symlinks=False);opened=os.fstat(child)
            _require(stat.S_ISDIR(named.st_mode) and named.st_uid==0 and not named.st_mode&0o022 and
                     (named.st_dev,named.st_ino)==identity==(opened.st_dev,opened.st_ino))

    def close(self):
        fds,self.fds=self.fds,[];failure=False
        for fd in reversed(fds):
            try:os.close(fd)
            except OSError:failure=True
        if failure:raise ResourceError('cleanup_unconfirmed')


class RuntimeResources:
    def __new__(cls,*args,**kwargs):raise TypeError('Use fixed resource admission')

    @classmethod
    def fixed(cls):
        _require(cls is RuntimeResources and sys.platform=='linux' and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0))
        value=object.__new__(cls)
        value._cache=None;value._groups=None;value._closed=False;value._poisoned=False;value._identity=None
        try:
            # Verify current membership before opening cache or reading policy.
            validate_membership(_proc('cgroup',4096))
            value._cache=_Chain(('var','cache','command-center-inventory-refresh'))
            value._groups=_Chain(('sys','fs','cgroup')+tuple(SELF_CGROUP.strip('/').split('/')))
            value.sample();return value
        except BaseException as exc:
            value.close()
            raise ResourceError(exc.reason if isinstance(exc,ResourceError) else 'policy_unsupported') from None

    def sample(self):
        try:
            _require(not self._closed and not self._poisoned and self._cache is not None and self._groups is not None)
            validate_membership(_proc('cgroup',4096))
            self._cache.verify();self._groups.verify()
            cache=self._cache.fds[-1];groups=self._groups.fds[3]
            cached=os.fstat(cache);grouped=os.fstat(groups)
            mounts=validate_mounts(_proc('mountinfo',1024*1024),
                cache_device=(os.major(cached.st_dev),os.minor(cached.st_dev)),cache_mount_id=_mount_id(cache),
                cgroup_device=(os.major(grouped.st_dev),os.minor(grouped.st_dev)),cgroup_mount_id=_mount_id(groups))
            identity=mounts+(cached.st_dev,cached.st_ino,grouped.st_dev,grouped.st_ino)
            _require(self._identity is None or self._identity==identity)
            capacity=os.fstatvfs(cache)
            _require(capacity.f_blocks*capacity.f_frsize==CACHE_BYTES and capacity.f_files==INODES,'resource_limit')
            _require({b'memory',b'pids'}<=set(_read(groups,'cgroup.controllers').split()))
            aggregate=self._groups.fds[-2]
            wanted=('memory.max','memory.swap.max','pids.max')
            parent={name:_read(aggregate,name) for name in wanted}
            ancestors=[{name:_read(fd,name) for name in wanted} for fd in self._groups.fds[4:-2]]
            validate_profile(parent,ancestors)
            _require(_read(aggregate,'cgroup.type')==b'domain\n' and _read(self._groups.fds[-1],'cgroup.type')==b'domain\n')
            memory=limit(_read(aggregate,'memory.current'));tasks=limit(_read(aggregate,'pids.current'))
            _require(memory is not None and tasks is not None)
            self._cache.verify();self._groups.verify()
            validate_membership(_proc('cgroup',4096))
            # Mount identity may change without a directory inode changing.
            _require((_mount_id(cache),_mount_id(groups))==mounts)
            _require(validate_mounts(_proc('mountinfo',1024*1024),
                cache_device=(os.major(cached.st_dev),os.minor(cached.st_dev)),cache_mount_id=mounts[0],
                cgroup_device=(os.major(grouped.st_dev),os.minor(grouped.st_dev)),cgroup_mount_id=mounts[1])==mounts)
            final_capacity=os.fstatvfs(cache)
            _require(final_capacity.f_blocks*final_capacity.f_frsize==CACHE_BYTES and final_capacity.f_files==INODES,'resource_limit')
            validate_profile({name:_read(aggregate,name) for name in wanted},
                [{name:_read(fd,name) for name in wanted} for fd in self._groups.fds[4:-2]])
            self._identity=identity
            return {'memory_limit_bytes':MEMORY,'memory_current_bytes':memory,'tasks_limit':TASKS,'tasks_current':tasks,
                'cache_total_bytes':CACHE_BYTES,'cache_free_bytes':capacity.f_bavail*capacity.f_frsize,
                'cache_total_inodes':INODES,'cache_free_inodes':capacity.f_favail}
        except BaseException as exc:
            self._poisoned=True
            raise ResourceError(exc.reason if isinstance(exc,ResourceError) else 'policy_unsupported') from None

    def __enter__(self):
        try:self.sample();return self
        except BaseException:
            self.close();raise

    def __exit__(self,*_):self.close()

    def close(self):
        if self._closed:return
        self._closed=True;failure=False
        for name in ('_groups','_cache'):
            chain=getattr(self,name);setattr(self,name,None)
            if chain is not None:
                try:chain.close()
                except (ValueError,OSError):failure=True
        if failure:raise ResourceError('cleanup_unconfirmed')
