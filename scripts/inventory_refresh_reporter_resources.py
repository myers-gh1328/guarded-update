"""Current readonly reporter resources, not NSS/provenance/startup/fit proof.

No commands, mutable resource controls, private contents, source execution or
native completion authority. Root's separate RW sampler remains unchanged.
"""
import os
import sys

from inventory_refresh_resources import (CACHE, AGGREGATE, MEMORY, CACHE_BYTES, INODES, TASKS,
    mount_rows, ResourceError, validate_profile, limit, _Chain, _read, _proc, _mount_id)

SELF_CGROUP=AGGREGATE+'/command-center-inventory.service'


def _require(condition,reason='policy_unsupported'):
    if not condition:raise ResourceError(reason)


def validate_identity(raw,uid,gid):
    _require(type(raw) is bytes and 0<len(raw)<=65536 and type(uid) is int and type(gid) is int and
        0<uid<2**32-1 and 0<gid<2**32-1)
    needed={b'Uid',b'Gid',b'Groups',b'NoNewPrivs',b'CapInh',b'CapPrm',b'CapEff',b'CapBnd',b'CapAmb'}
    fields={}
    for line in raw.splitlines():
        key,separator,value=line.partition(b':')
        if key in needed:
            _require(separator and key not in fields);fields[key]=value.split()
    _require(set(fields)==needed and fields[b'Uid']==[str(uid).encode()]*4 and fields[b'Gid']==[str(gid).encode()]*4 and
        fields[b'Groups'] in ([],[str(gid).encode()]) and fields[b'NoNewPrivs']==[b'1'])
    _require(all(fields[key]==[b'0000000000000000'] for key in needed if key.startswith(b'Cap')))
    return uid,gid


def _profile():
    uids=os.getresuid();gids=os.getresgid()
    _require(len(set(uids))==len(set(gids))==1)
    with open('/proc/self/status','rb') as source:raw=source.read(65537)
    return validate_identity(raw,uids[0],gids[0])


def validate_membership(raw):
    _require(raw==('0::'+SELF_CGROUP+'\n').encode())


def validate_mounts(raw,*,cache_device,cache_mount_id,cgroup_device,cgroup_mount_id):
    rows=mount_rows(raw)
    cache=[row for row in rows.values() if row['path']==CACHE]
    groups=[row for row in rows.values() if row['path']=='/sys/fs/cgroup']
    _require(len(cache) in (1,2) and len(groups)==1)
    _require(all(row['fs']==b'tmpfs' and row['root']=='/' and row['device']==cache_device and
        {b'nodev',b'nosuid',b'noexec'}<=row['options'] for row in cache))
    visible=[row for row in cache if row['id']==cache_mount_id]
    _require(len(visible)==1 and b'ro' in visible[0]['options'])
    if len(cache)==2:
        lower=next(row for row in cache if row['id']!=cache_mount_id)
        _require(visible[0]['parent']==lower['id'] and lower['parent'] not in {row['id'] for row in cache})
    count=len(cache);cache=visible[0];groups=groups[0]
    _require(groups['fs']==b'cgroup2' and groups['root']=='/' and groups['device']==cgroup_device and groups['id']==cgroup_mount_id)
    _require(not any(row['path'].startswith(CACHE+'/') for row in rows.values()))
    _require(sum(row['device']==cache_device for row in rows.values())==count)
    return cache['id'],groups['id']


class ReporterResources:
    def __new__(cls,*args,**kwargs):raise TypeError('Use fixed reporter resource admission')

    @classmethod
    def fixed(cls):
        _require(cls is ReporterResources and sys.platform=='linux')
        value=object.__new__(cls)
        value._cache=None;value._groups=None;value._closed=False;value._poisoned=False;value._identity=None;value._ids=None
        try:
            value._ids=_profile()
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
            _require(_profile()==self._ids)
            validate_membership(_proc('cgroup',4096))
            self._cache.verify();self._groups.verify()
            cache=self._cache.fds[-1];groups=self._groups.fds[3]
            cached=os.fstat(cache);grouped=os.fstat(groups)
            arguments=dict(cache_device=(os.major(cached.st_dev),os.minor(cached.st_dev)),cache_mount_id=_mount_id(cache),
                cgroup_device=(os.major(grouped.st_dev),os.minor(grouped.st_dev)),cgroup_mount_id=_mount_id(groups))
            mounts=validate_mounts(_proc('mountinfo',1024*1024),**arguments)
            identity=mounts+(cached.st_dev,cached.st_ino,grouped.st_dev,grouped.st_ino)
            _require(self._identity is None or self._identity==identity)
            capacity=os.fstatvfs(cache);self._capacity(capacity)
            _require({b'memory',b'pids'}<=set(_read(groups,'cgroup.controllers').split()))
            aggregate=self._groups.fds[-2];wanted=('memory.max','memory.swap.max','pids.max')
            validate_profile({name:_read(aggregate,name) for name in wanted},
                [{name:_read(fd,name) for name in wanted} for fd in self._groups.fds[4:-2]])
            _require(_read(aggregate,'cgroup.type')==b'domain\n' and _read(self._groups.fds[-1],'cgroup.type')==b'domain\n')
            memory=limit(_read(aggregate,'memory.current'));tasks=limit(_read(aggregate,'pids.current'))
            _require(memory is not None and tasks is not None)
            self._cache.verify();self._groups.verify()
            _require((_mount_id(cache),_mount_id(groups))==mounts)
            _require(validate_mounts(_proc('mountinfo',1024*1024),**arguments)==mounts)
            self._capacity(os.fstatvfs(cache))
            validate_profile({name:_read(aggregate,name) for name in wanted},
                [{name:_read(fd,name) for name in wanted} for fd in self._groups.fds[4:-2]])
            _require(_profile()==self._ids)
            validate_membership(_proc('cgroup',4096))
            self._identity=identity
            return {'memory_limit_bytes':MEMORY,'memory_current_bytes':memory,'tasks_limit':TASKS,'tasks_current':tasks,
                'cache_total_bytes':CACHE_BYTES,'cache_free_bytes':capacity.f_bavail*capacity.f_frsize,
                'cache_total_inodes':INODES,'cache_free_inodes':capacity.f_favail}
        except BaseException as exc:
            self._poisoned=True
            raise ResourceError(exc.reason if isinstance(exc,ResourceError) else 'policy_unsupported') from None

    @staticmethod
    def _capacity(capacity):
        _require(capacity.f_blocks*capacity.f_frsize==CACHE_BYTES and capacity.f_files==INODES,'resource_limit')
        _require(bool(capacity.f_flag&os.ST_RDONLY))

    def close(self):
        if self._closed:return
        self._closed=True;failed=False
        for name in ('_groups','_cache'):
            chain=getattr(self,name);setattr(self,name,None)
            if chain is not None:
                try:chain.close()
                except BaseException:failed=True
        if failed:raise ResourceError('cleanup_unconfirmed')
