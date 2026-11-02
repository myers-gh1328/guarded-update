"""Readonly reporter parent origin/clock seams, not request or cleanup authority.

Same-UID admitted code remains trusted. Current view/origin checks do not prove
initial host namespaces, selected release provenance, or workload fit.
"""
import re
import os
import pwd
import grp
import stat
import select
import time
from inventory_refresh_resources import mount_rows, _Chain, _proc, _mount_id
from inventory_refresh_reporter_resources import ReporterResources, SELF_CGROUP, validate_identity

BINARY='/usr/local/libexec/command-center-inventory'
MAX_SAFE=9007199254740991


class ParentError(ValueError):
    def __init__(self,reason='state_inconsistent'):
        self.reason=reason
        super().__init__('Reporter parent admission unavailable: '+reason)


def _require(condition):
    if not condition:raise ParentError()


def _pid(value):
    return type(value) is int and 1<value<=2**31-1


def validate_process_view(raw,pid,expected_parent):
    _require(type(raw) is bytes and 0<len(raw)<=65536 and _pid(pid))
    _require(expected_parent is None or _pid(expected_parent))
    needed={b'Pid',b'Tgid',b'PPid',b'NSpid'};fields={}
    for line in raw.splitlines():
        name,separator,value=line.partition(b':')
        if name in needed:
            _require(separator and name not in fields);fields[name]=value.split()
    expected=str(pid).encode()
    _require(set(fields)==needed and all(fields[name]==[expected] for name in (b'Pid',b'Tgid',b'NSpid')))
    raw_parent=fields[b'PPid']
    _require(len(raw_parent)==1 and re.fullmatch(rb'[1-9][0-9]{0,9}',raw_parent[0]) is not None)
    parent=int(raw_parent[0]);_require(parent<=2**31-1)
    _require(expected_parent is None or parent==expected_parent)
    return parent


def validate_accounts(reporter,worker,reader_group,worker_group,uid,gid):
    try:
        values=(reporter.pw_uid,reporter.pw_gid,worker.pw_uid,worker.pw_gid)
        _require(all(type(value) is int and 0<value<2**32-1 for value in (*values,uid,gid)))
        _require(reporter.pw_name=='ccinventory' and worker.pw_name=='ccrefresh' and
            reader_group.gr_name=='ccinventory' and worker_group.gr_name=='ccrefresh')
        _require(type(reader_group.gr_gid) is int and type(worker_group.gr_gid) is int and
            reader_group.gr_gid==reporter.pw_gid and worker_group.gr_gid==worker.pw_gid and
            reporter.pw_uid==uid and reporter.pw_gid==gid and reporter.pw_uid!=worker.pw_uid and reporter.pw_gid!=worker.pw_gid)
        return values
    except AttributeError:raise ParentError() from None


def validate_proc_mounts(raw,*,proc_device,proc_mount_id,parent_pid,self_pid,boot_mount_id):
    _require(_pid(parent_pid) and _pid(self_pid) and parent_pid!=self_pid)
    rows=mount_rows(raw)
    roots=[row for row in rows.values() if row['path']=='/proc']
    _require(len(roots)==1)
    root=roots[0];safe={b'nodev',b'nosuid',b'noexec'}
    _require(root['fs']==b'proc' and root['root']=='/' and root['device']==proc_device and
        root['id']==proc_mount_id and safe<=root['options'])
    blocked=('/proc/'+str(parent_pid),'/proc/'+str(self_pid),'/proc/self','/proc/thread-self',
        '/proc/sys/kernel','/proc/sys/kernel/random','/proc/sys/kernel/random/boot_id')
    _require(not any(row['path']==prefix or row['path'].startswith(prefix+'/') for row in rows.values() for prefix in blocked))
    systems=[row for row in rows.values() if row['path']=='/proc/sys']
    _require(len(systems)<=1)
    if systems:
        system=systems[0]
        _require(system['fs']==b'proc' and system['root']=='/sys' and system['device']==proc_device and
            system['parent']==root['id'] and safe|{b'ro'}<=system['options'])
        expected=system['id']
    else:expected=root['id']
    _require(boot_mount_id==expected)
    return root['id'],expected


def _stable(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,
        info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _accounts():
    reader=pwd.getpwnam('ccinventory');worker=pwd.getpwnam('ccrefresh')
    values=validate_accounts(reader,worker,grp.getgrnam('ccinventory'),grp.getgrnam('ccrefresh'),
        os.getresuid()[0],os.getresgid()[0])
    _require(validate_accounts(pwd.getpwuid(values[0]),pwd.getpwuid(values[2]),
        grp.getgrgid(values[1]),grp.getgrgid(values[3]),values[0],values[1])==values)
    return values


def _now():
    value=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000
    _require(type(value) is int and 0<=value<=MAX_SAFE)
    return value


class ReporterParent:
    def __new__(cls,*args,**kwargs):raise TypeError('Use fixed reporter parent admission')

    @classmethod
    def fixed(cls):
        _require(cls is ReporterParent)
        value=object.__new__(cls)
        value._closed=False;value._poisoned=False;value._last=None;value._boot_id=None
        for name in value._owned_names():setattr(value,name,None)
        try:
            value._resources=ReporterResources.fixed()
            value._self_pid=os.getpid();value._parent_pid=os.getppid()
            _require(_pid(value._self_pid) and _pid(value._parent_pid) and hasattr(os,'pidfd_open'))
            value._pidfd=os.pidfd_open(value._parent_pid,0);value._alive()
            value._proc_dirs=_Chain(('proc',))
            value._proc_device=os.fstat(value._proc_dirs.fds[-1]).st_dev
            value._proc_mount=_mount_id(value._proc_dirs.fds[-1])
            value._topology()
            _require(os.readlink('self',dir_fd=value._proc_dirs.fds[-1])==str(value._self_pid))
            value._self_proc=value._open_process(value._self_pid)
            validate_process_view(value._read_process(value._self_proc,'status',65536),value._self_pid,value._parent_pid)
            value._ids=_accounts()
            value._parent_proc=value._open_process(value._parent_pid)
            value._installed_dirs=_Chain(('usr','local','libexec'))
            value._installed=os.open('command-center-inventory',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value._installed_dirs.fds[-1])
            value._binary=value._binary_identity(os.fstat(value._installed))
            value._executable=os.open('exe',os.O_RDONLY|os.O_NONBLOCK,dir_fd=value._parent_proc)
            _require(_stable(os.fstat(value._executable))==value._binary)
            value._boot_dirs=_Chain(('proc','sys','kernel','random'))
            value._boot_fd=os.open('boot_id',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value._boot_dirs.fds[-1])
            value._topology()
            value.verify()
            return value
        except BaseException as exc:
            value.close()
            raise ParentError(value._reason(exc)) from None

    @staticmethod
    def _owned_names():
        return ('_resources','_pidfd','_proc_dirs','_self_proc','_parent_proc','_installed_dirs','_installed',
            '_executable','_boot_dirs','_boot_fd')

    @staticmethod
    def _reason(error):
        reason=getattr(error,'reason',None)
        return reason if reason in ('policy_unsupported','resource_limit','cleanup_unconfirmed') else 'state_inconsistent'

    def _alive(self):
        _require(not self._closed and not self._poisoned and self._pidfd is not None and
            os.getpid()==self._self_pid and os.getppid()==self._parent_pid)
        watch=select.poll();watch.register(self._pidfd,select.POLLIN|select.POLLERR|select.POLLHUP)
        _require(not watch.poll(0))

    def _topology(self):
        self._proc_dirs.verify()
        raw=_proc('mountinfo',1024*1024)
        if self._boot_fd is None:
            systems=[row for row in mount_rows(raw).values() if row['path']=='/proc/sys']
            boot_mount=systems[0]['id'] if len(systems)==1 else self._proc_mount
        else:boot_mount=_mount_id(self._boot_fd)
        validate_proc_mounts(raw,proc_device=(os.major(self._proc_device),os.minor(self._proc_device)),
            proc_mount_id=self._proc_mount,parent_pid=self._parent_pid,self_pid=self._self_pid,boot_mount_id=boot_mount)
        _require(os.fstat(self._proc_dirs.fds[-1]).st_dev==self._proc_device and
            _mount_id(self._proc_dirs.fds[-1])==self._proc_mount)

    def _open_process(self,pid):
        fd=os.open(str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._proc_dirs.fds[-1])
        try:
            info=os.fstat(fd)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getresuid()[0] and
                not info.st_mode&0o022 and info.st_dev==self._proc_device and _mount_id(fd)==self._proc_mount)
            return fd
        except BaseException:
            try:os.close(fd)
            except OSError:raise ParentError('cleanup_unconfirmed') from None
            raise

    def _read_process(self,directory,name,maximum):
        _require(name in ('status','cgroup'))
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            before=os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getresuid()[0] and
                not before.st_mode&0o022 and before.st_dev==self._proc_device and _mount_id(fd)==self._proc_mount)
            raw=bytearray()
            while True:
                chunk=os.read(fd,min(65536,maximum+1-len(raw)))
                if not chunk:break
                raw.extend(chunk);_require(len(raw)<=maximum)
            _require(_stable(before)==_stable(os.fstat(fd))==_stable(os.stat(name,dir_fd=directory,follow_symlinks=False)))
            return bytes(raw)
        finally:
            try:os.close(fd)
            except OSError:raise ParentError('cleanup_unconfirmed') from None

    @staticmethod
    def _binary_identity(info):
        _require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o6022 and
            bool(info.st_mode&0o111) and info.st_nlink==1 and 0<info.st_size<=128*1024*1024)
        return _stable(info)

    def _current_executable(self):
        # The sole intentional follow: literal Kernel exe in a pinned, derived,
        # admitted live-parent proc directory. Never a caller-selected symlink.
        _require(os.readlink('exe',dir_fd=self._parent_proc)==BINARY)
        fd=os.open('exe',os.O_RDONLY|os.O_NONBLOCK,dir_fd=self._parent_proc)
        try:
            _require(_stable(os.fstat(fd))==self._binary and os.readlink('exe',dir_fd=self._parent_proc)==BINARY)
        finally:
            try:os.close(fd)
            except OSError:raise ParentError('cleanup_unconfirmed') from None

    def clock(self):
        try:
            self._alive()
            raw=os.pread(self._boot_fd,65,0)
            _require(re.fullmatch(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n',raw) is not None)
            boot=raw[:-1].decode('ascii');now=_now()
            _require((self._boot_id is None or boot==self._boot_id) and (self._last is None or now>=self._last))
            self._alive()
            self._boot_id=boot;self._last=now
            return boot,now
        except BaseException as exc:
            self._poisoned=True
            raise ParentError(self._reason(exc)) from None

    def verify(self):
        try:
            self._alive();self._resources.sample();self._topology()
            _require(_accounts()==self._ids)
            _require(os.readlink('self',dir_fd=self._proc_dirs.fds[-1])==str(self._self_pid))
            for directory,pid,expected in ((self._self_proc,self._self_pid,self._parent_pid),(self._parent_proc,self._parent_pid,None)):
                raw=self._read_process(directory,'status',65536)
                validate_process_view(raw,pid,expected);validate_identity(raw,self._ids[0],self._ids[1])
                _require(self._read_process(directory,'cgroup',4096)==('0::'+SELF_CGROUP+'\n').encode())
                _require(_mount_id(directory)==self._proc_mount)
            self._installed_dirs.verify();self._boot_dirs.verify()
            _require(self._binary_identity(os.fstat(self._installed))==self._binary and
                self._binary_identity(os.stat('command-center-inventory',dir_fd=self._installed_dirs.fds[-1],follow_symlinks=False))==self._binary and
                _stable(os.fstat(self._executable))==self._binary)
            self._current_executable()
            boot=os.fstat(self._boot_fd)
            _require(stat.S_ISREG(boot.st_mode) and boot.st_uid==0 and not boot.st_mode&0o022 and boot.st_dev==self._proc_device and
                _stable(boot)==_stable(os.stat('boot_id',dir_fd=self._boot_dirs.fds[-1],follow_symlinks=False)))
            self.clock();self._topology();self._proc_dirs.verify();self._installed_dirs.verify();self._boot_dirs.verify()
            self._current_executable();self._alive()
        except BaseException as exc:
            self._poisoned=True
            raise ParentError(self._reason(exc)) from None

    def close(self):
        if self._closed:return
        self._closed=True;failed=False
        for name in reversed(self._owned_names()):
            owned=getattr(self,name,None);setattr(self,name,None)
            if owned is not None:
                try:
                    if name.endswith('_dirs') or name=='_resources':owned.close()
                    else:os.close(owned)
                except BaseException:failed=True
        if failed:raise ParentError('cleanup_unconfirmed')
