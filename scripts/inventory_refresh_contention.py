"""Advisory metadata-refresh contention view; acquires NO kernel file locks.

Trusted host PID/proc provenance is a provisioning prerequisite. This bounded
view is not an atomic interlock; coherent collection still uses guarded locks.
"""
import os
import re
import stat
import sys

from inventory_refresh_observation import (_Ancestry,_file,_stable,_identity,_before_deadline,
    _NATIVE_OWNER,ObservationError)
from inventory_refresh_resources import mount_rows,_mount_id,_proc
from inventory_refresh_writer_exclusion import proc_mount

LIMIT=1024*1024
MAX_RECORDS=8192
MAX_NUMBER=2**64-1


def _require(value):
    if not value:raise ObservationError('policy_unsupported')


def _decimal(raw,*,positive=False):
    _require(re.fullmatch(rb'(0|[1-9][0-9]{0,19})',raw) is not None)
    value=int(raw);_require(value<=MAX_NUMBER and (not positive or value>0));return value


def contention(raw,packages,executor):
    _require(type(raw) is bytes and len(raw)<=LIMIT and (not raw or raw.endswith(b'\n')))
    records=raw.splitlines();_require(len(records)<=MAX_RECORDS)
    busy=set()
    for line in records:
        fields=line.split()
        _require(fields and re.fullmatch(rb'[1-9][0-9]{0,19}:',fields[0]) is not None)
        if len(fields)>1 and fields[1]==b'->':fields=fields[:1]+fields[2:]
        _require(len(fields)==8)
        _,kind,advisory,mode,pid,key,start,end=fields
        # Unknown leases/delegations/mandatory records never become "clear".
        _require(kind in (b'POSIX',b'OFDLCK',b'FLOCK') and advisory==b'ADVISORY' and mode in (b'READ',b'WRITE'))
        if kind==b'OFDLCK':_require(pid==b'-1')
        else:_require(0<_decimal(pid)<=2**31-1)
        parts=key.split(b':')
        _require(len(parts)==3 and all(re.fullmatch(rb'[0-9a-f]{1,8}',part) for part in parts[:2]))
        identity=(int(parts[0],16),int(parts[1],16),_decimal(parts[2],positive=True))
        first=_decimal(start);last=MAX_NUMBER if end==b'EOF' else _decimal(end)
        _require(first<=last and (kind!=b'FLOCK' or first==0 and end==b'EOF'))
        if mode==b'WRITE':
            if kind in (b'POSIX',b'OFDLCK') and identity in packages:busy.add('package_manager_busy')
            if kind==b'FLOCK' and identity==executor:busy.add('executor_busy')
    return 'executor_busy' if 'executor_busy' in busy else 'package_manager_busy' if busy else None


class ContentionProbe:
    def __init__(self,dpkg,runtime,proc,*,deadline_ms=None,now=None,owner=0):
        self._fds=[];self._refs=[];self._ancestries=[];self._closed=False;self._process_owned=False
        self._owner=owner;self._deadline=deadline_ms;self._now=now
        try:
            _before_deadline(deadline_ms,now)
            # Closing any descriptor for a POSIX lock inode could release this
            # process's existing locks. Only a process-local mutex is held here.
            if not _NATIVE_OWNER.acquire(blocking=False):raise ObservationError('busy')
            self._process_owned=True
            self._dpkg=self._own(os.dup(dpkg));self._runtime=self._own(os.dup(runtime));self._proc=self._own(os.dup(proc))
            for fd in self._fds:self._directory(fd)
            _require(hasattr(os,'O_PATH'))
            for directory,name in ((self._dpkg,'lock-frontend'),(self._dpkg,'lock'),(self._runtime,'guarded-update-executor.lock')):
                fd=self._own(os.open(name,os.O_PATH|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory))
                _file(fd,owner);self._refs.append((directory,name,fd,os.fstat(fd)))
            self._locks=self._own(os.open('locks',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._proc))
            _file(self._locks,owner);self._proc_info=os.fstat(self._locks)
            self.check()
        except BaseException as error:
            try:self.close()
            except BaseException:raise ObservationError('cleanup_unconfirmed') from None
            raise ObservationError(error.reason if isinstance(error,ObservationError) else 'policy_unsupported') from None

    def __repr__(self):return '<ContentionProbe read-only kernel view>'

    @classmethod
    def fixed(cls,*,deadline_ms=None,now=None):
        _require(sys.platform=='linux' and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0) and hasattr(os,'O_PATH'))
        root=None;ancestries=[];value=None
        try:
            root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            for parts in (('var','lib','dpkg'),('run',),('proc',)):
                ancestries.append(_Ancestry.open(root,parts))
            value=cls(*(item.fds[-1] for item in ancestries),deadline_ms=deadline_ms,now=now)
            value._ancestries=ancestries;ancestries=[];value._verify();return value
        except BaseException:
            if value is not None:value.close()
            raise
        finally:
            failure=False
            if root is not None:
                try:os.close(root)
                except OSError:failure=True
            for ancestry in ancestries:
                try:ancestry.close()
                except (OSError,ValueError):failure=True
            if failure:
                if value is not None:value.close()
                raise ObservationError('cleanup_unconfirmed') from None

    def _own(self,fd):self._fds.append(fd);return fd

    def _directory(self,fd):
        info=os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid==self._owner and not info.st_mode&0o022)

    def _view(self):
        root=os.fstat(self._proc);raw=_proc('mountinfo',LIMIT);identifier=_mount_id(self._proc)
        proc_mount(raw,mount_id=identifier,device=(os.major(root.st_dev),os.minor(root.st_dev)))
        _require(os.fstat(self._locks).st_dev==root.st_dev and _mount_id(self._locks)==identifier)
        rows=mount_rows(raw)
        for _,_,fd,info in self._refs:
            row=rows.get(_mount_id(fd))
            _require(row is not None and row['fs'] in (b'ext4',b'tmpfs') and
                     row['device']==(os.major(info.st_dev),os.minor(info.st_dev)))

    def _verify(self):
        _require(not self._closed and self._process_owned)
        _before_deadline(self._deadline,self._now)
        for ancestry in self._ancestries:ancestry.verify()
        for fd in (self._dpkg,self._runtime,self._proc):self._directory(fd)
        for directory,name,fd,info in self._refs:
            _file(fd,self._owner)
            _require(_stable(info)==_stable(os.fstat(fd))==_stable(os.stat(name,dir_fd=directory,follow_symlinks=False)))
        _file(self._locks,self._owner)
        _require(_stable(self._proc_info)==_stable(os.fstat(self._locks))==
                 _stable(os.stat('locks',dir_fd=self._proc,follow_symlinks=False)))
        self._view()

    def check(self):
        self._verify();os.lseek(self._locks,0,os.SEEK_SET);raw=bytearray()
        while True:
            _before_deadline(self._deadline,self._now)
            chunk=os.read(self._locks,min(65536,LIMIT+1-len(raw)))
            if not chunk:break
            raw.extend(chunk);_require(len(raw)<=LIMIT)
        self._verify()
        keys=[(os.major(info.st_dev),os.minor(info.st_dev),info.st_ino) for _,_,_,info in self._refs]
        reason=contention(bytes(raw),set(keys[:2]),keys[2])
        if reason is not None:raise ObservationError(reason)

    def close(self):
        if self._closed:return
        self._closed=True;failure=False
        fds,self._fds=self._fds,[]
        for fd in reversed(fds):
            try:os.close(fd)
            except OSError:failure=True
        ancestries,self._ancestries=self._ancestries,[]
        for ancestry in ancestries:
            try:ancestry.close()
            except (OSError,ValueError):failure=True
        if failure:
            # Prevent this process later acquiring native locks while an old
            # descriptor's disposition is uncertain. No kernel lock is held.
            raise ObservationError('cleanup_unconfirmed') from None
        if self._process_owned:self._process_owned=False;_NATIVE_OWNER.release()
