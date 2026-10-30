"""Protected cooperative maintenance lock; no process-cleanup authority.

Unregistered prerequisite. Every producer must cooperate, and caller-owned
ancestry/exclusive mutation are assumptions. Never unlock an inherited open
file description: close once, so a descendant retaining it keeps the lock held.
"""
import fcntl
import os
import pwd
import stat
import sys

from inventory_refresh_observation import _Ancestry

ERROR='Inventory maintenance lock unavailable'
NAME='maintenance.lock'
GATE='admission.lock'


class MaintenanceContended(ValueError):
    """A nonblocking lock was held by another owner; no acquisition occurred."""


def _metadata(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


class MaintenanceLock:
    @classmethod
    def fixed(cls,mode):
        """Open only the preprovisioned fixed Linux lock; never create it."""
        if sys.platform!='linux' or mode not in ('participant','maintenance'):
            raise ValueError(ERROR)
        root=None;ancestry=None;value=None;failed=False
        try:
            uid=os.geteuid();gid=os.getegid()
            account=pwd.getpwnam('ccinventory')
            if (account.pw_uid<=0 or account.pw_gid<=0 or
                (mode=='maintenance' and (uid,gid)!=(0,0)) or
                (mode=='participant' and (uid,gid) not in ((0,0),(account.pw_uid,account.pw_gid))) or
                os.getresuid()!=(uid,uid,uid) or os.getresgid()!=(gid,gid,gid)):
                raise ValueError(ERROR)
            root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
            ancestry=_Ancestry.open(root,('run','command-center-inventory-refresh'))
            value=cls.from_directory(ancestry.fds[-1],mode,0,0,ancestry.verify)
            value._ancestry=ancestry;ancestry=None
        except BaseException:failed=True
        finally:
            if root is not None:
                try:os.close(root)
                except OSError:failed=True
            if ancestry is not None:
                try:ancestry.close()
                except BaseException:failed=True
        if failed:
            if value is not None:
                try:value.close()
                except BaseException:pass
            raise ValueError(ERROR)
        return value

    @classmethod
    def from_directory(cls,directory,mode,owner,group,verify_ancestry=lambda:None,*,name=NAME):
        """Private seam; caller pins ancestry and prevents concurrent mutation."""
        value=cls();value._fds=[];value._closed=False;value._failed=False;value._ancestry=None
        try:
            if cls is not MaintenanceLock or mode not in ('participant','maintenance') or name not in (NAME,GATE) or type(owner) is not int or type(group) is not int:
                raise ValueError(ERROR)
            value._name=name
            value._owner=owner;value._group=group;value._mode=mode;value._verify_ancestry=verify_ancestry
            value._inheritable=False;value._exported=False
            value._directory=os.dup(directory);value._fds.append(value._directory)
            parent=os.fstat(value._directory)
            if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=owner or parent.st_mode&0o022:
                raise ValueError(ERROR)
            value._parent_identity=(parent.st_dev,parent.st_ino,parent.st_mode,parent.st_uid,parent.st_gid)
            value._file=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value._directory)
            value._fds.append(value._file)
            value._identity=_metadata(os.fstat(value._file))
            value.verify()
            try:fcntl.flock(value._file,(fcntl.LOCK_SH if mode=='participant' else fcntl.LOCK_EX)|fcntl.LOCK_NB)
            except BlockingIOError:
                value.close()
                raise MaintenanceContended(ERROR) from None
            value.verify()
            return value
        except MaintenanceContended:
            raise
        except BaseException:
            value._failed=True
            try:value.close()
            except BaseException:pass
            raise ValueError(ERROR) from None

    def verify(self):
        try:
            if self._closed or self._failed:raise ValueError(ERROR)
            self._verify_ancestry()
            parent=os.fstat(self._directory)
            if os.get_inheritable(self._directory) or os.get_inheritable(self._file)!=self._inheritable:
                raise ValueError(ERROR)
            flags=fcntl.fcntl(self._file,fcntl.F_GETFL)
            if flags&os.O_ACCMODE!=os.O_RDONLY or not flags&os.O_NONBLOCK:
                raise ValueError(ERROR)
            if (parent.st_dev,parent.st_ino,parent.st_mode,parent.st_uid,parent.st_gid)!=self._parent_identity:
                raise ValueError(ERROR)
            held=os.fstat(self._file);named=os.stat(self._name,dir_fd=self._directory,follow_symlinks=False)
            if (not stat.S_ISREG(held.st_mode) or held.st_uid!=self._owner or held.st_gid!=self._group or
                stat.S_IMODE(held.st_mode)!=0o644 or held.st_nlink!=1 or held.st_size!=0 or
                held.st_dev!=parent.st_dev or _metadata(held)!=self._identity or _metadata(named)!=self._identity):
                raise ValueError(ERROR)
            self._verify_ancestry()
        except BaseException:
            self._failed=True
            raise ValueError(ERROR) from None

    def inheritable_fd(self):
        """Retain the shared description across an immediate owned exec.

        Caller excludes concurrent process creation until exec or close.
        """
        try:
            if self._mode!='participant' or self._name!=NAME or self._exported:raise ValueError(ERROR)
            self.verify();self._exported=True;os.set_inheritable(self._file,True);self._inheritable=True
            if not os.get_inheritable(self._file):raise ValueError(ERROR)
            self.verify();return self._file
        except BaseException:
            self._failed=True
            raise ValueError(ERROR) from None

    def close(self):
        if self._closed:
            if self._failed:raise ValueError(ERROR)
            return
        try:self.verify()
        except BaseException:self._failed=True
        self._closed=True
        for fd in reversed(self._fds):
            try:os.close(fd)
            except OSError:self._failed=True
        self._fds=[]
        ancestry,self._ancestry=self._ancestry,None
        if ancestry is not None:
            try:ancestry.close()
            except BaseException:self._failed=True
        if self._failed:raise ValueError(ERROR)


class MaintenanceAdmission:
    """Unregistered cooperative two-lock protocol; no readiness authority.

    No built-in deadline: a future maintenance owner must bound drain and
    preserve uncertainty on timeout. All producers must cooperate.
    """
    @staticmethod
    def participant(directory,owner,group,verify_ancestry=lambda:None):
        gate=MaintenanceLock.from_directory(directory,'participant',owner,group,verify_ancestry,name=GATE)
        try:
            lifetime=MaintenanceLock.from_directory(directory,'participant',owner,group,verify_ancestry)
        except MaintenanceContended:
            gate.close()
            raise
        # On ambiguity, retain descriptors; process exit is the final fallback.
        if gate._identity[:2]==lifetime._identity[:2]:raise ValueError(ERROR)
        gate.verify();lifetime.verify();gate.close()
        return lifetime

    @classmethod
    def maintenance(cls,directory,owner,group,verify_ancestry=lambda:None):
        value=cls();value._owner=owner;value._group=group
        value._verify_ancestry=verify_ancestry;value._lifetime=None;value._failed=False;value._closed=False
        value._gate=MaintenanceLock.from_directory(directory,'maintenance',owner,group,verify_ancestry,name=GATE)
        value._directory=value._gate._directory
        return value

    def try_lifetime(self):
        if self._closed or self._failed or self._lifetime is not None:raise ValueError(ERROR)
        try:
            self._gate.verify()
            try:
                lifetime=MaintenanceLock.from_directory(self._directory,'maintenance',self._owner,self._group,self._verify_ancestry)
            except MaintenanceContended:
                self._gate.verify()
                return False
            self._lifetime=lifetime
            if self._gate._identity[:2]==lifetime._identity[:2]:raise ValueError(ERROR)
            lifetime.verify();self._gate.verify()
            return True
        except BaseException:
            self._failed=True
            raise ValueError(ERROR) from None

    def close(self):
        if self._closed:
            if self._failed:raise ValueError(ERROR)
            return
        self._closed=True
        if self._failed:raise ValueError(ERROR)
        try:
            if self._lifetime is not None:self._lifetime.close()
            self._gate.close()
        except BaseException:
            self._failed=True
            raise ValueError(ERROR) from None
