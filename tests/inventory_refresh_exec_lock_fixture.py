"""Disposable held-FD reporter lifetime lock, not maintenance inhibition."""
import os
import stat

DIRECTORY='inventory-held-fd-fixture'
FILE='maintenance.lock'
ERROR='Synthetic exec lock unavailable'


def _identity(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
def _metadata(info):return _identity(info)+(info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


class ExecLock:
    @classmethod
    def create(cls,parent,owner,group,verify_parent):
        value=cls();value.fds=[];value.identities={};value.closed=False;value.close_failed=False;value.failed=False
        value.verify_parent=verify_parent;value.owner=owner;value.group=group
        try:
            value.parent=os.dup(parent);value.fds.append(value.parent)
            info=os.fstat(value.parent)
            value.identities[value.parent]=(info.st_dev,info.st_ino)
            if not stat.S_ISDIR(info.st_mode) or (info.st_uid,info.st_gid)!=(owner,group) or info.st_mode&0o022:raise ValueError(ERROR)
            value.parent_identity=_identity(info);verify_parent()
            os.mkdir(DIRECTORY,0o755,dir_fd=value.parent);os.fsync(value.parent)
            value.directory=os.open(DIRECTORY,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value.parent)
            value.fds.append(value.directory);os.fchmod(value.directory,0o755)
            info=os.fstat(value.directory);value.dir_identity=_identity(info)
            value.identities[value.directory]=(info.st_dev,info.st_ino)
            if (not stat.S_ISDIR(info.st_mode) or (info.st_uid,info.st_gid)!=(owner,group) or
                stat.S_IMODE(info.st_mode)!=0o755 or info.st_dev!=value.parent_identity[0]):raise ValueError(ERROR)
            fd=os.open(FILE,os.O_RDONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o644,dir_fd=value.directory)
            value.file=fd;value.fds.append(fd);os.fchmod(fd,0o644)
            info=os.fstat(fd);value.file_metadata=_metadata(info)
            value.identities[fd]=(info.st_dev,info.st_ino)
            if (not stat.S_ISREG(info.st_mode) or (info.st_uid,info.st_gid)!=(owner,group) or
                stat.S_IMODE(info.st_mode)!=0o644 or info.st_nlink!=1 or info.st_size!=0 or info.st_dev!=value.dir_identity[0]):raise ValueError(ERROR)
            os.fsync(fd);os.fsync(value.directory);os.fsync(value.parent);value.verify()
            return value
        except BaseException:
            try:value.close()
            except BaseException:pass
            raise ValueError(ERROR) from None

    def verify(self):
        try:
            if self.closed or self.failed:raise ValueError(ERROR)
            self.verify_parent()
            if _identity(os.fstat(self.parent))!=self.parent_identity:raise ValueError(ERROR)
            if _identity(os.fstat(self.directory))!=self.dir_identity or _identity(os.stat(DIRECTORY,dir_fd=self.parent,follow_symlinks=False))!=self.dir_identity:raise ValueError(ERROR)
            if _metadata(os.fstat(self.file))!=self.file_metadata or _metadata(os.stat(FILE,dir_fd=self.directory,follow_symlinks=False))!=self.file_metadata:raise ValueError(ERROR)
            self.verify_parent()
        except BaseException:
            self.failed=True;raise ValueError(ERROR) from None

    def close(self):
        if self.closed:
            if self.close_failed or self.failed:raise ValueError(ERROR)
            return
        self.closed=True
        for fd in reversed(self.fds):
            try:
                info=os.fstat(fd)
                if self.identities.get(fd)!=(info.st_dev,info.st_ino):
                    self.close_failed=True;continue
                os.close(fd)
            except OSError:self.close_failed=True
        self.fds=[]
        if self.close_failed or self.failed:raise ValueError(ERROR)
