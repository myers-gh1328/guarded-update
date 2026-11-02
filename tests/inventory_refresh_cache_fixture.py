"""Disposable hosted tmpfs fixture; never unmounts or claims cleanup."""
import math
import os
import stat
import subprocess
import sys
import time

NAME='command-center-inventory-refresh'
PATH='/var/cache/'+NAME
ERROR='Synthetic reporter cache unavailable'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}


def _identity(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)


def _mount(deadline):
    if time.monotonic()>=deadline:raise ValueError(ERROR)
    child=subprocess.Popen(['/bin/mount','-t','tmpfs','-o','size=128m,nr_inodes=32768,mode=0755,nodev,nosuid,noexec','tmpfs',PATH],
        env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    while child.poll() is None:
        if time.monotonic()>=deadline:raise ValueError(ERROR)
        time.sleep(.01)
    if child.returncode!=0 or time.monotonic()>=deadline:raise ValueError(ERROR)


def _verify_mount(fd):
    from inventory_refresh_resources import _mount_id,_proc,mount_rows
    info=os.fstat(fd);capacity=os.fstatvfs(fd);identifier=_mount_id(fd)
    rows=mount_rows(_proc('mountinfo',1024*1024));row=rows.get(identifier)
    if (row is None or row['path']!=PATH or row['root']!='/' or row['fs']!=b'tmpfs' or
        row['device']!=(os.major(info.st_dev),os.minor(info.st_dev)) or
        not {b'rw',b'nodev',b'nosuid',b'noexec'}<=row['options'] or
        sum(item['path']==PATH for item in rows.values())!=1 or
        capacity.f_blocks*capacity.f_frsize!=128*1024*1024 or capacity.f_files!=32768):raise ValueError(ERROR)
    return (info.st_dev,info.st_ino,identifier)


class CacheFixture:
    @classmethod
    def fixed(cls,deadline):
        if sys.platform!='linux' or os.getresuid()!=(0,0,0) or os.getresgid()!=(0,0,0) or os.environ.get('GITHUB_ACTIONS')!='true':raise ValueError(ERROR)
        from inventory_refresh_resources import _Chain,_proc,mount_rows
        chain=None;value=None
        try:
            if any(row['path']==PATH for row in mount_rows(_proc('mountinfo',1024*1024)).values()):raise ValueError(ERROR)
            chain=_Chain(('var','cache'));chain.verify()
            value=cls._create(chain.fds[-1],0,chain.verify,deadline,_mount,_verify_mount)
            value.chain=chain;chain=None;value.verify();return value
        except BaseException:
            if value is not None:
                try:value.close()
                except BaseException:pass
            raise ValueError(ERROR) from None
        finally:
            if chain is not None:chain.close()

    @classmethod
    def _create(cls,parent,owner,verify_parent,deadline,mount,verify_mount):
        value=cls();value.fds=[];value.identities={};value.closed=False;value.failed=False;value.close_failed=False;value.chain=None
        try:
            if type(deadline) not in (int,float) or not math.isfinite(deadline) or time.monotonic()>=deadline:raise ValueError(ERROR)
            value.deadline=deadline;value.verify_parent=verify_parent;value.verify_mount=verify_mount
            value.parent=os.dup(parent);value.fds.append(value.parent)
            info=os.fstat(value.parent);value.identities[value.parent]=(info.st_dev,info.st_ino)
            if not stat.S_ISDIR(info.st_mode) or (info.st_uid,info.st_gid)!=(owner,os.getegid()) or info.st_mode&0o022:raise ValueError(ERROR)
            value.parent_identity=_identity(info);verify_parent()
            os.mkdir(NAME,0o755,dir_fd=value.parent);os.fsync(value.parent)
            value.underlying=os.open(NAME,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value.parent);value.fds.append(value.underlying)
            info=os.fstat(value.underlying);value.identities[value.underlying]=(info.st_dev,info.st_ino)
            if (not stat.S_ISDIR(info.st_mode) or (info.st_uid,info.st_gid)!=(owner,os.getegid()) or stat.S_IMODE(info.st_mode)!=0o755 or
                _identity(info)!=_identity(os.stat(NAME,dir_fd=value.parent,follow_symlinks=False))):raise ValueError(ERROR)
            value.underlying_identity=_identity(info);verify_parent()
            if time.monotonic()>=deadline:raise ValueError(ERROR)
            mount(deadline)
            value.mounted=os.open(NAME,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value.parent);value.fds.append(value.mounted)
            info=os.fstat(value.mounted);value.identities[value.mounted]=(info.st_dev,info.st_ino)
            if not stat.S_ISDIR(info.st_mode) or (info.st_uid,info.st_gid)!=(owner,os.getegid()) or stat.S_IMODE(info.st_mode)!=0o755 or info.st_dev==value.underlying_identity[0]:raise ValueError(ERROR)
            value.mount_identity=_identity(info);value.mount_view=verify_mount(value.mounted);value.verify();return value
        except BaseException:
            value.failed=True
            try:value.close()
            except BaseException:pass
            raise ValueError(ERROR) from None

    def verify(self):
        try:
            if self.closed or self.failed or time.monotonic()>=self.deadline:raise ValueError(ERROR)
            self.verify_parent()
            if _identity(os.fstat(self.parent))!=self.parent_identity or _identity(os.fstat(self.underlying))!=self.underlying_identity:raise ValueError(ERROR)
            if _identity(os.fstat(self.mounted))!=self.mount_identity or _identity(os.stat(NAME,dir_fd=self.parent,follow_symlinks=False))!=self.mount_identity:raise ValueError(ERROR)
            if self.verify_mount(self.mounted)!=self.mount_view or time.monotonic()>=self.deadline:raise ValueError(ERROR)
            self.verify_parent()
        except BaseException:self.failed=True;raise ValueError(ERROR) from None

    def close(self):
        if self.closed:
            if self.failed or self.close_failed:raise ValueError(ERROR)
            return
        self.closed=True
        for fd in reversed(self.fds):
            try:
                info=os.fstat(fd)
                if self.identities.get(fd)!=(info.st_dev,info.st_ino):self.close_failed=True;continue
                os.close(fd)
            except OSError:self.close_failed=True
        self.fds=[]
        if self.chain is not None:
            try:self.chain.close()
            except BaseException:self.close_failed=True
            self.chain=None
        if self.failed or self.close_failed:raise ValueError(ERROR)
