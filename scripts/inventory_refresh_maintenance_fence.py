"""Unregistered persistent marker; it does not yet inhibit any producer.

Caller supplies protected ancestry and exclusive mutation. Presence, including
partial or malformed entries, must be treated as fenced by future consumers.
Absence alone grants no startup or maintenance authority. No removal is offered.
Before successful file and directory fsync, power loss may erase the entry; a
future owner must perform no dependent effect before confirmed publication and
must reconcile uncertain startup separately rather than trust absence.
"""
import os
import pwd
import stat
import sys
from inventory_refresh_observation import _Ancestry

NAME='maintenance.pending'
BODY=b'command-center-inventory-maintenance-v1\n'
ERROR='Inventory maintenance fence unavailable'


def _directory(fd,owner,verify):
    verify();info=os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:
        raise ValueError(ERROR)
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)


def present(directory,owner,verify):
    """Sample existence only; any existing inode, even a symlink, fences."""
    try:
        before=_directory(directory,owner,verify)
        try:os.stat(NAME,dir_fd=directory,follow_symlinks=False);found=True
        except FileNotFoundError:found=False
        if _directory(directory,owner,verify)!=before:raise ValueError(ERROR)
        try:os.stat(NAME,dir_fd=directory,follow_symlinks=False);again=True
        except FileNotFoundError:again=False
        if found!=again or _directory(directory,owner,verify)!=before:raise ValueError(ERROR)
        return found
    except BaseException:raise ValueError(ERROR) from None


def create(directory,owner,group,verify):
    """Create once; any failure leaves partial/uncertain marker in place."""
    fd=None;identity=None;failed=False
    try:
        before=_directory(directory,owner,verify)
        fd=os.open(NAME,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
        info=os.fstat(fd);identity=(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_gid!=group or
            stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_dev!=before[0]):raise ValueError(ERROR)
        written=0
        while written<len(BODY):
            count=os.write(fd,BODY[written:])
            if count<=0 or count>len(BODY)-written:raise ValueError(ERROR)
            written+=count
        os.fsync(fd);os.fsync(directory)
        os.lseek(fd,0,os.SEEK_SET);content=b''
        while len(content)<=len(BODY):
            chunk=os.read(fd,len(BODY)+1-len(content))
            if not chunk:break
            content+=chunk
        if content!=BODY:raise ValueError(ERROR)
        held=os.fstat(fd);named=os.stat(NAME,dir_fd=directory,follow_symlinks=False)
        if ((held.st_dev,held.st_ino,held.st_mode,held.st_uid,held.st_gid)!=identity or
            (named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid)!=identity or
            held.st_nlink!=1 or held.st_size!=len(BODY) or _directory(directory,owner,verify)!=before):raise ValueError(ERROR)
    except BaseException:failed=True
    finally:
        if fd is not None:
            try:
                info=os.fstat(fd)
                if identity!=(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid):failed=True
                else:os.close(fd)
            except OSError:failed=True
    if not failed:
        try:
            named=os.stat(NAME,dir_fd=directory,follow_symlinks=False)
            if ((named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid)!=identity or
                    named.st_nlink!=1 or named.st_size!=len(BODY) or _directory(directory,owner,verify)!=before):raise ValueError(ERROR)
        except BaseException:failed=True
    if failed:raise ValueError(ERROR)


def _fixed(operation):
    if sys.platform!='linux' or os.getresuid()!=(0,0,0) or os.getresgid()!=(0,0,0):raise ValueError(ERROR)
    root=None;ancestry=None;result=None;failed=False
    try:
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
        ancestry=_Ancestry.open(root,('var','lib','command-center-inventory-refresh'))
        if operation=='present':result=present(ancestry.fds[-1],0,ancestry.verify)
        elif operation=='create':result=create(ancestry.fds[-1],0,0,ancestry.verify)
        else:raise ValueError(ERROR)
    except BaseException:failed=True
    finally:
        if ancestry is not None:
            try:ancestry.close()
            except BaseException:failed=True
        if root is not None:
            try:os.close(root)
            except OSError:failed=True
    if failed:raise ValueError(ERROR)
    return result


def _public_directory(directory,owner,group,verify):
    identity=_directory(directory,owner,verify)
    if identity[4]!=group or stat.S_IMODE(identity[2])!=0o755:raise ValueError(ERROR)
    return identity


def _fixed_public(operation):
    """Sample or publish one public marker; no launch or startup authority.

    This alternate location is not registered. A future migration must check
    both it and the private marker, never silently move or discard either.
    """
    if sys.platform!='linux' or operation not in ('present','create'):raise ValueError(ERROR)
    root=None;ancestry=None;result=None;failed=False
    try:
        uid=os.geteuid();gid=os.getegid();account=pwd.getpwnam('ccinventory')
        if (account.pw_uid<=0 or account.pw_gid<=0 or
            (uid,gid) not in ((0,0),(account.pw_uid,account.pw_gid)) or
            (operation=='create' and (uid,gid)!=(0,0)) or
            os.getresuid()!=(uid,uid,uid) or os.getresgid()!=(gid,gid,gid)):
            raise ValueError(ERROR)
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
        ancestry=_Ancestry.open(root,('var','lib','command-center-inventory-maintenance'))
        def verify():
            ancestry.verify();_public_directory(ancestry.fds[-1],0,0,lambda:None)
        verify()
        if operation=='present':result=present(ancestry.fds[-1],0,verify)
        else:result=create(ancestry.fds[-1],0,0,verify)
    except BaseException:failed=True
    finally:
        if ancestry is not None:
            try:ancestry.close()
            except BaseException:failed=True
        if root is not None:
            try:os.close(root)
            except OSError:failed=True
    if failed:raise ValueError(ERROR)
    return result
