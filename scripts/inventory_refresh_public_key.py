"""Sample the public fingerprint of the fixed reporting key; no authority.

Caller must exclude concurrent mutation of the path and key for the entire
call. Metadata rechecks are not an atomic snapshot or post-return guarantee.
The awake-time deadline does not interrupt blocking filesystem operations;
timeout/close uncertainty never proves a child or descendants have stopped.
"""
import hashlib
import math
import os
import pwd
import select
import stat
import subprocess
import sys
import time


class KeyErrorState(ValueError):
    pass


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _derive_from(root,uid,gid,deadline,*,ancestor_owner=0,clock=time.monotonic):
    """Fixture seam borrowing a protected root; returns only public digest."""
    if (type(uid) is not int or uid<0 or type(gid) is not int or gid<0 or
            type(ancestor_owner) is not int or type(deadline) not in (int,float) or not math.isfinite(deadline)):
        raise KeyErrorState('Reporting public key unavailable')
    def remaining():
        now=clock()
        if type(now) not in (int,float) or not math.isfinite(now) or now>=deadline:
            raise KeyErrorState('Reporting public key unavailable')
        return deadline-now
    directories=[];links=[];keyfd=None;process=None;stream=None;failed=False;result=None
    try:
        remaining()
        root_info=os.fstat(root)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=ancestor_owner or root_info.st_mode&0o022:
            raise KeyErrorState('Reporting public key unavailable')
        directories.append((os.dup(root),_identity(root_info)))
        for index,name in enumerate(('var','lib','command-center-inventory','keys','inventory-v1')):
            parent=directories[-1][0]
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            info=os.fstat(child);directories.append((child,_identity(info)))
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=(uid if index==4 else ancestor_owner) or
                    (index==4 and (info.st_gid!=gid or stat.S_IMODE(info.st_mode)!=0o700)) or
                    (index!=4 and info.st_mode&0o022)):
                raise KeyErrorState('Reporting public key unavailable')
            links.append((parent,name,child,_identity(info)))
        parent=directories[-1][0]
        keyfd=os.open('private.pem',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        key_info=os.fstat(keyfd);key_identity=_identity(key_info)
        if (not stat.S_ISREG(key_info.st_mode) or key_info.st_uid!=uid or key_info.st_gid!=gid or
                stat.S_IMODE(key_info.st_mode)!=0o600 or key_info.st_nlink!=1 or not 0<key_info.st_size<=4096):
            raise KeyErrorState('Reporting public key unavailable')
        def verify():
            remaining()
            if _identity(os.fstat(root))!=_identity(root_info):raise KeyErrorState('Reporting public key unavailable')
            for directory,identity in directories:
                if _identity(os.fstat(directory))!=identity:raise KeyErrorState('Reporting public key unavailable')
            for parent,name,child,identity in links:
                if _identity(os.fstat(child))!=identity or _identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=identity:
                    raise KeyErrorState('Reporting public key unavailable')
            if (_identity(os.fstat(keyfd))!=key_identity or
                    _identity(os.stat('private.pem',dir_fd=directories[-1][0],follow_symlinks=False))!=key_identity):
                raise KeyErrorState('Reporting public key unavailable')
            remaining()
        verify()
        # The private descriptor is stdin; no private bytes enter captured output.
        process=subprocess.Popen(['/usr/bin/openssl','pkey','-pubout','-outform','DER'],
            stdin=keyfd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
        stream=process.stdout
        if stream is None:raise KeyErrorState('Reporting public key unavailable')
        os.set_blocking(stream.fileno(),False)
        output=bytearray();eof=False
        while not eof:
            budget=remaining()
            readable,_,_=select.select([stream.fileno()],[],[],min(budget,0.05))
            remaining()
            if not readable:continue
            try:chunk=os.read(stream.fileno(),513-len(output))
            except BlockingIOError:continue
            remaining()
            if not chunk:eof=True
            else:
                output.extend(chunk)
                if len(output)>512:raise KeyErrorState('Reporting public key unavailable')
        while process.poll() is None:
            time.sleep(min(remaining(),0.01))
        remaining()
        prefix=bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004')
        if process.returncode!=0 or len(output)!=91 or not output.startswith(prefix):
            raise KeyErrorState('Reporting public key unavailable')
        verify();result=hashlib.sha256(output).hexdigest()
    except BaseException:
        failed=True
    finally:
        if stream is not None:
            try:stream.close()
            except BaseException:failed=True
        if keyfd is not None:
            try:os.close(keyfd)
            except OSError:failed=True
        for directory,_ in reversed(directories):
            try:os.close(directory)
            except OSError:failed=True
        if process is not None:
            try:
                while process.poll() is None:
                    time.sleep(min(remaining(),0.01))
            except BaseException:
                # Never signal a process on an uncertain timeout or cleanup.
                failed=True
    if failed or result is None:raise KeyErrorState('Reporting public key unavailable')
    remaining()
    return result


def fixed(deadline):
    """Unregistered Linux reporter-only fixed path; never enrollment proof."""
    if sys.platform!='linux':raise KeyErrorState('Reporting public key unavailable')
    try:
        account=pwd.getpwnam('ccinventory')
        if (account.pw_uid<=0 or account.pw_gid<=0 or os.getresuid()!=(account.pw_uid,)*3 or
                os.getresgid()!=(account.pw_gid,)*3):raise KeyErrorState('Reporting public key unavailable')
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    except (KeyError,OSError):raise KeyErrorState('Reporting public key unavailable') from None
    failed=False;value=None
    try:value=_derive_from(root,account.pw_uid,account.pw_gid,deadline)
    except BaseException:failed=True
    finally:
        try:os.close(root)
        except OSError:failed=True
    if failed or value is None or time.monotonic()>=deadline:raise KeyErrorState('Reporting public key unavailable')
    return value
