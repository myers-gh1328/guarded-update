"""Read-only historical enrollment marker; never enrollment or start authority.

The fixed constructor is not registered in the runtime. The private fixture
seam borrows an already trusted root FD. Sampled monotonic deadlines do not
interrupt blocking filesystem calls or establish post-return immutability.
"""
import math
import os
import re
import stat
import sys
import time

from inventory_refresh_observation import _Ancestry


class MarkerError(ValueError):
    pass


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _read_from(root,owner,group,deadline,*,clock=time.monotonic):
    """Fixture seam: literal components, borrowed root, no authority."""
    if type(owner) is not int or type(group) is not int or type(deadline) not in (float,int) or not math.isfinite(deadline):
        raise MarkerError('Enrollment marker unavailable')
    def remaining():
        sample=clock()
        if type(sample) not in (float,int) or not math.isfinite(sample) or sample>=deadline:
            raise MarkerError('Enrollment marker unavailable')
    ancestry=None;fd=None;failed=False;value=None
    try:
        remaining()
        ancestry=_Ancestry.open(root,('var','lib','command-center-inventory'),owner=owner)
        parent=ancestry.fds[-1]
        fd=os.open('initialized-enrollment',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or before.st_gid!=group or
                stat.S_IMODE(before.st_mode)!=0o644 or before.st_nlink!=1 or before.st_size!=37):
            raise MarkerError('Enrollment marker unavailable')
        named=os.stat('initialized-enrollment',dir_fd=parent,follow_symlinks=False)
        if _identity(named)!=_identity(before):raise MarkerError('Enrollment marker unavailable')
        raw=bytearray()
        while True:
            remaining();chunk=os.read(fd,38-len(raw));remaining()
            if not chunk:break
            raw.extend(chunk)
            if len(raw)>37:raise MarkerError('Enrollment marker unavailable')
        if (len(raw)!=37 or re.fullmatch(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n',raw) is None or
                _identity(os.fstat(fd))!=_identity(before) or
                _identity(os.stat('initialized-enrollment',dir_fd=parent,follow_symlinks=False))!=_identity(before)):
            raise MarkerError('Enrollment marker unavailable')
        ancestry.verify();remaining();value=raw[:-1].decode('ascii')
    except BaseException:
        failed=True
    finally:
        if fd is not None:
            try:os.close(fd)
            except OSError:failed=True
        if ancestry is not None:
            try:ancestry.close()
            except BaseException:failed=True
    if failed or value is None:raise MarkerError('Enrollment marker unavailable')
    remaining()
    return value


def fixed(deadline):
    """Fixed Linux Root-only path; marker contents remain historical data."""
    if sys.platform!='linux' or os.geteuid()!=0:
        raise MarkerError('Enrollment marker unavailable')
    root=None;failed=False;value=None
    try:
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        value=_read_from(root,0,0,deadline)
    except BaseException:
        failed=True
    finally:
        if root is not None:
            try:os.close(root)
            except OSError:failed=True
    if failed or value is None or time.monotonic()>=deadline:raise MarkerError('Enrollment marker unavailable')
    return value
