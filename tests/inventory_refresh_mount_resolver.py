"""Read-only rooted path sample, not process provenance or mount admission.

The caller must protect the root and ensure exclusive namespace mutation. This
sample is not atomic and does not show whether other aliases are reachable.
"""
import math
import os
import re
import stat
import time


def resolve(root,path,deadline,mount_id):
    owned=[];refs=[];failed=False;result=None
    try:
        assert type(path) is str and path.startswith('/') and len(path)<=1024
        components=path.split('/')[1:]
        assert 0<len(components)<=32 and all(re.fullmatch(r'[A-Za-z0-9_.-]{1,255}',part) and part not in ('.','..') for part in components)
        assert type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic()<deadline and callable(mount_id)
        def identity(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
        root_info=os.fstat(root);assert stat.S_ISDIR(root_info.st_mode)
        owned.append(os.dup(root));assert identity(root_info)==identity(os.fstat(owned[0]))
        for part in components:
            assert time.monotonic()<deadline
            parent=owned[-1];child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            owned.append(child);info=os.fstat(child);named=os.stat(part,dir_fd=parent,follow_symlinks=False)
            assert stat.S_ISDIR(info.st_mode) and stat.S_ISDIR(named.st_mode) and identity(info)==identity(named)
            refs.append((parent,part,child,identity(info)))
        first=mount_id(owned[-1]);assert type(first) is int and 0<first<2**64 and time.monotonic()<deadline
        assert identity(os.fstat(root))==identity(root_info)==identity(os.fstat(owned[0]))
        for parent,part,child,expected in refs:
            assert time.monotonic()<deadline
            assert identity(os.fstat(child))==expected==identity(os.stat(part,dir_fd=parent,follow_symlinks=False))
        assert mount_id(owned[-1])==first and time.monotonic()<deadline
        result=first
    except BaseException:failed=True
    finally:
        for fd in reversed(owned):
            try:os.close(fd)
            except BaseException:failed=True
    if failed or time.monotonic()>=deadline:raise ValueError('Mount sample unavailable')
    return result
