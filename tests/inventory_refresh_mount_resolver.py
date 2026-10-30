"""Read-only rooted path sample, not process provenance or mount admission.

The caller must protect the root and ensure exclusive namespace mutation. This
sample is not atomic and does not show whether other aliases are reachable.
"""
import math
import errno
import os
import stat
import time


class ResolutionError(ValueError):
    pass


def resolve(root,path,deadline,mount_id):
    owned=[];refs=[];failed=False;result=None;stage='validation'
    try:
        assert type(path) is str and path.startswith('/') and len(os.fsencode(path))<=1024
        components=path.split('/')[1:]
        assert 0<len(components)<=32 and all(part not in ('','.','..') and '\x00' not in part and 0<len(os.fsencode(part))<=255 for part in components)
        assert type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic()<deadline and callable(mount_id)
        def identity(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
        stage='root';root_info=os.fstat(root);assert stat.S_ISDIR(root_info.st_mode)
        owned.append(os.dup(root));assert identity(root_info)==identity(os.fstat(owned[0]))
        for part in components:
            assert time.monotonic()<deadline
            stage='open';parent=owned[-1];child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            stage='identity';owned.append(child);info=os.fstat(child);named=os.stat(part,dir_fd=parent,follow_symlinks=False)
            assert stat.S_ISDIR(info.st_mode) and stat.S_ISDIR(named.st_mode) and identity(info)==identity(named)
            refs.append((parent,part,child,identity(info)))
        stage='mount_id';first=mount_id(owned[-1]);assert type(first) is int and 0<first<2**64 and time.monotonic()<deadline
        stage='recheck';assert identity(os.fstat(root))==identity(root_info)==identity(os.fstat(owned[0]))
        for parent,part,child,expected in refs:
            assert time.monotonic()<deadline
            assert identity(os.fstat(child))==expected==identity(os.stat(part,dir_fd=parent,follow_symlinks=False))
        assert mount_id(owned[-1])==first and time.monotonic()<deadline
        result=first
    except OSError as error:
        failed=True
        if stage=='open':stage='open_missing' if error.errno==errno.ENOENT else 'open_denied' if error.errno in (errno.EACCES,errno.EPERM) else 'open_other'
    except BaseException:failed=True
    finally:
        for fd in reversed(owned):
            try:os.close(fd)
            except BaseException:failed=True;stage='close'
    if failed or time.monotonic()>=deadline:raise ResolutionError(stage)
    return result


def classify_detail(root,rows,deadline,mount_id):
    """Classify point samples only; different never proves a mount is hidden."""
    stage='rows'
    try:
        assert type(rows) is list and 0<len(rows)<=512 and type(deadline) in (int,float) and math.isfinite(deadline)
        seen=set();candidates=[]
        for row in rows:
            assert time.monotonic()<deadline and type(row) is dict
            identifier=row.get('id');path=row.get('path');filesystem=row.get('fs');options=row.get('options')
            assert type(identifier) is int and 0<identifier<2**64 and identifier not in seen
            seen.add(identifier)
            assert type(path) is str and 0<len(path)<=1024 and type(filesystem) is bytes and type(options) is set
            assert all(type(item) is bytes for item in options) and (b'ro' in options)!=(b'rw' in options)
            if filesystem==b'cgroup2' and b'rw' in options:candidates.append((identifier,path))
        stage='candidates';assert 0<len(candidates)<=64
        matching=False
        for identifier,path in candidates:
            stage='resolve';actual=resolve(root,path,deadline,mount_id)
            if actual==identifier:matching=True
        assert time.monotonic()<deadline
        return ('matching' if matching else 'different'),'ok'
    except ResolutionError as error:
        return 'unavailable',str(error) if str(error) in ('validation','root','open_missing','open_denied','open_other','identity','mount_id','recheck','close') else 'resolve'
    except BaseException:return 'unavailable',stage


def classify(root,rows,deadline,mount_id):
    return classify_detail(root,rows,deadline,mount_id)[0]
