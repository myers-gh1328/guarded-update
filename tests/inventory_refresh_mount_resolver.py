"""Read-only rooted path sample, not process provenance or mount admission.

The caller must protect the root and ensure exclusive namespace mutation. This
sample is not atomic and does not show whether other aliases are reachable.
"""
import math
import errno
import os
import stat
import sys
import time


class ResolutionError(ValueError):
    pass


def _resolve(root,path,deadline,mount_id,metadata_identity=None):
    owned=[];refs=[];failed=False;result=None;stage='validation'
    try:
        assert type(path) is str and path.startswith('/') and len(os.fsencode(path))<=1024
        components=path.split('/')[1:]
        assert 0<len(components)<=32 and all(part not in ('','.','..') and '\x00' not in part and 0<len(os.fsencode(part))<=255 for part in components)
        assert type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic()<deadline and callable(mount_id)
        def identity(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
        stage='root';root_info=os.fstat(root);assert stat.S_ISDIR(root_info.st_mode)
        owned.append(os.dup(root));assert identity(root_info)==identity(os.fstat(owned[0]))
        for index,part in enumerate(components):
            assert time.monotonic()<deadline
            parent=owned[-1];last=index==len(components)-1
            stage='open';before=os.stat(part,dir_fd=parent,follow_symlinks=False)
            stage='identity';assert stat.S_ISDIR(before.st_mode) or last and stat.S_ISREG(before.st_mode)
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(0 if last else os.O_DIRECTORY)
            stage='open';child=os.open(part,flags,dir_fd=parent)
            stage='identity';owned.append(child);info=os.fstat(child);named=os.stat(part,dir_fd=parent,follow_symlinks=False)
            assert identity(before)==identity(info)==identity(named)
            assert stat.S_ISDIR(info.st_mode) or last and stat.S_ISREG(info.st_mode)
            refs.append((parent,part,child,identity(info)))
        stage='mount_id';first=mount_id(owned[-1]);assert type(first) is int and 0<first<2**64 and time.monotonic()<deadline
        metadata=None;acl_first=None
        if metadata_identity is not None:
            assert type(metadata_identity) is tuple and len(metadata_identity)==2 and all(type(value) is int and value>=0 for value in metadata_identity)
            def acl():
                try:
                    data=os.getxattr(owned[-1],'system.posix_acl_access')
                    assert len(data)<=65536
                    return 'present',data
                except OSError as error:
                    return ('absent' if sys.platform=='linux' and error.errno==errno.ENODATA else 'unknown'),None
            acl_first=acl();metadata=identity(os.fstat(owned[-1]))
        stage='recheck';assert identity(os.fstat(root))==identity(root_info)==identity(os.fstat(owned[0]))
        for parent,part,child,expected in refs:
            assert time.monotonic()<deadline
            assert identity(os.fstat(child))==expected==identity(os.stat(part,dir_fd=parent,follow_symlinks=False))
        assert mount_id(owned[-1])==first and time.monotonic()<deadline
        final=os.fstat(owned[-1]);kind='file' if stat.S_ISREG(final.st_mode) else 'directory'
        detail=None
        if metadata_identity is not None:
            acl_second=acl()
            assert metadata==identity(final)==identity(os.fstat(owned[-1])) and acl_first==acl_second and time.monotonic()<deadline
            uid,gid=metadata_identity
            owner='self' if final.st_uid==uid else 'root' if final.st_uid==0 else 'other'
            group='self' if final.st_gid==gid else 'other'
            detail=(owner,group,*('yes' if final.st_mode&bit else 'no' for bit in (stat.S_IWUSR,stat.S_IWGRP,stat.S_IWOTH)),acl_first[0])
        result=(first,kind,detail)
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


def resolve(root,path,deadline,mount_id):
    return _resolve(root,path,deadline,mount_id)[0]

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
        matches=[]
        for identifier,path in candidates:
            stage='resolve';actual,kind,_=_resolve(root,path,deadline,mount_id)
            if actual==identifier:
                name=path.rsplit('/',1)[-1]
                category={'cgroup.procs':'procs','cgroup.threads':'threads','cgroup.subtree_control':'subtree'}.get(name,'other')
                matches.append(kind+'_'+category)
        assert time.monotonic()<deadline
        return ('matching',matches[0] if len(matches)==1 else 'multiple') if matches else ('different','ok')
    except ResolutionError as error:
        return 'unavailable',str(error) if str(error) in ('validation','root','open_missing','open_denied','open_other','identity','mount_id','recheck','close') else 'resolve'
    except BaseException:return 'unavailable',stage


def classify(root,rows,deadline,mount_id):
    return classify_detail(root,rows,deadline,mount_id)[0]


def classify_metadata(root,rows,deadline,mount_id,uid,gid):
    """Sample fixed metadata categories only; never infer actor access."""
    try:
        assert type(rows) is list and 0<len(rows)<=512 and type(uid) is int and type(gid) is int and uid>=0 and gid>=0
        seen=set();matched=[];count=0
        for row in rows:
            assert type(row) is dict and type(row.get('id')) is int and 0<row['id']<2**64 and row['id'] not in seen
            seen.add(row['id']);options=row.get('options');path=row.get('path');filesystem=row.get('fs')
            assert type(path) is str and type(filesystem) is bytes and type(options) is set and all(type(item) is bytes for item in options)
            assert (b'ro' in options)!=(b'rw' in options) and time.monotonic()<deadline
            if filesystem==b'cgroup2' and b'rw' in options:
                count+=1;assert count<=64
                actual,_,detail=_resolve(root,path,deadline,mount_id,(uid,gid))
                if actual==row['id']:matched.append(detail)
        assert count and len(matched)==1 and time.monotonic()<deadline
        return ('sample',*matched[0])
    except BaseException:return ('unavailable',)
