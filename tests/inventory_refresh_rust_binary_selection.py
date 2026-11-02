"""Read-only CI test binary selection; no source or production provenance.

The caller owns the target root FD and exclusive mutation of its fresh target.
This validates Cargo output and bytes, not what was compiled or the compiler.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ERROR='Rust test binary selection unavailable'
LIMIT=128*1024*1024


def require(value):
    if not value:raise ValueError(ERROR)


def _unique(pairs):
    value={}
    for key,item in pairs:
        require(key not in value);value[key]=item
    return value


def _constant(_):raise ValueError(ERROR)


def _metadata(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,
        value.st_size,value.st_mtime_ns,value.st_ctime_ns)


def _dir(value,owner):
    require(stat.S_ISDIR(value.st_mode) and value.st_uid==owner and not value.st_mode&0o022)
    return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid)


def _select(raw,repo,target):
    require(type(raw) is bytes and 0<len(raw)<=8*1024*1024 and raw.endswith(b'\n'))
    require(isinstance(repo,Path) and repo.is_absolute() and isinstance(target,Path) and target.is_absolute())
    require(str(repo)==os.path.normpath(str(repo)) and str(target)==os.path.normpath(str(target)))
    selected=[];finished=False;lines=raw.splitlines();require(0<len(lines)<=32768)
    package='path+'+repo.as_uri()+'#guarded-update@0.1.9'
    for line in lines:
        require(not finished and 0<len(line)<=256*1024)
        item=json.loads(line,object_pairs_hook=_unique,parse_constant=_constant)
        require(type(item) is dict and type(item.get('reason')) is str)
        if item['reason']=='build-finished':
            require(item.get('success') is True);finished=True;continue
        if item['reason']!='compiler-artifact':continue
        candidate=item.get('target');require(type(candidate) is dict)
        if candidate.get('name')!='command-center-inventory':continue
        require(item.get('package_id')==package and item.get('manifest_path')==str(repo/'Cargo.toml') and
            candidate.get('kind')==['bin'] and candidate.get('src_path')==str(repo/'src'/'inventory_main.rs') and
            type(item.get('profile')) is dict and item['profile'].get('test') is True and
            item.get('features')==['inventory-agent'] and item.get('fresh') is False)
        path=item.get('executable');require(type(path) is str and path.startswith(str(target/'debug'/'deps')+'/'))
        name=path[len(str(target/'debug'/'deps'))+1:]
        require(re.fullmatch(r'command_center_inventory-[0-9a-f]{16}',name) is not None and
            path==str(target/'debug'/'deps'/name))
        selected.append(name)
    require(finished and len(selected)==1);return selected[0]


def admit(raw,repo,target,target_fd,owner):
    """Return bounded digest metadata only after all owned descriptors close."""
    descriptors=[];failed=False;result=None
    try:
        require(type(owner) is int and owner>=0 and type(target_fd) is int)
        name=_select(raw,repo,target)
        root=os.dup(target_fd);descriptors.append(root);root_info=os.fstat(root);root_id=_dir(root_info,owner)
        require(_dir(os.stat(target,follow_symlinks=False),owner)==root_id)
        refs=[];parent=root
        for part in ('debug','deps'):
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            descriptors.append(child);info=os.fstat(child);identity=_dir(info,owner)
            require(_dir(os.stat(part,dir_fd=parent,follow_symlinks=False),owner)==identity)
            refs.append((parent,part,child,identity));parent=child
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);descriptors.append(fd)
        initial=os.fstat(fd)
        require(stat.S_ISREG(initial.st_mode) and initial.st_uid==owner and initial.st_nlink==1 and initial.st_dev==os.fstat(parent).st_dev and
            initial.st_mode&0o111 and not initial.st_mode&0o6022 and 0<initial.st_size<=LIMIT)
        digest=hashlib.sha256();size=0
        while True:
            chunk=os.read(fd,min(65536,LIMIT+1-size))
            if not chunk:break
            size+=len(chunk);require(size<=LIMIT);digest.update(chunk)
        require(size==initial.st_size and _metadata(initial)==_metadata(os.fstat(fd))==
            _metadata(os.stat(name,dir_fd=parent,follow_symlinks=False)))
        for parent,part,child,identity in refs:
            require(_dir(os.fstat(child),owner)==identity==_dir(os.stat(part,dir_fd=parent,follow_symlinks=False),owner))
        require(_dir(os.fstat(root),owner)==root_id==_dir(os.stat(target,follow_symlinks=False),owner))
        result=dict(name=name,size=size,sha256=digest.hexdigest())
    except BaseException:failed=True
    finally:
        for fd in reversed(descriptors):
            try:os.close(fd)
            except BaseException:failed=True
    if failed:raise ValueError(ERROR) from None
    return result
