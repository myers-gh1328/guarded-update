"""Verify exact caller-supplied private source bytes; no build or provenance claim.

The caller must exclusively own mutations to the snapshot and tree throughout
verification. This is neither an atomic snapshot nor an after-return witness.
"""
import os
from pathlib import Path
import stat
import time
from inventory_refresh_rust_source_copy import directory,meta,validate

ERROR='Private Rust source verification unavailable'


def require(value):
    if not value:raise ValueError(ERROR)


def verify(value,output,output_fd,owner):
    descriptors=[];failed=False;deadline=time.monotonic()+30
    def clock():require(time.monotonic()<deadline)
    try:
        dirs=validate(value);require(isinstance(output,Path) and output.is_absolute() and
            str(output)==os.path.normpath(str(output)) and type(output_fd) is int and type(owner) is int and owner>=0)
        expected={'':set()}
        for relative in dirs:
            parent,_,name=relative.rpartition('/');expected.setdefault(parent,set()).add(name);expected[relative]=set()
        for relative in value['files']:
            parent,_,name=relative.rpartition('/');expected[parent].add(name)
        root=os.dup(output_fd);descriptors.append(root);root_id=directory(os.fstat(root),owner)
        require(directory(os.stat(output,follow_symlinks=False),owner)==root_id)
        child_name='source-'+value['source_commit'];clock()
        child=os.open(child_name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=root);descriptors.append(child)
        child_id=directory(os.fstat(child),owner,root_id[0])
        require(child_id==directory(os.stat(child_name,dir_fd=root,follow_symlinks=False),owner,root_id[0]))
        opened={'':child};refs=[(root,child_name,child,child_id)];records=[]
        for relative in dirs:
            parent_name,_,name=relative.rpartition('/');parent=opened[parent_name];clock()
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);descriptors.append(fd)
            identity=directory(os.fstat(fd),owner,root_id[0]);require(identity==directory(os.stat(name,dir_fd=parent,follow_symlinks=False),owner,root_id[0]))
            refs.append((parent,name,fd,identity));opened[relative]=fd
        def directories():
            clock();require(directory(os.fstat(root),owner)==root_id==directory(os.stat(output,follow_symlinks=False),owner))
            for parent,name,fd,identity in refs:
                require(directory(os.fstat(fd),owner,root_id[0])==identity==directory(os.stat(name,dir_fd=parent,follow_symlinks=False),owner,root_id[0]))
            for relative,fd in opened.items():require(set(os.listdir(fd))==expected[relative])
            clock()
        directories()
        for relative in sorted(value['files']):
            parent_name,_,name=relative.rpartition('/');parent=opened[parent_name];raw=value['files'][relative]
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);descriptors.append(fd)
            info=os.fstat(fd);mode=0o700 if value['modes'][relative]=='100755' else 0o600
            require(stat.S_ISREG(info.st_mode) and info.st_uid==owner and info.st_dev==root_id[0] and info.st_nlink==1 and
                stat.S_IMODE(info.st_mode)==mode and info.st_size==len(raw))
            data=bytearray()
            while True:
                clock();chunk=os.read(fd,min(65536,len(raw)+1-len(data)))
                if not chunk:break
                data.extend(chunk);require(len(data)<=len(raw))
            require(bytes(data)==raw and meta(info)==meta(os.fstat(fd))==meta(os.stat(name,dir_fd=parent,follow_symlinks=False)))
            records.append((parent,name,meta(info)));descriptors.remove(fd);os.close(fd)
        directories()
        for parent,name,expected_meta in records:
            clock();fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);descriptors.append(fd)
            require(meta(os.fstat(fd))==expected_meta==meta(os.stat(name,dir_fd=parent,follow_symlinks=False)))
            descriptors.remove(fd);os.close(fd)
        directories();clock()
    except BaseException:failed=True
    finally:
        for fd in reversed(descriptors):
            try:os.close(fd)
            except BaseException:failed=True
    if failed or time.monotonic()>=deadline:raise ValueError(ERROR) from None
