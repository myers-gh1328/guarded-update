"""Private temporary source materialization; no executable provenance or cleanup proof."""
import os
from pathlib import Path
import re
import stat
import time

ERROR='Private Rust source copy unavailable'
REQUIRED={'Cargo.toml','Cargo.lock','rust-toolchain.toml','src/inventory_main.rs'}


def require(value):
    if not value:raise ValueError(ERROR)


def meta(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
        info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def directory(info,owner,device=None):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==owner and stat.S_IMODE(info.st_mode)==0o700 and
        (device is None or info.st_dev==device))
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)


def validate(value):
    require(type(value) is dict and set(value)=={'source_commit','tree','files','modes'} and
        type(value['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',value['source_commit']) and
        type(value['tree']) is str and re.fullmatch('[0-9a-f]{40}',value['tree']) and
        type(value['files']) is dict and type(value['modes']) is dict and
        set(value['files'])==set(value['modes']) and REQUIRED<=set(value['files']) and len(value['files'])<=512)
    dirs=set();total=0
    for name,raw in value['files'].items():
        require(type(name) is str and type(raw) is bytes and len(raw)<=1024*1024 and value['modes'][name] in ('100644','100755'))
        parts=name.split('/');require(all(re.fullmatch('[A-Za-z0-9_.-]{1,255}',part) and part not in ('.','..') for part in parts)
            and '.cargo' not in parts and 'build.rs' not in parts)
        dirs.update('/'.join(parts[:i]) for i in range(1,len(parts)))
        total+=len(raw);require(total<=16*1024*1024)
    require(len(dirs)<=128 and not (dirs&set(value['files'])))
    return sorted(dirs,key=lambda item:(item.count('/'),item))


def materialize(value,output,output_fd,owner):
    """Copy caller-supplied snapshot bytes into one new private directory.

    This function does not prove those bytes came from Git. The caller must
    exclusively own mutations of both the snapshot and output tree during
    this call. It does not enumerate foreign injected entries. All partial or
    foreign trees stay untouched on failure. The result is neither an atomic
    snapshot nor an immutability witness after return; later build admission
    must reject unexpected entries and independently revalidate the tree.
    """
    descriptors=[];failed=False;result=None;deadline=time.monotonic()+30
    def check_time():require(time.monotonic()<deadline)
    try:
        directories=validate(value)
        require(isinstance(output,Path) and output.is_absolute() and str(output)==os.path.normpath(str(output)) and
            type(output_fd) is int and type(owner) is int and owner>=0)
        root=os.dup(output_fd);descriptors.append(root);root_id=directory(os.fstat(root),owner)
        require(directory(os.stat(output,follow_symlinks=False),owner)==root_id)
        refs=[];opened={'':root};records=[]
        def verify():
            check_time();require(directory(os.fstat(root),owner)==root_id==directory(os.stat(output,follow_symlinks=False),owner))
            for parent,name,fd,identity in refs:
                require(directory(os.fstat(fd),owner,root_id[0])==identity==
                    directory(os.stat(name,dir_fd=parent,follow_symlinks=False),owner,root_id[0]))
            check_time()
        name='source-'+value['source_commit'];verify();os.mkdir(name,0o700,dir_fd=root);check_time()
        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=root);descriptors.append(child)
        info=directory(os.fstat(child),owner,root_id[0]);refs.append((root,name,child,info));opened['.']=child
        os.fsync(root);verify()
        for relative in directories:
            parent_name,_,part=relative.rpartition('/');parent=opened[parent_name or '.'];verify()
            os.mkdir(part,0o700,dir_fd=parent);check_time()
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);descriptors.append(child)
            info=directory(os.fstat(child),owner,root_id[0]);refs.append((parent,part,child,info));opened[relative]=child
            os.fsync(parent);verify()
        for relative in sorted(value['files']):
            parent_name,_,part=relative.rpartition('/');parent=opened[parent_name or '.'];raw=value['files'][relative]
            mode=0o700 if value['modes'][relative]=='100755' else 0o600;verify()
            fd=os.open(part,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parent)
            descriptors.append(fd)
            offset=0
            while offset<len(raw):
                check_time();written=os.write(fd,raw[offset:]);require(0<written<=len(raw)-offset);offset+=written
            os.fchmod(fd,mode);os.fsync(fd);check_time();info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==owner and info.st_dev==root_id[0] and info.st_nlink==1 and
                stat.S_IMODE(info.st_mode)==mode and info.st_size==len(raw))
            os.lseek(fd,0,os.SEEK_SET);data=bytearray()
            while True:
                check_time();chunk=os.read(fd,min(65536,len(raw)+1-len(data)))
                if not chunk:break
                data.extend(chunk);require(len(data)<=len(raw))
            require(bytes(data)==raw and meta(info)==meta(os.fstat(fd))==meta(os.stat(part,dir_fd=parent,follow_symlinks=False)))
            records.append((parent,part,meta(info),raw));descriptors.remove(fd);os.close(fd)
            os.fsync(parent);verify()
        for parent,part,expected,raw in records:
            verify();fd=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);descriptors.append(fd)
            require(meta(os.fstat(fd))==expected==meta(os.stat(part,dir_fd=parent,follow_symlinks=False)))
            data=bytearray()
            while True:
                check_time();chunk=os.read(fd,min(65536,len(raw)+1-len(data)))
                if not chunk:break
                data.extend(chunk);require(len(data)<=len(raw))
            require(bytes(data)==raw and meta(os.fstat(fd))==expected==meta(os.stat(part,dir_fd=parent,follow_symlinks=False)))
            descriptors.remove(fd);os.close(fd)
        verify();result={'source_commit':value['source_commit'],'path':str(output/name)}
    except BaseException:failed=True
    finally:
        for fd in reversed(descriptors):
            try:os.close(fd)
            except BaseException:failed=True
    if failed or time.monotonic()>=deadline:raise ValueError(ERROR) from None
    return result
