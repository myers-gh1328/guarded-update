"""CI-only unprivileged build wrapper; manifest is not privileged provenance."""
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

if __name__=='__main__' and not (sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site):
    raise SystemExit('Isolated Python required')
sys.path.insert(0,str(Path(__file__).resolve().parent))
from inventory_refresh_rust_build import build
from inventory_refresh_rust_source_snapshot import git

ERROR='Native Rust fixture build unavailable'


def require(value):
    if not value:raise ValueError(ERROR)


def _dir(info,owner,mode=None):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==owner and not info.st_mode&0o022 and
        (mode is None or stat.S_IMODE(info.st_mode)==mode))
    return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid


def _meta(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _ancestor(info,owner):
    sticky_root=info.st_uid==0 and bool(info.st_mode&stat.S_ISVTX)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,owner) and (not info.st_mode&0o022 or sticky_root))
    return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid


def execute(repo,runner_temp,marker):
    descriptors=[];failed=False;result=None;deadline=time.monotonic()+600
    def clock():require(time.monotonic()<deadline)
    try:
        uid=os.geteuid();require(uid!=0 and marker=='true' and isinstance(repo,Path) and repo.is_absolute() and
            isinstance(runner_temp,Path) and runner_temp.is_absolute() and str(runner_temp)==os.path.normpath(str(runner_temp)) and runner_temp.resolve()==runner_temp)
        ancestry=[];parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK);descriptors.append(parent)
        origin=_ancestor(os.fstat(parent),uid);require(_ancestor(os.stat('/',follow_symlinks=False),uid)==origin)
        require(0<len(runner_temp.parts)-1<=64)
        for part in runner_temp.parts[1:]:
            require(part not in ('','.','..'))
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);descriptors.append(child)
            identity=_ancestor(os.fstat(child),uid);require(identity==_ancestor(os.stat(part,dir_fd=parent,follow_symlinks=False),uid))
            ancestry.append((parent,part,child,identity));parent=child
        root=parent
        def verify_ancestry():
            clock();require(_ancestor(os.fstat(descriptors[0]),uid)==origin==_ancestor(os.stat('/',follow_symlinks=False),uid))
            for parent,part,child,identity in ancestry:
                require(_ancestor(os.fstat(child),uid)==identity==_ancestor(os.stat(part,dir_fd=parent,follow_symlinks=False),uid))
            clock()
        verify_ancestry()
        root_id=_dir(os.fstat(root),uid);require(_dir(os.stat(runner_temp,follow_symlinks=False),uid)==root_id)
        head=git(repo,('rev-parse','--verify','HEAD^{commit}'),128,deadline).decode('ascii').strip()
        require(re.fullmatch('[0-9a-f]{40}',head) is not None);clock()
        name='inventory-rust-parent';os.mkdir(name,0o700,dir_fd=root);clock()
        out=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=root);descriptors.append(out)
        out_id=_dir(os.fstat(out),uid,0o700);require(out_id==_dir(os.stat(name,dir_fd=root,follow_symlinks=False),uid,0o700))
        os.fsync(root);verify_ancestry();output=runner_temp/name
        built=build(repo,output,out,uid);clock()
        require(type(built) is dict and set(built)=={'source_commit','tree','binary_sha256','binary_size','binary_path'} and
            built['source_commit']==head and type(built['tree']) is str and re.fullmatch('[0-9a-f]{40}',built['tree']) and
            type(built['binary_sha256']) is str and re.fullmatch('[0-9a-f]{64}',built['binary_sha256']) and
            type(built['binary_size']) is int and 0<built['binary_size']<=128*1024*1024 and type(built['binary_path']) is str)
        binary=Path(built['binary_path']);require(binary.parent==output/'target'/'debug'/'deps' and
            re.fullmatch('command_center_inventory-[0-9a-f]{16}',binary.name) is not None)
        require(git(repo,('rev-parse','--verify','HEAD^{commit}'),128,deadline).decode('ascii').strip()==head)
        manifest={'schema_version':1,'source_commit':head,'tree':built['tree'],'binary_name':binary.name,
            'binary_sha256':built['binary_sha256'],'binary_size':built['binary_size']}
        raw=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode();require(len(raw)<=1024)
        verify_ancestry();require(_dir(os.fstat(root),uid)==root_id==_dir(os.stat(runner_temp,follow_symlinks=False),uid))
        require(_dir(os.fstat(out),uid,0o700)==out_id==_dir(os.stat(name,dir_fd=root,follow_symlinks=False),uid,0o700))
        fd=os.open('manifest.json',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=out);descriptors.append(fd)
        offset=0
        while offset<len(raw):
            clock();count=os.write(fd,raw[offset:]);require(0<count<=len(raw)-offset);offset+=count
        os.fchmod(fd,0o600);os.fsync(fd);info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==uid and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and info.st_size==len(raw))
        os.lseek(fd,0,os.SEEK_SET);actual=bytearray()
        while True:
            clock();chunk=os.read(fd,len(raw)+1-len(actual))
            if not chunk:break
            actual.extend(chunk);require(len(actual)<=len(raw))
        require(bytes(actual)==raw and _meta(info)==_meta(os.fstat(fd))==_meta(os.stat('manifest.json',dir_fd=out,follow_symlinks=False)))
        os.fsync(out);clock();require(_dir(os.fstat(out),uid,0o700)==out_id==_dir(os.stat(name,dir_fd=root,follow_symlinks=False),uid,0o700))
        verify_ancestry();require(_dir(os.fstat(root),uid)==root_id==_dir(os.stat(runner_temp,follow_symlinks=False),uid));result=head
    except BaseException:failed=True
    finally:
        for fd in reversed(descriptors):
            try:os.close(fd)
            except BaseException:failed=True
    if failed or time.monotonic()>=deadline:raise ValueError(ERROR) from None
    return result


if __name__=='__main__':
    try:
        root=Path(__file__).resolve().parents[1]
        source=execute(root,Path(os.environ.get('RUNNER_TEMP','')),os.environ.get('GITHUB_ACTIONS'))
        sys.stdout.write('Unprivileged Rust fixture prepared for '+source+'\n')
    except BaseException:
        sys.stderr.write(ERROR+'\n');sys.exit(1)
