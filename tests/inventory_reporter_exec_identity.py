"""Disposable Linux held-FD exec fixture, not a deployed reporter wrapper."""
import hashlib
import errno
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_maintenance_lock import MaintenanceAdmission
STAGE='setup'


def close_inherited():
    """Fixture-only, single-thread cleanup before acquiring owned resources."""
    names=os.listdir('/proc/self/fd')
    if len(names)>4096:raise ValueError('descriptor inventory unavailable')
    for name in names:
        if not name.isascii() or not name.isdigit():raise ValueError('invalid descriptor')
        fd=int(name)
        if fd<3:continue
        try:os.close(fd)
        except OSError as error:
            if error.errno!=errno.EBADF:raise


def ticks():
    with open('/proc/self/stat','rb') as stream:raw=stream.read(4097)
    if len(raw)>4096:raise ValueError('process identity unavailable')
    return raw.rsplit(b') ',1)[1].split()[19].decode('ascii')


def main(binary):
    global STAGE
    close_inherited()
    if os.execve not in os.supports_fd:raise ValueError('fd exec unavailable')
    path=Path(binary)
    if not path.is_absolute() or any(x in ('.','..') for x in path.parts):raise ValueError('invalid executable')
    # Caller-owned directory ancestry is trusted and checked, but cannot be
    # proven immutable between samples.
    STAGE='ancestry';chain=[];links=[];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);chain.append(fd)
    try:
        for component in path.parts[1:-1]:
            next_fd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            named=os.stat(component,dir_fd=fd,follow_symlinks=False);held=os.fstat(next_fd)
            if (not stat.S_ISDIR(held.st_mode) or (held.st_dev,held.st_ino)!=(named.st_dev,named.st_ino) or
                held.st_uid not in (0,os.getuid()) or held.st_mode&0o022):raise ValueError('unsafe ancestry')
            links.append((fd,component,next_fd,(held.st_dev,held.st_ino,held.st_mode,held.st_uid,held.st_gid)))
            chain.append(next_fd);fd=next_fd
        STAGE='source';source=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
        info=os.fstat(source);named=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or
            info.st_mode&0o022 or not info.st_mode&0o111 or not 0<info.st_size<=128*1024*1024 or
            (info.st_dev,info.st_ino)!=(named.st_dev,named.st_ino)):raise ValueError('unsafe executable')
        raw=b'';digest=hashlib.sha256();total=0
        while True:
            chunk=os.read(source,65536)
            if not chunk:break
            total+=len(chunk)
            if total>128*1024*1024:raise ValueError('executable oversized')
            if len(raw)<4:raw+=chunk[:4-len(raw)]
            digest.update(chunk)
        if raw!=b'\x7fELF' or total!=info.st_size:raise ValueError('not ELF')
        before=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        def same(value):return (value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)==before
        if not same(os.fstat(source)) or not same(os.stat(path.name,dir_fd=fd,follow_symlinks=False)):raise ValueError('executable changed')
        STAGE='lock';fixture=Path(tempfile.mkdtemp(prefix='inventory-exec-identity-'))
        for name in ('maintenance.lock','admission.lock'):
            (fixture/name).write_bytes(b'');(fixture/name).chmod(0o644)
        directory=os.open(fixture,os.O_RDONLY|os.O_DIRECTORY)
        lock=MaintenanceAdmission.participant_checked(directory,os.getuid(),os.getgid(),lambda:False)
        inherited=lock.inheritable_fd();lockinfo=os.fstat(inherited)
        contender="import fcntl,os,sys\nf=os.open(sys.argv[1],os.O_RDONLY)\ntry:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError:sys.exit(42)\nsys.exit(1)"
        result=subprocess.Popen([sys.executable,'-I','-B','-S','-c',contender,str(fixture/'maintenance.lock')],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).wait(timeout=5)
        if result!=42:raise ValueError('lifetime lock unavailable')
        for parent,name,held_fd,identity in links:
            held=os.fstat(held_fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if any((item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid)!=identity for item in (held,named)):
                raise ValueError('ancestry changed')
        os.lseek(source,0,os.SEEK_SET);again=hashlib.sha256();total=0
        while True:
            chunk=os.read(source,65536)
            if not chunk:break
            total+=len(chunk)
            if total>128*1024*1024:raise ValueError('executable oversized')
            again.update(chunk)
        if total!=info.st_size or again.digest()!=digest.digest():raise ValueError('executable changed')
        if not same(os.fstat(source)) or not same(os.stat(path.name,dir_fd=fd,follow_symlinks=False)):raise ValueError('executable changed')
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','EXEC_IDENTITY':','.join(map(str,(os.getpid(),ticks(),info.st_dev,info.st_ino,inherited,lockinfo.st_dev,lockinfo.st_ino))),
             'EXEC_LOCK_PATH':str(fixture/'maintenance.lock')}
        STAGE='exec';os.execve(source,[binary,'--exact','inventory::process::tests::held_fd_exec_child','--ignored','--test-threads=1'],env)
    finally:
        # Only reached on error; the fixture retains unknown state.
        for item in reversed(chain):os.close(item)


if __name__=='__main__':
    try:main(sys.argv[1])
    except BaseException:
        print('Synthetic held-fd exec stage='+STAGE,file=sys.stderr)
        sys.exit(74)
