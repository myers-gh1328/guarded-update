#!/usr/bin/python3
"""Fixed observation bootstrap, copied to two root-admitted entry scripts.

The parent must admit this entry BEFORE execution. Self-validation cannot make
an already untrusted entry safe. No project import path or caller-selected code.
"""
import os
import stat
import sys
import types

LIB_ROOT='/usr/local/libexec/command-center-inventory-refresh'
SOURCES=tuple((name,name+'.py') for name in (
    'inventory_refresh_protocol','inventory_refresh_receipt','inventory_refresh_state','inventory_refresh_storage',
    'inventory_refresh_status','inventory_refresh_observation',
    'inventory_refresh_cached_observation','inventory_refresh_channel'))+(
    ('inventory_refresh_guardian','guardian.py'),
    ('inventory_refresh_observer','inventory_refresh_observer.py'))


def _require(condition):
    if not condition:raise ValueError('Inventory observation library unavailable')


def _stable(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def read_sources(directory,*,owner=0):
    """Admit the entire fixed bundle before any project byte executes."""
    info=os.fstat(directory)
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid==owner and not info.st_mode&0o022)
    sources={};total=0
    for module,filename in SOURCES:
        try:fd=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        except OSError:raise ValueError('Inventory observation library unavailable') from None
        try:
            before=os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and before.st_uid==owner and
                     not before.st_mode&0o022 and before.st_nlink==1 and 0<before.st_size<=65536)
            chunks=[];size=0
            while True:
                chunk=os.read(fd,min(65537-size,65536))
                if not chunk:break
                chunks.append(chunk);size+=len(chunk)
                _require(size<=65536)
            _require(size==before.st_size and _stable(before)==_stable(os.fstat(fd)) and
                     _stable(before)==_stable(os.stat(filename,dir_fd=directory,follow_symlinks=False)))
            total+=size;_require(total<=512*1024)
            sources[module]=b''.join(chunks)
        finally:os.close(fd)
    return sources


def execute_sources(sources):
    _require(tuple(sources)==tuple(name for name,_ in SOURCES))
    _require(all(name not in sys.modules for name,_ in SOURCES))
    # Compile ALL admitted bytes before executing any module. Dataclasses require
    # their module in sys.modules; imports see only these exact explicit objects.
    compiled={name:compile(sources[name],LIB_ROOT+'/'+filename,'exec',dont_inherit=True)
              for name,filename in SOURCES}
    modules={}
    try:
        for name,filename in SOURCES:
            module=types.ModuleType(name);module.__file__=LIB_ROOT+'/'+filename
            modules[name]=module;sys.modules[name]=module
            exec(compiled[name],module.__dict__)
        return modules
    except BaseException:
        for name,module in modules.items():
            if sys.modules.get(name) is module:del sys.modules[name]
        raise


def fixed_sources():
    fds=[];links=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        for part in ('usr','local','libexec','command-center-inventory-refresh'):
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            fds.append(child);links.append((fd,part,child));fd=child
        for item in fds:
            info=os.fstat(item)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022)
        sources=read_sources(fd)
        for parent,name,child in links:
            named=os.stat(name,dir_fd=parent,follow_symlinks=False);opened=os.fstat(child)
            _require((named.st_dev,named.st_ino)==(opened.st_dev,opened.st_ino) and
                     stat.S_ISDIR(named.st_mode) and named.st_uid==0 and not named.st_mode&0o022)
        return sources
    finally:
        failure=None
        for fd in reversed(fds):
            try:os.close(fd)
            except OSError as exc:failure=exc
        if failure is not None:raise failure


def main():
    try:
        _require(sys.platform=='linux' and sys.flags.isolated and sys.flags.dont_write_bytecode and
                 len(sys.argv)==1 and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0))
        roles={LIB_ROOT+'/observation-native.py':'run_native',
               LIB_ROOT+'/observation-guardian.py':'run_guardian'}
        _require(sys.argv[0] in roles)
        modules=execute_sources(fixed_sources())
        return getattr(modules['inventory_refresh_observer'],roles[sys.argv[0]])()
    except BaseException:
        return 74


if __name__=='__main__':sys.exit(main())
