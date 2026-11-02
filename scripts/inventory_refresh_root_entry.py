#!/usr/bin/python3
"""Fixed coordinator bootstrap. Launcher must admit this entry before execution.

Current self-checks cannot establish initial host provenance or past allocation.
Only stdlib is imported until the entire fixed project bundle is admitted and
compiled. No caller paths/options or ambient project imports are accepted.
"""
import os
import re
import stat
import sys
import time
import types

LIB_ROOT='/usr/local/libexec/command-center-inventory-refresh'
ENTRY=LIB_ROOT+'/coordinator.py'
SELF_CGROUP='/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory-coordinator.service'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}
SOURCES=tuple((name,'guardian.py' if name=='inventory_refresh_guardian' else name+'.py') for name in (
    'inventory_refresh_protocol','inventory_refresh_receipt','inventory_refresh_state','inventory_refresh_storage',
    'inventory_refresh_status','inventory_refresh_observation','inventory_refresh_cached_observation',
    'inventory_refresh_channel','inventory_refresh_guardian','inventory_refresh_observer','inventory_refresh_entry',
    'inventory_refresh_unit_status','inventory_refresh_service','inventory_refresh_policy',
    'inventory_refresh_policy_admission','inventory_refresh_materialized_policy','inventory_refresh_worker_service',
    'inventory_refresh_resources','inventory_refresh_materializer','inventory_refresh_writer_exclusion',
    'inventory_refresh_io','inventory_refresh_coordinator','inventory_refresh_contention','inventory_refresh_transaction',
    'inventory_refresh_observation_transaction','inventory_refresh_dispatch','inventory_refresh_runtime'))


def _require(condition):
    if not condition:raise ValueError('Fixed inventory root entry unavailable')


def _stable(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _directory(info,owner):
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid==owner and not info.st_mode&0o022)
    return info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode


def _proc(name,limit):
    fd=os.open('/proc/self/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        _require(stat.S_ISREG(os.fstat(fd).st_mode));raw=bytearray()
        while True:
            chunk=os.read(fd,min(65536,limit+1-len(raw)))
            if not chunk:break
            raw.extend(chunk);_require(len(raw)<=limit)
        return bytes(raw)
    finally:os.close(fd)


def admit_profile():
    _require(sys.platform=='linux' and sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site and
             sys.argv==[ENTRY] and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0))
    _require(_proc('cgroup',4096)==('0::'+SELF_CGROUP+'\n').encode('ascii'))
    wanted={'CapPrm':3,'CapEff':3,'CapBnd':3,'CapInh':0,'CapAmb':0,'NoNewPrivs':1};fields={}
    for line in _proc('status',65536).splitlines():
        key,separator,value=line.partition(b':')
        key=key.decode('ascii')
        if key in wanted:
            _require(separator and key not in fields);value=value.strip()
            _require(value==b'1' if key=='NoNewPrivs' else re.fullmatch(rb'[0-9a-f]{16}',value) is not None)
            fields[key]=int(value,10 if key=='NoNewPrivs' else 16)
    _require(fields==wanted)


def _environment():
    os.environ.clear();os.environ.update(ENV)


class RootSources:
    def __init__(self,directory,*,owner=0):
        self._owner=owner;self._directory=None;self._files=[];self._chain=[];self._links=[]
        self._closed=False;self._executed=False;self._sources={}
        try:
            self._identity=_directory(os.fstat(directory),owner);self._directory=os.dup(directory)
            total=0
            for module,filename in SOURCES:
                fd=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._directory)
                self._files.append((filename,fd,None));before=os.fstat(fd)
                _require(stat.S_ISREG(before.st_mode) and before.st_uid==owner and not before.st_mode&0o022 and
                         before.st_nlink==1 and 0<before.st_size<=65536)
                self._files[-1]=(filename,fd,_stable(before));raw=bytearray()
                while True:
                    chunk=os.read(fd,min(65536,65537-len(raw)))
                    if not chunk:break
                    raw.extend(chunk);_require(len(raw)<=65536)
                _require(len(raw)==before.st_size)
                total+=len(raw);_require(total<=512*1024);self._sources[module]=bytes(raw)
            self._verify()
        except BaseException:
            try:self.close()
            except BaseException:pass
            raise ValueError('Fixed inventory root source admission unavailable') from None

    @classmethod
    def fixed(cls):
        _require(cls is RootSources)
        chain=[];links=[];value=None
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);chain.append(fd)
            for part in ('usr','local','libexec','command-center-inventory-refresh'):
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                chain.append(child);links.append((fd,part,child));fd=child
            for item in chain:_directory(os.fstat(item),0)
            value=cls(fd);value._chain=chain;value._links=links;chain=[]
            value._verify();return value
        except BaseException:
            if value is not None:
                try:value.close()
                except BaseException:pass
            raise ValueError('Fixed inventory root source ancestry unavailable') from None
        finally:
            failed=False
            for fd in reversed(chain):
                try:os.close(fd)
                except OSError:failed=True
            if failed:raise ValueError('Fixed inventory root source cleanup unconfirmed')

    def _verify(self):
        _require(not self._closed and self._directory is not None)
        _require(_directory(os.fstat(self._directory),self._owner)==self._identity)
        for filename,fd,expected in self._files:
            _require(_stable(os.fstat(fd))==expected and
                     _stable(os.stat(filename,dir_fd=self._directory,follow_symlinks=False))==expected)
        for fd in self._chain:_directory(os.fstat(fd),0)
        for parent,name,child in self._links:
            _require(_directory(os.stat(name,dir_fd=parent,follow_symlinks=False),0)==_directory(os.fstat(child),0))

    def execute(self):
        installed={}
        try:
            _require(not self._executed);self._executed=True;self._verify()
            _require(tuple(self._sources)==tuple(name for name,_ in SOURCES))
            _require(all(name not in sys.modules for name,_ in SOURCES))
            compiled={name:compile(self._sources[name],LIB_ROOT+'/'+filename,'exec',dont_inherit=True)
                      for name,filename in SOURCES}
            # Final WHOLE batch fence after the last compile, before first exec.
            self._verify();_require(all(name not in sys.modules for name,_ in SOURCES))
            for name,filename in SOURCES:
                module=types.ModuleType(name);module.__file__=LIB_ROOT+'/'+filename
                installed[name]=module;sys.modules[name]=module
                exec(compiled[name],module.__dict__)
            return installed
        except BaseException:
            for name,module in installed.items():
                if sys.modules.get(name) is module:del sys.modules[name]
            raise ValueError('Fixed inventory root source execution unavailable') from None

    def close(self):
        if self._closed:return
        self._closed=True;fds=[item[1] for item in self._files];self._files=[]
        if self._directory is not None:fds.append(self._directory);self._directory=None
        fds+=list(reversed(self._chain));self._chain=[];self._links=[];self._sources={};failed=False
        for fd in fds:
            try:os.close(fd)
            except OSError:failed=True
        if failed:raise ValueError('Fixed inventory root source cleanup unconfirmed')


def main():
    sources=None;runtime=None
    try:
        admit_profile();_environment();sources=RootSources.fixed()
        modules=sources.execute()
        closing,sources=sources,None;closing.close()
        runtime=modules['inventory_refresh_runtime'].FixedRuntime.fixed()
        while True:
            runtime.step();time.sleep(.25)
    except BaseException:return 74
    finally:
        failed=False
        for owned in (runtime,sources):
            if owned is not None:
                try:owned.close()
                except BaseException:failed=True
        if failed:return 74


if __name__=='__main__':sys.exit(main())
