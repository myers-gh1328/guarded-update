#!/usr/bin/env python3
"""Disposable hosted cross-UID marker mechanics; no production authority."""
import json
import os
import select
import stat
import subprocess
import sys
import time
from pathlib import Path

ERROR='Synthetic public maintenance marker unavailable'
LIB='/usr/local/libexec/command-center-inventory-refresh'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}
SOURCE_NAMES=('inventory_refresh_maintenance_fence.py','inventory_refresh_observation.py')
PARENT_SOURCE_NAMES=('inventory_refresh_resources.py','inventory_refresh_reporter_resources.py','inventory_refresh_reporter_parent.py')
PROGRAM=r'''import os,sys
sys.path.insert(0,'/usr/local/libexec/command-center-inventory-refresh')
import inventory_refresh_maintenance_fence as fence
mode=sys.argv[1]
if mode!='create':
 if os.getresuid()!=(60002,60002,60002) or os.getresgid()!=(60002,60002,60002) or os.getgroups()!=[]:sys.exit(91)
 with open('/proc/self/status','rb') as stream: raw=stream.read(65537)
 if len(raw)>65536:sys.exit(91)
 fields={}
 for line in raw.splitlines():
  if b':' not in line:continue
  key,value=line.split(b':',1)
  if key in (b'CapInh',b'CapPrm',b'CapEff',b'CapBnd',b'CapAmb',b'NoNewPrivs'):
   if key in fields:sys.exit(91)
   fields[key]=value.strip()
 if set(fields)!={b'CapInh',b'CapPrm',b'CapEff',b'CapBnd',b'CapAmb',b'NoNewPrivs'} or fields[b'NoNewPrivs']!=b'1' or any(fields[k]!=b'0000000000000000' for k in fields if k!=b'NoNewPrivs'):sys.exit(91)
if mode=='absent':
 if fence._fixed_public('present') is not False:sys.exit(92)
 print('ABSENT')
elif mode=='deny':
 try:fence._fixed_public('create')
 except ValueError:print('DENIED')
 else:sys.exit(92)
elif mode=='create':
 fence._fixed_public('create');print('CREATED')
elif mode=='present':
 if fence._fixed_public('present') is not True:sys.exit(92)
 print('PRESENT')
else:sys.exit(93)
'''


def _metadata(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


class MarkerSources:
    """One fixed archive-file profile; partial state is never retired here."""
    def __init__(self,directory,contents,uid,gid,*,profile='marker'):
        self.fd=os.dup(directory);self.uid=uid;self.gid=gid;self.contents=contents
        self.closed=False;self.failed=False;self.close_failed=False;self.published=False;self.records={}
        try:
            info=os.fstat(self.fd);self.identity=(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
            if type(profile) is not str or profile not in ('marker','parent'):raise ValueError(ERROR)
            self.names=SOURCE_NAMES if profile=='marker' else PARENT_SOURCE_NAMES
            if (not stat.S_ISDIR(info.st_mode) or (info.st_uid,info.st_gid)!=(uid,gid) or info.st_mode&0o022 or
                type(contents) is not dict or set(contents)!=set(self.names) or
                any(type(data) is not bytes or not 0<len(data)<=65536 for data in contents.values())):raise ValueError(ERROR)
        except BaseException:
            try:os.close(self.fd)
            except OSError:pass
            self.closed=True;raise ValueError(ERROR) from None

    def _directory(self):
        info=os.fstat(self.fd)
        if self.closed or (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)!=self.identity:raise ValueError(ERROR)

    def publish(self):
        if self.failed or self.published:raise ValueError(ERROR)
        try:
            self._directory()
            if os.listdir(self.fd):raise ValueError(ERROR)
            for name in self.names:
                self._directory()
                if set(os.listdir(self.fd))!=set(self.records):raise ValueError(ERROR)
                fd=None;identity=None
                try:
                    fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.fd)
                    first=os.fstat(fd);identity=(first.st_dev,first.st_ino)
                    raw=self.contents[name];offset=0
                    while offset<len(raw):
                        count=os.write(fd,raw[offset:])
                        if count<=0 or count>len(raw)-offset:raise ValueError(ERROR)
                        offset+=count
                    os.fsync(fd);os.fchmod(fd,0o444);os.fsync(fd)
                    info=os.fstat(fd);named=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
                    if ((info.st_dev,info.st_ino)!=identity or not stat.S_ISREG(info.st_mode) or
                        (info.st_uid,info.st_gid)!=(self.uid,self.gid) or stat.S_IMODE(info.st_mode)!=0o444 or
                        info.st_nlink!=1 or info.st_size!=len(raw) or info.st_dev!=self.identity[0] or _metadata(info)!=_metadata(named)):
                        raise ValueError(ERROR)
                    self.records[name]=_metadata(info)
                finally:
                    if fd is not None:
                        info=os.fstat(fd)
                        if identity!=(info.st_dev,info.st_ino):raise ValueError(ERROR)
                        os.close(fd)
            os.fsync(self.fd);self.published=True;self.verify()
        except BaseException:
            self.failed=True;raise ValueError(ERROR) from None

    def verify(self):
        try:
            if self.failed or not self.published:raise ValueError(ERROR)
            self._directory()
            if set(os.listdir(self.fd))!=set(self.names):raise ValueError(ERROR)
            for name in self.names:
                fd=None;identity=None
                try:
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
                    info=os.fstat(fd);identity=(info.st_dev,info.st_ino);raw=b''
                    while len(raw)<=len(self.contents[name]):
                        chunk=os.read(fd,len(self.contents[name])+1-len(raw))
                        if not chunk:break
                        raw+=chunk
                    named=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
                    if raw!=self.contents[name] or _metadata(info)!=self.records[name] or _metadata(os.fstat(fd))!=self.records[name] or _metadata(named)!=self.records[name]:raise ValueError(ERROR)
                finally:
                    if fd is not None:
                        info=os.fstat(fd)
                        if identity!=(info.st_dev,info.st_ino):raise ValueError(ERROR)
                        os.close(fd)
            self._directory()
        except BaseException:
            self.failed=True;raise ValueError(ERROR) from None

    def close(self):
        if self.closed:
            if self.close_failed:raise ValueError(ERROR)
            return
        self.closed=True
        try:
            info=os.fstat(self.fd)
            if (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)!=self.identity:raise ValueError(ERROR)
            os.close(self.fd)
        except ValueError:self.close_failed=True;raise ValueError(ERROR) from None
        except OSError:self.close_failed=True;raise ValueError(ERROR) from None


def command(mode,root):
    if mode not in ('absent','deny','create','present') or type(root) is not bool or root!=(mode=='create'):raise ValueError(ERROR)
    command=[] if root else ['/usr/bin/setpriv','--reuid=60002','--regid=60002','--clear-groups','--inh-caps=-all','--bounding-set=-all','--ambient-caps=-all','--no-new-privs','--']
    return command+['/usr/bin/python3','-I','-B','-S','-c',PROGRAM,mode]


def validate_output(mode,data):
    expected={'absent':b'ABSENT\n','deny':b'DENIED\n','create':b'CREATED\n','present':b'PRESENT\n'}
    if mode not in expected or data!=expected[mode]:raise ValueError(ERROR)


def invoke(mode,deadline):
    if time.monotonic()>=deadline:raise ValueError(ERROR)
    child=subprocess.Popen(command(mode,mode=='create'),env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    data=bytearray();failed=False
    try:
        os.set_blocking(child.stdout.fileno(),False)
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ValueError(ERROR)
            if not select.select([child.stdout],[],[],remaining)[0]:raise ValueError(ERROR)
            chunk=os.read(child.stdout.fileno(),129-len(data))
            if time.monotonic()>=deadline:raise ValueError(ERROR)
            if not chunk:break
            data.extend(chunk)
            if len(data)>128:raise ValueError(ERROR)
        while child.poll() is None:
            if time.monotonic()>=deadline:raise ValueError(ERROR)
            time.sleep(.01)
        if child.returncode!=0:raise ValueError(ERROR)
        validate_output(mode,bytes(data))
    except BaseException:failed=True
    finally:
        try:child.stdout.close()
        except BaseException:failed=True
    if failed or time.monotonic()>=deadline:raise ValueError(ERROR)


def run(archive):
    if sys.platform!='linux' or os.getresuid()!=(0,0,0) or os.getresgid()!=(0,0,0) or os.environ.get('GITHUB_ACTIONS')!='true':raise ValueError(ERROR)
    repo=Path(__file__).resolve().parents[1];sys.path.insert(0,str(repo/'scripts'))
    from inventory_refresh_artifact_fixture import verify_archive,LIB as ARCHIVE_LIB
    from inventory_refresh_resources import _Chain
    from native_inventory_cross_uid import create_account,ensure_libexec
    deadline=time.monotonic()+45;owned=[];failed=False;complete=False;stage='account'
    try:
        create_account(deadline);stage='archive';verified=verify_archive(repo,archive)
        stage='libexec'
        local=_Chain(('usr','local'));owned.append(local);local.verify();ensure_libexec(local.fds[-1],0,deadline);local.verify()
        libexec=_Chain(('usr','local','libexec'));owned.append(libexec);libexec.verify()
        os.mkdir('command-center-inventory-refresh',0o755,dir_fd=libexec.fds[-1]);os.fsync(libexec.fds[-1]);libexec.verify()
        stage='sources';source_chain=_Chain(('usr','local','libexec','command-center-inventory-refresh'));owned.append(source_chain)
        source_chain.verify()
        contents={name:verified['files'][ARCHIVE_LIB+name] for name in SOURCE_NAMES}
        sources=MarkerSources(source_chain.fds[-1],contents,0,0);owned.append(sources);sources.publish();sources.verify();source_chain.verify()
        stage='public_directory'
        varlib=_Chain(('var','lib'));owned.append(varlib);varlib.verify()
        os.mkdir('command-center-inventory-maintenance',0o755,dir_fd=varlib.fds[-1]);os.fsync(varlib.fds[-1]);varlib.verify()
        public=_Chain(('var','lib','command-center-inventory-maintenance'));owned.append(public);public.verify()
        info=os.fstat(public.fds[-1])
        if (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o755):raise ValueError(ERROR)
        for mode in ('absent','deny','absent','create','present'):
            stage='invoke_'+mode
            sources.verify();source_chain.verify();public.verify();varlib.verify();invoke(mode,deadline)
            sources.verify();source_chain.verify();public.verify();varlib.verify()
        complete=True
    except BaseException:failed=True
    finally:
        for item in reversed(owned):
            try:item.close()
            except BaseException:failed=True
    if failed or not complete or time.monotonic()>=deadline:
        print('Synthetic public marker stage='+stage,file=sys.stderr)
        raise ValueError(ERROR)
    return {'synthetic_public_marker_cross_uid':True,'production_authority':False,'cleanup_proven':False}


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit(ERROR)
    print(json.dumps(run(sys.argv[1]),sort_keys=True))
