#!/usr/bin/env python3
"""Disposable held-FD ReporterParent proof; no production or cleanup authority."""
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import stat
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from native_inventory_cross_uid import (ENV,SLICE,UNIT,SliceFile,UnitReference,check_loaded_slices,
    create_account,ensure_libexec,manager_command,read_completion,require_cgroup_absent,
    slice_status,unit_pin_decision,unit_status,validate_final_identity,validate_live_identity,
    validate_slice_config,validate_slice_identity,verify_endpoints)
from inventory_refresh_cgroup_witness import observe_empty,observe_single_process
from inventory_refresh_exec_lock_fixture import ExecLock
from inventory_refresh_exec_parent_fixture import wrapper_command,READY,ACK
from native_inventory_maintenance_public import MarkerSources,PARENT_SOURCE_NAMES
from inventory_refresh_process_snapshot import ProcessProbe
from inventory_cross_uid_bus import NativeBus

ERROR='Synthetic held-fd ReporterParent unavailable'
BARRIER=b'INVENTORY-BARRIER-1\n'


def validate_output(raw):
    if type(raw) is not bytes or len(raw)>8192:raise ValueError(ERROR)
    try:
        lines=[line for line in raw.decode('ascii').splitlines() if line]
        if (len(lines)!=3 or lines[0]!='running 1 test' or
            lines[1]!='test inventory::process::tests::hosted_fd_reporter_parent_admission ... ok' or
            not re.fullmatch(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s',lines[2])):raise ValueError(ERROR)
    except (UnicodeError,ValueError):raise ValueError(ERROR) from None


def read_frame(fd,expected,deadline,verify):
    if expected not in (READY,BARRIER):raise ValueError(ERROR)
    data=bytearray();poll=select.poll();poll.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR)
    while len(data)<len(expected):
        verify();remaining=deadline-time.monotonic()
        if remaining<=0 or not poll.poll(max(1,int(remaining*1000))):raise ValueError(ERROR)
        try:chunk=os.read(fd,len(expected)+1-len(data))
        except BlockingIOError:continue
        if not chunk or time.monotonic()>=deadline:raise ValueError(ERROR)
        data.extend(chunk)
        if not expected.startswith(data):raise ValueError(ERROR)
        verify()


def write_frame(fd,data,deadline,verify):
    if data not in (ACK,b'ACK-1\n'):raise ValueError(ERROR)
    offset=0;poll=select.poll();poll.register(fd,select.POLLOUT|select.POLLHUP|select.POLLERR)
    while offset<len(data):
        verify();remaining=deadline-time.monotonic()
        if remaining<=0 or not poll.poll(max(1,int(remaining*1000))):raise ValueError(ERROR)
        try:count=os.write(fd,data[offset:])
        except BlockingIOError:continue
        if count<=0 or count>len(data)-offset or time.monotonic()>=deadline:raise ValueError(ERROR)
        offset+=count;verify()


def require_shared_lock(lock):
    lock.verify();fd=None
    try:
        fd=os.open('maintenance.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=lock.directory)
        info=os.fstat(fd)
        if (info.st_dev,info.st_ino)!=lock.file_metadata[:2]:raise ValueError(ERROR)
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:pass
        else:raise ValueError(ERROR)
        lock.verify()
    finally:
        if fd is not None:
            info=os.fstat(fd)
            if (info.st_dev,info.st_ino)!=lock.file_metadata[:2]:raise ValueError(ERROR)
            os.close(fd)


def verify_exec_identity(pid,start,expected,probe):
    if type(pid) is not int or pid<=1 or type(start) is not int or type(expected) is not tuple or len(expected)!=2:raise ValueError(ERROR)
    if probe.sample()!=start:raise ValueError(ERROR)
    executable=os.stat('/proc/'+str(pid)+'/exe')
    if (executable.st_dev,executable.st_ino)!=expected or probe.sample()!=start:raise ValueError(ERROR)


def worker_account(deadline):
    for query,value in ((pwd.getpwnam,'ccrefresh'),(pwd.getpwuid,60001),(grp.getgrnam,'ccrefresh'),(grp.getgrgid,60001)):
        try:query(value)
        except KeyError:pass
        else:raise ValueError(ERROR)
    for args in (['/usr/sbin/groupadd','--system','--gid','60001','ccrefresh'],
                 ['/usr/sbin/useradd','--system','--uid','60001','--gid','ccrefresh','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','ccrefresh']):
        if time.monotonic()>=deadline:raise ValueError(ERROR)
        child=subprocess.Popen(args,env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        while child.poll() is None:
            if time.monotonic()>=deadline:raise ValueError(ERROR)
            time.sleep(.01)
        if child.returncode!=0 or time.monotonic()>=deadline:raise ValueError(ERROR)
    account=pwd.getpwnam('ccrefresh');group=grp.getgrnam('ccrefresh')
    if (account.pw_uid,account.pw_gid,group.gr_gid)!=(60001,60001,60001):raise ValueError(ERROR)


def run(archive):
    if sys.platform!='linux' or os.getresuid()!=(0,0,0) or os.getresgid()!=(0,0,0) or os.environ.get('GITHUB_ACTIONS')!='true':raise ValueError(ERROR)
    repo=Path(__file__).resolve().parents[1];sys.path.insert(0,str(repo/'scripts'))
    from inventory_refresh_artifact_fixture import verify_archive,LIB
    from inventory_refresh_rust_native_admission import RunnerArtifact
    from inventory_refresh_rust_parent_fixture import FixtureBinary
    from inventory_refresh_resources import _Chain,_read,limit
    from inventory_refresh_cache_fixture import CacheFixture
    deadline=time.monotonic()+90;owned=[];launcher=None;reference=None;bus=None;probe=None;failed=False;complete=False;stage='preflight'
    try:
        check_loaded_slices(min(deadline,time.monotonic()+3))
        if unit_status(min(deadline,time.monotonic()+3))['LoadState']!='not-found':raise ValueError(ERROR)
        cgbase=_Chain(('sys','fs','cgroup'));owned.append(cgbase);cgbase.verify();require_cgroup_absent(cgbase.fds[-1],0,deadline)
        systemd=_Chain(('run','systemd','system'));owned.append(systemd);systemd.verify()
        description='Synthetic inventory slice '+secrets.token_hex(16)
        check_loaded_slices(min(deadline,time.monotonic()+3));require_cgroup_absent(cgbase.fds[-1],0,deadline)
        cgbase.verify();systemd.verify()
        slice_file=SliceFile.create(systemd.fds[-1],0,description,deadline,reporter_resources=True);owned.append(slice_file)
        slice_file.verify();systemd.verify();manager_command('reload',deadline)
        slice_file.verify();systemd.verify();cgbase.verify()
        validate_slice_config(slice_status(min(deadline,time.monotonic()+3)),description)
        slice_file.verify();systemd.verify();cgbase.verify();manager_command('start',deadline)
        slice_file.verify();systemd.verify();cgbase.verify()
        slice_group='/command.slice/command-center.slice/'+SLICE
        slice_invocation=validate_slice_identity(slice_status(min(deadline,time.monotonic()+3)),description,slice_group)
        slice_chain=_Chain(('sys','fs','cgroup','command.slice','command-center.slice',SLICE));owned.append(slice_chain);slice_chain.verify()
        observe_empty(slice_chain.fds[-2],SLICE,slice_chain.fds[-1],deadline)
        if tuple(limit(_read(slice_chain.fds[-1],name)) for name in ('memory.max','memory.swap.max','pids.max'))!=(268435456,0,64):raise ValueError(ERROR)
        stage='account';create_account(deadline);worker_account(deadline)
        stage='archive';verified=verify_archive(repo,archive)
        artifact=RunnerArtifact.fixed(verified['source_commit'],deadline);owned.append(artifact)
        local=_Chain(('usr','local'));owned.append(local);local.verify();ensure_libexec(local.fds[-1],0,deadline);local.verify()
        libexec=_Chain(('usr','local','libexec'));owned.append(libexec);libexec.verify()
        os.mkdir('command-center-inventory-refresh',0o755,dir_fd=libexec.fds[-1]);os.fsync(libexec.fds[-1]);libexec.verify()
        source_chain=_Chain(('usr','local','libexec','command-center-inventory-refresh'));owned.append(source_chain);source_chain.verify()
        sources=MarkerSources(source_chain.fds[-1],{name:verified['files'][LIB+name] for name in PARENT_SOURCE_NAMES},0,0,profile='parent')
        owned.append(sources);sources.publish();sources.verify();source_chain.verify()
        binary=FixtureBinary.fixed(artifact);owned.append(binary);binary.publish();binary.verify_published()
        stage='cache';cache=CacheFixture.fixed(deadline);owned.append(cache);cache.verify()
        run_chain=_Chain(('run',));owned.append(run_chain);run_chain.verify()
        lock=ExecLock.create(run_chain.fds[-1],0,0,run_chain.verify);owned.append(lock);lock.verify()
        target=binary._target_metadata;lock_metadata=lock.file_metadata
        unit_description='Synthetic held-fd reporter '+secrets.token_hex(16)
        expected=slice_group+'/'+UNIT
        args=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--unit='+UNIT,'--slice='+SLICE,'--description='+unit_description]
        for item in ('User=60002','Group=60002','Type=exec','Restart=no','RemainAfterExit=no','RuntimeMaxSec=20','TasksMax=8',
            'NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=','ProtectSystem=strict','ProtectHome=yes',
            'ProtectControlGroups=yes','ProtectKernelTunables=yes','PrivateDevices=yes','PrivateTmp=yes','PrivateNetwork=yes',
            'Delegate=no','ReadOnlyPaths=/sys/fs/cgroup','MountFlags=private','MemoryPressureWatch=off'):
            args+=['-p',item]
        args+=wrapper_command(target[0],target[1],target[6],binary._digest,lock_metadata[0],lock_metadata[1])
        artifact.verify();binary.verify_published();sources.verify();source_chain.verify();cache.verify();lock.verify();slice_chain.verify();slice_file.verify()
        stage='launch';launcher=subprocess.Popen(args,env=ENV,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        endpoints=((launcher.stdin,os.O_WRONLY),(launcher.stdout,os.O_RDONLY),(launcher.stderr,os.O_RDONLY));identities=[]
        for stream,direction in endpoints:
            info=os.fstat(stream.fileno());flags=fcntl.fcntl(stream.fileno(),fcntl.F_GETFL)
            if not stat.S_ISFIFO(info.st_mode) or flags&os.O_ACCMODE!=direction:raise ValueError(ERROR)
            identities.append((info.st_dev,info.st_ino))
        if len(set(identities))!=3:raise ValueError(ERROR)
        for stream,_ in endpoints:os.set_blocking(stream.fileno(),False)
        checked=tuple((stream,direction,identity) for (stream,direction),identity in zip(endpoints,identities))
        def endpoints_ok():verify_endpoints(checked)
        stage='unit_pin';pinned=None
        while True:
            status=unit_status(min(deadline,time.monotonic()+3))
            decision=unit_pin_decision(status,launcher.poll(),expected,unit_description,deadline,pinned)
            if status['LoadState']=='loaded' and status['InvocationID'] and status['ControlGroup']==expected:pinned=status['InvocationID']
            if decision=='ready':break
            time.sleep(.02)
        invocation,pid=validate_live_identity(status,unit_description,expected)
        bus=NativeBus.fixed(deadline);validate_live_identity(unit_status(min(deadline,time.monotonic()+3)),unit_description,expected,invocation,pid)
        reference=UnitReference.acquire(bus,deadline);bus=None;reference.verify()
        validate_live_identity(unit_status(min(deadline,time.monotonic()+3)),unit_description,expected,invocation,pid)
        group=_Chain(('sys','fs','cgroup','command.slice','command-center.slice',SLICE,UNIT));owned.append(group);group.verify();slice_chain.verify()
        if (os.fstat(group.fds[-2]).st_dev,os.fstat(group.fds[-2]).st_ino)!=(os.fstat(slice_chain.fds[-1]).st_dev,os.fstat(slice_chain.fds[-1]).st_ino):raise ValueError(ERROR)
        info=os.fstat(group.fds[-1]);probe=ProcessProbe.fixed(pid,(os.major(info.st_dev),os.minor(info.st_dev)),deadline)
        stage='wrapper_ready';read_frame(launcher.stderr.fileno(),READY,deadline,endpoints_ok)
        first=probe.sample();observe_single_process(group.fds[-2],UNIT,group.fds[-1],pid,deadline)
        lock.verify();binary.verify_published();sources.verify();source_chain.verify();cache.verify();reference.verify()
        require_shared_lock(lock)
        validate_live_identity(unit_status(min(deadline,time.monotonic()+3)),unit_description,expected,invocation,pid)
        stage='exec_ack';write_frame(launcher.stdin.fileno(),ACK,deadline,endpoints_ok)
        stage='reporter_barrier';read_frame(launcher.stderr.fileno(),BARRIER,deadline,endpoints_ok)
        verify_exec_identity(pid,first,target[:2],probe)
        observe_single_process(group.fds[-2],UNIT,group.fds[-1],pid,deadline)
        validate_live_identity(unit_status(min(deadline,time.monotonic()+3)),unit_description,expected,invocation,pid)
        require_shared_lock(lock);binary.verify_published();sources.verify();source_chain.verify();cache.verify();reference.verify()
        stage='barrier_ack';write_frame(launcher.stdin.fileno(),b'ACK-1\n',deadline,endpoints_ok)
        launcher.stdin.close();launcher.stdin=None
        stage='completion';output=read_completion(launcher.stdout.fileno(),launcher.stderr.fileno(),deadline,lambda:verify_endpoints(checked[1:]))
        if launcher.wait(timeout=max(0,deadline-time.monotonic()))!=0 or time.monotonic()>=deadline:raise ValueError(ERROR)
        validate_output(output);reference.verify()
        validate_final_identity(unit_status(min(deadline,time.monotonic()+3)),unit_description,invocation)
        validate_slice_identity(slice_status(min(deadline,time.monotonic()+3)),description,slice_group,slice_invocation)
        slice_chain.verify();slice_file.verify();systemd.verify();cgbase.verify()
        observe_empty(slice_chain.fds[-2],SLICE,slice_chain.fds[-1],deadline)
        slice_chain.verify();slice_file.verify();systemd.verify();cgbase.verify()
        validate_slice_identity(slice_status(min(deadline,time.monotonic()+3)),description,slice_group,slice_invocation)
        if tuple(limit(_read(slice_chain.fds[-1],name)) for name in ('memory.max','memory.swap.max','pids.max'))!=(268435456,0,64):raise ValueError(ERROR)
        artifact.verify();binary.verify_published();sources.verify();source_chain.verify();cache.verify();lock.verify();reference.verify()
        complete=True
    except BaseException:failed=True
    finally:
        if launcher is not None:
            for stream in (launcher.stdin,launcher.stdout,launcher.stderr):
                if stream is not None:
                    try:stream.close()
                    except BaseException:failed=True
        for item in (probe,reference,bus):
            if item is not None:
                try:
                    result=item.close()
                    if item is bus and result is not True:failed=True
                except BaseException:failed=True
        for item in reversed(owned):
            try:item.close()
            except BaseException:failed=True
    if failed or not complete or time.monotonic()>=deadline:
        print('Synthetic held-fd ReporterParent stage='+stage,file=sys.stderr);raise ValueError(ERROR)
    return {'synthetic_held_fd_reporter_parent':True,'production_authority':False,'global_cleanup_proven':False}


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit(ERROR)
    print(json.dumps(run(sys.argv[1]),sort_keys=True))
