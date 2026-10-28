"""Fixed observation service adapter, no executable command/path interface.

Caller owns actual readiness/policy/cache, full lifecycle and aggregate cleanup.
An existing running journal record cannot authorize launch. This adapter consumes
one new-start permission and pins invocation/cgroup identity before stopping.
"""
import os
import re
import stat
import subprocess
import sys
import time

from inventory_refresh_entry import LIB_ROOT, read_sources, _stable
from inventory_refresh_observation import _Ancestry
from inventory_refresh_observer import kernel_clock

UNIT='command-center-inventory-observation.service'
SLICE='command-center-inventory-worker.slice'
CGROUP='/command.slice/command-center.slice/command-center-inventory.slice/'+SLICE+'/'+UNIT
PRIVATE='/run/command-center-inventory-refresh/observation-private'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}
PROPERTIES=('LoadState','ActiveState','Transient','Description','InvocationID','MainPID','ControlGroup')


def _require(condition):
    if not condition:raise ValueError('Inventory observation service ownership unavailable')


def observation_argv():
    properties=('User=0','Group=0','Type=exec','ExitType=main','RemainAfterExit=no','Restart=no',
        'KillMode=control-group','KillSignal=SIGKILL','SendSIGKILL=yes','TimeoutStopSec=1',
        'OOMPolicy=kill','TasksMax=2','RuntimeMaxSec=125','NoNewPrivileges=yes',
        'CapabilityBoundingSet=CAP_KILL CAP_SETPCAP','AmbientCapabilities=',
        'ProtectSystem=strict','ProtectHome=yes','PrivateDevices=yes','ProtectControlGroups=yes',
        'RestrictNamespaces=yes','PrivateNetwork=yes','InaccessiblePaths=/tmp /var/tmp /dev/shm',
        'TemporaryFileSystem=/etc:ro /var/lib:ro /run:ro',
        'BindReadOnlyPaths=/var/lib/dpkg '+PRIVATE+' /run/guarded-update-executor.lock',
        'BindPaths='+PRIVATE+'/results','ReadWritePaths='+PRIVATE+'/results')
    return ('/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe','--unit='+UNIT,'--slice='+SLICE)+tuple(
        item for value in properties for item in ('-p',value))+(
        '/usr/bin/python3','-I','-B',LIB_ROOT+'/observation-guardian.py')


def show_unit():
    result=subprocess.run(('/bin/systemctl','show','--property='+','.join(PROPERTIES),UNIT),
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        env=ENV,close_fds=True,timeout=2)
    _require(result.returncode in (0,4) and len(result.stdout)<=4096)
    values={}
    for line in result.stdout.decode('ascii').splitlines():
        key,separator,value=line.partition('=')
        _require(separator and key in PROPERTIES and key not in values)
        values[key]=value
    _require(set(values)==set(PROPERTIES))
    return values


def stop_unit():
    result=subprocess.run(('/bin/systemctl','stop',UNIT),stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=ENV,close_fds=True,timeout=3)
    _require(result.returncode==0)


def open_cgroup():
    # Every component is fixed here, never taken from systemctl or reporter data.
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in ('sys','fs','cgroup')+tuple(CGROUP.strip('/').split('/')):
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            closing,fd=fd,child;os.close(closing)
            info=os.fstat(fd)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022)
        result,fd=fd,None
        return result
    finally:
        if fd is not None:os.close(fd)


def cgroup_identity():
    fd=open_cgroup()
    try:
        info=os.fstat(fd);return info.st_dev,info.st_ino
    finally:os.close(fd)


class SourceBundle:
    """Pre-exec admission only; provisioning must drain root bundle updates."""
    def __init__(self):
        self._ancestry=None
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            self._ancestry=_Ancestry.open(root,('usr','local','libexec','command-center-inventory-refresh'))
            self._sources=self._read()
        except BaseException:
            self.close();raise
        finally:os.close(root)

    def _read(self):
        self._ancestry.verify();directory=self._ancestry.fds[-1]
        sources=read_sources(directory)
        entries={}
        for name in ('observation-native.py','observation-guardian.py'):
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            try:
                before=os.fstat(fd)
                _require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022 and
                         before.st_nlink==1 and 0<before.st_size<=65536)
                raw=b''
                while True:
                    chunk=os.read(fd,65537-len(raw))
                    if not chunk:break
                    raw+=chunk;_require(len(raw)<=65536)
                _require(len(raw)==before.st_size and _stable(before)==_stable(os.fstat(fd)) and
                         _stable(before)==_stable(os.stat(name,dir_fd=directory,follow_symlinks=False)))
                entries[name]=raw
            finally:os.close(fd)
        _require(entries['observation-native.py']==entries['observation-guardian.py'])
        self._ancestry.verify()
        return sources,entries

    def verify(self):_require(self._read()==self._sources)

    def close(self):
        ancestry,self._ancestry=self._ancestry,None
        if ancestry is not None:ancestry.close()


class ObservationService:
    def __init__(self,journal,channel,job):
        self._closed=False;self._attempted=False;self._wrapper=None
        self._invocation=None;self._cgroup=None;self._cgroup_fd=None
        _require(channel._journal is journal)
        channel._parent_snapshot(job)
        _require(channel.read_job()==job)
        journal._consume_launch('observation',job.operation_nonce,job.boot_id,job.policy_generation)
        self._journal=journal;self._channel=channel;self._job=job
        self._generation=journal._launch_epoch
        self._marker='Command Center inventory observation '+job.job_id

    def launch(self):
        _require(not self._closed and not self._attempted)
        self._attempted=True
        bundle=None
        try:
            self._journal._locked()
            _require(self._journal._launch_epoch is self._generation)
            _require(sys.platform=='linux' and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0))
            self._channel._parent_snapshot(self._job)
            _require(self._channel.read_job()==self._job)
            boot_id,now=kernel_clock()
            _require(boot_id==self._job.boot_id and self._job.started_boottime_ms<=now<self._job.deadline_boottime_ms)
            bundle=SourceBundle()
            _require(show_unit()['LoadState']=='not-found')
            args=observation_argv()
            args=args[:-4]+('--description='+self._marker,)+args[-4:]
            bundle.verify()
            self._wrapper=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,env=ENV,close_fds=True,cwd='/')
            limit=time.monotonic()+2
            while time.monotonic()<limit:
                properties=show_unit()
                if properties['LoadState']!='not-found':
                    _require(properties['Description']==self._marker and properties['Transient']=='yes')
                    if re.fullmatch('[0-9a-f]{32}',properties['InvocationID']) and properties['InvocationID']!='0'*32 and properties['ControlGroup']==CGROUP:
                        self._cgroup_fd=open_cgroup();info=os.fstat(self._cgroup_fd)
                        self._cgroup=info.st_dev,info.st_ino
                        self._invocation=properties['InvocationID']
                        # Check again after pinning the cgroup incarnation.
                        self._same_invocation(show_unit())
                        bundle.verify()
                        return self
                if self._wrapper.poll() is not None:break
                time.sleep(0.02)
            raise ValueError('Inventory observation service creation unconfirmed')
        except BaseException:
            self.close();raise
        finally:
            if bundle is not None:
                try:bundle.close()
                except BaseException:
                    self.close();raise

    def _same_invocation(self,properties):
        _require(properties['LoadState']=='loaded' and properties['Transient']=='yes' and
                 properties['Description']==self._marker and properties['InvocationID']==self._invocation and
                 properties['ControlGroup']==CGROUP and cgroup_identity()==self._cgroup)

    def poll(self):
        _require(self._wrapper is not None)
        return self._wrapper.poll()

    def wait(self,timeout):
        _require(self._wrapper is not None)
        return self._wrapper.wait(timeout=timeout)

    def close(self):
        if self._closed:return
        self._closed=True
        try:
            if self._invocation is not None:
                properties=show_unit()
                if properties['LoadState']!='not-found':
                    self._same_invocation(properties)
                    stop_unit()
        finally:
            try:
                if self._wrapper is not None:
                    if self._wrapper.poll() is None:self._wrapper.kill()
                    self._wrapper.wait(timeout=5)
            finally:
                fd,self._cgroup_fd=self._cgroup_fd,None
                if fd is not None:os.close(fd)
