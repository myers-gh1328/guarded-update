"""Fixed refresh service adapter; no caller command/path/options interface.

Caller must own full readiness/UID exclusion/aggregate admission and publication.
A service exit code is never sufficient authority to seal or publish metadata.
"""
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
import types

from inventory_refresh_service import LIB_ROOT, ENV, PROPERTIES, SourceBundle
from inventory_refresh_observation import _Ancestry, _stable
from inventory_refresh_materialized_policy import MaterializedPolicy
from inventory_refresh_observer import kernel_clock

CACHE_ROOT='/var/cache/command-center-inventory-refresh'
RUNTIME_ROOT='/run/command-center-inventory-refresh'
UNIT='command-center-inventory-refresh-worker.service'
SLICE='command-center-inventory-worker.slice'
CGROUP='/command.slice/command-center.slice/command-center-inventory.slice/'+SLICE+'/'+UNIT


def _require(condition):
    if not condition:raise ValueError('Inventory fixed refresh service unavailable')


def refresh_argv(token):
    _require(type(token) is str and re.fullmatch('[0-9a-f]{32}',token) is not None)
    properties=('User=0','Group=0','Type=exec','ExitType=main','RemainAfterExit=no','Restart=no',
        'KillMode=control-group','KillSignal=SIGKILL','SendSIGKILL=yes','TimeoutStopSec=1',
        'OOMPolicy=kill','MemoryAccounting=yes','TasksMax=64','RuntimeMaxSec=610','NoNewPrivileges=yes',
        'CapabilityBoundingSet=CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP','AmbientCapabilities=CAP_SETUID',
        'ProtectSystem=strict','ProtectHome=yes','ProtectControlGroups=yes','RestrictNamespaces=yes',
        'PrivateDevices=yes','PrivateTmp=yes','InaccessiblePaths=/tmp /var/tmp /dev/shm',
        'ReadWritePaths='+CACHE_ROOT+'/staging-'+token)
    return ('/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe','--unit='+UNIT,'--slice='+SLICE)+tuple(
        item for value in properties for item in ('-p',value))+('/usr/bin/python3','-I','-B',LIB_ROOT+'/guardian.py')


def show_unit():
    result=subprocess.run(('/bin/systemctl','show','--property='+','.join(PROPERTIES),UNIT),stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,close_fds=True,timeout=2)
    _require(result.returncode in (0,4) and len(result.stdout)<=4096)
    values={}
    for line in result.stdout.decode('ascii').splitlines():
        key,separator,value=line.partition('=')
        _require(separator and key in PROPERTIES and key not in values);values[key]=value
    _require(set(values)==set(PROPERTIES));return values


def stop_unit():
    result=subprocess.run(('/bin/systemctl','stop',UNIT),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,env=ENV,close_fds=True,timeout=3)
    _require(result.returncode==0)


def open_cgroup():
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in ('sys','fs','cgroup')+tuple(CGROUP.strip('/').split('/')):
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            closing,fd=fd,child;os.close(closing)
            info=os.fstat(fd);_require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022)
        result,fd=fd,None;return result
    finally:
        if fd is not None:os.close(fd)


def cgroup_identity():
    fd=open_cgroup()
    try:
        info=os.fstat(fd);return info.st_dev,info.st_ino
    finally:os.close(fd)


class _WorkerSources(SourceBundle):
    def _read(self):
        self._ancestry.verify();directory=self._ancestry.fds[-1];sources={}
        for filename in ('worker.py','guardian.py'):
            fd=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            try:
                info=os.fstat(fd)
                _require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022 and
                         info.st_nlink==1 and 0<info.st_size<=65536)
                raw=bytearray()
                while True:
                    chunk=os.read(fd,65537-len(raw))
                    if not chunk:break
                    raw.extend(chunk);_require(len(raw)<=65536)
                _require(len(raw)==info.st_size and _stable(info)==_stable(os.fstat(fd))==
                         _stable(os.stat(filename,dir_fd=directory,follow_symlinks=False)))
                sources[filename]=bytes(raw)
            finally:os.close(fd)
        self._ancestry.verify();return sources

    def worker(self):
        # Both fixed sources were admitted before this first project byte executes.
        self.verify()
        module=types.ModuleType('_admitted_inventory_refresh_worker')
        module.__file__=LIB_ROOT+'/worker.py'
        exec(compile(self._sources['worker.py'],module.__file__,'exec',dont_inherit=True),module.__dict__)
        self.verify();return module


class _JobInput:
    def __init__(self,group):
        self._ancestry=None;self._fd=None;self._before=None;self._raw=None
        root=None
        try:
            root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            self._ancestry=_Ancestry.open(root,('run','command-center-inventory-refresh'))
            self._fd=os.open('job.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._ancestry.fds[-1])
            info=os.fstat(self._fd);self._before=info
            _require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==group and
                     stat.S_IMODE(info.st_mode) in (0o440,0o640) and info.st_nlink==1 and 0<info.st_size<=65536)
            self._raw=self.read()
        except BaseException:
            self.close();raise
        finally:
            if root is not None:
                try:os.close(root)
                except OSError:
                    self.close();raise

    def read(self):
        _require(self._fd is not None)
        self._ancestry.verify();os.lseek(self._fd,0,os.SEEK_SET);raw=bytearray()
        while True:
            chunk=os.read(self._fd,65537-len(raw))
            if not chunk:break
            raw.extend(chunk);_require(len(raw)<=65536)
        named=os.stat('job.json',dir_fd=self._ancestry.fds[-1],follow_symlinks=False)
        _require(len(raw)==self._before.st_size and _stable(self._before)==_stable(os.fstat(self._fd))==_stable(named))
        _require(self._raw is None or bytes(raw)==self._raw)
        self._ancestry.verify();return bytes(raw)

    def close(self):
        fd,self._fd=self._fd,None;ancestry,self._ancestry=self._ancestry,None;failure=False
        if fd is not None:
            try:os.close(fd)
            except OSError:failure=True
        if ancestry is not None:
            try:ancestry.close()
            except (OSError,ValueError):failure=True
        if failure:raise ValueError('Inventory refresh job cleanup unconfirmed') from None


def _accounts():
    user=pwd.getpwnam('ccrefresh');reporter=pwd.getpwnam('ccinventory')
    _require(user.pw_uid>0 and user.pw_gid>0 and reporter.pw_uid>0 and reporter.pw_gid>0 and
             user.pw_uid!=reporter.pw_uid and user.pw_gid!=reporter.pw_gid and
             user.pw_gid not in os.getgrouplist('ccinventory',reporter.pw_gid))
    return user,reporter


class RefreshService:
    def __init__(self,journal,policy):
        self._closed=False;self._attempted=False;self._wrapper=None;self._invocation=None
        self._cgroup=None;self._cgroup_fd=None;self._sources=None;self._input=None;self._binding=None
        self._journal=journal;self._policy=policy
        try:
            journal._locked();snapshot=journal.snapshot();record=snapshot['capabilities']['refresh']['active']
            _require(not snapshot['unconfirmed'] and record is not None and record['phase']=='running')
            journal._consume_launch('refresh',record['correlator'],record['boot_id'],record['policy_generation'])
            self._generation=journal._launch_epoch
            self._sources=_WorkerSources();self._worker=self._sources.worker()
            self._user,self._reporter=_accounts()
            self._identities=(self._user.pw_uid,self._user.pw_gid,self._reporter.pw_uid,self._reporter.pw_gid)
            self._input=_JobInput(self._user.pw_gid)
            self._job=self._worker.parse_job(self._input.read())
            self._job_bytes=json.dumps(self._job,sort_keys=True,separators=(',',':')).encode('ascii')
            self._marker='Command Center inventory refresh '+self._job['staging_token']
            self._parent_snapshot();self._policy.recheck()
            _require(self._job['policy_generation']==self._policy.generation)
        except BaseException:
            self.close();raise

    def _parent_snapshot(self):
        self._journal._locked();snapshot=self._journal.snapshot()
        record=snapshot['capabilities']['refresh']['active'];job=self._job
        _require(not snapshot['unconfirmed'] and record is not None and record['phase']=='running' and
                 all(record[key]==job[target] for key,target in (
                    ('correlator','operation_nonce'),('helper_sequence','helper_sequence'),('boot_id','boot_id'),
                    ('accepted_boottime_ms','accepted_boottime_ms'),('started_boottime_ms','started_boottime_ms'),
                    ('policy_generation','policy_generation'))))

    def verify_current_inputs(self):
        _require(not self._closed)
        self._parent_snapshot();self._sources.verify();self._policy.recheck()
        _require(self._policy.generation==self._job['policy_generation'])
        current=self._worker.parse_job(self._input.read())
        _require(json.dumps(current,sort_keys=True,separators=(',',':')).encode('ascii')==self._job_bytes)
        user,reporter=_accounts()
        _require((user.pw_uid,user.pw_gid,reporter.pw_uid,reporter.pw_gid)==self._identities)
        if self._binding is not None:self._binding.recheck()

    def launch(self):
        _require(not self._closed and not self._attempted);self._attempted=True
        try:
            self._journal._locked();_require(self._journal._launch_epoch is self._generation)
            _require(sys.platform=='linux' and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0))
            self.verify_current_inputs();boot,current=kernel_clock()
            _require(boot==self._job['boot_id'] and self._job['started_boottime_ms']<=current<self._job['deadline_boottime_ms'])
            self._worker.stage_ready(self._job['staging_token'],self._user)
            self._binding=MaterializedPolicy.fixed(self._policy,self._job['staging_token'],self._user.pw_gid,self._job['config_sha256'])
            _require(show_unit()['LoadState']=='not-found')
            args=refresh_argv(self._job['staging_token']);args=args[:-4]+('--description='+self._marker,)+args[-4:]
            self.verify_current_inputs()
            boot,current=kernel_clock()
            _require(boot==self._job['boot_id'] and self._job['started_boottime_ms']<=current<self._job['deadline_boottime_ms'])
            self._wrapper=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                env=ENV,close_fds=True,cwd='/')
            limit=time.monotonic()+2
            while time.monotonic()<limit:
                properties=show_unit()
                if properties['LoadState']!='not-found':
                    _require(properties['Description']==self._marker and properties['Transient']=='yes')
                    if re.fullmatch('[0-9a-f]{32}',properties['InvocationID']) and properties['InvocationID']!='0'*32 and properties['ControlGroup']==CGROUP:
                        self._cgroup_fd=open_cgroup();info=os.fstat(self._cgroup_fd);self._cgroup=(info.st_dev,info.st_ino)
                        self._invocation=properties['InvocationID'];self._same_invocation(show_unit())
                        self.verify_current_inputs();return self
                if self._wrapper.poll() is not None:break
                time.sleep(0.02)
            raise ValueError('Inventory refresh service creation unconfirmed')
        except BaseException:
            self.close();raise

    def _same_invocation(self,properties):
        _require(properties['LoadState']=='loaded' and properties['Transient']=='yes' and properties['Description']==self._marker and
                 properties['InvocationID']==self._invocation and properties['ControlGroup']==CGROUP and cgroup_identity()==self._cgroup)

    def poll(self):
        _require(self._wrapper is not None);return self._wrapper.poll()

    def wait(self,timeout):
        _require(self._wrapper is not None);return self._wrapper.wait(timeout=timeout)

    def close(self):
        if self._closed:return
        self._closed=True
        try:
            if self._invocation is not None:
                properties=show_unit()
                if properties['LoadState']!='not-found':self._same_invocation(properties);stop_unit()
        finally:
            try:
                if self._wrapper is not None:
                    if self._wrapper.poll() is None:self._wrapper.kill()
                    self._wrapper.wait(timeout=5)
            finally:
                failure=False
                for name in ('_binding','_input','_sources'):
                    value=getattr(self,name);setattr(self,name,None)
                    if value is not None:
                        try:value.close()
                        except (OSError,ValueError):failure=True
                fd,self._cgroup_fd=self._cgroup_fd,None
                if fd is not None:
                    try:os.close(fd)
                    except OSError:failure=True
                if failure:raise ValueError('Inventory refresh owned cleanup unconfirmed') from None
