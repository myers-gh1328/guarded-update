"""Pure hosted fixture decoding; byte input is untrusted, never a PID witness."""
from inventory_refresh_cgroup_witness import process_start_ticks
from inventory_refresh_reporter_parent import validate_process_view
from inventory_refresh_resources import mount_rows
from inventory_refresh_reporter_resources import validate_identity

class ProfileError(ValueError):
    pass


CGROUP=b'0::/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory.service\n'


def identity_failure_category(raw):
    # Diagnostics only: never include kernel values or alter the admission check.
    needed={b'Uid',b'Gid',b'Groups',b'NoNewPrivs',b'CapInh',b'CapPrm',b'CapEff',b'CapBnd',b'CapAmb'};fields={}
    try:
        for line in raw.splitlines():
            name,separator,value=line.partition(b':')
            if name in needed:
                if not separator or name in fields:return 'profile_identity_fields'
                fields[name]=value.split()
        if set(fields)!=needed:return 'profile_identity_fields'
        if fields[b'Uid']!=[b'60002']*4:return 'profile_uid'
        if fields[b'Gid']!=[b'60002']*4:return 'profile_gid'
        if fields[b'Groups'] not in ([],[b'60002']):return 'profile_groups'
        if fields[b'NoNewPrivs']!=[b'1']:return 'profile_nnp'
        if any(fields[key]!=[b'0000000000000000'] for key in needed if key.startswith(b'Cap')):return 'profile_caps'
    except BaseException:pass
    return 'profile_identity_fields'


def validate_snapshot(pid,stat,status,cgroup,mountinfo,device):
    stage='profile_device'
    try:
        assert type(device) is tuple and len(device)==2 and all(type(v) is int and v>=0 for v in device)
        stage='profile_stat';start=process_start_ticks(stat,pid)
        stage='profile_view';validate_process_view(status,pid,None)
        stage='profile_identity_fields'
        try:validate_identity(status,60002,60002)
        except BaseException:
            stage=identity_failure_category(status);raise
        stage='profile_cgroup';assert type(cgroup) is bytes and cgroup==CGROUP
        stage='profile_mount_parse';rows=mount_rows(mountinfo).values()
        groups=[row for row in rows if row['fs']==b'cgroup2']
        stage='profile_mount_missing';assert groups
        stage='profile_mount_writable';assert all(b'ro' in row['options'] for row in groups)
        stage='profile_mount_device';assert all(row['device']==device for row in groups)
        stage='profile_mount_root';root=[row for row in groups if row['path']=='/sys/fs/cgroup' and row['root']=='/']
        assert len(root)==1
        stage='profile_mount_nested';assert not any(row['path'].startswith('/sys/fs/cgroup/') for row in rows)
        return start
    except BaseException:raise ProfileError(stage) from None


import math
import os
import stat as filetype
import time
import sys


class ProcessProbe:
    """Borrowed-input sampled fixture; caller must pin PID/unit and cgroup device."""
    @classmethod
    def fixed(cls,pid,device,deadline):
        from inventory_refresh_resources import _Chain,_mount_id,_proc
        from inventory_refresh_writer_exclusion import proc_mount
        assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
        chain=_Chain(('proc',));value=None
        try:
            info=os.fstat(chain.fds[-1]);proc_mount(_proc('mountinfo',1024*1024),mount_id=_mount_id(chain.fds[-1]),
                device=(os.major(info.st_dev),os.minor(info.st_dev)))
            mount_id=_mount_id(chain.fds[-1]);proc_device=(os.major(info.st_dev),os.minor(info.st_dev))
            value=cls._from_directory(chain.fds[-1],pid,device,deadline,owner=60002)
            value._chain=chain;chain=None
            def verify_mount():
                assert _mount_id(value._chain.fds[-1])==mount_id
                proc_mount(_proc('mountinfo',1024*1024),mount_id=mount_id,device=proc_device)
            value._proc_verify=verify_mount;value._check();return value
        except BaseException:
            if value is not None:value.close()
            raise ValueError('Process profile unavailable') from None
        finally:
            if chain is not None:chain.close()

    @classmethod
    def _from_directory(cls,parent,pid,device,deadline,*,owner):
        value=cls();value._parent=None;value._process=None;value._chain=None;value._closed=False;value._failed=False
        value._close_failed=False;value._start=None;value._proc_verify=None
        try:
            assert type(pid) is int and 0<pid<=2147483647 and type(owner) is int and owner>=0
            assert type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic()<deadline
            value._pid=pid;value._device=device;value._deadline=deadline;value._owner=owner
            value._parent=os.dup(parent);parent_info=os.fstat(value._parent)
            assert filetype.S_ISDIR(parent_info.st_mode)
            value._parent_id=(parent_info.st_dev,parent_info.st_ino)
            value._process=os.open(str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value._parent)
            info=os.fstat(value._process)
            assert filetype.S_ISDIR(info.st_mode) and info.st_uid in (0,owner) and not info.st_mode&0o022 and info.st_dev==parent_info.st_dev
            value._id=(info.st_dev,info.st_ino);value._check();return value
        except BaseException:
            try:value.close()
            except BaseException:pass
            raise ValueError('Process profile unavailable') from None

    def _check(self):
        assert not self._closed and not self._failed and time.monotonic()<self._deadline
        parent=os.fstat(self._parent);held=os.fstat(self._process)
        named=os.stat(str(self._pid),dir_fd=self._parent,follow_symlinks=False)
        assert filetype.S_ISDIR(parent.st_mode) and (parent.st_dev,parent.st_ino)==self._parent_id
        assert filetype.S_ISDIR(held.st_mode) and filetype.S_ISDIR(named.st_mode)
        assert (held.st_dev,held.st_ino)==(named.st_dev,named.st_ino)==self._id
        assert held.st_uid in (0,self._owner) and named.st_uid==held.st_uid and not held.st_mode&0o022 and not named.st_mode&0o022
        if self._chain is not None:self._chain.verify()
        if self._proc_verify is not None:self._proc_verify()
        assert time.monotonic()<self._deadline

    def _read(self,name,limit):
        assert name in ('stat','status','cgroup','mountinfo');self._check();fd=None;failed=False;raw=bytearray()
        try:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._process)
            before=os.fstat(fd)
            assert filetype.S_ISREG(before.st_mode) and before.st_uid in (0,self._owner) and not before.st_mode&0o022 and before.st_dev==self._id[0]
            while True:
                assert time.monotonic()<self._deadline
                try:chunk=os.read(fd,min(65536,limit+1-len(raw)))
                except InterruptedError:continue
                assert time.monotonic()<self._deadline
                if not chunk:break
                raw.extend(chunk);assert len(raw)<=limit
            named=os.stat(name,dir_fd=self._process,follow_symlinks=False);after=os.fstat(fd)
            identity=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
            assert identity(before)==identity(named)==identity(after)
        except BaseException:failed=True
        finally:
            if fd is not None:
                try:os.close(fd)
                except BaseException:failed=True
        if failed or time.monotonic()>=self._deadline:raise ValueError('Process profile unavailable')
        self._check();return bytes(raw)

    def sample(self):
        stage='check'
        try:
            self._check();stage='stat';first=self._read('stat',8192)
            stage='status';status=self._read('status',65536)
            stage='cgroup';group=self._read('cgroup',4096)
            stage='mountinfo';mount=self._read('mountinfo',1024*1024)
            stage='profile';start=validate_snapshot(self._pid,first,status,group,mount,self._device)
            stage='stat_recheck';assert process_start_ticks(self._read('stat',8192),self._pid)==start
            assert self._start is None or self._start==start
            stage='final';self._start=start;self._check();return start
        except BaseException as exc:
            self._failed=True
            labels={'check','stat','status','cgroup','mountinfo','profile','stat_recheck','final',
                'profile_device','profile_stat','profile_view','profile_identity_fields','profile_uid','profile_gid',
                'profile_groups','profile_nnp','profile_caps','profile_cgroup','profile_mount_parse','profile_mount_missing',
                'profile_mount_writable','profile_mount_device','profile_mount_root','profile_mount_nested'}
            if isinstance(exc,ProfileError) and str(exc) in labels:stage=str(exc)
            if os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and stage in labels:
                print('Native fixture process probe stage='+stage,file=sys.stderr)
            raise ValueError('Process profile unavailable') from None

    def close(self):
        if self._closed:
            if self._close_failed:raise ValueError('Process profile cleanup unavailable')
            return
        self._closed=True;failed=False
        for name in ('_process','_parent'):
            fd=getattr(self,name);setattr(self,name,None)
            if fd is not None:
                try:os.close(fd)
                except BaseException:failed=True
        chain,self._chain=self._chain,None
        if chain is not None:
            try:chain.close()
            except BaseException:failed=True
        if failed:
            self._close_failed=True;raise ValueError('Process profile cleanup unavailable')
