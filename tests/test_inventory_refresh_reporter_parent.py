"""Readonly parent/clock admission; synthetic vectors do not attest origin."""
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from unittest.mock import Mock
from contextlib import contextmanager
import os
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_reporter_parent as parent

PROC=b'50 1 0:30 / /proc rw,nosuid,nodev,noexec - proc proc rw\n'
SYS=b'60 50 0:30 /sys /proc/sys ro,nosuid,nodev,noexec - proc proc rw\n'


class ParentOriginTests(unittest.TestCase):
    def mounts(self,raw=PROC+SYS,boot_id=60):
        return parent.validate_proc_mounts(raw,proc_device=(0,30),proc_mount_id=50,
            parent_pid=42,self_pid=43,boot_mount_id=boot_id)

    def test_proc_origin_allows_only_canonical_readonly_sys_protection(self):
        self.assertEqual(self.mounts(),(50,60))
        self.assertEqual(self.mounts(PROC,50),(50,50))
        for raw in (PROC+SYS+SYS.replace(b'60 50',b'61 50'),PROC+SYS.replace(b'/sys /proc/sys',b'/other /proc/sys'),
            PROC+SYS.replace(b'60 50',b'60 1'),PROC+SYS.replace(b'ro,nosuid',b'rw,nosuid'),
            PROC+SYS.replace(b'0:30 /sys',b'0:31 /sys'),PROC.replace(b'/ /proc',b'/delegated /proc')+SYS):
            with self.subTest(raw=raw),self.assertRaises(ValueError):self.mounts(raw)
        for path in ('/proc/42','/proc/42/exe','/proc/43/status','/proc/self/status','/proc/thread-self',
                     '/proc/sys/kernel','/proc/sys/kernel/random','/proc/sys/kernel/random/boot_id'):
            raw=PROC+SYS+('70 50 0:40 / '+path+' ro,nosuid,nodev,noexec - tmpfs tmpfs rw\n').encode()
            with self.subTest(path=path),self.assertRaises(ValueError):self.mounts(raw)
        with self.assertRaises(ValueError):self.mounts(boot_id=50)

    def test_numeric_proc_view_requires_current_pid_parent_and_single_namespace_id(self):
        raw=b'Pid:\t43\nTgid:\t43\nPPid:\t42\nNSpid:\t43\n'
        self.assertEqual(parent.validate_process_view(raw,43,42),42)
        self.assertEqual(parent.validate_process_view(raw,43,None),42)
        for bad in (b'',raw.replace(b'Pid:\t43',b'Pid:\t143',1),raw.replace(b'PPid:\t42',b'PPid:\t1'),
            raw.replace(b'NSpid:\t43',b'NSpid:\t143 43'),raw.replace(b'NSpid:\t43',b'NSpid:\t043'),
            raw.replace(b'Tgid:\t43',b'Tgid:\t44'),raw+b'Pid:\t43\n',raw.replace(b'NSpid:\t43\n',b'')):
            with self.subTest(raw=bad),self.assertRaises(ValueError):parent.validate_process_view(bad,43,42)

    def test_account_mapping_is_canonical_distinct_and_matches_current_numbers(self):
        reporter=SimpleNamespace(pw_name='ccinventory',pw_uid=60002,pw_gid=60002)
        worker=SimpleNamespace(pw_name='ccrefresh',pw_uid=60001,pw_gid=60001)
        reader_group=SimpleNamespace(gr_name='ccinventory',gr_gid=60002)
        worker_group=SimpleNamespace(gr_name='ccrefresh',gr_gid=60001)
        self.assertEqual(parent.validate_accounts(reporter,worker,reader_group,worker_group,60002,60002),(60002,60002,60001,60001))
        for member,key,value in ((reporter,'pw_uid',0),(reporter,'pw_uid',True),(reporter,'pw_name','alias'),
            (worker,'pw_uid',60002),(worker,'pw_gid',60002),(reader_group,'gr_gid',60003),(worker_group,'gr_name','alias')):
            old=getattr(member,key);setattr(member,key,value)
            try:
                with self.subTest(key=key,value=value),self.assertRaises(ValueError):parent.validate_accounts(reporter,worker,reader_group,worker_group,60002,60002)
            finally:setattr(member,key,old)

    def test_factory_requires_resource_admission_before_any_nss_lookup(self):
        self.assertTrue(hasattr(parent,'ReporterParent'))
        with patch.object(parent.ReporterResources,'fixed',side_effect=ValueError('synthetic resource unavailable')),\
            patch.object(parent.pwd,'getpwnam') as lookup:
            with self.assertRaises(ValueError):parent.ReporterParent.fixed()
            lookup.assert_not_called()

    @contextmanager
    def clock_owner(self):
        # Private real-FD fixture for ownership/data behavior, never fixed()
        # admission or an actual pidfd/proc/kernel-origin proof.
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'boot';path.write_bytes(b'11111111-1111-4111-8111-111111111111\n')
            value=object.__new__(parent.ReporterParent)
            for name in value._owned_names():setattr(value,name,None)
            value._closed=False;value._poisoned=False;value._boot_id=None;value._last=None
            value._self_pid=os.getpid();value._parent_pid=os.getppid()
            value._boot_fd=os.open(path,os.O_RDONLY);value._pidfd=os.dup(value._boot_fd)
            watch=Mock();watch.poll.return_value=[]
            try:
                with patch.object(parent.select,'poll',return_value=watch):yield value,path
            finally:value.close()

    def test_parent_exit_during_clock_read_returns_no_time_and_consumes_owner(self):
        with self.clock_owner() as (value,_):
            original=value._parent_pid
            with patch.object(parent.os,'getppid',side_effect=[original,1]),patch.object(parent,'_now',return_value=100):
                with self.assertRaises(parent.ParentError):value.clock()
            self.assertTrue(value._poisoned);self.assertIsNone(value._last);self.assertIsNone(value._boot_id)

    def test_open_process_close_failure_keeps_cleanup_uncertainty(self):
        with self.clock_owner() as (value,path):
            value._proc_dirs=Mock();value._proc_dirs.fds=[value._boot_fd]
            value._proc_device=os.fstat(value._boot_fd).st_dev
            value._resources=Mock()
            fd=os.open(path,os.O_RDONLY);close=os.close;closed=[]
            def failure(number):
                closed.append(number);close(number);raise OSError('synthetic close failure')
            with patch.object(parent.os,'open',return_value=fd),patch.object(parent.os,'close',side_effect=failure):
                with self.assertRaises(parent.ParentError) as caught:value._open_process(value._self_pid)
            self.assertEqual(caught.exception.reason,'cleanup_unconfirmed');self.assertEqual(closed,[fd])
            resource=value._resources;chain=value._proc_dirs;value.close()
            resource.close.assert_called_once();chain.close.assert_called_once()

    def test_clock_is_native_monotonic_stable_boot_data_and_never_wall_fallback(self):
        with self.clock_owner() as (value,path):
            with patch.object(parent,'_now',side_effect=[100,110,109]):
                self.assertEqual(value.clock(),('11111111-1111-4111-8111-111111111111',100))
                self.assertEqual(value.clock()[1],110)
                with self.assertRaises(parent.ParentError):value.clock()
            with patch.object(parent,'_now') as now:
                with self.assertRaises(parent.ParentError):value.clock()
                now.assert_not_called()
        for raw in (b'22222222-2222-4222-8222-222222222222\n',b'11111111-1111-4111-8111-111111111111',b'invalid\n'):
            with self.subTest(raw=raw),self.clock_owner() as (value,path),patch.object(parent,'_now',return_value=100):
                value.clock();path.write_bytes(raw)
                with self.assertRaises(parent.ParentError):value.clock()
                self.assertTrue(value._poisoned)

    def test_ready_pidfd_or_reparented_process_is_not_a_live_clock(self):
        with self.clock_owner() as (value,_),patch.object(parent.select,'poll') as poll,patch.object(parent,'_now') as now:
            poll.return_value.poll.return_value=[(value._pidfd,1)]
            with self.assertRaises(parent.ParentError):value.clock()
            now.assert_not_called()

    def test_current_exe_link_is_checked_again_after_opening_it(self):
        with self.clock_owner() as (value,path):
            value._parent_proc=37;value._binary=parent._stable(os.fstat(value._boot_fd))
            current=os.open(path,os.O_RDONLY)
            try:
                with patch.object(parent.os,'readlink',side_effect=[parent.BINARY,parent.BINARY+' (deleted)']),\
                    patch.object(parent.os,'open',return_value=current):
                    with self.assertRaises(parent.ParentError):value._current_executable()
                with self.assertRaises(OSError):os.fstat(current)
            finally:value._parent_proc=None

    def test_close_attempts_every_owned_capability_once_after_an_error(self):
        with self.clock_owner() as (value,_):
            boot=value._boot_fd;pid=value._pidfd
            value._boot_dirs=Mock();value._boot_dirs.close.side_effect=OSError('synthetic close')
            value._proc_dirs=Mock();value._resources=Mock()
            boot_dirs=value._boot_dirs;proc=value._proc_dirs;resources=value._resources
            with self.assertRaises(parent.ParentError) as caught:value.close()
            self.assertEqual(caught.exception.reason,'cleanup_unconfirmed')
            for item in (boot_dirs,proc,resources):item.close.assert_called_once()
            for fd in (boot,pid):
                with self.assertRaises(OSError):os.fstat(fd)
            value.close()
            for item in (boot_dirs,proc,resources):item.close.assert_called_once()


if __name__=='__main__':unittest.main()
