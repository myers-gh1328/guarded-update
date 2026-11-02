"""Synthetic kernel lock-table parsing; no package locks or host mutations."""
from pathlib import Path
import sys
import os
import fcntl
import tempfile
from unittest.mock import patch
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_contention as probe
from inventory_refresh_contention import contention,ContentionProbe

PACKAGE=(8,1,100)
EXECUTOR=(0,25,200)


class ContentionTests(unittest.TestCase):
    def inspect(self,raw):return contention(raw,{PACKAGE},EXECUTOR)

    def row(self,kind='POSIX',mode='WRITE',key='08:01:100',pid='123',start='0',end='EOF',ordinal='1:',advisory='ADVISORY'):
        return f'{ordinal} {kind} {advisory} {mode} {pid} {key} {start} {end}\n'.encode()

    def test_actual_namespaces_and_every_byte_range_are_distinguished(self):
        self.assertIsNone(self.inspect(b''))
        self.assertEqual(self.inspect(self.row()),'package_manager_busy')
        self.assertEqual(self.inspect(self.row(kind='OFDLCK',pid='-1',start='128',end='191')),'package_manager_busy')
        self.assertEqual(self.inspect(self.row(kind='FLOCK',key='00:19:200')),'executor_busy')
        for raw in (self.row(mode='READ'),self.row(kind='FLOCK'),self.row(key='08:01:101'),self.row(key='00:19:200')):
            with self.subTest(raw=raw):self.assertIsNone(self.inspect(raw))

    def test_blocked_rows_may_repeat_ids_and_conservatively_defer(self):
        raw=self.row(mode='READ')+b'  '+self.row(ordinal='1: ->',start='4',end='4')
        self.assertEqual(self.inspect(raw),'package_manager_busy')
        self.assertEqual(self.inspect(raw+self.row(kind='FLOCK',key='00:19:200')),'executor_busy')

    def test_truncated_malformed_unsupported_or_partial_rows_never_mean_clear(self):
        for raw in (self.row()[:-1],b'\n',b'x'*(1024*1024+1),
                    self.row()+b'partial\n',self.row(kind='DELEG'),self.row(advisory='MANDATORY'),
                    self.row(pid='-1'),self.row(kind='OFDLCK',pid='123'),self.row(start='20',end='1'),
                    self.row(key='zz:01:100'),self.row(key='08:01:0100'),self.row(mode='UNLCK'),
                    self.row(kind='FLOCK',start='1'),self.row()*8193):
            with self.subTest(raw=raw[:90]),self.assertRaises(ValueError):self.inspect(raw)

    def test_all_rows_are_validated_even_after_observed_contention(self):
        with self.assertRaises(ValueError):self.inspect(self.row()+b'2: unparsed kernel record\n')


class ContentionFDTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.fds=[];self.value=None
        for name in ('dpkg','run','proc'):
            path=self.root/name;path.mkdir(mode=0o700)
            self.fds.append(os.open(path,os.O_RDONLY|os.O_DIRECTORY))
        for path in (self.root/'dpkg/lock-frontend',self.root/'dpkg/lock',self.root/'run/guarded-update-executor.lock',self.root/'proc/locks'):
            path.write_bytes(b'');path.chmod(0o600)

    def tearDown(self):
        if self.value is not None:
            self.value.close()
            # Only fixtures undo a deliberately simulated uncertain close.
            if self.value._process_owned:self.value._process_owned=False;probe._NATIVE_OWNER.release()
        for fd in self.fds:os.close(fd)
        self.temp.cleanup()

    def admit(self):
        with patch.object(probe.os,'O_PATH',os.O_RDONLY,create=True),patch.object(ContentionProbe,'_view'):
            self.value=ContentionProbe(*self.fds,owner=os.getuid(),deadline_ms=100,now=lambda:10)
        return self.value

    def test_no_kernel_locks_are_acquired_and_borrowed_directories_remain_open(self):
        with patch.object(fcntl,'lockf') as posix,patch.object(fcntl,'flock') as flock:
            value=self.admit();value.close()
            posix.assert_not_called();flock.assert_not_called()
        for fd in self.fds:os.fstat(fd)
        self.assertFalse(probe._NATIVE_OWNER.locked())

    def test_exact_actual_file_identity_drives_busy_and_constructor_unwinds(self):
        info=(self.root/'dpkg/lock-frontend').stat()
        key=f'{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino}'
        (self.root/'proc/locks').write_text(f'1: POSIX ADVISORY WRITE 123 {key} 5 8\n')
        with self.assertRaises(ValueError) as error:self.admit()
        self.assertEqual(error.exception.reason,'package_manager_busy')
        self.assertFalse(probe._NATIVE_OWNER.locked())

    def test_existing_process_native_owner_blocks_without_opening_target_files(self):
        probe._NATIVE_OWNER.acquire()
        try:
            with patch.object(probe.os,'open') as opened,self.assertRaises(ValueError) as error:self.admit()
            self.assertEqual(error.exception.reason,'busy');opened.assert_not_called()
        finally:probe._NATIVE_OWNER.release()

    def test_changed_named_lock_reference_and_unsafe_links_never_become_clear(self):
        value=self.admit();target=self.root/'dpkg/lock'
        target.rename(self.root/'dpkg/old');target.write_bytes(b'');target.chmod(0o600)
        with patch.object(ContentionProbe,'_view'),self.assertRaises(ValueError):value.check()
        value.close();self.value=None
        os.link(target,self.root/'dpkg/alias')
        with self.assertRaises(ValueError):self.admit()
        self.assertFalse(probe._NATIVE_OWNER.locked())

    def test_proc_file_must_share_mount_and_target_fs_semantics_are_not_assumed(self):
        value=self.admit();info=os.fstat(value._proc)
        device=f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}'
        raw=(f'1 9 {device} / /proc ro - proc proc rw\n'+f'2 9 {device} / /native ro - ext4 fixture rw\n').encode()
        def mount_id(fd):return 1 if fd in (value._proc,value._locks) else 2
        with patch.object(probe,'_proc',return_value=raw),patch.object(probe,'_mount_id',side_effect=mount_id):value._view()
        with patch.object(probe,'_proc',return_value=raw),patch.object(probe,'_mount_id',side_effect=lambda fd:99 if fd==value._locks else mount_id(fd)):
            with self.assertRaises(ValueError):value._view()
        with patch.object(probe,'_proc',return_value=raw.replace(b'- ext4 ',b'- overlay ')),patch.object(probe,'_mount_id',side_effect=mount_id):
            with self.assertRaises(ValueError):value._view()

    def test_close_uncertainty_attempts_all_fds_and_keeps_process_fence(self):
        value=self.admit();original=os.close;seen=[];uncertain=[]
        def close(fd):
            seen.append(fd)
            if not uncertain:uncertain.append(fd);raise OSError('synthetic private error')
            return original(fd)
        count=len(value._fds)
        with patch.object(probe.os,'close',side_effect=close),self.assertRaises(ValueError):value.close()
        for fd in uncertain:original(fd)
        self.assertEqual(len(seen),count);self.assertTrue(probe._NATIVE_OWNER.locked())


if __name__=='__main__':unittest.main()
