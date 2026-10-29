"""Untrusted fixture bytes: no live PID or namespace authority."""
import unittest
import os
import tempfile
import time
from unittest.mock import patch
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from inventory_refresh_process_snapshot import validate_snapshot, ProcessProbe


class ProcessSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.pid=123
        self.stat=b'123 (command_center_) S '+b' '.join([b'0']*18+[b'98765']+[b'0']*8)+b'\n'
        self.status=(b'Pid:\t123\nTgid:\t123\nPPid:\t1\nNSpid:\t123\nUid:\t60002 60002 60002 60002\n'
            b'Gid:\t60002 60002 60002 60002\nGroups:\t\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n'
            b'CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n')
        self.cgroup=b'0::/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory.service\n'
        self.mounts=b'42 1 0:27 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup ro\n'
    def validate(self):return validate_snapshot(self.pid,self.stat,self.status,self.cgroup,self.mounts,(0,27))
    def test_borrowed_probe_rechecks_process_directory_and_start_ticks(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);proc=root/'123';proc.mkdir()
            for name,raw in (('stat',self.stat),('status',self.status),('cgroup',self.cgroup),('mountinfo',self.mounts)):
                (proc/name).write_bytes(raw)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                owner=ProcessProbe._from_directory(fd,123,(0,27),time.monotonic()+2,owner=os.getuid())
                self.assertEqual(owner.sample(),98765)
                (proc/'stat').write_bytes(self.stat.replace(b'98765',b'98766'))
                with self.assertRaises(ValueError):owner.sample()
                owner.close()
            finally:os.close(fd)

    def test_probe_rejects_pid_replacement_and_uncertain_file_close(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);proc=root/'123';proc.mkdir()
            for name,raw in (('stat',self.stat),('status',self.status),('cgroup',self.cgroup),('mountinfo',self.mounts)):(proc/name).write_bytes(raw)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                owner=ProcessProbe._from_directory(fd,123,(0,27),time.monotonic()+2,owner=os.getuid())
                proc.rename(root/'old');proc.mkdir()
                with self.assertRaises(ValueError):owner.sample()
                owner.close()
            finally:os.close(fd)

    def test_probe_file_close_failure_poison_and_cleanup_closes_both(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);proc=root/'123';proc.mkdir()
            for name,raw in (('stat',self.stat),('status',self.status),('cgroup',self.cgroup),('mountinfo',self.mounts)):(proc/name).write_bytes(raw)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);actual=os.close;calls=[]
            try:
                owner=ProcessProbe._from_directory(fd,123,(0,27),time.monotonic()+2,owner=os.getuid())
                def uncertain(number):calls.append(number);actual(number);raise OSError('uncertain close')
                with patch('inventory_refresh_process_snapshot.os.close',side_effect=uncertain):
                    with self.assertRaises(ValueError):owner.sample()
                with self.assertRaises(ValueError):owner.sample()
                calls.clear()
                with patch('inventory_refresh_process_snapshot.os.close',side_effect=uncertain):
                    with self.assertRaises(ValueError):owner.close()
                self.assertEqual(len(calls),2)
                with self.assertRaises(ValueError):owner.close()
            finally:actual(fd)

    def test_exact_restricted_fixture(self):self.assertEqual(self.validate(),98765)
    def test_wrong_process_or_privileges_are_rejected(self):
        for replacement in (self.status.replace(b'Pid:\t123',b'Pid:\t124',1),self.status.replace(b'NoNewPrivs:\t1',b'NoNewPrivs:\t0'),
                self.status+b'Uid:\t60002 60002 60002 60002\n',self.status.replace(b'Groups:\t\n',b'Groups:\t7\n')):
            previous=self.status;self.status=replacement
            with self.assertRaises(ValueError):self.validate()
            self.status=previous
    def test_wrong_start_cgroup_and_device_are_rejected(self):
        for name,value in (('stat',self.stat.replace(b'98765',b'0')),('cgroup',self.cgroup+b'extra\n')):
            previous=getattr(self,name);setattr(self,name,value)
            with self.assertRaises(ValueError):self.validate()
            setattr(self,name,previous)
        with self.assertRaises(ValueError):validate_snapshot(self.pid,self.stat,self.status,self.cgroup,self.mounts,(0,28))
        with self.assertRaises(ValueError):validate_snapshot(True,self.stat,self.status,self.cgroup,self.mounts,(0,27))

    def test_writable_or_ambiguous_cgroup_mount_is_rejected(self):
        for replacement in (self.mounts.replace(b' ro,nosuid',b' rw,nosuid'),
                self.mounts+b'43 1 0:27 / /other rw - cgroup2 cgroup rw\n',
                self.mounts+b'44 42 0:28 / /sys/fs/cgroup/child rw - tmpfs tmpfs rw\n',b''):
            previous=self.mounts;self.mounts=replacement
            with self.assertRaises(ValueError):self.validate()
            self.mounts=previous
