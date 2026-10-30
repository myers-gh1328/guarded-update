"""Untrusted fixture bytes: no live PID or namespace authority."""
import unittest
import os
import io
import contextlib
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

    def test_hosted_status_diagnostic_distinguishes_reporter_group(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);proc=root/'123';proc.mkdir()
            status=self.status.replace(b'Groups:\t\n',b'Groups:\t7\n')
            for name,raw in (('stat',self.stat),('status',status),('cgroup',self.cgroup),('mountinfo',self.mounts)):(proc/name).write_bytes(raw)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);output=io.StringIO()
            try:
                owner=ProcessProbe._from_directory(fd,123,(0,27),time.monotonic()+2,owner=os.getuid())
                with patch('inventory_refresh_process_snapshot.os.geteuid',return_value=0),patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}),contextlib.redirect_stderr(output):
                    with self.assertRaises(ValueError):owner.sample()
                self.assertEqual(output.getvalue(),'Native fixture process probe stage=profile_groups\n')
                owner.close()
            finally:os.close(fd)

    def test_hosted_descendant_mount_diagnostic_uses_only_fixed_categories(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);proc=root/'123';proc.mkdir()
            unit=b'/sys/fs/cgroup/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory.service'
            mounts=self.mounts+b'43 1 0:27 / '+unit+b'/secret-name rw - cgroup2 cgroup rw\n'
            for name,raw in (('stat',self.stat),('status',self.status),('cgroup',self.cgroup),('mountinfo',mounts)):(proc/name).write_bytes(raw)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);output=io.StringIO()
            try:
                owner=ProcessProbe._from_directory(fd,123,(0,27),time.monotonic()+2,owner=os.getuid())
                with patch('inventory_refresh_process_snapshot.os.geteuid',return_value=0),patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}),contextlib.redirect_stderr(output):
                    with self.assertRaises(ValueError):owner.sample()
                self.assertEqual(output.getvalue(),'Native fixture mount comparison=unavailable\nNative fixture mount detail=root_link\nNative fixture process probe stage=profile_mount_writable_nested_descendant_one_other_root_single\n')
                owner.close()
            finally:os.close(fd)

    def test_matching_object_diagnostic_is_fixed_and_still_rejects(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);proc=root/'123';proc.mkdir()
            for name,raw in (('stat',self.stat),('status',self.status),('cgroup',self.cgroup),('mountinfo',self.mounts.replace(b' ro,nosuid',b' rw,nosuid'))):
                (proc/name).write_bytes(raw)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);output=io.StringIO()
            try:
                owner=ProcessProbe._from_directory(fd,123,(0,27),time.monotonic()+2,owner=os.getuid())
                def diagnostic(*args):owner._mount_detail='file_procs';owner._mount_metadata=('sample','root','other','yes','no','no','absent');return 'matching'
                with patch.object(owner,'mount_diagnostic',side_effect=diagnostic),patch('inventory_refresh_process_snapshot.os.geteuid',return_value=0),patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}),contextlib.redirect_stderr(output):
                    with self.assertRaises(ValueError):owner.sample()
                self.assertEqual(output.getvalue(),'Native fixture mount comparison=matching\nNative fixture mount object=file_procs\nNative fixture mount metadata=root,other,yes,no,no,absent\nNative fixture process probe stage=profile_mount_writable_root\n')
                owner.close()
            finally:os.close(fd)

    def test_hosted_failure_reports_only_fixed_probe_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);proc=root/'123';proc.mkdir()
            for name,raw in (('stat',self.stat),('status',self.status),('cgroup',self.cgroup),('mountinfo',self.mounts.replace(b' ro,nosuid',b' rw,nosuid'))):
                (proc/name).write_bytes(raw)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);output=io.StringIO()
            try:
                owner=ProcessProbe._from_directory(fd,123,(0,27),time.monotonic()+2,owner=os.getuid())
                with patch('inventory_refresh_process_snapshot.os.geteuid',return_value=0),patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}),contextlib.redirect_stderr(output):
                    with self.assertRaises(ValueError):owner.sample()
                self.assertEqual(output.getvalue(),'Native fixture mount comparison=unavailable\nNative fixture mount detail=root_link\nNative fixture process probe stage=profile_mount_writable_root\n')
                owner.close()
            finally:os.close(fd)

    def test_proc_root_mount_diagnostic_is_fixed_and_absorbs_uncertainty(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);proc=root/'123';proc.mkdir();(proc/'ns').mkdir()
            (proc/'root').symlink_to('/',target_is_directory=True)
            (proc/'ns'/'mnt:[123]').write_bytes(b'namespace');(proc/'ns'/'mnt').symlink_to('mnt:[123]')
            for name,raw in (('stat',self.stat),('status',self.status),('cgroup',self.cgroup),('mountinfo',self.mounts)):(proc/name).write_bytes(raw)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                owner=ProcessProbe._from_directory(fd,123,(0,27),time.monotonic()+2,owner=os.getuid())
                with patch('inventory_refresh_process_snapshot.classify_mounts',return_value=('matching','ok')):
                    self.assertEqual(owner.mount_diagnostic(self.stat,self.mounts),'matching')
                actual_close=os.close;closed=[];classified=[]
                def uncertain(number):
                    actual_close(number)
                    if classified:closed.append(number);raise OSError('uncertain')
                def compare(*args):classified.append(True);return ('matching','ok')
                with patch('inventory_refresh_process_snapshot.classify_mounts',side_effect=compare),patch('inventory_refresh_process_snapshot.os.close',side_effect=uncertain):
                    self.assertEqual(owner.mount_diagnostic(self.stat,self.mounts),'unavailable')
                self.assertGreaterEqual(len(closed),4)
                (proc/'root').unlink();(proc/'root').symlink_to('/tmp',target_is_directory=True)
                with patch('inventory_refresh_process_snapshot.classify_mounts',return_value=('matching','ok')):
                    self.assertEqual(owner.mount_diagnostic(self.stat,self.mounts),'unavailable')
                self.assertEqual(owner._mount_detail,'root_link')
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
    def test_reporter_primary_group_only_is_admitted(self):
        original=self.status
        self.status=original.replace(b'Groups:\t\n',b'Groups:\t60002\n')
        self.assertEqual(self.validate(),98765)
        for groups in (b'7',b'60002 7',b'60002 60002'):
            self.status=original.replace(b'Groups:\t\n',b'Groups:\t'+groups+b'\n')
            with self.assertRaises(ValueError):self.validate()
        self.status=original

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

    def test_writable_nested_mount_relation_to_unit_is_fixed_category(self):
        unit=b'/sys/fs/cgroup/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory.service'
        for path,label in ((unit,'unit'),(b'/sys/fs/cgroup/command.slice','ancestor'),(unit+b'/child','descendant_one_other_root_single')):
            mount=self.mounts+b'43 1 0:27 / '+path+b' rw - cgroup2 cgroup rw\n'
            with self.assertRaisesRegex(ValueError,'profile_mount_writable_nested_'+label):
                validate_snapshot(self.pid,self.stat,self.status,self.cgroup,mount,(0,27))

    def test_writable_mount_fixed_path_categories(self):
        for path,label in ((b'/sys/fs/cgroup/leaf','profile_mount_writable_nested_other'),
            (b'/sys/other','profile_mount_writable_sys'),(b'/run/other','profile_mount_writable_run'),
            (b'/var/other','profile_mount_writable_var'),(b'/proc/other','profile_mount_writable_proc')):
            mount=self.mounts+b'43 1 0:27 / '+path+b' rw - cgroup2 cgroup rw\n'
            with self.assertRaisesRegex(ValueError,label):
                validate_snapshot(self.pid,self.stat,self.status,self.cgroup,mount,(0,27))

    def test_writable_mount_category_distinguishes_root_and_other(self):
        for mount,label in ((self.mounts.replace(b' ro,nosuid',b' rw,nosuid'),'profile_mount_writable_root'),
            (self.mounts+b'43 1 0:27 / /other rw - cgroup2 cgroup rw\n','profile_mount_writable_other')):
            with self.assertRaisesRegex(ValueError,label):
                validate_snapshot(self.pid,self.stat,self.status,self.cgroup,mount,(0,27))

    def test_writable_or_ambiguous_cgroup_mount_is_rejected(self):
        for replacement in (self.mounts.replace(b' ro,nosuid',b' rw,nosuid'),
                self.mounts+b'43 1 0:27 / /other rw - cgroup2 cgroup rw\n',
                self.mounts+b'44 42 0:28 / /sys/fs/cgroup/child rw - tmpfs tmpfs rw\n',b''):
            previous=self.mounts;self.mounts=replacement
            with self.assertRaises(ValueError):self.validate()
            self.mounts=previous
