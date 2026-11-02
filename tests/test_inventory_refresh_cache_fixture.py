"""Disposable tmpfs cache fixture; no production resource authority."""
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import inventory_refresh_cache_fixture as fixture


class CacheFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)
        self.parent=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY)
    def tearDown(self):os.close(self.parent);self.temp.cleanup()
    def test_existing_path_fails_before_mount(self):
        (self.path/fixture.NAME).mkdir();mount=Mock()
        with self.assertRaises(ValueError):fixture.CacheFixture._create(self.parent,os.getuid(),lambda:None,time.monotonic()+5,mount,lambda fd:None)
        mount.assert_not_called()
    def test_mount_failure_preserves_created_directory(self):
        mount=Mock(side_effect=ValueError('uncertain'))
        with self.assertRaises(ValueError):fixture.CacheFixture._create(self.parent,os.getuid(),lambda:None,time.monotonic()+5,mount,lambda fd:None)
        self.assertTrue((self.path/fixture.NAME).is_dir());mount.assert_called_once()
    def test_mount_timeout_never_signals_child(self):
        spawned=[];original=subprocess.Popen
        def spawn(*args,**kwargs):
            child=original([sys.executable,'-I','-c','import time;time.sleep(.2)'],**kwargs);spawned.append(child);return child
        with (patch.object(original,'kill',side_effect=AssertionError('signal')),
              patch.object(original,'terminate',side_effect=AssertionError('signal')),
              patch.object(fixture.subprocess,'Popen',side_effect=spawn)):
            with self.assertRaises(ValueError):fixture._mount(time.monotonic()+.03)
            self.assertEqual(spawned[0].wait(timeout=3),0)
    def test_nonroot_fixed_constructor_rejects_before_mount(self):
        with (patch.object(fixture.sys,'platform','linux'),
              patch.object(fixture.os,'getresuid',return_value=(1,1,1),create=True),
              patch.object(fixture,'_mount') as mount):
            with self.assertRaises(ValueError):fixture.CacheFixture.fixed(time.monotonic()+5)
        mount.assert_not_called()
    def test_failed_close_attempts_each_owned_descriptor_once(self):
        value=fixture.CacheFixture();value.fds=[os.dup(self.parent),os.dup(self.parent)]
        value.identities={fd:(os.fstat(fd).st_dev,os.fstat(fd).st_ino) for fd in value.fds}
        value.closed=False;value.failed=False;value.close_failed=False;value.chain=None
        original=os.close;calls=[]
        def close(fd):
            calls.append(fd);original(fd)
            if len(calls)==1:raise OSError('uncertain')
        with patch.object(fixture.os,'close',side_effect=close):
            with self.assertRaises(ValueError):value.close()
            with self.assertRaises(ValueError):value.close()
        self.assertEqual(len(calls),2);self.assertEqual(len(set(calls)),2)

    def test_mounted_name_replacement_latches_uncertainty(self):
        path=self.path/fixture.NAME;path.mkdir()
        value=fixture.CacheFixture();value.parent=os.dup(self.parent);value.underlying=os.dup(self.parent)
        value.mounted=os.open(path,os.O_RDONLY|os.O_DIRECTORY);value.fds=[value.parent,value.underlying,value.mounted]
        value.identities={fd:(os.fstat(fd).st_dev,os.fstat(fd).st_ino) for fd in value.fds}
        value.parent_identity=fixture._identity(os.fstat(value.parent));value.underlying_identity=fixture._identity(os.fstat(value.underlying))
        value.mount_identity=fixture._identity(os.fstat(value.mounted));value.mount_view=(1,2,3)
        value.verify_parent=lambda:None;value.verify_mount=lambda fd:(1,2,3);value.deadline=time.monotonic()+5
        value.closed=False;value.failed=False;value.close_failed=False;value.chain=None
        value.verify();path.rename(self.path/'old');path.mkdir()
        with self.assertRaises(ValueError):value.verify()
        path.rmdir();(self.path/'old').rename(path)
        with self.assertRaises(ValueError):value.verify()
        with self.assertRaises(ValueError):value.close()
