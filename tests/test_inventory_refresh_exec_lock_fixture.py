"""Disposable lifetime lock; no maintenance admission authority."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import inventory_refresh_exec_lock_fixture as fixture


class ExecLockFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)
        self.parent=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY)
    def tearDown(self):os.close(self.parent);self.temp.cleanup()
    def create(self):return fixture.ExecLock.create(self.parent,os.getuid(),os.getgid(),lambda:None)

    def test_exclusive_creation_and_replacement(self):
        value=self.create();value.verify()
        with self.assertRaises(ValueError):self.create()
        path=self.path/fixture.DIRECTORY/fixture.FILE;path.rename(path.with_name('old'))
        path.write_bytes(b'');path.chmod(0o644)
        with self.assertRaises(ValueError):value.verify()
        path.unlink();path.with_name('old').rename(path)
        with self.assertRaises(ValueError):value.verify()
        with self.assertRaises(ValueError):value.close()

    def test_fsync_failure_preserves_partial_directory(self):
        with patch.object(fixture.os,'fsync',side_effect=OSError('uncertain')):
            with self.assertRaises(ValueError):self.create()
        self.assertTrue((self.path/fixture.DIRECTORY).exists())

    def test_close_failure_is_absorbing_and_attempts_all(self):
        value=self.create();original=os.close;calls=[]
        def fail_first(fd):
            calls.append(fd);original(fd)
            if len(calls)==1:raise OSError('uncertain')
        with patch.object(fixture.os,'close',side_effect=fail_first):
            with self.assertRaises(ValueError):value.close()
            with self.assertRaises(ValueError):value.close()
        self.assertEqual(len(calls),3);self.assertEqual(len(set(calls)),3)

    def test_replaced_directory_is_never_accepted(self):
        value=self.create();path=self.path/fixture.DIRECTORY
        path.rename(self.path/'old');path.mkdir()
        with self.assertRaises(ValueError):value.verify()
        with self.assertRaises(ValueError):value.close()
