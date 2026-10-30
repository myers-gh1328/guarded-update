"""Persistent maintenance marker mechanics, not an active startup fence."""
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_maintenance_fence as fence


class FenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)
        self.directory=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY)
    def tearDown(self):os.close(self.directory);self.temp.cleanup()
    def present(self):return fence.present(self.directory,os.getuid(),lambda:None)
    def create(self):return fence.create(self.directory,os.getuid(),os.getgid(),lambda:None)

    def test_absent_create_reopen_and_duplicate(self):
        self.assertFalse(self.present());self.create();self.assertTrue(self.present())
        self.assertEqual((self.path/fence.NAME).read_bytes(),fence.BODY)
        with self.assertRaises(ValueError):self.create()
        self.assertTrue(self.present())

    def test_dangling_symlink_counts_as_present_and_is_never_overwritten(self):
        (self.path/fence.NAME).symlink_to('missing')
        self.assertTrue(self.present())
        with self.assertRaises(ValueError):self.create()
        self.assertTrue((self.path/fence.NAME).is_symlink())

    def test_failed_fsync_preserves_visible_fence(self):
        with patch.object(fence.os,'fsync',side_effect=OSError('injected')):
            with self.assertRaises(ValueError):self.create()
        self.assertTrue(self.present());self.assertTrue((self.path/fence.NAME).exists())

    def test_short_write_and_close_failure_do_not_remove_fence(self):
        original=fence.os.write
        with patch.object(fence.os,'write',side_effect=lambda fd,data:original(fd,data[:1])):
            self.create()
        self.assertTrue(self.present())
        (self.path/fence.NAME).unlink()
        original_close=fence.os.close
        def fail(fd):original_close(fd);raise OSError('injected')
        with patch.object(fence.os,'close',side_effect=fail):
            with self.assertRaises(ValueError):self.create()
        self.assertTrue(self.present())

    def test_replaced_marker_cannot_report_success(self):
        original=fence.os.fsync;called=[]
        def replace(fd):
            original(fd);called.append(1)
            if len(called)==2:
                (self.path/fence.NAME).rename(self.path/'previous')
                (self.path/fence.NAME).write_bytes(b'foreign')
        with patch.object(fence.os,'fsync',side_effect=replace):
            with self.assertRaises(ValueError):self.create()
        self.assertEqual((self.path/fence.NAME).read_bytes(),b'foreign');self.assertTrue(self.present())

    def test_crash_during_publication_leaves_visible_marker(self):
        program="import os,sys\nsys.path.insert(0,sys.argv[1])\nimport inventory_refresh_maintenance_fence as f\nd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)\nf.os.fsync=lambda fd:os._exit(73)\nf.create(d,os.getuid(),os.getgid(),lambda:None)"
        child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,str(Path(fence.__file__).parent),str(self.path)],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.assertEqual(child.wait(timeout=5),73);self.assertTrue(self.present())

    def test_crash_after_durable_create_keeps_marker(self):
        program="import os,sys\nsys.path.insert(0,sys.argv[1])\nimport inventory_refresh_maintenance_fence as f\nd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)\nf.create(d,os.getuid(),os.getgid(),lambda:None)\nos._exit(74)"
        child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,str(Path(fence.__file__).parent),str(self.path)],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.assertEqual(child.wait(timeout=5),74);self.assertTrue(self.present())

    def test_public_directory_requires_exact_read_only_access_profile(self):
        os.fchmod(self.directory,0o755)
        fence._public_directory(self.directory,os.getuid(),os.getgid(),lambda:None)
        with self.assertRaises(ValueError):fence._public_directory(self.directory,os.getuid()+1,os.getgid(),lambda:None)
        with self.assertRaises(ValueError):fence._public_directory(self.directory,os.getuid(),os.getgid()+1,lambda:None)
        for mode in (0o700,0o775,0o777):
            os.fchmod(self.directory,mode)
            with self.assertRaises(ValueError):fence._public_directory(self.directory,os.getuid(),os.getgid(),lambda:None)

    def test_public_publisher_rejects_nonroot_before_open(self):
        account=type('Account',(),{'pw_uid':12345,'pw_gid':12345})()
        with (patch.object(fence.sys,'platform','linux'),patch.object(fence.pwd,'getpwnam',return_value=account),
              patch.object(fence.os,'geteuid',return_value=12345),patch.object(fence.os,'getegid',return_value=12345),
              patch.object(fence.os,'getresuid',return_value=(12345,12345,12345),create=True),
              patch.object(fence.os,'getresgid',return_value=(12345,12345,12345),create=True),
              patch.object(fence.os,'open') as opened):
            with self.assertRaises(ValueError):fence._fixed_public('create')
        opened.assert_not_called()


if __name__=='__main__':unittest.main()
