"""Real cooperative maintenance locks; no process-set or readiness authority."""
import os
import select
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import inventory_refresh_maintenance_lock as module


PROGRAM = '''import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW)
try:
 fcntl.flock(fd,(fcntl.LOCK_SH if sys.argv[2]=='shared' else fcntl.LOCK_EX)|fcntl.LOCK_NB)
except BlockingIOError: sys.exit(42)
finally: os.close(fd)
'''


class MaintenanceLockTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)
        (self.path/'maintenance.lock').write_bytes(b'');(self.path/'maintenance.lock').chmod(0o644)
        self.parent=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY)
    def tearDown(self):
        os.close(self.parent);self.temp.cleanup()
    def guard(self,mode):
        return module.MaintenanceLock.from_directory(self.parent,mode,os.geteuid(),os.getegid())
    def contender(self,mode):
        child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',PROGRAM,str(self.path/'maintenance.lock'),mode],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return child.wait(timeout=5)
    def test_shared_and_exclusive_are_real_cross_process_guards(self):
        shared=self.guard('participant')
        self.assertEqual(self.contender('exclusive'),42)
        shared.close()
        exclusive=self.guard('maintenance')
        self.assertEqual(self.contender('shared'),42)
        exclusive.close()
        self.assertEqual(self.contender('exclusive'),0)
    def test_replacement_and_hardlink_are_never_admitted(self):
        os.link(self.path/'maintenance.lock',self.path/'other')
        with self.assertRaises(ValueError):self.guard('participant')
        (self.path/'other').unlink()
        original=module.fcntl.flock
        def replace(fd,mode):
            (self.path/'maintenance.lock').rename(self.path/'old')
            (self.path/'maintenance.lock').write_bytes(b'')
            (self.path/'maintenance.lock').chmod(0o644)
            return original(fd,mode)
        with patch.object(module.fcntl,'flock',side_effect=replace):
            with self.assertRaises(ValueError):self.guard('participant')
        self.assertTrue((self.path/'old').exists());self.assertTrue((self.path/'maintenance.lock').exists())

    def test_exec_child_retains_shared_lock_after_parent_close_and_crash(self):
        shared=self.guard('participant');fd=shared.inheritable_fd()
        program="import os,sys\nos.fstat(int(sys.argv[1]))\nos.write(1,b'ready\\n')\nsys.stdin.buffer.read(1)\nos._exit(77)"
        child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,str(fd)],pass_fds=(fd,),
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            ready,_,_=select.select([child.stdout],[],[],5)
            self.assertTrue(ready);self.assertEqual(child.stdout.readline(),b'ready\n')
            shared.close()
            self.assertEqual(self.contender('exclusive'),42)
            child.stdin.write(b'x');child.stdin.close();child.stdin=None
            self.assertEqual(child.wait(timeout=5),77)
            self.assertEqual(self.contender('exclusive'),0)
        finally:
            if child.stdin is not None:child.stdin.close()
            child.stdout.close()

    def test_close_attempts_every_descriptor_once_and_latches_failure(self):
        guard=self.guard('participant');calls=[];original=os.close
        def fail_first(fd):
            calls.append(fd);original(fd)
            if len(calls)==1:raise OSError('injected')
        with patch.object(module.os,'close',side_effect=fail_first),patch.object(module.fcntl,'flock') as flock:
            with self.assertRaises(ValueError):guard.close()
            with self.assertRaises(ValueError):guard.close()
        self.assertEqual(len(calls),2);self.assertEqual(len(set(calls)),2)
        flock.assert_not_called()

    def test_foreign_symlink_and_unsafe_mode_are_rejected(self):
        (self.path/'maintenance.lock').unlink()
        (self.path/'maintenance.lock').symlink_to('missing')
        with self.assertRaises(ValueError):self.guard('participant')
        (self.path/'maintenance.lock').unlink()
        (self.path/'maintenance.lock').write_bytes(b'');(self.path/'maintenance.lock').chmod(0o666)
        with self.assertRaises(ValueError):self.guard('participant')

    def test_unexpected_inheritance_and_duplicate_export_fail_closed(self):
        guard=self.guard('participant')
        os.set_inheritable(guard._file,True)
        with self.assertRaises(ValueError):guard.verify()
        with self.assertRaises(ValueError):guard.close()
        guard=self.guard('participant')
        guard.inheritable_fd()
        with self.assertRaises(ValueError):guard.inheritable_fd()
        with self.assertRaises(ValueError):guard.close()

    def test_changed_open_file_flags_are_absorbing(self):
        guard=self.guard('participant')
        flags=module.fcntl.fcntl(guard._file,module.fcntl.F_GETFL)
        module.fcntl.fcntl(guard._file,module.fcntl.F_SETFL,flags & ~os.O_NONBLOCK)
        with self.assertRaises(ValueError):guard.verify()
        with self.assertRaises(ValueError):guard.close()


if __name__=='__main__':unittest.main()
