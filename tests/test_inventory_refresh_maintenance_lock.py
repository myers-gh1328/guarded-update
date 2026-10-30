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
    def contender(self,mode,name='maintenance.lock'):
        child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',PROGRAM,str(self.path/name),mode],
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

    def test_admission_blocks_new_participants_during_drain(self):
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        participant=module.MaintenanceAdmission.participant(self.parent,os.geteuid(),os.getegid())
        owner=module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid())
        self.assertFalse(owner.try_lifetime())
        with self.assertRaises(module.MaintenanceContended):
            module.MaintenanceAdmission.participant(self.parent,os.geteuid(),os.getegid())
        participant.close()
        self.assertTrue(owner.try_lifetime())
        owner.close()

    def test_paused_admission_and_competing_maintenance(self):
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        gate=module.MaintenanceLock.from_directory(self.parent,'participant',os.geteuid(),os.getegid(),name=module.GATE)
        with self.assertRaises(module.MaintenanceContended):
            module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid())
        lifetime=self.guard('participant');gate.close()
        owner=module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid())
        with self.assertRaises(module.MaintenanceContended):
            module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid())
        self.assertFalse(owner.try_lifetime());lifetime.close()
        self.assertTrue(owner.try_lifetime());owner.close()

    def test_gate_cannot_be_exported_and_replacement_is_absorbing(self):
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        gate=module.MaintenanceLock.from_directory(self.parent,'participant',os.geteuid(),os.getegid(),name=module.GATE)
        with self.assertRaises(ValueError):gate.inheritable_fd()
        with self.assertRaises(ValueError):gate.close()
        owner=module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid())
        (self.path/'admission.lock').rename(self.path/'old-gate')
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        with self.assertRaises(ValueError):owner.try_lifetime()
        with self.assertRaises(ValueError):owner.close()
        # Close the deliberately retained test descriptor after asserting unknown.
        for fd in owner._gate._fds:os.close(fd)
        owner._gate._fds=[]

    def test_gate_blocks_new_participant_in_a_separate_process(self):
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        owner=module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid())
        program="import os,sys\nsys.path.insert(0,sys.argv[1])\nfrom inventory_refresh_maintenance_lock import MaintenanceAdmission,MaintenanceContended\nd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)\ntry:\n g=MaintenanceAdmission.participant(d,os.getuid(),os.getgid())\nexcept MaintenanceContended: sys.exit(42)\ng.close();os.close(d)"
        def contender():
            child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,str(Path(module.__file__).parent),str(self.path)],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            return child.wait(timeout=5)
        self.assertEqual(contender(),42);owner.close();self.assertEqual(contender(),0)

    def test_separate_process_admission_pause_and_owner_crash(self):
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        program="import os,sys\nsys.path.insert(0,sys.argv[1])\nfrom inventory_refresh_maintenance_lock import MaintenanceLock,GATE\nd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)\ng=MaintenanceLock.from_directory(d,sys.argv[3],os.getuid(),os.getgid(),name=GATE)\nos.write(1,b'ready\\n');sys.stdin.buffer.read(1);os._exit(77)"
        def start(mode):
            child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,str(Path(module.__file__).parent),str(self.path),mode],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            self.assertTrue(select.select([child.stdout],[],[],5)[0]);self.assertEqual(child.stdout.readline(),b'ready\n')
            return child
        def finish(child):
            child.stdin.write(b'x');child.stdin.close();child.stdin=None
            self.assertEqual(child.wait(timeout=5),77);child.stdout.close()
        paused=start('participant')
        with self.assertRaises(module.MaintenanceContended):
            module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid())
        finish(paused)
        exclusive=start('maintenance')
        with self.assertRaises(module.MaintenanceContended):
            module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid())
        with self.assertRaises(module.MaintenanceContended):
            module.MaintenanceAdmission.participant(self.parent,os.geteuid(),os.getegid())
        finish(exclusive)
        owner=module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid());owner.close()

    def test_uncertain_lifetime_does_not_release_gate(self):
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        owner=module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid())
        self.assertTrue(owner.try_lifetime())
        with patch.object(owner._lifetime,'close',side_effect=ValueError('uncertain')):
            with self.assertRaises(ValueError):owner.close()
            with self.assertRaises(ValueError):owner.close()
        with self.assertRaises(module.MaintenanceContended):
            module.MaintenanceAdmission.participant(self.parent,os.geteuid(),os.getegid())
        owner._lifetime.close();owner._gate.close()

    def test_lifetime_failure_is_not_reported_as_contention(self):
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        owner=module.MaintenanceAdmission.maintenance(self.parent,os.geteuid(),os.getegid())
        (self.path/'maintenance.lock').unlink()
        with self.assertRaises(ValueError) as raised:owner.try_lifetime()
        self.assertNotIsInstance(raised.exception,module.MaintenanceContended)
        with self.assertRaises(ValueError):owner.close()
        owner._gate.close()

    def test_checked_participant_checks_marker_twice_under_shared_gate(self):
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        calls=[]
        def absent():
            calls.append(1)
            self.assertEqual(self.contender('exclusive','admission.lock'),42)
            return False
        lifetime=module.MaintenanceAdmission.participant_checked(self.parent,os.geteuid(),os.getegid(),absent)
        self.assertEqual(calls,[1,1]);lifetime.close()

    def test_checked_participant_rejects_marker_change_and_nonboolean(self):
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        program="import os,sys\nsys.path.insert(0,sys.argv[1])\nfrom inventory_refresh_maintenance_lock import MaintenanceAdmission\nd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY);mode=sys.argv[3];seen=[]\ndef sample():\n seen.append(1)\n if mode=='error':raise OSError('private')\n return 0 if mode=='nonboolean' else len(seen)>1\ntry: MaintenanceAdmission.participant_checked(d,os.getuid(),os.getgid(),sample)\nexcept ValueError:os._exit(42)\nos._exit(1)"
        for mode in ('changed','error','nonboolean'):
            child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,str(Path(module.__file__).parent),str(self.path),mode],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            self.assertEqual(child.wait(timeout=5),42)

    def test_checked_participant_never_transfers_on_partial_or_close_failure(self):
        (self.path/'admission.lock').write_bytes(b'');(self.path/'admission.lock').chmod(0o644)
        original=module.MaintenanceLock.from_directory;owned=[]
        def fail_lifetime(*args,**kwargs):
            if kwargs.get('name')!=module.GATE:raise ValueError('uncertain')
            value=original(*args,**kwargs);owned.append(value);return value
        with patch.object(module.MaintenanceLock,'from_directory',side_effect=fail_lifetime):
            with self.assertRaises(ValueError):
                module.MaintenanceAdmission.participant_checked(self.parent,os.geteuid(),os.getegid(),lambda:False)
        self.assertEqual(self.contender('exclusive','admission.lock'),42);owned.pop().close()
        def gate_close_fails(*args,**kwargs):
            value=original(*args,**kwargs);owned.append(value)
            if kwargs.get('name')==module.GATE:
                value.close=unittest.mock.Mock(side_effect=ValueError('uncertain'))
            return value
        with patch.object(module.MaintenanceLock,'from_directory',side_effect=gate_close_fails):
            with self.assertRaises(ValueError):
                module.MaintenanceAdmission.participant_checked(self.parent,os.geteuid(),os.getegid(),lambda:False)
        self.assertEqual(self.contender('exclusive'),42)
        owned[1].close();module.MaintenanceLock.close(owned[0])


if __name__=='__main__':unittest.main()
