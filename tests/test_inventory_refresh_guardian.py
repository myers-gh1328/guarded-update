"""Guardian contract: fixed privilege drop and independent suspend-aware budget."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('refresh_guardian',ROOT/'scripts/inventory_refresh_guardian.py')
guardian=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guardian)


class GuardianTests(unittest.TestCase):
    def test_diagnostics_emit_only_static_stages_and_bounded_numeric_exit(self):
        with patch.object(guardian.os,'write') as write:
            guardian.diagnostic('child',127)
            self.assertEqual(write.call_args.args,(2,b'inventory_guardian_stage=child:127\n'))
            write.reset_mock()
            guardian.diagnostic('untrusted secret',127)
            guardian.diagnostic('child','untrusted secret')
            write.assert_not_called()

    def test_expired_or_invalid_job_never_spawns(self):
        for started,deadline,now in [(100,100,100),(100,600101,101),(100,200,200),(100,200,99)]:
            spawn=Mock()
            with self.subTest(started=started,deadline=deadline,now=now):
                self.assertEqual(guardian.supervise(started,deadline,spawn,lambda:now,Mock()),74 if deadline<=started or deadline-started>600000 or now<started else 76)
                spawn.assert_not_called()

    def test_clock_jump_expires_stopped_child_without_waiting_for_output(self):
        child=SimpleNamespace(poll=Mock(return_value=None),kill=Mock(),wait=Mock())
        spawn=Mock(return_value=child)
        clock=Mock(side_effect=[100,101,900000])
        self.assertEqual(guardian.supervise(100,600100,spawn,clock,Mock()),76)
        child.kill.assert_called_once_with()
        child.wait.assert_not_called()
        spawn.assert_called_once_with()

    def test_early_exit_never_claims_descendant_cleanup(self):
        child=SimpleNamespace(poll=Mock(return_value=0),kill=Mock())
        self.assertEqual(guardian.supervise(100,200,lambda:child,lambda:101,Mock()),0)
        child.kill.assert_not_called()

    def test_clock_rewind_or_probe_failure_terminates_owned_child(self):
        for events in [[100,101,99],[100,OSError('synthetic')],[100,True]]:
            child=SimpleNamespace(poll=Mock(return_value=None),kill=Mock())
            self.assertEqual(guardian.supervise(100,200,lambda:child,Mock(side_effect=events),Mock()),74)
            child.kill.assert_called_once_with()

    def test_loader_executes_only_admitted_source_without_import_search_or_bytecode(self):
        import sys
        before=list(sys.path)
        source=b"marker='admitted source'\n"
        with patch.object(guardian,'admit_library',return_value=source):
            worker=guardian.load_worker()
        self.assertEqual(worker.marker,'admitted source')
        self.assertEqual(sys.path,before)
        self.assertNotIn('worker',sys.modules)

    def test_fixed_setpriv_has_no_inherited_environment_or_command_surface(self):
        args=guardian.worker_argv(60001,60002)
        self.assertEqual(args,('/usr/bin/setpriv','--reuid=60001','--regid=60002','--clear-groups',
            '--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',
            '/usr/bin/python3','-I','-B',guardian.LIB_ROOT+'/worker.py'))
        for uid,gid in [(0,1),(1,0),(True,2),('60001',2),(-1,2)]:
            with self.subTest(uid=uid,gid=gid),self.assertRaises(ValueError):
                guardian.worker_argv(uid,gid)


if __name__=='__main__':
    unittest.main()
