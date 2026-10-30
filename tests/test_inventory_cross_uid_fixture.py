"""The synthetic cross-UID fixture accepts exactly one bounded binding shape."""
import importlib.util
import contextlib
import io
import os
from pathlib import Path
import tempfile
import time
import subprocess
import sys
import unittest
from unittest.mock import patch, Mock

SPEC = importlib.util.spec_from_file_location('native_inventory_cross_uid', Path(__file__).with_name('native_inventory_cross_uid.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from inventory_refresh_state import Journal
from inventory_refresh_io import Inbox


class BindingTest(unittest.TestCase):
    def test_unit_pin_distinguishes_exit_and_wrong_cgroup_without_raw_values(self):
        status = {'LoadState': 'loaded', 'InvocationID': 'a' * 32, 'ControlGroup': '/expected'}
        self.assertEqual(MODULE.unit_pin_decision(status, None, '/expected', time.monotonic() + 5), 'ready')
        with self.assertRaises(MODULE.PinError) as wrong:
            MODULE.unit_pin_decision(dict(status, ControlGroup='/private-detail'), None, '/expected', time.monotonic() + 5)
        self.assertEqual(wrong.exception.reason, 'unit_pin_cgroup')
        with self.assertRaises(MODULE.PinError) as exited:
            MODULE.unit_pin_decision({'LoadState': 'not-found', 'InvocationID': '', 'ControlGroup': ''}, 1, '/expected', time.monotonic() + 5)
        self.assertEqual(exited.exception.reason, 'unit_pin_exited')

    def test_libexec_creation_is_exclusive_and_preserves_uncertain_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                MODULE.ensure_libexec(parent, os.geteuid(), time.monotonic() + 5)
                self.assertTrue((Path(temporary) / 'libexec').is_dir())
                MODULE.ensure_libexec(parent, os.geteuid(), time.monotonic() + 5)
                (Path(temporary) / 'libexec').chmod(0o777)
                with self.assertRaises(ValueError): MODULE.ensure_libexec(parent, os.geteuid(), time.monotonic() + 5)
                (Path(temporary) / 'libexec').chmod(0o755)
                (Path(temporary) / 'libexec').rmdir()
                os.symlink('missing', Path(temporary) / 'libexec')
                with self.assertRaises(ValueError): MODULE.ensure_libexec(parent, os.geteuid(), time.monotonic() + 5)
                (Path(temporary) / 'libexec').unlink()
                with patch.object(MODULE.os, 'fsync', side_effect=OSError('injected')):
                    with self.assertRaises(ValueError): MODULE.ensure_libexec(parent, os.geteuid(), time.monotonic() + 5)
                self.assertTrue((Path(temporary) / 'libexec').is_dir())
            finally:
                os.close(parent)

    def test_libexec_replacement_fails_and_keeps_both_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            path = Path(temporary) / 'libexec'
            path.mkdir()
            real_open = os.open
            def replace_after_open(name, flags, *args, **kwargs):
                fd = real_open(name, flags, *args, **kwargs)
                if name == 'libexec':
                    path.rename(Path(temporary) / 'old-libexec')
                    path.mkdir()
                return fd
            try:
                with patch.object(MODULE.os, 'open', side_effect=replace_after_open):
                    with self.assertRaises(ValueError): MODULE.ensure_libexec(parent, os.geteuid(), time.monotonic() + 5)
                self.assertTrue(path.is_dir())
                self.assertTrue((Path(temporary) / 'old-libexec').is_dir())
            finally:
                os.close(parent)

    def test_libexec_close_failure_cannot_report_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            (Path(temporary) / 'libexec').mkdir()
            real_close = os.close
            calls = []
            def fail_after_close(fd):
                calls.append(fd)
                real_close(fd)
                raise OSError('injected')
            try:
                with patch.object(MODULE.os, 'close', side_effect=fail_after_close):
                    with self.assertRaises(ValueError): MODULE.ensure_libexec(parent, os.geteuid(), time.monotonic() + 5)
                self.assertEqual(len(calls), 1)
                self.assertTrue((Path(temporary) / 'libexec').is_dir())
            finally:
                real_close(parent)

    def test_failure_reports_only_fixed_stage_and_never_reaches_setup(self):
        output = io.StringIO()
        with patch.object(MODULE.sys, 'platform', 'linux'), patch.object(MODULE.os, 'geteuid', return_value=0), \
             patch.dict(MODULE.os.environ, {'GITHUB_ACTIONS': 'true'}), \
             patch.object(MODULE, 'unit_status', side_effect=ValueError('secret detail')), \
             patch.object(MODULE, 'create_account') as account, contextlib.redirect_stderr(output):
            with self.assertRaises(ValueError): MODULE.run('ignored')
        account.assert_not_called()
        self.assertEqual(output.getvalue(), 'Synthetic cross-UID stage=unit_status\n')

    def test_account_setup_timeout_does_not_signal_root_child(self):
        child = Mock()
        child.wait.side_effect = subprocess.TimeoutExpired('groupadd', 1)
        with patch.object(MODULE.subprocess, 'Popen', return_value=child):
            with self.assertRaises(ValueError): MODULE.account_command('group', time.monotonic() + 5)
        child.kill.assert_not_called()
        child.terminate.assert_not_called()
        with self.assertRaises(ValueError): MODULE.account_command('arbitrary', time.monotonic() + 5)

    def test_partial_ack_and_changed_pipe_flags_fail(self):
        read_fd, write_fd = os.pipe()
        reader = os.fdopen(read_fd, 'rb', buffering=0)
        writer = os.fdopen(write_fd, 'wb', buffering=0)
        try:
            os.set_blocking(writer.fileno(), False)
            info = os.fstat(writer.fileno())
            endpoints = ((writer, os.O_WRONLY, (info.st_dev, info.st_ino)),)
            MODULE.verify_endpoints(endpoints)
            with patch.object(MODULE.os, 'write', side_effect=[2, 0]):
                with self.assertRaises(ValueError): MODULE.write_ack(writer.fileno(), time.monotonic() + 5)
            os.set_blocking(writer.fileno(), True)
            with self.assertRaises(ValueError): MODULE.verify_endpoints(endpoints)
        finally:
            reader.close(); writer.close()

    def test_completion_requires_eof_and_no_extra_control_bytes(self):
        for unexpected in [False, True]:
            stdout, out_write = os.pipe()
            stderr, err_write = os.pipe()
            try:
                os.write(out_write, b'finished')
                if unexpected: os.write(err_write, b'x')
                os.close(out_write); out_write = None
                os.close(err_write); err_write = None
                if unexpected:
                    with self.assertRaises(ValueError): MODULE.read_completion(stdout, stderr, time.monotonic() + 5)
                else:
                    self.assertEqual(MODULE.read_completion(stdout, stderr, time.monotonic() + 5), b'finished')
            finally:
                os.close(stdout); os.close(stderr)
                if out_write is not None: os.close(out_write)
                if err_write is not None: os.close(err_write)

    def test_cgroup_sample_requires_same_named_directory_and_empty_events(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            os.mkdir('unit', dir_fd=parent)
            group = os.open('unit', os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
            try:
                path = Path(temporary) / 'unit'
                (path / 'cgroup.events').write_bytes(b'populated 0\nfrozen 0\n')
                MODULE.empty_group(parent, 'unit', group, time.monotonic() + 5)
                (path / 'cgroup.events').write_bytes(b'populated 1\nfrozen 0\n')
                with self.assertRaises(ValueError): MODULE.empty_group(parent, 'unit', group, time.monotonic() + 5)
                (path / 'cgroup.events').write_bytes(b'populated 0\npopulated 0\nfrozen 0\n')
                with self.assertRaises(ValueError): MODULE.empty_group(parent, 'unit', group, time.monotonic() + 5)
                (path / 'cgroup.events').write_bytes(b'populated 0\nfrozen 0\n')
                (path / 'child').mkdir()
                with self.assertRaises(ValueError): MODULE.empty_group(parent, 'unit', group, time.monotonic() + 5)
                (path / 'child').rmdir()
                path.rename(Path(temporary) / 'old')
                path.mkdir()
                with self.assertRaises(ValueError): MODULE.empty_group(parent, 'unit', group, time.monotonic() + 5)
            finally:
                os.close(group)
                os.close(parent)

    def test_marker_must_be_exact_and_bounded(self):
        for raw, valid in [(b'INVENTORY-BARRIER-1\n', True), (b'wrong\n', False),
                           (b'INVENTORY-BARRIER-1\nextra', False)]:
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, raw)
                os.close(write_fd)
                write_fd = None
                if valid:
                    self.assertEqual(MODULE.read_marker(read_fd, time.monotonic() + 5), raw)
                else:
                    with self.assertRaises(ValueError): MODULE.read_marker(read_fd, time.monotonic() + 5)
            finally:
                os.close(read_fd)
                if write_fd is not None: os.close(write_fd)

    def test_only_exact_executed_test_is_accepted(self):
        good = (b'running 1 test\n'
                b'test inventory::reporter_obs::tests::hosted_cross_uid_counter_admission ... ok\n'
                b'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.12s\n')
        MODULE.validate_test_output(good)
        for bad in [good.replace(b'running 1 test', b'running 0 tests'), good.replace(b' ... ok', b' ... ignored'),
                    good + b'extra\n', good.replace(b'1 passed', b'0 passed')]:
            with self.subTest(bad=bad[:40]), self.assertRaises(ValueError): MODULE.validate_test_output(bad)

    def test_root_accepts_only_after_exact_marker_and_never_starts(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            fixture = MODULE.Fixture.create(parent, os.geteuid(), os.getegid(), time.monotonic() + 10)
            journal = Journal(fixture.state, owner=os.geteuid())
            inbox = Inbox(fixture.root, 'observation', os.geteuid(), os.getegid(), owner=os.geteuid())
            try:
                fd = os.open('request', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fixture.observation)
                os.write(fd, MODULE.BINDING['nonce'].encode('ascii'))
                os.fsync(fd)
                os.close(fd)
                with journal.exclusive():
                    journal.initialize(MODULE.BINDING['epoch'])
                    state = journal.snapshot()
                    state['capabilities']['observation']['high_water'] = 7
                    state['capabilities']['release']['high_water'] = 7
                    journal._save(state)
                    with self.assertRaises(ValueError): MODULE.accept_after_marker(b'bad', fixture, journal, inbox)
                    self.assertIsNone(journal.snapshot()['capabilities']['observation']['active'])
                    MODULE.accept_after_marker(b'INVENTORY-BARRIER-1\n', fixture, journal, inbox)
                    active = journal.snapshot()['capabilities']['observation']['active']
                    self.assertEqual(active['phase'], 'received')
                    self.assertIsNone(active['started_boottime_ms'])
                    with self.assertRaises(ValueError): MODULE.accept_after_marker(b'INVENTORY-BARRIER-1\n', fixture, journal, inbox)
            finally:
                inbox.close()
                fixture.close()
                os.close(parent)

    def test_stale_epoch_or_floor_does_not_mutate_root_journal(self):
        for stale_epoch in [False, True]:
            with self.subTest(stale_epoch=stale_epoch), tempfile.TemporaryDirectory() as temporary:
                parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
                fixture = MODULE.Fixture.create(parent, os.geteuid(), os.getegid(), time.monotonic() + 10)
                journal = Journal(fixture.state, owner=os.geteuid())
                inbox = Inbox(fixture.root, 'observation', os.geteuid(), os.getegid(), owner=os.geteuid())
                try:
                    fd = os.open('request', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fixture.observation)
                    os.write(fd, MODULE.BINDING['nonce'].encode('ascii'))
                    os.close(fd)
                    with journal.exclusive():
                        journal.initialize('b' * 32 if stale_epoch else MODULE.BINDING['epoch'])
                        state = journal.snapshot()
                        state['capabilities']['observation']['high_water'] = 7 if stale_epoch else 8
                        journal._save(state)
                        before = journal.snapshot()
                        with self.assertRaises(ValueError): MODULE.accept_after_marker(b'INVENTORY-BARRIER-1\n', fixture, journal, inbox)
                        self.assertEqual(journal.snapshot(), before)
                finally:
                    inbox.close()
                    fixture.close()
                    os.close(parent)

    def test_status_timeout_never_signals_the_owned_root_child(self):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        child = Mock()
        child.stdout = os.fdopen(read_fd, 'rb', buffering=0)
        child.wait.side_effect = subprocess.TimeoutExpired('systemctl', 1)
        with patch.object(MODULE.subprocess, 'Popen', return_value=child):
            with self.assertRaises(ValueError): MODULE.unit_status(time.monotonic() + 5)
        child.kill.assert_not_called()
        child.terminate.assert_not_called()
        self.assertTrue(child.stdout.closed)

    def test_unit_status_has_exact_unambiguous_fields(self):
        raw = b'LoadState=loaded\nActiveState=active\nDescription=test\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nControlGroup=/system.slice/x.service\nMainPID=42\nResult=success\nExecMainCode=0\nExecMainStatus=0\nDelegate=no\nProtectControlGroups=yes\nMemoryPressureWatch=off\n'
        self.assertEqual(MODULE.parse_unit_status(raw)['MainPID'], '42')
        for bad in [raw + b'MainPID=42\n', raw + b'Unexpected=x\n', raw.replace(b'MainPID=42\n', b''), raw + b'x' * 4097]:
            with self.subTest(bad=bad[-32:]), self.assertRaises(ValueError):
                MODULE.parse_unit_status(bad)

    def test_live_identity_rejects_invocation_pid_and_profile_drift(self):
        status = {'LoadState':'loaded', 'ActiveState':'active', 'Description':'test',
                  'InvocationID':'a' * 32, 'ControlGroup':'/fixture', 'MainPID':'42',
                  'Delegate':'no', 'ProtectControlGroups':'yes', 'MemoryPressureWatch':'off'}
        self.assertEqual(MODULE.validate_live_identity(status, 'test', '/fixture'), ('a' * 32, 42))
        for field, value in [('InvocationID', 'b' * 32), ('MainPID', '43'), ('ControlGroup', '/other'),
                             ('Delegate', 'yes'), ('ProtectControlGroups', 'no'), ('ActiveState', 'inactive')]:
            changed = dict(status); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                MODULE.validate_live_identity(changed, 'test', '/fixture', 'a' * 32, 42)

    def test_exact_fixture_binding_only(self):
        good = b'{"schema_version":1,"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","enrollment":"00000000-0000-4000-8000-000000000001","nonce":"0000000000000008dddddddddddddddd","policy":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'
        self.assertEqual(MODULE.parse_binding(good)['nonce'], '0000000000000008dddddddddddddddd')
        for bad in [good + b' ', good.replace(b'"schema_version":1', b'"schema_version":true'),
                    good.replace(b'"epoch":', b'"epoch":"x","epoch":'),
                    good.replace(b'dddddddddddddddd', b'eeeeeeeeeeeeeeee'), good + b'x', b' ' * 1025]:
            with self.subTest(bad=bad[:32]), self.assertRaises(ValueError):
                MODULE.parse_binding(bad)

    def test_exclusive_creation_preserves_existing_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fixture = MODULE.Fixture.create(parent, os.geteuid(), os.getegid(), time.monotonic() + 10)
                fixture.verify()
                with self.assertRaises(ValueError):
                    MODULE.Fixture.create(parent, os.geteuid(), os.getegid(), time.monotonic() + 10)
                fixture.verify()
                fixture.close()
            finally:
                os.close(parent)

    def test_partial_sync_failure_is_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(MODULE.os, 'fsync', side_effect=OSError('injected')):
                    with self.assertRaises(ValueError):
                        MODULE.Fixture.create(parent, os.geteuid(), os.getegid(), time.monotonic() + 10)
                self.assertTrue((Path(temporary) / MODULE.Fixture.NAME).is_dir())
            finally:
                os.close(parent)

    def test_deadline_and_close_uncertainty_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for deadline in [float('inf'), time.monotonic() - 1]:
                    with self.assertRaises(ValueError):
                        MODULE.Fixture.create(parent, os.geteuid(), os.getegid(), deadline)
                self.assertFalse((Path(temporary) / MODULE.Fixture.NAME).exists())
                fixture = MODULE.Fixture.create(parent, os.geteuid(), os.getegid(), time.monotonic() + 10)
                expected = len(fixture._fds)
                real_close = os.close
                calls = []
                def close_once(fd):
                    calls.append(fd)
                    real_close(fd)
                    if len(calls) == 1: raise OSError('injected close failure')
                with patch.object(MODULE.os, 'close', side_effect=close_once):
                    with self.assertRaises(ValueError): fixture.close()
                    with self.assertRaises(ValueError): fixture.close()
                self.assertEqual(len(calls), expected)
                self.assertEqual(len(set(calls)), expected)
                self.assertTrue((Path(temporary) / MODULE.Fixture.NAME).exists())
            finally:
                os.close(parent)

    def test_changed_named_directory_or_binding_is_rejected(self):
        for binding in [False, True]:
            with self.subTest(binding=binding), tempfile.TemporaryDirectory() as temporary:
                parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    fixture = MODULE.Fixture.create(parent, os.geteuid(), os.getegid(), time.monotonic() + 10)
                    root = Path(temporary) / MODULE.Fixture.NAME
                    if binding:
                        (root / 'binding.json').write_bytes(b'changed')
                    else:
                        (root / 'observation').rename(root / 'old-observation')
                        (root / 'observation').mkdir(mode=0o770)
                    with self.assertRaises(ValueError): fixture.verify()
                    fixture.close()
                finally:
                    os.close(parent)


if __name__ == '__main__':
    unittest.main()
