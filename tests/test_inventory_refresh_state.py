"""Durable fixed-helper metadata only; no APT/process/service operations."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))


def module():
    spec = importlib.util.spec_from_file_location('inventory_refresh_state', ROOT/'scripts/inventory_refresh_state.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class RefreshStateTests(unittest.TestCase):
    def setUp(self):
        self.p = module()
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        self.journal = self.p.Journal(self.fd, owner=os.getuid())
        self.nonce = '0000000000000001'+'a'*16
        self.boot = '11111111-1111-4111-8111-111111111111'

    def tearDown(self):
        os.close(self.fd)
        self.temp.cleanup()

    def initialize(self):
        with self.journal.exclusive():
            self.journal.initialize('a'*32)

    def test_missing_state_never_silently_initializes_or_resets(self):
        with self.assertRaises(ValueError):
            self.journal.snapshot()
        self.assertFalse((self.directory/'control.json').exists())
        self.initialize()
        (self.directory/'control.json').unlink()
        with self.assertRaises(ValueError):
            self.journal.snapshot()
        with self.journal.exclusive(), self.assertRaises(ValueError):
            self.journal.initialize('b'*32)

    def test_receive_burns_durable_high_water_and_replay_preserves_acceptance(self):
        self.initialize()
        with self.journal.exclusive():
            self.assertEqual(self.journal.receive('refresh', self.nonce, self.boot, 100, 'b'*64), 'new')
            self.assertEqual(self.journal.receive('refresh', self.nonce, self.boot, 200, 'b'*64), 'existing')
            self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['high_water'], 1)
            self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['active']['accepted_boottime_ms'], 100)
            self.assertEqual(self.journal.receive('refresh', '0000000000000001'+'c'*16,
                                                 self.boot, 200, 'b'*64), 'stale')

    def test_start_is_persisted_once_before_permission_to_spawn(self):
        self.initialize()
        with self.journal.exclusive():
            self.journal.receive('refresh', self.nonce, self.boot, 100, 'b'*64)
            self.assertTrue(self.journal.start('refresh', self.nonce, self.boot, 101, policy='b'*64))
            self.assertFalse(self.journal.start('refresh', self.nonce, self.boot, 200, policy='b'*64))
            active = self.journal.snapshot()['capabilities']['refresh']['active']
            self.assertEqual(active['started_boottime_ms'], 101)
            self.assertEqual(active['phase'], 'running')

    def test_start_fsync_failure_does_not_grant_spawn_permission(self):
        self.initialize()
        with self.journal.exclusive():
            self.journal.receive('refresh', self.nonce, self.boot, 100, 'b'*64)
            with patch.object(self.p.os, 'fsync', side_effect=OSError('synthetic disk full')):
                with self.assertRaises(OSError):
                    self.journal.start('refresh', self.nonce, self.boot, 101, policy='b'*64)
            self.assertIsNone(self.journal.snapshot()['capabilities']['refresh']['active']['started_boottime_ms'])
            self.assertFalse(any(p.name.startswith('.control-') for p in self.directory.iterdir()))

    def test_success_requires_start_and_matching_immutable_terminal_result(self):
        self.initialize()
        with self.journal.exclusive():
            self.journal.receive('refresh', self.nonce, self.boot, 100, 'b'*64)
            with self.assertRaises(ValueError):
                self.journal.finish('refresh', self.nonce, self.boot, 102, 'succeeded', cache='c'*32, policy='b'*64)
            self.journal.start('refresh', self.nonce, self.boot, 101, policy='b'*64)
            self.journal.finish('refresh', self.nonce, self.boot, 102, 'succeeded', cache='c'*32, policy='b'*64)
            self.journal.finish('refresh', self.nonce, self.boot, 200, 'succeeded', cache='c'*32, policy='b'*64)
            terminal = self.journal.snapshot()['capabilities']['refresh']['terminal']
            self.assertEqual(terminal['finished_boottime_ms'], 102)
            with self.assertRaises(ValueError):
                self.journal.finish('refresh', self.nonce, self.boot, 200, 'succeeded', cache='d'*32, policy='b'*64)

    def test_restart_with_unresolved_active_work_blocks_new_work(self):
        self.initialize()
        with self.journal.exclusive():
            self.journal.receive('refresh', self.nonce, self.boot, 100, 'b'*64)
            self.journal.start('refresh', self.nonce, self.boot, 101, policy='b'*64)
        restarted = self.p.Journal(self.fd, owner=os.getuid())
        with restarted.exclusive():
            self.assertFalse(restarted.startup_ready())
            self.assertTrue(restarted.snapshot()['unconfirmed'])
            self.assertEqual(restarted.receive('refresh', '0000000000000002'+'b'*16,
                                               self.boot, 200, 'b'*64), 'unconfirmed')

    def test_unstarted_deferral_preserves_identity_and_allows_cached_observation(self):
        self.initialize()
        observe = '0000000000000002'+'b'*16
        with self.journal.exclusive():
            self.journal.receive('refresh', self.nonce, self.boot, 100, 'b'*64)
            self.journal.defer('refresh', self.nonce, self.boot, 'minimum_interval')
            self.assertTrue(self.journal.startup_ready())
            self.assertEqual(self.journal.receive('observation', observe, self.boot, 101, 'b'*64), 'new')
            self.assertTrue(self.journal.start('observation', observe, self.boot, 102, policy='b'*64))
            self.assertFalse(self.journal.start('refresh', self.nonce, self.boot, 103, policy='b'*64))
            self.journal.finish('observation', observe, self.boot, 104, 'succeeded', cache='c'*32, policy='b'*64)
            self.assertTrue(self.journal.start('refresh', self.nonce, self.boot, 105, policy='b'*64))
            self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['active']['accepted_boottime_ms'], 100)

    def test_release_can_only_join_its_exact_running_observation(self):
        self.initialize()
        with self.journal.exclusive():
            self.journal.receive('observation', self.nonce, self.boot, 100, 'b'*64)
            self.journal.start('observation', self.nonce, self.boot, 101, policy='b'*64)
            with self.assertRaises(ValueError):
                self.journal.receive('release', '0000000000000002'+'b'*16, self.boot, 102, 'b'*64)
            self.assertEqual(self.journal.receive('release', self.nonce, self.boot, 102, 'b'*64), 'new')
            self.assertTrue(self.journal.start('release', self.nonce, self.boot, 103, policy='b'*64))

    def test_only_known_unstarted_work_can_be_abandoned_for_a_higher_correlator(self):
        self.initialize()
        newer = '0000000000000002'+'b'*16
        with self.journal.exclusive():
            self.journal.receive('refresh', self.nonce, self.boot, 100, 'b'*64)
            self.journal.defer('refresh', self.nonce, self.boot, 'minimum_interval')
            self.assertEqual(self.journal.receive('refresh', newer, self.boot, 200, 'b'*64), 'new')
            prior = self.journal.snapshot()['capabilities']['refresh']['terminal']
            self.assertIsNone(prior['started_boottime_ms'])
            self.assertEqual(prior['phase'], 'failed')
            self.journal.start('refresh', newer, self.boot, 201, policy='b'*64)
            self.assertEqual(self.journal.receive('refresh', '0000000000000003'+'c'*16,
                                                 self.boot, 300, 'b'*64), 'busy')

    def test_hostile_operation_types_are_bounded_static_failures(self):
        self.initialize()
        with self.journal.exclusive():
            self.journal.receive('refresh', self.nonce, self.boot, 100, 'b'*64)
        original = (self.directory/'control.json').read_bytes()
        for field, invalid in [('reason', []), ('phase', []), ('helper_sequence', True)]:
            data = json.loads(original)
            data['capabilities']['refresh']['active'][field] = invalid
            (self.directory/'control.json').write_text(json.dumps(data))
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.journal.snapshot()

    def test_changed_policy_cannot_relabel_a_deferred_operation_or_published_result(self):
        self.initialize()
        with self.journal.exclusive():
            self.journal.receive('refresh', self.nonce, self.boot, 100, 'b'*64)
            self.journal.defer('refresh', self.nonce, self.boot, 'policy_changed')
            self.assertEqual(self.journal.receive('refresh', self.nonce, self.boot, 101, 'c'*64), 'existing')
            with self.assertRaises(ValueError):
                self.journal.start('refresh', self.nonce, self.boot, 102, policy='c'*64)
            self.assertIsNone(self.journal.snapshot()['capabilities']['refresh']['active']['started_boottime_ms'])
            self.journal.start('refresh', self.nonce, self.boot, 103, policy='b'*64)
            with self.assertRaises(ValueError):
                self.journal.finish('refresh', self.nonce, self.boot, 104, 'succeeded',
                                    cache='d'*32, policy='c'*64)

    def test_counter_alias_and_unknown_schema_fail_closed(self):
        self.initialize()
        content = (self.directory/'control.json').read_bytes()
        (self.directory/'control.json').unlink()
        other = self.directory/'other'
        other.write_bytes(content)
        other.chmod(0o600)
        (self.directory/'control.json').symlink_to(other)
        with self.assertRaises(ValueError):
            self.journal.snapshot()
        (self.directory/'control.json').unlink()
        data = json.loads(content)
        data['schema_version'] = 2
        (self.directory/'control.json').write_text(json.dumps(data))
        (self.directory/'control.json').chmod(0o600)
        with self.assertRaises(ValueError):
            self.journal.snapshot()


if __name__ == '__main__':
    unittest.main()
