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

    def test_no_work_decision_is_durable_immutable_and_old_nonce_never_starts_later(self):
        self.initialize()
        newer='0000000000000002'+'c'*16
        with self.journal.exclusive():
            self.journal.receive('refresh',self.nonce,self.boot,100,'b'*64)
            self.journal.defer('refresh',self.nonce,self.boot,'minimum_interval',now=101)
            original=self.journal.snapshot()['capabilities']['refresh']['active']
            self.assertEqual(original.get('decision_boottime_ms'),101)
            self.assertIsNone(original['started_boottime_ms'])
            self.assertIsNone(original['finished_boottime_ms'])
            self.journal.defer('refresh',self.nonce,self.boot,'executor_busy',now=200)
            self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['active'],original)
            self.assertFalse(self.journal.start('refresh',self.nonce,self.boot,1000000,policy='b'*64))
            self.assertEqual(self.journal.receive('refresh',newer,self.boot,1000001,'b'*64),'new')
            self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['terminal'],original)
            self.assertEqual(self.journal.receive('refresh',self.nonce,self.boot,1000002,'b'*64),'existing')
            self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['terminal'],original)
            self.assertTrue(self.journal.start('refresh',newer,self.boot,1000003,policy='b'*64))
            self.assertFalse(self.journal.start('refresh',newer,self.boot,1000004,policy='b'*64))

    def test_minimum_interval_records_one_no_work_endpoint_and_requires_a_new_nonce(self):
        self.initialize()
        second='0000000000000002'+'b'*16
        third='0000000000000003'+'c'*16
        with self.journal.exclusive():
            self.journal.receive('refresh',self.nonce,self.boot,10,'b'*64)
            self.journal.start('refresh',self.nonce,self.boot,11,policy='b'*64)
            self.journal.finish('refresh',self.nonce,self.boot,12,'succeeded',cache='c'*32,policy='b'*64)
            self.journal.receive('refresh',second,self.boot,100,'b'*64)
            self.assertFalse(self.journal.start('refresh',second,self.boot,101,policy='b'*64))
            frozen=self.journal.snapshot()['capabilities']['refresh']['active']
            self.assertEqual(frozen['decision_boottime_ms'],101)
            self.assertEqual(frozen['reason'],'minimum_interval')
            self.assertFalse(self.journal.start('refresh',second,self.boot,1000012,policy='b'*64))
            self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['active'],frozen)
            self.journal.receive('refresh',third,self.boot,1000013,'b'*64)
            self.assertTrue(self.journal.start('refresh',third,self.boot,1000014,policy='b'*64))
            self.assertEqual(self.journal.receive('refresh',second,self.boot,1000015,'b'*64),'existing')
            self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['terminal'],frozen)
            self.assertEqual(self.journal.receive('refresh',self.nonce,self.boot,1000016,'b'*64),'stale')

    def test_no_work_fsync_failure_does_not_return_a_durable_decision_or_reset_counter(self):
        self.initialize()
        with self.journal.exclusive():
            self.journal.receive('refresh',self.nonce,self.boot,100,'b'*64)
            with patch.object(self.p.os,'fsync',side_effect=OSError('synthetic disk failure')):
                with self.assertRaises(OSError):
                    self.journal.defer('refresh',self.nonce,self.boot,'minimum_interval',now=101)
            with self.assertRaises(ValueError):
                self.journal.snapshot()
            self.assertTrue(self.journal.startup_ready())
            state=self.journal.snapshot()['capabilities']['refresh']
            self.assertEqual(state['high_water'],1)
            self.assertEqual(state['active']['phase'],'received')
            self.assertIsNone(state['active']['decision_boottime_ms'])
            self.assertIsNone(state['active']['started_boottime_ms'])
            self.assertFalse(any(path.name.startswith('.control-') for path in self.directory.iterdir()))

    def test_visible_decision_after_directory_fsync_failure_is_not_durable_evidence_until_reconciled(self):
        self.initialize()
        with self.journal.exclusive():
            self.journal.receive('refresh',self.nonce,self.boot,100,'b'*64)
            original_fsync=self.p.os.fsync
            calls=[0]
            def fail_directory(fd):
                calls[0]+=1
                if calls[0]==2:
                    raise OSError('synthetic directory persistence failure')
                return original_fsync(fd)
            with patch.object(self.p.os,'fsync',side_effect=fail_directory):
                with self.assertRaises(OSError):
                    self.journal.defer('refresh',self.nonce,self.boot,'minimum_interval',now=101)
            visible=json.loads((self.directory/'control.json').read_bytes())
            self.assertEqual(visible['capabilities']['refresh']['active']['decision_boottime_ms'],101)
            with self.assertRaises(ValueError):
                self.journal.snapshot()
            self.assertTrue(self.journal.startup_ready())
            durable=self.journal.snapshot()['capabilities']['refresh']
            self.assertEqual(durable['high_water'],1)
            self.assertEqual(durable['active']['decision_boottime_ms'],101)
            self.assertFalse(self.journal.start('refresh',self.nonce,self.boot,1000000,policy='b'*64))

    def test_failed_private_temp_creation_cannot_delete_existing_root_metadata(self):
        self.initialize()
        temporary=self.directory/('.control-'+'d'*32)
        temporary.write_bytes(b'existing synthetic private metadata')
        temporary.chmod(0o600)
        with self.journal.exclusive(),patch.object(self.p.secrets,'token_hex',return_value='d'*32):
            with self.assertRaises(OSError):
                self.journal.receive('refresh',self.nonce,self.boot,100,'b'*64)
        self.assertEqual(temporary.read_bytes(),b'existing synthetic private metadata')

    def test_new_or_failed_barrier_blocks_snapshot_start_and_publication(self):
        from inventory_refresh_io import StatusPublisher
        self.initialize()
        with self.journal.exclusive():
            self.journal.receive('refresh',self.nonce,self.boot,100,'b'*64)
        reopened=self.p.Journal(self.fd,owner=os.getuid())
        public=self.directory/'public-status'
        public.mkdir(mode=0o750)
        public.chmod(0o750)
        public_fd=os.open(public,os.O_RDONLY|os.O_DIRECTORY)
        publisher=StatusPublisher(public_fd,reopened,os.getgid(),owner=os.getuid())
        try:
            with reopened.exclusive():
                for after_failed_barrier in [False,True]:
                    if after_failed_barrier:
                        with patch.object(self.p.os,'fsync',side_effect=OSError('synthetic barrier failure')):
                            with self.assertRaises(OSError):
                                reopened.startup_ready()
                    with self.assertRaises(ValueError):
                        reopened.snapshot()
                    with self.assertRaises(ValueError):
                        reopened.start('refresh',self.nonce,self.boot,101,policy='b'*64)
                    with self.assertRaises(ValueError):
                        publisher._publish(b'{"schema_version":1}')
                    self.assertFalse((public/'status.json').exists())
                self.assertTrue(reopened.startup_ready())
                self.assertEqual(reopened.snapshot()['capabilities']['refresh']['high_water'],1)
                publisher._publish(b'{"schema_version":1}')
                self.assertTrue(reopened.start('refresh',self.nonce,self.boot,101,policy='b'*64))
        finally:
            publisher.close()
            os.close(public_fd)

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
            with self.assertRaises(ValueError):
                self.journal.snapshot()
            self.assertTrue(self.journal.startup_ready())
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
            self.journal.defer('refresh', self.nonce, self.boot, 'minimum_interval', now=101)
            self.assertTrue(self.journal.startup_ready())
            self.assertEqual(self.journal.receive('observation', observe, self.boot, 101, 'b'*64), 'new')
            self.assertTrue(self.journal.start('observation', observe, self.boot, 102, policy='b'*64))
            self.assertFalse(self.journal.start('refresh', self.nonce, self.boot, 103, policy='b'*64))
            self.journal.finish('observation', observe, self.boot, 104, 'succeeded', cache='c'*32, policy='b'*64)
            self.assertFalse(self.journal.start('refresh', self.nonce, self.boot, 105, policy='b'*64))
            newer='0000000000000002'+'c'*16
            self.assertEqual(self.journal.receive('refresh',newer,self.boot,105,'b'*64),'new')
            self.assertTrue(self.journal.start('refresh',newer,self.boot,106,policy='b'*64))
            self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['terminal']['accepted_boottime_ms'],100)

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
            self.journal.defer('refresh', self.nonce, self.boot, 'minimum_interval', now=101)
            self.assertEqual(self.journal.receive('refresh', newer, self.boot, 200, 'b'*64), 'new')
            prior = self.journal.snapshot()['capabilities']['refresh']['terminal']
            self.assertIsNone(prior['started_boottime_ms'])
            self.assertEqual(prior['phase'], 'deferred')
            self.assertEqual(prior['reason'], 'minimum_interval')
            self.assertEqual(prior['decision_boottime_ms'], 101)
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
            self.journal.defer('refresh', self.nonce, self.boot, 'policy_changed', now=101)
            self.assertEqual(self.journal.receive('refresh', self.nonce, self.boot, 101, 'c'*64), 'existing')
            with self.assertRaises(ValueError):
                self.journal.start('refresh', self.nonce, self.boot, 102, policy='c'*64)
            self.assertIsNone(self.journal.snapshot()['capabilities']['refresh']['active']['started_boottime_ms'])
            self.assertFalse(self.journal.start('refresh', self.nonce, self.boot, 103, policy='b'*64))
            newer='0000000000000002'+'c'*16
            self.journal.receive('refresh',newer,self.boot,103,'b'*64)
            self.journal.start('refresh',newer,self.boot,104,policy='b'*64)
            with self.assertRaises(ValueError):
                self.journal.finish('refresh', newer, self.boot, 105, 'succeeded',
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
