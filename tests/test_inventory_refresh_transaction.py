"""Real journal/cache/status transaction contracts; service calls are test fakes."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_inventory_refresh_policy import fixture
from inventory_refresh_state import Journal
from inventory_refresh_storage import Store
from inventory_refresh_policy_admission import PolicyGuard
from inventory_refresh_io import StatusPublisher
from inventory_refresh_observation import ObservationError
from inventory_refresh_transaction import RefreshTransaction,TransactionError


class RefreshTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.fds=[]
        for name in ('state','cache','policy','status'):
            path=self.root/name;path.mkdir(mode=0o700 if name in ('state','policy') else 0o750)
            self.fds.append(os.open(path,os.O_RDONLY|os.O_DIRECTORY))
        for name,data in [('policy.json',json.dumps(fixture()).encode()),('policy-commitment.key',b'k'*32)]:
            path=self.root/'policy'/name;path.write_bytes(data);path.chmod(0o600)
        self.policy=PolicyGuard(self.fds[2],owner=os.getuid(),group=os.getgid())
        self.journal=Journal(self.fds[0],owner=os.getuid());self.lock=self.journal.exclusive();self.lock.__enter__()
        self.journal.initialize('a'*32)
        self.store=Store(self.fds[1],os.getuid(),os.getgid(),os.getuid())
        self.publisher=StatusPublisher(self.fds[3],self.journal,os.getgid(),owner=os.getuid())
        self.resources=Mock();self.writers=Mock();self.events=[]
        self.boot='11111111-1111-4111-8111-111111111111';self.now=900000
        self.native=Mock();self.service=Mock();self.service.launch.return_value=self.service;self.service.wait.return_value=90
        self.service.launch.side_effect=lambda:self.event('launch',self.service)
        self.service.close.side_effect=lambda:self.event('service_closed')
        self.writers.check.side_effect=lambda:self.event('writers_empty')
        self.preparer=Mock();self.preparer.prepare.side_effect=self.prepare;self.preparer.close.side_effect=lambda:self.event('preparer_closed')
        self.transaction=RefreshTransaction(self.journal,self.policy,self.resources,self.store,self.publisher,self.writers,
            materializer_factory=lambda:self.preparer,service_factory=lambda *_:self.service,
            contention_factory=lambda **_:self.native,clock=self.clock)
        self.nonce='0000000000000001'+'a'*16

    def event(self,name,value=None):self.events.append(name);return value
    def clock(self):self.now+=1;return self.boot,self.now
    def prepare(self,journal,policy):
        record=journal.snapshot()['capabilities']['refresh']['active']
        self.assertEqual(record['phase'],'running');self.events.append('materialize')
        stage=self.root/'cache'/('staging-'+'b'*32);(stage/'lists').mkdir(parents=True)
        (stage/'lists/synthetic_Packages').write_bytes(b'synthetic metadata')
        return {'staging_token':'b'*32,'deadline_boottime_ms':record['started_boottime_ms']+600000}

    def tearDown(self):
        self.publisher.close();self.policy.close();self.lock.__exit__(None,None,None)
        for fd in self.fds:os.close(fd)
        self.temp.cleanup()

    def test_same_journal_new_start_actual_store_and_public_status_complete_once(self):
        self.assertEqual(self.transaction.refresh(self.nonce),'succeeded')
        value=self.journal.snapshot();self.assertIsNone(value['capabilities']['refresh']['active'])
        self.assertEqual(value['last_success']['attempt']['phase'],'succeeded')
        public=json.loads((self.root/'status/status.json').read_bytes())
        self.assertEqual(public['phase'],'succeeded');self.assertEqual(public['operation_nonce'],self.nonce)
        self.assertEqual(public['cache_generation'],value['last_success']['attempt']['cache_generation'])
        with self.store.lease_current() as lease:self.assertEqual(lease.read_index('synthetic_Packages'),b'synthetic metadata')
        self.assertLess(self.events.index('materialize'),self.events.index('launch'))
        self.assertLess(self.events.index('preparer_closed'),self.events.index('launch'))
        self.assertIn('writers_empty',self.events[self.events.index('service_closed')+1:])
        self.assertEqual(self.transaction.refresh(self.nonce),'existing')
        self.service.launch.assert_called_once();self.preparer.prepare.assert_called_once()

    def test_minimum_interval_retains_prior_cache_without_another_launch(self):
        self.transaction.refresh(self.nonce)
        success=self.journal.snapshot()['last_success']
        second='0000000000000002'+'a'*16
        self.assertEqual(self.transaction.refresh(second),'deferred')
        decision=self.journal.snapshot()['capabilities']['refresh']['active']
        self.assertEqual(decision['reason'],'minimum_interval')
        self.assertIsNone(decision['started_boottime_ms'])
        self.assertEqual(self.journal.snapshot()['last_success'],success)
        public=json.loads((self.root/'status/status.json').read_bytes())
        self.assertEqual(public['cache_generation'],success['attempt']['cache_generation'])
        self.assertEqual(self.transaction.refresh(second),'existing')
        self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['active'],decision)
        self.service.launch.assert_called_once();self.preparer.prepare.assert_called_once()

    def test_visible_cache_pointer_without_durable_success_is_not_rolled_back_or_confirmed(self):
        original=self.store.publish
        def uncertain(*args,**kwargs):
            original(*args,**kwargs)
            raise OSError('synthetic post-promotion uncertainty')
        self.store.publish=uncertain
        with self.assertRaises(ValueError) as error:self.transaction.refresh(self.nonce)
        self.assertEqual(error.exception.stage,'sealing')
        self.assertTrue((self.root/'cache/current.json').exists())
        value=self.journal.snapshot();self.assertTrue(value['unconfirmed']);self.assertIsNone(value['last_success'])
        public=json.loads((self.root/'status/status.json').read_bytes())
        self.assertNotEqual(public['phase'],'succeeded')
        self.assertIsNone(public['cache_generation'])

    def test_policy_change_after_service_exit_prevents_publication(self):
        def change(*args,**kwargs):
            (self.root/'policy/policy-commitment.key').write_bytes(b'x'*32)
            return 90
        self.service.wait.side_effect=change
        with self.assertRaises(ValueError) as error:self.transaction.refresh(self.nonce)
        self.assertEqual(error.exception.stage,'publication_admission')
        self.assertTrue(self.journal.snapshot()['unconfirmed'])
        self.assertFalse((self.root/'cache/current.json').exists())
        self.assertIsNone(self.journal.snapshot()['last_success'])

    def test_diagnostics_keep_only_fixed_source_sites_kinds_and_numeric_errno(self):
        try:
            try:
                exec(compile("raise PermissionError(13,'synthetic-private-value')",'/synthetic-private-path/inventory_refresh_worker_service.py','exec'))
            except PermissionError:
                raise ValueError('another-synthetic-private-value') from None
        except ValueError as error:
            public=TransactionError('service_launch',error)
        encoded=json.dumps(public.diagnostics)
        self.assertIn('inventory_refresh_worker_service.py',encoded)
        self.assertIn('PermissionError',encoded);self.assertIn('13',encoded)
        for secret in ('synthetic-private-value','another-synthetic-private-value','synthetic-private-path'):
            self.assertNotIn(secret,encoded);self.assertNotIn(secret,str(public))
        self.assertLessEqual(len(public.diagnostics),4)

    def test_unsupported_readonly_precheck_defers_without_start_or_global_uncertainty(self):
        self.transaction._contention_factory=Mock(side_effect=ObservationError('policy_unsupported'))
        self.assertEqual(self.transaction.refresh(self.nonce),'deferred')
        value=self.journal.snapshot();record=value['capabilities']['refresh']['active']
        self.assertFalse(value['unconfirmed']);self.assertIsNone(record['started_boottime_ms'])
        self.assertEqual(record['reason'],'policy_unsupported')
        self.preparer.prepare.assert_not_called();self.service.launch.assert_not_called()

    def test_native_busy_defers_without_actual_start_or_worker(self):
        self.transaction._contention_factory=Mock(side_effect=ObservationError('package_manager_busy'))
        self.assertEqual(self.transaction.refresh(self.nonce),'deferred')
        record=self.journal.snapshot()['capabilities']['refresh']['active']
        self.assertEqual(record['phase'],'deferred');self.assertIsNone(record['started_boottime_ms'])
        self.preparer.prepare.assert_not_called();self.service.launch.assert_not_called()

    def test_existing_other_started_work_does_not_burn_nonce_or_invent_no_work(self):
        other='0000000000000001'+'b'*16
        self.journal.receive('observation',other,self.boot,899998,self.policy.generation)
        self.journal.start('observation',other,self.boot,899999,policy=self.policy.generation)
        self.assertEqual(self.transaction.refresh(self.nonce),'busy')
        self.assertEqual(self.journal.snapshot()['capabilities']['refresh']['high_water'],0)
        self.assertFalse((self.root/'status/status.json').exists());self.service.launch.assert_not_called()

    def test_worker_failure_has_no_current_cache_and_preserves_actual_failed_result(self):
        self.service.wait.return_value=75
        self.assertEqual(self.transaction.refresh(self.nonce),'failed')
        value=self.journal.snapshot();self.assertIsNone(value['last_success'])
        self.assertEqual(value['capabilities']['refresh']['terminal']['reason'],'repository_failed')
        self.assertFalse((self.root/'cache/current.json').exists())

    def test_status_failure_after_terminal_success_fences_without_losing_success(self):
        original=self.publisher.publish
        def publish(status):
            if json.loads(status.encoded())['phase']=='succeeded':raise OSError('synthetic uncertain status')
            return original(status)
        self.publisher.publish=publish
        with self.assertRaises(ValueError):self.transaction.refresh(self.nonce)
        value=self.journal.snapshot();self.assertTrue(value['unconfirmed']);self.assertIsNotNone(value['last_success'])
        self.assertEqual(self.transaction.refresh('0000000000000002'+'a'*16),'unconfirmed')
        self.service.launch.assert_called_once()

    def test_cleanup_failure_prevents_sealing_and_fences_started_work(self):
        self.service.close.side_effect=OSError('synthetic private detail')
        with self.assertRaises(ValueError) as error:self.transaction.refresh(self.nonce)
        self.assertNotIn('synthetic private detail',str(error.exception))
        self.assertEqual(error.exception.stage,'service_cleanup')
        self.assertTrue(self.journal.snapshot()['unconfirmed'])
        self.assertIsNone(self.journal.snapshot()['last_success']);self.assertFalse((self.root/'cache/current.json').exists())


if __name__=='__main__':unittest.main()
