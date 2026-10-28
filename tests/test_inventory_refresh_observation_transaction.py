"""Actual journal/cache/channel/status integration with test-only process scope."""
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
from inventory_refresh_channel import ObservationChannel
from inventory_refresh_cached_observation import ObservationResult
from inventory_refresh_observation_transaction import ObservationTransaction


class ObservationTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.fds=[]
        for name in ('state','cache','policy','status','control','results'):
            path=self.root/name;path.mkdir(mode=0o750 if name in ('cache','status') else 0o700)
            self.fds.append(os.open(path,os.O_RDONLY|os.O_DIRECTORY))
        for name,data in [('policy.json',json.dumps(fixture()).encode()),('policy-commitment.key',b'k'*32)]:
            path=self.root/'policy'/name;path.write_bytes(data);path.chmod(0o600)
        self.policy=PolicyGuard(self.fds[2],owner=os.getuid(),group=os.getgid())
        self.journal=Journal(self.fds[0],owner=os.getuid());self.lock=self.journal.exclusive();self.lock.__enter__()
        self.journal.initialize('a'*32);self.boot='11111111-1111-4111-8111-111111111111';self.now=200
        self.store=Store(self.fds[1],os.getuid(),os.getgid(),os.getuid())
        stage=self.root/'cache'/('staging-'+'b'*32);(stage/'lists').mkdir(parents=True)
        (stage/'lists/synthetic_Packages').write_bytes(b'synthetic metadata')
        self.store.publish('b'*32,'c'*32,self.policy.generation,'2026-10-28T00:00:00Z')
        nonce='0000000000000001'+'a'*16
        self.journal.receive('refresh',nonce,self.boot,100,self.policy.generation)
        self.journal.start('refresh',nonce,self.boot,101,policy=self.policy.generation)
        self.journal.finish('refresh',nonce,self.boot,102,'succeeded',cache='c'*32,
            policy=self.policy.generation,successful_checked_at='2026-10-28T00:00:00Z')
        self.publisher=StatusPublisher(self.fds[3],self.journal,os.getgid(),owner=os.getuid())
        self.channel=ObservationChannel(*self.fds[4:],journal=self.journal,owner=os.getuid())
        self.child=ObservationChannel(*self.fds[4:],owner=os.getuid())
        self.events=[];self.writers=Mock();self.writers.check.side_effect=lambda:self.events.append('empty')
        self.service=Mock();self.service.launch.return_value=self.service;self.service.wait.return_value=90;self.service.poll.return_value=None
        self.service.live_opened.side_effect=lambda:self.channel.read_result(expected_job=self.channel.read_job())
        self.service.close.side_effect=lambda:self.events.append('closed')
        def factory(journal,channel,job):
            journal._consume_launch('observation',job.operation_nonce,job.boot_id,job.policy_generation)
            self.events.append('launch');return self.service
        self.transaction=ObservationTransaction(self.journal,self.policy,Mock(),self.store,self.publisher,self.writers,
            self.channel,service_factory=factory,clock=self.clock)
        self.nonce='0000000000000001'+'d'*16

    def clock(self):self.now+=1;return self.boot,self.now
    def status(self):return json.loads((self.root/'status/status.json').read_bytes())
    def opened(self):
        job=self.channel.read_job();self.now+=1
        value={'nonce':job.operation_nonce,'boot_id':job.boot_id,'cache_generation':job.cache_generation,
            'policy_generation':job.policy_generation,'lock_open_boottime_ms':self.now,'expires_boottime_ms':job.deadline_boottime_ms}
        self.child.write_result(ObservationResult.create(job,'opened',lease=value));return value
    def released(self,lease):
        job=self.channel.read_job();self.now+=1
        receipt=dict(lease,lock_held_until_boottime_ms=self.now,released_boottime_ms=self.now+1,
            outcome='released',installed_before_sha256='e'*64,installed_after_sha256='e'*64)
        self.now+=2;self.child.write_result(ObservationResult.create(job,'released',receipt=receipt));return receipt
    def tearDown(self):
        self.transaction.close();self.child.close();self.channel.close();self.publisher.close();self.policy.close()
        self.lock.__exit__(None,None,None)
        for fd in self.fds:os.close(fd)
        self.temp.cleanup()

    def test_owned_offer_release_cleanup_and_atomic_receipt_share_one_journal(self):
        frozen=self.journal.snapshot()['last_success']
        self.assertEqual(self.transaction.begin(self.nonce),'dispatched')
        self.assertEqual(self.transaction.poll(),'opening')
        lease=self.opened();self.assertEqual(self.transaction.poll(),'opened')
        self.assertEqual(self.status()['observation_lease'],lease)
        self.writers.check.assert_called_once()
        self.assertEqual(self.transaction.release(self.nonce),'releasing')
        self.assertIsNone(self.status()['observation_lease'])
        before=self.journal.snapshot();self.assertEqual(self.transaction.release(self.nonce),'existing')
        self.assertEqual(self.journal.snapshot(),before)
        receipt=self.released(lease);self.assertEqual(self.transaction.poll(),'succeeded')
        self.assertLess(self.events.index('closed'),len(self.events)-1);self.assertEqual(self.events[-1],'empty')
        self.assertEqual(self.journal.snapshot()['last_observation']['receipt'],receipt)
        self.assertEqual(self.journal.snapshot()['last_success'],frozen)
        self.assertEqual(self.status()['observation_receipt'],receipt);self.assertIsNone(self.status()['observation_lease'])
        self.assertEqual(self.transaction.begin(self.nonce),'existing');self.service.launch.assert_called_once()

    def test_invalid_unrelated_and_premature_release_do_not_abort_active_scope(self):
        self.transaction.begin(self.nonce);before=self.journal.snapshot()
        for nonce in ('bad','0000000000000002'+'f'*16):
            try:result=self.transaction.release(nonce)
            except ValueError:pass
            else:self.assertEqual(result,'ignored')
        self.assertEqual(self.transaction.release(self.nonce),'not_ready')
        self.assertEqual(self.journal.snapshot(),before);self.service.close.assert_not_called()
        lease=self.opened();self.assertEqual(self.transaction.poll(),'opened')
        self.assertEqual(self.status()['observation_lease'],lease)

    def test_expiry_cleans_scope_without_accepting_success_or_old_offer(self):
        self.transaction.begin(self.nonce);self.opened();self.transaction.poll()
        self.now=self.channel.read_job().deadline_boottime_ms+1
        self.assertEqual(self.transaction.poll(),'failed')
        value=self.journal.snapshot();self.assertFalse(value['unconfirmed']);self.assertIsNone(value['last_observation'])
        self.assertEqual(value['capabilities']['observation']['terminal']['reason'],'lease_expired')
        self.assertIsNone(self.status()['observation_lease']);self.assertIsNone(self.status()['operation_nonce'])

    def test_uncertain_cleanup_cannot_accept_a_released_child_receipt(self):
        self.transaction.begin(self.nonce);lease=self.opened();self.transaction.poll()
        self.transaction.release(self.nonce);self.released(lease)
        self.service.close.side_effect=OSError('synthetic private detail')
        with self.assertRaises(ValueError) as error:self.transaction.poll()
        self.assertNotIn('synthetic private detail',str(error.exception))
        value=self.journal.snapshot();self.assertTrue(value['unconfirmed']);self.assertIsNone(value['last_observation'])

    def test_disappearing_opened_scope_withdraws_offer_and_fences(self):
        self.transaction.begin(self.nonce);self.opened();self.transaction.poll()
        self.service.live_opened.side_effect=None;self.service.live_opened.return_value=None
        with self.assertRaises(ValueError):self.transaction.poll()
        self.assertIsNone(self.status()['observation_lease'])
        self.assertTrue(self.journal.snapshot()['unconfirmed'])
        self.service.close.assert_called_once()

    def test_disappearing_opened_scope_during_release_cannot_retain_offer(self):
        self.transaction.begin(self.nonce);self.opened();self.transaction.poll()
        self.service.live_opened.side_effect=None;self.service.live_opened.return_value=None
        with self.assertRaises(ValueError):self.transaction.release(self.nonce)
        self.assertIsNone(self.status()['observation_lease'])
        self.assertIsNone(self.journal.snapshot()['capabilities']['release']['active'])

    def test_changed_cache_cannot_accept_receipt(self):
        self.transaction.begin(self.nonce);lease=self.opened();self.transaction.poll()
        self.transaction.release(self.nonce);self.released(lease)
        (self.root/'cache/current.json').unlink()
        with self.assertRaises(ValueError):self.transaction.poll()
        self.assertTrue(self.journal.snapshot()['unconfirmed'])
        self.assertIsNone(self.journal.snapshot()['last_observation'])
        self.assertIsNone(self.status()['observation_lease'])

    def test_changed_policy_withdraws_offer_and_cannot_accept(self):
        self.transaction.begin(self.nonce);self.opened();self.transaction.poll()
        self.policy.recheck=Mock(side_effect=ValueError('private fixture detail'))
        with self.assertRaises(ValueError):self.transaction.poll()
        self.assertIsNone(self.status()['observation_lease'])
        self.assertTrue(self.journal.snapshot()['unconfirmed'])

    def test_real_policy_guard_poison_withdraws_offer_without_old_policy(self):
        self.transaction.begin(self.nonce);self.opened();self.transaction.poll()
        (self.root/'policy/policy.json').write_bytes(b'{}')
        with self.assertRaises(ValueError):self.transaction.poll()
        value=self.status();self.assertIsNone(value['observation_lease'])
        self.assertIsNone(value['policy_generation']);self.assertIsNone(value['cache_generation'])
        self.assertIsNone(value['operation_nonce']);self.assertIsNone(value['attempt'])
        self.assertTrue(self.journal.snapshot()['unconfirmed'])

    def test_new_object_cannot_reattach_to_running_record(self):
        self.transaction.begin(self.nonce)
        other=ObservationTransaction(self.journal,self.policy,Mock(),self.store,self.publisher,self.writers,
            self.channel,service_factory=Mock(),clock=self.clock)
        self.assertEqual(other.begin(self.nonce),'existing')
        self.assertEqual(other.release(self.nonce),'ignored')
        self.assertEqual(other.poll(),'idle')
        other._factory.assert_not_called();other.close()

    def test_clock_rewind_fences_and_withdraws(self):
        self.transaction.begin(self.nonce);self.opened();self.transaction.poll();self.now=0
        with self.assertRaises(ValueError):self.transaction.poll()
        self.assertTrue(self.journal.snapshot()['unconfirmed'])
        self.assertIsNone(self.status()['observation_lease'])

    def test_child_failure_requires_cleanup_and_preserves_last_success(self):
        frozen=self.journal.snapshot()['last_success'];self.transaction.begin(self.nonce)
        self.child.write_result(ObservationResult.create(self.channel.read_job(),'failed',reason='package_manager_busy'))
        self.assertEqual(self.transaction.poll(),'failed')
        self.assertEqual(self.events[-1],'empty');self.service.close.assert_called_once()
        value=self.journal.snapshot();self.assertEqual(value['last_success'],frozen)
        self.assertFalse(value['unconfirmed']);self.assertIsNone(value['last_observation'])
        self.assertIsNone(self.status()['operation_nonce'])

    def test_terminal_metadata_is_not_sufficient_without_owned_service_success(self):
        self.transaction.begin(self.nonce);lease=self.opened();self.transaction.poll()
        self.transaction.release(self.nonce);self.released(lease);self.service.wait.return_value=74
        with self.assertRaises(ValueError):self.transaction.poll()
        self.assertIsNone(self.journal.snapshot()['last_observation'])
        self.assertTrue(self.journal.snapshot()['unconfirmed'])

    def test_unavailable_cache_does_not_burn_observation_counter(self):
        (self.root/'cache/current.json').unlink()
        self.assertEqual(self.transaction.begin(self.nonce),'unavailable')
        self.assertEqual(self.journal.snapshot()['capabilities']['observation']['high_water'],0)
        self.service.launch.assert_not_called();self.assertEqual(self.status()['reason'],'cache_unavailable')


if __name__=='__main__':unittest.main()
