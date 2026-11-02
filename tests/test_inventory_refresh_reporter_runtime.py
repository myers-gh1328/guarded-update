"""Actual fixed inbox files with transferred Env fixtures, not origin proof."""
from pathlib import Path
import os
import json
import time
import subprocess
from contextlib import contextmanager
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import test_inventory_refresh_reporter_environment as fixtures
from inventory_refresh_reporter_io import ReporterRequestWriter
from inventory_refresh_status import PublicStatus
import inventory_refresh_reader_session as reader_session
import inventory_refresh_observation as observation
import inventory_refresh_reader_tools as reader_tools
import inventory_refresh_reporter_io as reporter_io
import inventory_refresh_reporter_runtime as runtime

NONCE='0000000000000001'+'a'*16


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.EnvironmentTests(methodName='runTest');self.fixture.setUp()
        self.env=self.fixture.admit();self.owner=None
        self.inboxes=self.fixture.root/'inboxes';self.inboxes.mkdir(mode=0o750)
        for name in ('observation','release','refresh'):
            (self.inboxes/name).mkdir(mode=0o770);(self.inboxes/name).chmod(0o770)
        self.fd=os.open(self.inboxes,os.O_RDONLY|os.O_DIRECTORY)
        self.env._chains['runtime'].fds=[self.fd]
        self.observation=ReporterRequestWriter(self.fd,'observation',os.getuid(),os.getgid(),owner=os.getuid())
        self.release=ReporterRequestWriter(self.fd,'release',os.getuid(),os.getgid(),owner=os.getuid())
        self.dpkg=self.fixture.root/'dpkg';self.dpkg.mkdir();(self.dpkg/'updates').mkdir()
        (self.dpkg/'status').write_bytes(b'Package: synthetic\nVersion: 1\n')
        self.dpkg_fd=os.open(self.dpkg,os.O_RDONLY|os.O_DIRECTORY)
        self.env._chains['dpkg'].fds=[self.dpkg_fd]
    def tearDown(self):
        if self.owner is not None:self.owner.close()
        self.release.close();self.observation.close();os.close(self.fd);os.close(self.dpkg_fd);self.fixture.tearDown()
    def admit(self):
        self.owner=runtime.ReporterRuntime._from_capabilities(self.env,self.observation,self.release)
        return self.owner

    def offer(self,**changes):
        return dict(dict(nonce=NONCE,boot_id=fixtures.BOOT,cache_generation=fixtures.GEN,
            policy_generation=fixtures.POLICY,lock_open_boottime_ms=110,expires_boottime_ms=1000),**changes)

    def status(self,lease=None,receipt=None):
        context=lease or receipt or {'policy_generation':fixtures.POLICY,'cache_generation':fixtures.GEN}
        value=dict(schema_version=1,operation_nonce=None,phase='unconfirmed',reason='cache_unavailable',
            policy_generation=context['policy_generation'],cache_generation=context['cache_generation'],successful_checked_at=fixtures.CHECKED,
            started_at=None,finished_at=None,attempt=None,observation_lease=lease,observation_receipt=receipt)
        path=self.fixture.status/'status.json';path.write_bytes(PublicStatus.create(value).encoded());path.chmod(0o640)

    def open_scan(self,offer=None,admit=None):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE)
        self.status(lease=offer or self.offer());self.fixture.now=(offer or self.offer())['lock_open_boottime_ms']+10
        owner.begin_scan(admit or (lambda *_:True))
        return owner

    def expire_during_hash(self,operation):
        info=os.stat(self.dpkg/'status');actual=os.read;reads=[]
        def read(fd,limit):
            identity=os.fstat(fd);value=actual(fd,limit)
            if (identity.st_dev,identity.st_ino)==(info.st_dev,info.st_ino):
                reads.append(True);self.fixture.now=120100
            return value
        with patch.object(observation.os,'read',side_effect=read):
            with self.assertRaises(runtime.ReporterRuntimeError):operation()
        self.assertEqual(reads,[True])  # No second read after Runtime expiry.
        self.fixture.parent.close.assert_called_once()

    def rejected_admission(self,callback):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE)
        self.status(lease=self.offer());self.fixture.now=120
        with patch.object(reader_session,'installed_fingerprint',side_effect=AssertionError('hash before durable ACK')) as hashed:
            with self.assertRaises(runtime.ReporterRuntimeError):owner.begin_scan(lambda started,offer:callback(owner,started,offer))
            hashed.assert_not_called()
        self.fixture.parent.close.assert_called_once()

    def rejected_offer(self,**changes):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE)
        self.status(lease=self.offer(**changes));self.fixture.now=120
        with patch.object(reader_session,'installed_fingerprint') as hashed:
            with self.assertRaises(runtime.ReporterRuntimeError):owner.begin_scan(lambda *_:True)
            hashed.assert_not_called()

    def frozen_release(self):
        owner=self.open_scan();self.fixture.now=130;frozen=owner.freeze_scan()
        self.fixture.now=140;owner.publish_release(NONCE)
        return owner,frozen

    def receipt(self,frozen,**changes):
        return dict(dict(self.offer(),lock_held_until_boottime_ms=140,released_boottime_ms=145,outcome='released',
            installed_before_sha256=frozen['installed_before_sha256'],installed_after_sha256=frozen['installed_after_sha256']),**changes)

    def rejected_receipt(self,**changes):
        owner,frozen=self.frozen_release();session=self.env._session
        self.status(receipt=self.receipt(frozen,**changes));self.fixture.now=150
        with self.assertRaises(runtime.ReporterRuntimeError):owner.prepare_evidence()
        self.assertTrue(session._closed);self.fixture.parent.close.assert_called_once()

    def test_pin_then_literal_observation_and_exact_release_publish_real_nonce_files(self):
        owner=self.admit();self.assertEqual(owner.pin_current()['cache_generation'],fixtures.GEN)
        self.assertIsNone(owner.publish_observation(NONCE))
        self.assertEqual((self.inboxes/'observation'/'request').read_bytes(),NONCE.encode())
        self.assertIsNone(owner.publish_release(NONCE))
        self.assertEqual((self.inboxes/'release'/'request').read_bytes(),NONCE.encode())
        self.assertEqual(list((self.inboxes/'refresh').iterdir()),[])
        self.assertEqual(owner.clock(),(fixtures.BOOT,100))
        owner.close();os.fstat(self.fd)
        self.fixture.parent.close.assert_called_once()

    def test_parent_clock_closing_owner_during_postverification_cannot_return_success(self):
        owner=self.admit();owner.pin_current()
        def clock():
            if (self.inboxes/'observation'/'request').exists():owner.close()
            return fixtures.BOOT,100
        self.fixture.parent.clock.side_effect=clock
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_observation(NONCE)
        self.assertEqual((self.inboxes/'observation'/'request').read_bytes(),NONCE.encode())
        self.assertFalse((self.inboxes/'release'/'request').exists())

    def test_clock_cannot_escape_after_owner_is_closed_during_sample(self):
        owner=self.admit()
        def clock():owner.close();return fixtures.BOOT,100
        self.fixture.parent.clock.side_effect=clock
        with self.assertRaises(runtime.ReporterRuntimeError):owner.clock()

    def test_transferred_writer_must_belong_to_the_same_environment_runtime_ancestor(self):
        foreign=self.fixture.root/'foreign';foreign.mkdir(mode=0o750)
        (foreign/'observation').mkdir(mode=0o770);(foreign/'observation').chmod(0o770)
        fd=os.open(foreign,os.O_RDONLY|os.O_DIRECTORY)
        writer=ReporterRequestWriter(fd,'observation',os.getuid(),os.getgid(),owner=os.getuid())
        try:
            with self.assertRaises(runtime.ReporterRuntimeError):
                runtime.ReporterRuntime._from_capabilities(self.env,writer,self.release)
            os.fstat(fd);self.fixture.parent.close.assert_called_once()
        finally:writer.close();os.close(fd)

    def test_fixed_factory_admits_environment_before_constructing_only_literal_ports(self):
        events=[];original=ReporterRequestWriter.__init__
        def environment():events.append('environment');return self.env
        def writer(value,directory,role,uid,gid):
            events.append(role)
            original(value,directory,role,uid,gid,owner=os.getuid())
        with patch.object(runtime.ReporterEnvironment,'fixed',side_effect=environment),\
                patch.object(ReporterRequestWriter,'__init__',writer):
            self.owner=runtime.ReporterRuntime.fixed()
        self.assertEqual(events,['environment','observation','release'])
        self.owner.pin_current();self.owner.publish_observation(NONCE);self.owner.publish_release(NONCE)
        self.assertEqual((self.inboxes/'release'/'request').read_bytes(),NONCE.encode())

    def test_fixed_environment_failure_prevents_any_writer_construction(self):
        with patch.object(runtime.ReporterEnvironment,'fixed',side_effect=ValueError('synthetic Parent rejection')),\
                patch.object(ReporterRequestWriter,'__init__') as construct:
            with self.assertRaises(runtime.ReporterRuntimeError):runtime.ReporterRuntime.fixed()
            construct.assert_not_called()

    def test_second_writer_construction_failure_closes_first_and_environment(self):
        first=[];original=ReporterRequestWriter.__init__
        def writer(value,directory,role,uid,gid):
            if role=='release':raise OSError('synthetic release admission failure')
            original(value,directory,role,uid,gid,owner=os.getuid());first.append(value)
        with patch.object(runtime.ReporterEnvironment,'fixed',return_value=self.env),\
                patch.object(ReporterRequestWriter,'__init__',writer):
            with self.assertRaises(runtime.ReporterRuntimeError):runtime.ReporterRuntime.fixed()
        self.assertEqual(len(first),1);self.assertIsNone(first[0]._inbox)
        self.fixture.parent.close.assert_called_once();os.fstat(self.fd)

    def test_observation_before_pin_consumes_owner_without_writing(self):
        owner=self.admit()
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_observation(NONCE)
        with self.assertRaises(runtime.ReporterRuntimeError):owner.pin_current()
        self.assertFalse((self.inboxes/'observation'/'request').exists())
        self.fixture.parent.close.assert_called_once()

    def test_release_before_observation_consumes_without_writing(self):
        owner=self.admit();owner.pin_current()
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_release(NONCE)
        self.assertFalse((self.inboxes/'release'/'request').exists())

    def test_foreign_release_nonce_is_rejected_and_never_recoverable_in_this_owner(self):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE)
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_release('0000000000000002'+'b'*16)
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_release(NONCE)
        self.assertFalse((self.inboxes/'release'/'request').exists())
        self.assertEqual((self.inboxes/'observation'/'request').read_bytes(),NONCE.encode())

    def test_second_observation_cannot_advance_or_replay_nonce(self):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE)
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_observation('0000000000000002'+'b'*16)
        self.assertEqual((self.inboxes/'observation'/'request').read_bytes(),NONCE.encode())

    def test_second_release_cannot_replay_and_second_pin_cannot_repin(self):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE);owner.publish_release(NONCE)
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_release(NONCE)
        with self.assertRaises(runtime.ReporterRuntimeError):owner.pin_current()
        self.assertEqual((self.inboxes/'release'/'request').read_bytes(),NONCE.encode())

    def test_missing_status_pin_failure_closes_everything_without_publishing(self):
        owner=self.admit();(self.fixture.status/'status.json').unlink()
        with self.assertRaises(runtime.ReporterRuntimeError) as caught:owner.pin_current()
        self.assertEqual(caught.exception.reason,'cache_unavailable')
        self.assertIsNone(self.release._inbox);self.assertIsNone(self.observation._inbox)
        self.assertFalse((self.inboxes/'observation'/'request').exists())
        self.fixture.parent.close.assert_called_once()

    def test_postpublication_verification_failure_is_not_local_success_or_cleanup(self):
        owner=self.admit();owner.pin_current()
        self.fixture.parent.verify.side_effect=[None,ValueError('synthetic lost parent')]
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_observation(NONCE)
        self.assertEqual((self.inboxes/'observation'/'request').read_bytes(),NONCE.encode())
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_release(NONCE)
        self.fixture.parent.close.assert_called_once()

    def test_rename_error_after_visibility_remains_unknown_and_cannot_retry(self):
        owner=self.admit();owner.pin_current();actual=os.replace
        def visible(*args,**kwargs):actual(*args,**kwargs);raise OSError('synthetic uncertain publication')
        with patch.object(reporter_io.os,'replace',side_effect=visible):
            with self.assertRaises(runtime.ReporterRuntimeError) as caught:owner.publish_observation(NONCE)
        self.assertEqual(caught.exception.reason,'persistence_unconfirmed')
        self.assertEqual((self.inboxes/'observation'/'request').read_bytes(),NONCE.encode())
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_observation(NONCE)
        self.fixture.parent.close.assert_called_once()

    def test_aliased_ports_are_rejected_and_transferred_owner_is_closed_once(self):
        with patch.object(self.observation,'close',wraps=self.observation.close) as close:
            with self.assertRaises(runtime.ReporterRuntimeError):
                runtime.ReporterRuntime._from_capabilities(self.env,self.observation,self.observation)
            close.assert_called_once()
        self.fixture.parent.close.assert_called_once()

    def test_mislabelled_distinct_port_is_rejected(self):
        wrong=ReporterRequestWriter(self.fd,'observation',os.getuid(),os.getgid(),owner=os.getuid())
        try:
            with self.assertRaises(runtime.ReporterRuntimeError):
                runtime.ReporterRuntime._from_capabilities(self.env,self.observation,wrong)
            self.assertIsNone(wrong._inbox)
        finally:wrong.close()

    def test_close_failure_attempts_every_owner_once_and_preserves_borrowed_fd(self):
        owner=self.admit();events=[]
        release=self.release.close;observation=self.observation.close;environment=self.env.close
        def first():events.append('release');release();raise OSError('synthetic close uncertainty')
        def second():events.append('observation');observation()
        def last():events.append('environment');environment()
        with patch.object(self.release,'close',side_effect=first),patch.object(self.observation,'close',side_effect=second),\
                patch.object(self.env,'close',side_effect=last):
            with self.assertRaises(runtime.ReporterRuntimeError) as caught:owner.close()
            self.assertEqual(caught.exception.reason,'cleanup_unconfirmed');owner.close()
        self.assertEqual(events,['release','observation','environment']);os.fstat(self.fd)

    def test_native_runtime_budget_does_not_renew_after_pin_or_publication(self):
        owner=self.admit();self.fixture.now=120099
        owner.pin_current();owner.publish_observation(NONCE)
        self.assertEqual(owner.clock(),(fixtures.BOOT,120099))
        self.fixture.now=120100
        with self.assertRaises(runtime.ReporterRuntimeError):owner.clock()
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_release(NONCE)

    def test_native_scan_ack_and_frozen_end_bind_matching_released_receipt(self):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE)
        offer=self.offer();self.status(lease=offer);self.fixture.now=120;events=[]
        fingerprint=reader_session.installed_fingerprint
        def admit(started,metadata):
            self.assertEqual(started,120);self.assertEqual(metadata,offer);events.append('durable ACK')
            metadata['cache_generation']='f'*32
            return True
        def hashed(*args):events.append('hash');return fingerprint(*args)
        with patch.object(reader_session,'installed_fingerprint',side_effect=hashed):
            self.assertEqual(owner.begin_scan(admit),120)
        self.assertEqual(events,['durable ACK','hash'])
        self.fixture.now=130;frozen=owner.freeze_scan()
        self.assertEqual(frozen['scan_started_boottime_ms'],120);self.assertEqual(frozen['scan_finished_boottime_ms'],130)
        frozen['scan_finished_boottime_ms']=999  # Detached data cannot change proof.
        self.fixture.now=140;owner.publish_release(NONCE)
        receipt=dict(offer,lock_held_until_boottime_ms=140,released_boottime_ms=145,outcome='released',
            installed_before_sha256=frozen['installed_before_sha256'],installed_after_sha256=frozen['installed_after_sha256'])
        self.status(receipt=receipt);self.fixture.now=150
        evidence=json.loads(owner.prepare_evidence())
        self.assertEqual(evidence['scan_finished_boottime_ms'],130);self.assertEqual(evidence['observation_receipt'],receipt)
        self.assertTrue(self.env._session._closed);self.fixture.parent.close.assert_not_called()
        self.assertEqual(owner.clock(),(fixtures.BOOT,150))
        with self.assertRaises(runtime.ReporterRuntimeError):owner.prepare_evidence()

    def test_earlier_runtime_deadline_stops_first_fingerprint_while_root_lease_remains_valid(self):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE)
        self.status(lease=self.offer(lock_open_boottime_ms=119000,expires_boottime_ms=239000))
        self.fixture.now=119020
        self.expire_during_hash(lambda:owner.begin_scan(lambda *_:True))

    def test_earlier_runtime_deadline_stops_last_fingerprint_while_root_lease_remains_valid(self):
        owner=self.open_scan(self.offer(lock_open_boottime_ms=119000,expires_boottime_ms=239000))
        self.expire_during_hash(owner.freeze_scan)

    def query_failure_pin_order(self,parent_failure=False):
        owner=self.open_scan(self.offer(lock_open_boottime_ms=119000,expires_boottime_ms=239000))
        session=self.env._session;children=[];events=[];actual_launch=subprocess.Popen;started=time.monotonic()
        def clock():
            if children and time.monotonic()-started>.1:
                if parent_failure:raise ValueError('synthetic native Parent clock failure')
                self.fixture.now=120100
            return fixtures.BOOT,self.fixture.now
        self.fixture.parent.clock.side_effect=clock
        @contextmanager
        def generation(*_):yield '/synthetic-reader/apt.conf',lambda:None
        def launch(argv,**kwargs):
            child=actual_launch([sys.executable,'-I','-B','-S','-c','import time;time.sleep(30)'],**kwargs)
            children.append(child);wait=child.wait
            def reaped(*args,**options):
                self.assertFalse(session._closed);self.assertFalse(self.env._closed)
                result=wait(*args,**options);events.append('reaped');return result
            child.wait=reaped
            return child
        with patch.object(reader_tools,'_fixed_generation',generation),patch.object(reader_tools.subprocess,'Popen',side_effect=launch):
            with self.assertRaises(runtime.ReporterRuntimeError):owner.policy(['synthetic'])
        self.assertLess(time.monotonic()-started,2);self.assertEqual(len(children),1)
        self.assertIsNotNone(children[0].returncode);self.assertNotEqual(children[0].returncode,0)
        self.assertTrue(children[0].stdout.closed);self.assertIn('reaped',events)
        self.assertTrue(session._closed);self.fixture.parent.close.assert_called_once()

    def test_running_query_keeps_pin_until_child_is_reaped_at_earlier_runtime_deadline(self):
        self.query_failure_pin_order()

    def test_native_parent_clock_failure_keeps_pin_until_running_child_is_reaped(self):
        self.query_failure_pin_order(parent_failure=True)

    def test_rejected_durable_ack_never_starts_fingerprint(self):
        self.rejected_admission(lambda *_:False)

    def test_numeric_alias_ack_never_starts_fingerprint(self):
        self.rejected_admission(lambda *_:1)

    def test_expiry_during_durable_ack_never_starts_fingerprint(self):
        def expires(*_):self.fixture.now=1000;return True
        self.rejected_admission(expires)

    def test_owner_close_during_durable_ack_never_starts_fingerprint(self):
        def closes(owner,*_):owner.close();return True
        self.rejected_admission(closes)

    def test_release_reentry_during_durable_ack_cannot_escape_as_success(self):
        def reentry(owner,*_):
            try:owner.publish_release(NONCE)
            except runtime.ReporterRuntimeError:pass
            return True
        self.rejected_admission(reentry)
        self.assertFalse((self.inboxes/'release'/'request').exists())

    def test_matching_root_nonce_with_wrong_boot_consumes_instead_of_waiting(self):
        self.rejected_offer(boot_id='22222222-2222-4222-8222-222222222222')

    def test_matching_root_nonce_with_wrong_pin_consumes_instead_of_waiting(self):
        self.rejected_offer(cache_generation='e'*32)

    def test_matching_root_nonce_with_wrong_policy_consumes_instead_of_waiting(self):
        self.rejected_offer(policy_generation='e'*64)

    def test_foreign_root_offer_polls_only_within_original_budget(self):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE)
        self.status(lease=self.offer(nonce='0000000000000002'+'b'*16));self.fixture.now=120
        def expires(_):self.fixture.now=120100
        with patch.object(runtime.time,'sleep',side_effect=expires) as wait:
            with self.assertRaises(runtime.ReporterRuntimeError):owner.begin_scan(lambda *_:True)
            wait.assert_called_once_with(.025)

    def test_fixed_data_methods_use_session_only_in_scan_and_do_not_reset_once_limits(self):
        owner=self.open_scan()
        with patch.object(reader_tools,'_fixed_read',return_value='synthetic\n') as fixed:
            self.assertEqual(owner.installed(),'synthetic\n');self.assertEqual(owner.native_architecture(),'synthetic\n')
            self.assertEqual(owner.holds(),'synthetic\n')
            self.assertEqual([call.args[2] for call in fixed.call_args_list],['installed','architecture','holds'])
            with self.assertRaises(runtime.ReporterRuntimeError):owner.installed()
            self.assertEqual(fixed.call_count,3)

    def test_data_before_durable_scan_admission_cannot_run_a_package_tool(self):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE)
        with patch.object(reader_tools,'_fixed_read') as fixed:
            with self.assertRaises(runtime.ReporterRuntimeError):owner.installed()
            fixed.assert_not_called()

    def test_release_during_active_scan_is_rejected_without_cleanup_claim(self):
        owner=self.open_scan()
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_release(NONCE)
        self.assertFalse((self.inboxes/'release'/'request').exists())

    def test_cleanup_only_release_cannot_prepare_scan_evidence(self):
        owner=self.admit();owner.pin_current();owner.publish_observation(NONCE);owner.publish_release(NONCE)
        with self.assertRaises(runtime.ReporterRuntimeError):owner.prepare_evidence()
        self.assertEqual((self.inboxes/'release'/'request').read_bytes(),NONCE.encode())

    def test_mutated_installed_state_between_hashes_cannot_freeze_or_release(self):
        owner=self.open_scan();(self.dpkg/'status').write_bytes(b'Package: changed\nVersion: 2\n')
        with self.assertRaises(runtime.ReporterRuntimeError):owner.freeze_scan()
        with self.assertRaises(runtime.ReporterRuntimeError):owner.publish_release(NONCE)
        self.assertFalse((self.inboxes/'release'/'request').exists())

    def test_initial_native_budget_overflow_is_rejected_without_writers_effects(self):
        self.fixture.now=9007199254740991-119999
        with self.assertRaises(runtime.ReporterRuntimeError):self.admit()
        self.assertFalse((self.inboxes/'observation'/'request').exists())

    def test_native_clock_rewind_is_absorbing_and_cannot_return_to_work(self):
        owner=self.admit();self.fixture.now=99
        with self.assertRaises(runtime.ReporterRuntimeError):owner.clock()
        self.fixture.now=100
        with self.assertRaises(runtime.ReporterRuntimeError):owner.pin_current()

    def test_receipt_wrong_boot_cannot_prepare_evidence(self):
        self.rejected_receipt(boot_id='22222222-2222-4222-8222-222222222222')

    def test_receipt_wrong_generation_cannot_prepare_evidence(self):
        self.rejected_receipt(cache_generation='e'*32)

    def test_receipt_wrong_policy_cannot_prepare_evidence(self):
        self.rejected_receipt(policy_generation='e'*64)

    def test_receipt_equal_but_foreign_hashes_cannot_prepare_evidence(self):
        self.rejected_receipt(installed_before_sha256='d'*64,installed_after_sha256='d'*64)

    def test_receipt_lock_held_until_before_actual_scan_end_cannot_prepare_evidence(self):
        self.rejected_receipt(lock_held_until_boottime_ms=125)

    def test_expired_root_receipt_cannot_prepare_released_evidence(self):
        self.rejected_receipt(outcome='expired')

    def test_receipt_not_yet_released_in_native_time_cannot_prepare_evidence(self):
        self.rejected_receipt(released_boottime_ms=160)

    def test_foreign_receipt_wait_cannot_reset_original_root_expiry(self):
        owner,frozen=self.frozen_release()
        self.status(receipt=self.receipt(frozen,nonce='0000000000000002'+'b'*16));self.fixture.now=150
        def expires(_):self.fixture.now=1000
        with patch.object(runtime.time,'sleep',side_effect=expires) as wait:
            with self.assertRaises(runtime.ReporterRuntimeError):owner.prepare_evidence()
            wait.assert_called_once_with(.025)

    def test_postreceipt_verification_failure_returns_no_prepared_evidence(self):
        owner,frozen=self.frozen_release();session=self.env._session
        self.status(receipt=self.receipt(frozen));self.fixture.now=150
        def verify():
            if session._closed:raise ValueError('synthetic Parent lost after receipt')
        self.fixture.parent.verify.side_effect=verify
        with self.assertRaises(runtime.ReporterRuntimeError):owner.prepare_evidence()
        self.assertTrue(session._closed);self.fixture.parent.close.assert_called_once()

    def test_prepared_phase_cannot_start_any_more_package_tools(self):
        owner,frozen=self.frozen_release();self.status(receipt=self.receipt(frozen));self.fixture.now=150
        owner.prepare_evidence()
        with patch.object(reader_tools,'_policy') as policy:
            with self.assertRaises(runtime.ReporterRuntimeError):owner.policy(['synthetic'])
            policy.assert_not_called()


if __name__=='__main__':unittest.main()
