"""Actual cache leases with synthetic installed-state guard/clock fixtures."""
import json
from contextlib import contextmanager
from unittest.mock import Mock, patch
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_storage import Store
from inventory_refresh_observation import ObservationError
from inventory_refresh_cached_observation import ObservationJob, CachedObservation, ObservationResult

BOOT='11111111-1111-4111-8111-111111111111'
NONCE='0000000000000001'+'a'*16
CHECKED='2026-10-28T07:00:00Z'


class Guard:
    def __init__(self,on_close=lambda:None):
        self.closed=False
        self.on_close=on_close
    def verify(self):
        if self.closed:
            raise ObservationError('state_inconsistent')
    def fingerprint(self,deadline,now):
        self.verify();now()
        return 'f'*64
    def close(self):
        if not self.closed:
            self.on_close()
            self.closed=True


class CachedObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        self.store=Store(self.fd,os.getuid(),os.getgid(),os.getuid())
        self.stage('1'*32)
        self.manifest=self.store.publish('1'*32,'2'*32,'b'*64,CHECKED)
        self.job_data={'schema_version':1,'job_id':'c'*32,'operation_nonce':NONCE,'helper_sequence':1,
                       'boot_id':BOOT,'cache_generation':'2'*32,'policy_generation':'b'*64,
                       'successful_checked_at':CHECKED,'accepted_boottime_ms':100,
                       'started_boottime_ms':101,'deadline_boottime_ms':1000}
        self.now=110
        self.clock=lambda:(BOOT,self.now)
    def tearDown(self):
        os.close(self.fd)
        self.temp.cleanup()
    def stage(self,token):
        directory=self.root/('staging-'+token)/'lists'
        directory.mkdir(parents=True,mode=0o700)
        (directory/'synthetic_Packages').write_bytes(b'synthetic-package-index')
    def job(self,**changes):
        return ObservationJob.parse(json.dumps(dict(self.job_data,**changes)).encode())

    def test_cache_identity_mismatch_never_opens_native_and_releases_its_pin(self):
        factory=Mock()
        for changes in [dict(cache_generation='3'*32),dict(policy_generation='d'*64),
                        dict(successful_checked_at='2026-10-28T08:00:00Z')]:
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                CachedObservation.begin(self.store,self.job(**changes),self.clock,guard_factory=factory)
        factory.assert_not_called()
        self.stage('3'*32);self.store.publish('3'*32,'4'*32,'b'*64,CHECKED)
        self.assertTrue(self.store.retire('2'*32))

    def test_expired_or_foreign_boot_never_acquires_cache_or_native(self):
        factory=Mock()
        with patch.object(self.store,'lease_current',wraps=self.store.lease_current) as cache:
            for clock in [lambda:(BOOT,1000),lambda:(BOOT,1001),lambda:(BOOT,100),
                          lambda:('22222222-2222-4222-8222-222222222222',110)]:
                with self.subTest(clock=clock),self.assertRaises(ValueError):
                    CachedObservation.begin(self.store,self.job(),clock,guard_factory=factory)
            cache.assert_not_called()
        factory.assert_not_called()

    def test_time_is_rechecked_after_cache_admission_before_native(self):
        factory=Mock()
        closed=[]
        @contextmanager
        def delayed_cache():
            with self.store.lease_current() as lease:
                self.now=1000
                try:
                    yield lease
                finally:
                    closed.append(True)
        from types import SimpleNamespace
        proxy=SimpleNamespace(lease_current=delayed_cache)
        with self.assertRaises(ValueError):
            CachedObservation.begin(proxy,self.job(),self.clock,guard_factory=factory)
        factory.assert_not_called()
        self.assertEqual(closed,[True])

    def test_native_close_failure_cannot_return_receipt_and_still_closes_cache(self):
        def fail_close():
            self.assertFalse(self.store.retire('2'*32))
            raise ObservationError('cleanup_unconfirmed')
        guard=Guard(on_close=fail_close)
        session=CachedObservation.begin(self.store,self.job(),self.clock,guard_factory=lambda **_:guard)
        self.stage('3'*32);self.store.publish('3'*32,'4'*32,'b'*64,CHECKED)
        with self.assertRaises(ValueError):
            session.finish(NONCE)
        self.assertTrue(self.store.retire('2'*32))
        with self.assertRaises(ValueError):
            session.opened_result()

    def test_cache_close_failure_occurs_after_native_unlock_and_cannot_return_receipt(self):
        guard=Guard()
        closed=[]
        @contextmanager
        def bad_close():
            with self.store.lease_current() as lease:
                yield lease
            self.assertTrue(guard.closed)
            closed.append(True)
            raise OSError('synthetic cache close failure')
        from types import SimpleNamespace
        session=CachedObservation.begin(SimpleNamespace(lease_current=bad_close),self.job(),self.clock,
                                        guard_factory=lambda **_:guard)
        with self.assertRaises(OSError):
            session.finish(NONCE)
        self.assertEqual(closed,[True])
        with self.assertRaises(ValueError):
            session.finish(NONCE)

    def test_jobs_and_results_reject_unknown_duplicate_and_oversized_data(self):
        valid=json.dumps(self.job_data).encode()
        for raw in [valid[:-1]+b',"schema_version":1}',b'x'*65537,
                    json.dumps(dict(self.job_data,command='synthetic')).encode(),
                    json.dumps(dict(self.job_data,deadline_boottime_ms=120101)).encode(),
                    json.dumps(dict(self.job_data,helper_sequence=True)).encode(),
                    json.dumps(dict(self.job_data,successful_checked_at='2026-02-30T00:00:00Z')).encode()]:
            with self.subTest(raw=raw[:50]),self.assertRaises(ValueError):
                ObservationJob.parse(raw)
        result=ObservationResult.create(self.job(),'failed',reason='cache_unavailable')
        for raw in [result.encoded()[:-1]+b',"reason":"timeout"}',b'x'*65537,
                    json.dumps(dict(result.document(),extra=True)).encode()]:
            with self.subTest(raw=raw[:50]),self.assertRaises(ValueError):
                ObservationResult.parse(raw,expected_job=self.job())
        with self.assertRaises(ValueError):
            ObservationResult.create(self.job(),'failed',reason='untrusted arbitrary diagnostic')

    def test_exception_in_reader_scope_aborts_native_before_releasing_cache_pin(self):
        guard=Guard(on_close=lambda:self.assertFalse(self.store.retire('2'*32)))
        session=CachedObservation.begin(self.store,self.job(),self.clock,guard_factory=lambda **_:guard)
        self.stage('3'*32);self.store.publish('3'*32,'4'*32,'b'*64,CHECKED)
        with self.assertRaisesRegex(RuntimeError,'synthetic reader error'):
            with session:
                raise RuntimeError('synthetic reader error')
        self.assertTrue(guard.closed)
        self.assertTrue(self.store.retire('2'*32))
        with self.assertRaises(ValueError):
            session.opened_result()

    def test_job_has_no_mutable_field_dictionary(self):
        job=self.job()
        with self.assertRaises(AttributeError):
            job.deadline_boottime_ms=999999
        self.assertFalse(hasattr(job,'__dict__'))

    def test_wrong_release_does_not_consume_native_or_cache_ownership(self):
        guard=Guard()
        session=CachedObservation.begin(self.store,self.job(),self.clock,guard_factory=lambda **_:guard)
        try:
            opened=session.opened_result().encoded()
            with self.assertRaises(ValueError):
                session.finish('0000000000000002'+'d'*16)
            self.assertFalse(guard.closed)
            self.assertEqual(session.opened_result().encoded(),opened)
            self.assertEqual(session.verify_cache_index('synthetic_Packages')[0],23)
            session.finish(NONCE)
        finally:
            session.abort()

    def test_result_rejects_numeric_aliases_and_different_expected_job(self):
        result=ObservationResult.create(self.job(),'failed',reason='cache_unavailable')
        for field,value in [('schema_version',True),('helper_sequence',True),
                            ('helper_sequence',1.0),('accepted_boottime_ms',100.0)]:
            changed=result.document()
            changed['job'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                ObservationResult.parse(json.dumps(changed).encode(),expected_job=self.job())
        with self.assertRaises(ValueError):
            ObservationResult.parse(result.encoded(),expected_job=self.job(job_id='d'*32))

    def test_cache_stays_pinned_until_actual_native_release_and_result_is_one_use(self):
        guard=Guard(on_close=lambda:self.assertFalse(self.store.retire('2'*32)))
        session=CachedObservation.begin(self.store,self.job(),self.clock,
            guard_factory=lambda **_:guard)
        opened=session.opened_result()
        self.assertEqual(opened.document()['phase'],'opened')
        self.assertEqual(opened.document()['observation_lease']['lock_open_boottime_ms'],110)
        self.assertEqual(session.verify_cache_index('synthetic_Packages')[0],23)
        # Current is normally protected regardless of leases. Publish a successor
        # before checking retirement to prove this session's actual old-cache pin.
        self.stage('3'*32)
        self.store.publish('3'*32,'4'*32,'b'*64,CHECKED)
        self.assertFalse(self.store.retire('2'*32))
        self.now=120
        result=session.finish(NONCE)
        self.assertTrue(guard.closed)
        self.assertEqual(result.document()['phase'],'released')
        self.assertEqual(ObservationResult.parse(result.encoded(),expected_job=self.job()).encoded(),result.encoded())
        self.assertTrue(self.store.retire('2'*32))
        with self.assertRaises(ValueError):
            session.opened_result()
        with self.assertRaises(ValueError):
            session.finish(NONCE)


if __name__=='__main__':
    unittest.main()
