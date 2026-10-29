"""Read-only reporter session with actual cache leases and installed-state files."""
import os
import json
from contextlib import contextmanager
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_storage import Store, ReaderProjection, READER_FILES
from inventory_refresh_reader_session import ReaderSession
from inventory_refresh_status import PublicStatus

BOOT='11111111-1111-4111-8111-111111111111'
GEN='b'*32
POLICY='c'*64
CHECKED='2026-10-28T00:00:00Z'


class ReaderSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.cache=self.root/'cache';self.cache.mkdir()
        self.fd=os.open(self.cache,os.O_RDONLY|os.O_DIRECTORY)
        self.store=Store(self.fd,os.getuid(),os.getgid(),os.getuid())
        self.publish('a'*32,GEN)
        self.dpkg=self.root/'dpkg';self.dpkg.mkdir();(self.dpkg/'updates').mkdir()
        (self.dpkg/'status').write_bytes(b'Package: synthetic\nVersion: 1\n')
        self.dpkg_fd=os.open(self.dpkg,os.O_RDONLY|os.O_DIRECTORY)
        self.now=100
    def tearDown(self):
        os.close(self.dpkg_fd);os.close(self.fd);self.temp.cleanup()
    def publish(self,stage,generation):
        directory=self.cache/('staging-'+stage)/'lists';directory.mkdir(parents=True)
        (directory/'synthetic_Packages').write_bytes(b'synthetic metadata')
        files=tuple((name,b'' if name.startswith('empty-') else b'synthetic '+name.encode()) for name in READER_FILES)
        projection=ReaderProjection._from_policy(generation,POLICY,files)
        return self.store.publish(stage,generation,POLICY,CHECKED,reader_projection=projection)
    def pin(self):
        return ReaderSession.pin(self.store,cache_generation=GEN,policy_generation=POLICY,
            successful_checked_at=CHECKED,boot_id=BOOT,clock=lambda:(BOOT,self.now))
    def status(self,lease=None,receipt=None):
        return PublicStatus.create(dict(schema_version=1,operation_nonce=None,phase='unconfirmed',
            reason='cache_unavailable',policy_generation=lease['policy_generation'] if lease else POLICY,
            cache_generation=lease['cache_generation'] if lease else GEN,
            successful_checked_at=CHECKED,started_at=None,finished_at=None,attempt=None,
            observation_lease=lease,observation_receipt=receipt))
    def offer(self,**changes):
        return dict(dict(nonce='0000000000000001'+'a'*16,boot_id=BOOT,cache_generation=GEN,
            policy_generation=POLICY,lock_open_boottime_ms=110,expires_boottime_ms=1000),**changes)
    def test_scan_admitted_once_after_open_and_hashes_match_actual_released_receipt(self):
        session=self.pin();admitted=[];self.now=120
        started=session.begin_scan(self.status(lease=self.offer()),observation_nonce=self.offer()['nonce'],
            dpkg_fd=self.dpkg_fd,owner=os.getuid(),admit_scan=lambda at:admitted.append(at) or True)
        self.assertEqual(started,120);self.assertEqual(admitted,[120])
        self.now=130
        hashes=session.finish_scan()
        self.assertEqual(hashes['installed_before_sha256'],hashes['installed_after_sha256'])
        receipt=dict(self.offer(),lock_held_until_boottime_ms=140,released_boottime_ms=145,
            outcome='released',installed_before_sha256=hashes['installed_before_sha256'],
            installed_after_sha256=hashes['installed_after_sha256'])
        self.now=150
        evidence=json.loads(session.finish(self.status(receipt=receipt)))
        self.assertEqual(evidence['scan_started_boottime_ms'],120)
        self.assertEqual(evidence['scan_finished_boottime_ms'],130)
        self.assertEqual(evidence['observation_receipt'],receipt)
        with self.assertRaises(ValueError):session.finish(self.status(receipt=receipt))
        os.fstat(self.dpkg_fd)

    def test_fixed_policy_query_is_available_only_inside_the_admitted_scan(self):
        session=self.pin()
        with self.assertRaises(ValueError):session.policy(['synthetic'])
        self.now=100;session=self.pin();self.start(session)
        with patch('inventory_refresh_reader_tools._policy',return_value='synthetic:\n Candidate: 2\n') as query:
            self.assertEqual(session.policy(['synthetic']),'synthetic:\n Candidate: 2\n')
            self.assertEqual(query.call_args.args[2],['synthetic'])
        self.now=130;session.finish_scan()
        with self.assertRaises(ValueError):session.policy(['synthetic'])
        session.close()

    def test_policy_query_budget_is_cumulative_and_failure_consumes_session(self):
        session=self.pin();self.start(session)
        with patch('inventory_refresh_reader_tools._policy',return_value='synthetic') as query:
            for _ in range(67):session.policy(['synthetic'])
            with self.assertRaises(ValueError):session.policy(['synthetic'])
            self.assertEqual(query.call_count,67)
        with self.assertRaises(ValueError):session.finish_scan()
        self.now=100;session=self.pin();self.start(session)
        with patch('inventory_refresh_reader_tools._policy',side_effect=ValueError('synthetic child failure')) as query:
            with self.assertRaises(ValueError):session.policy(['synthetic'])
            with self.assertRaises(ValueError):session.policy(['synthetic'])
            query.assert_called_once()
        self.publish('d'*32,'e'*32);self.assertTrue(self.store.retire(GEN))

    def test_policy_total_output_budget_cannot_reset_between_batches(self):
        session=self.pin();self.start(session)
        with patch('inventory_refresh_reader_tools._policy',return_value='a'*(16*1024*1024)) as query:
            for _ in range(4):session.policy(['synthetic'])
            with self.assertRaises(ValueError):session.policy(['synthetic'])
            self.assertEqual(query.call_count,4)
        session.close()

    def test_policy_post_query_projection_change_and_clock_rewind_withhold_output(self):
        for mutation in ('projection','clock','closed'):
            self.now=100;session=self.pin();self.start(session)
            def changed(*_):
                if mutation=='projection':
                    path=self.cache/('generation-'+GEN)/'_inventory-reader'/'apt.conf'
                    path.chmod(0o640);path.write_bytes(b'changed');path.chmod(0o440)
                elif mutation=='clock':self.now=119
                else:session.close()
                return 'never publish'
            with self.subTest(mutation=mutation),patch('inventory_refresh_reader_tools._policy',side_effect=changed):
                with self.assertRaises(ValueError):session.policy(['synthetic'])
                with self.assertRaises(ValueError):session.finish_scan()
            if mutation=='projection':
                path=self.cache/('generation-'+GEN)/'_inventory-reader'/'apt.conf'
                path.chmod(0o640);path.write_bytes(b'synthetic apt.conf');path.chmod(0o440)

    def test_projection_requires_empty_readonly_parts_directory(self):
        directory=self.cache/('generation-'+GEN)/'_inventory-reader'/'empty.d'
        directory.chmod(0o750)
        (directory/'unexpected.conf').write_bytes(b'synthetic')
        directory.chmod(0o550)
        with self.assertRaises(ValueError):self.pin()

    def test_projection_requires_readonly_files_even_if_bytes_match_manifest(self):
        path=self.cache/('generation-'+GEN)/'_inventory-reader'/'apt.conf'
        path.chmod(0o640)
        with self.assertRaises(ValueError):self.pin()

    def test_receipt_cannot_claim_release_in_future(self):
        session=self.pin();self.now=120
        session.begin_scan(self.status(lease=self.offer()),observation_nonce=self.offer()['nonce'],
            dpkg_fd=self.dpkg_fd,owner=os.getuid(),admit_scan=lambda _:True)
        self.now=130;hashes=session.finish_scan()
        receipt=dict(self.offer(),lock_held_until_boottime_ms=140,released_boottime_ms=145,
            outcome='released',**hashes)
        with self.assertRaises(ValueError):session.finish(self.status(receipt=receipt))

    def start(self,session,offer=None,admit=lambda _:True):
        self.now=120
        return session.begin_scan(self.status(lease=offer or self.offer()),
            observation_nonce=self.offer()['nonce'],dpkg_fd=self.dpkg_fd,owner=os.getuid(),admit_scan=admit)
    def completed(self,session):
        self.start(session);self.now=130;hashes=session.finish_scan()
        return dict(self.offer(),lock_held_until_boottime_ms=140,released_boottime_ms=145,outcome='released',**hashes)
    def test_foreign_or_pre_pin_offer_rejected_before_admission(self):
        for changes in [dict(nonce='0000000000000002'+'a'*16),dict(boot_id='22222222-2222-4222-8222-222222222222'),
                        dict(policy_generation='d'*64),dict(lock_open_boottime_ms=99),dict(lock_open_boottime_ms=125)]:
            with self.subTest(changes=changes):
                self.now=100;session=self.pin();admitted=[]
                with self.assertRaises(ValueError):self.start(session,self.offer(**changes),lambda _:admitted.append(True) or True)
                self.assertEqual(admitted,[])
                with self.assertRaises(ValueError):self.start(session)
    def test_scan_admission_failure_closes_pin_before_any_installed_read(self):
        (self.dpkg/'status').unlink()
        session=self.pin()
        with self.assertRaises(ValueError):self.start(session,admit=lambda _:False)
        self.publish('d'*32,'e'*32);self.assertTrue(self.store.retire(GEN))
        with self.assertRaises(ValueError):self.start(session)
    def test_installed_mutation_cannot_become_coherent_evidence(self):
        session=self.pin();self.start(session)
        (self.dpkg/'status').write_bytes(b'changed synthetic state')
        self.now=130
        with self.assertRaises(ValueError):session.finish_scan()
        with self.assertRaises(ValueError):session.finish_scan()
        os.fstat(self.dpkg_fd)
    def test_clock_rewind_expiry_and_boot_change_consume_session(self):
        for now,boot in [(119,BOOT),(1001,BOOT),(130,'22222222-2222-4222-8222-222222222222')]:
            with self.subTest(now=now,boot=boot):
                self.now=100;session=self.pin();self.start(session)
                session._clock=lambda:(boot,now)
                with self.assertRaises(ValueError):session.finish_scan()
                with self.assertRaises(ValueError):session.finish_scan()
    def test_receipt_must_match_frozen_offer_all_hashes_and_whole_interval(self):
        for changes in [dict(nonce='0000000000000002'+'a'*16),dict(cache_generation='d'*32),
                        dict(policy_generation='e'*64),dict(lock_open_boottime_ms=109),
                        dict(expires_boottime_ms=999),dict(lock_held_until_boottime_ms=129),
                        dict(outcome='unconfirmed'),dict(installed_before_sha256='a'*64,installed_after_sha256='a'*64)]:
            with self.subTest(changes=changes):
                self.now=100;session=self.pin();receipt=self.completed(session);self.now=150
                with self.assertRaises(ValueError):session.finish(self.status(receipt=dict(receipt,**changes)))
                with self.assertRaises(ValueError):session.finish(self.status(receipt=receipt))
    def test_local_pin_close_failure_cannot_return_evidence_and_never_retries_close(self):
        closed=[]
        @contextmanager
        def failing_close():
            with self.store.lease_current() as lease:yield lease
            closed.append(True)
            raise OSError('synthetic close failure')
        cache=SimpleNamespace(lease_current=failing_close)
        session=ReaderSession.pin(cache,cache_generation=GEN,policy_generation=POLICY,
            successful_checked_at=CHECKED,boot_id=BOOT,clock=lambda:(BOOT,self.now))
        receipt=self.completed(session);self.now=150
        with self.assertRaises(OSError):session.finish(self.status(receipt=receipt))
        session.close();self.assertEqual(closed,[True])
    def test_corrupt_projection_is_not_replaced_by_a_fallback(self):
        path=self.cache/('generation-'+GEN)/'_inventory-reader'/'apt.conf'
        path.chmod(0o640);path.write_bytes(b'changed synthetic config');path.chmod(0o440)
        with self.assertRaises(ValueError):self.pin()
        self.publish('d'*32,'e'*32);self.assertTrue(self.store.retire(GEN))

    def test_admission_callback_cannot_close_pin_and_resume_scan(self):
        session=self.pin()
        def close_during_admission(_):
            session.close()
            return True
        with self.assertRaises(ValueError):self.start(session,admit=close_during_admission)
        with self.assertRaises(ValueError):session.finish_scan()

    def test_missing_receipt_consumes_session_and_releases_only_own_pin(self):
        session=self.pin();self.completed(session);self.now=150
        self.publish('d'*32,'e'*32)
        with self.assertRaises(ValueError):session.finish(self.status())
        self.assertTrue(self.store.retire(GEN));os.fstat(self.fd);os.fstat(self.dpkg_fd)
        with self.assertRaises(ValueError):session.finish(self.status())
    def test_foreign_current_context_rejected_without_leaking_pin(self):
        for key,value in [('cache_generation','d'*32),('policy_generation','e'*64),
                          ('successful_checked_at','2026-10-28T01:00:00Z')]:
            kwargs=dict(cache_generation=GEN,policy_generation=POLICY,successful_checked_at=CHECKED,
                boot_id=BOOT,clock=lambda:(BOOT,self.now));kwargs[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):ReaderSession.pin(self.store,**kwargs)
        self.publish('d'*32,'e'*32);self.assertTrue(self.store.retire(GEN))

    def test_exact_generation_stays_pinned_until_idempotent_close(self):
        session=self.pin()
        self.publish('d'*32,'e'*32)
        self.assertFalse(self.store.retire(GEN))
        session.close();session.close()
        self.assertTrue(self.store.retire(GEN))
        os.fstat(self.fd)  # borrowed root stays caller-owned


if __name__=='__main__':unittest.main()
