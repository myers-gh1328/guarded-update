"""Capability composition fixtures are not fixed Root/kernel origin proof."""
import os
import sys
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_storage import Store,ReaderProjection,READER_FILES
from inventory_refresh_status import PublicStatus
from inventory_refresh_reporter_io import StatusReader,ReporterIOError
import inventory_refresh_reporter_environment as environment

BOOT='11111111-1111-4111-8111-111111111111'
GEN='b'*32
POLICY='c'*64
CHECKED='2026-10-28T00:00:00Z'


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        cache=self.root/'cache';cache.mkdir();self.cache_fd=os.open(cache,os.O_RDONLY|os.O_DIRECTORY)
        self.store=Store(self.cache_fd,os.getuid(),os.getgid(),os.getuid());self.publish('a'*32,GEN)
        self.status=self.root/'status';self.status.mkdir(mode=0o750);self.status.chmod(0o750)
        self.status_fd=os.open(self.status,os.O_RDONLY|os.O_DIRECTORY)
        self.now=100;self.parent=Mock();self.parent.clock.side_effect=lambda:(BOOT,self.now)
        self.chains={name:Mock() for name in ('runtime','status','cache','dpkg','library')}
        self.owner=None;self.write_status(GEN)
    def tearDown(self):
        if self.owner is not None:self.owner.close()
        os.close(self.cache_fd);os.close(self.status_fd);self.temp.cleanup()
    def publish(self,stage,generation):
        directory=self.root/'cache'/('staging-'+stage)/'lists';directory.mkdir(parents=True)
        (directory/'synthetic_Packages').write_bytes(b'synthetic metadata')
        files=tuple((name,b'' if name.startswith('empty-') else b'synthetic '+name.encode()) for name in READER_FILES)
        self.store.publish(stage,generation,POLICY,CHECKED,reader_projection=ReaderProjection._from_policy(generation,POLICY,files))
    def write_status(self,generation):
        value=dict(schema_version=1,operation_nonce=None,phase='unconfirmed',reason='cache_unavailable',
            policy_generation=POLICY,cache_generation=generation,successful_checked_at=CHECKED,
            started_at=None,finished_at=None,attempt=None,observation_lease=None,observation_receipt=None)
        (self.status/'status.json').write_bytes(PublicStatus.create(value).encoded());(self.status/'status.json').chmod(0o640)
    def admit(self):
        reader=StatusReader(self.status_fd,os.getgid(),owner=os.getuid())
        self.owner=environment.ReporterEnvironment._from_capabilities(self.parent,reader,self.store,self.chains)
        return self.owner

    def test_readonly_composition_pins_actual_cache_and_retains_old_context(self):
        owner=self.admit();context=owner.pin_current()
        expected=dict(cache_generation=GEN,policy_generation=POLICY,successful_checked_at=CHECKED,
            boot_id=BOOT,pinned_boottime_ms=100)
        self.assertEqual(context,expected);context['cache_generation']='f'*32
        self.publish('d'*32,'e'*32);self.write_status('e'*32);self.now=110
        self.assertEqual(json.loads(owner.read_status().encoded())['cache_generation'],'e'*32)
        self.assertEqual(owner.pinned_context(),expected)
        self.assertFalse(self.store.retire(GEN));owner.close();self.assertTrue(self.store.retire(GEN))
        os.fstat(self.cache_fd);os.fstat(self.status_fd)

    def test_fixed_parent_admission_precedes_any_inventory_ancestry_or_reader(self):
        with patch.object(environment.ReporterParent,'fixed',side_effect=ValueError('synthetic rejected Parent')),\
            patch.object(environment,'_Chain') as chains,patch.object(environment,'StatusReader') as reader:
            with self.assertRaises(ValueError):environment.ReporterEnvironment.fixed()
            chains.assert_not_called();reader.assert_not_called()

    def test_missing_and_publication_change_reverify_then_allow_only_fresh_status(self):
        owner=self.admit();(self.status/'status.json').unlink();self.parent.verify.reset_mock()
        self.assertIsNone(owner.read_status());self.assertEqual(self.parent.verify.call_count,2)
        self.write_status(GEN);fresh=owner.read_status()
        with patch.object(owner._reader,'read',side_effect=[ReporterIOError('publication_changed'),fresh]) as read:
            self.assertIsNone(owner.read_status());self.assertIs(owner.read_status(),fresh)
            self.assertEqual(read.call_count,2)
        self.parent.close.assert_not_called()

    def test_postverification_failure_cannot_return_publication_change_none(self):
        owner=self.admit();self.parent.verify.side_effect=[None,ValueError('synthetic Parent lost')]
        with patch.object(owner._reader,'read',side_effect=ReporterIOError('publication_changed')):
            with self.assertRaises(ValueError):owner.read_status()
        self.parent.close.assert_called_once()
        for chain in self.chains.values():chain.close.assert_called_once()

    def test_pin_source_race_consumes_context_without_retrying_new_generation(self):
        owner=self.admit();self.publish('d'*32,'e'*32)
        with patch.object(self.store,'lease_current',wraps=self.store.lease_current) as acquire:
            with self.assertRaises(ValueError):owner.pin_current()
            self.write_status('e'*32)
            with self.assertRaises(ValueError):owner.pin_current()
            self.assertEqual(acquire.call_count,1)
        self.parent.close.assert_called_once()

    def test_pin_none_or_second_attempt_consumes_instead_of_waiting_or_repinning(self):
        owner=self.admit();(self.status/'status.json').unlink()
        with self.assertRaises(ValueError) as caught:owner.pin_current()
        self.assertEqual(caught.exception.reason,'cache_unavailable')
        self.write_status(GEN)
        with self.assertRaises(ValueError):owner.pin_current()
        self.parent.close.assert_called_once()

    def test_successful_pin_cannot_be_replaced_by_a_second_pin(self):
        owner=self.admit();owner.pin_current();self.publish('d'*32,'e'*32);self.write_status('e'*32)
        with patch.object(self.store,'lease_current',wraps=self.store.lease_current) as acquire:
            with self.assertRaises(ValueError):owner.pin_current()
            acquire.assert_not_called()
        self.assertTrue(self.store.retire(GEN));self.parent.close.assert_called_once()

    def test_unsafe_status_does_not_fall_back_to_previous_successful_read(self):
        owner=self.admit();self.assertIsNotNone(owner.read_status())
        (self.status/'status.json').write_bytes(b'{invalid')
        with self.assertRaises(ValueError):owner.read_status()
        self.write_status(GEN)
        with self.assertRaises(ValueError):owner.read_status()
        self.parent.close.assert_called_once()

    def test_parent_clock_failure_after_pin_releases_local_pin_and_all_caps(self):
        owner=self.admit();owner.pin_current();self.publish('d'*32,'e'*32)
        self.parent.clock.side_effect=ValueError('synthetic clock unavailable')
        with self.assertRaises(ValueError):owner.pinned_context()
        self.assertTrue(self.store.retire(GEN));self.parent.close.assert_called_once()
        for chain in self.chains.values():chain.close.assert_called_once()

    def test_session_close_failure_still_closes_reader_chains_and_parent_once(self):
        owner=self.admit();owner.pin_current();session=owner._session;reader=owner._reader
        close=session.close
        def failure():close();raise OSError('synthetic pin close')
        with patch.object(session,'close',side_effect=failure) as failed:
            with self.assertRaises(ValueError) as caught:owner.close()
            self.assertEqual(caught.exception.reason,'cleanup_unconfirmed');failed.assert_called_once()
            owner.close();failed.assert_called_once()
        self.assertIsNone(reader._directory);self.parent.close.assert_called_once()
        for chain in self.chains.values():chain.close.assert_called_once()
        os.fstat(self.cache_fd);os.fstat(self.status_fd)
