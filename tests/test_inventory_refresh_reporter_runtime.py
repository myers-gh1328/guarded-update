"""Actual fixed inbox files with transferred Env fixtures, not origin proof."""
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import test_inventory_refresh_reporter_environment as fixtures
from inventory_refresh_reporter_io import ReporterRequestWriter
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
    def tearDown(self):
        if self.owner is not None:self.owner.close()
        self.release.close();self.observation.close();os.close(self.fd);self.fixture.tearDown()
    def admit(self):
        self.owner=runtime.ReporterRuntime._from_capabilities(self.env,self.observation,self.release)
        return self.owner

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
        owner=self.admit();owner.pin_current();calls=[]
        def clock():
            calls.append(True)
            if len(calls)==2:owner.close()
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


if __name__=='__main__':unittest.main()
