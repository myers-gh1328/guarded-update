"""Runtime ownership/failure ordering; actual journal/cache/status are retained."""
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import test_inventory_refresh_observation_transaction as fixture_module
import inventory_refresh_runtime as module


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture_module.ObservationTransactionTests();self.f.setUp();f=self.f
        self.events=[];self.runtime=None;self.patches=[];self.original_policy_close=f.policy.close;self.original_state=module._state
        self.resources=Mock();self.resources._cache.fds=[f.fds[1]]
        self.resources.close.side_effect=lambda:self.events.append('resources_close')
        self.state=Mock();self.state.fds=[f.fds[0]];self.state.close.side_effect=lambda:self.events.append('state_close')
        self.accounts=(SimpleNamespace(pw_uid=501,pw_gid=501),SimpleNamespace(pw_uid=502,pw_gid=502))
        self.lock=Mock();self.lock.__enter__=Mock(side_effect=lambda:self.events.append('lock_enter'))
        self.lock.__exit__=Mock(side_effect=lambda *args:self.events.append('lock_exit'))
        self.inboxes={name:Mock(_capability=name) for name in ('release','observation','refresh')}
        for name,inbox in self.inboxes.items():inbox.read.return_value=None;inbox.close.side_effect=lambda name=name:self.events.append(name+'_close')
        def add(target,**kwargs):
            value=patch(target,**kwargs);self.patches.append(value);self.addCleanup(value.stop);return value.start()
        self.resource_factory=add('inventory_refresh_runtime.RuntimeResources.fixed',side_effect=lambda:(self.events.append('resources_open'),self.resources)[1])
        self.policy_factory=add('inventory_refresh_runtime.PolicyGuard.fixed',side_effect=lambda:(self.events.append('policy_open'),f.policy)[1])
        add('inventory_refresh_runtime._state',return_value=self.state)
        add('inventory_refresh_runtime._accounts',return_value=self.accounts)
        add('inventory_refresh_runtime.Journal',return_value=f.journal)
        add('inventory_refresh_runtime.Store',return_value=f.store)
        add('inventory_refresh_runtime.WriterExclusion.fixed',return_value=f.writers)
        add('inventory_refresh_runtime.StatusPublisher.fixed',return_value=f.publisher)
        add('inventory_refresh_runtime.ObservationChannel.fixed',return_value=f.channel)
        add('inventory_refresh_runtime.Inbox.fixed',side_effect=lambda name:self.inboxes[name])
        add('inventory_refresh_runtime.kernel_clock',side_effect=f.clock)
        add('inventory_refresh_runtime.sys.platform',new='linux')
        add('inventory_refresh_runtime.os.getresuid',return_value=(0,0,0),create=True)
        add('inventory_refresh_runtime.os.getresgid',return_value=(0,0,0),create=True)
        self.original_exclusive=f.journal.exclusive;f.journal.exclusive=Mock(return_value=self.lock)

    def tearDown(self):
        if self.runtime is not None:
            try:self.runtime.close()
            except ValueError:pass
        self.f.journal.exclusive=self.original_exclusive
        self.f.policy.close=self.original_policy_close
        for value in reversed(self.patches):value.stop()
        self.f.tearDown()

    def test_resource_admission_precedes_policy_and_same_journal_dispatch(self):
        self.runtime=module.FixedRuntime.fixed()
        self.assertLess(self.events.index('resources_open'),self.events.index('policy_open'))
        self.assertEqual(self.runtime.step()['state'],'ready')
        self.assertIs(self.runtime._dispatcher._journal,self.f.journal)
        self.assertEqual(self.f.status()['cache_generation'],'c'*32)

    def test_false_startup_barrier_refuses_dispatch_without_initialization(self):
        self.f.journal.startup_ready=Mock(return_value=False);self.f.journal.initialize=Mock()
        with self.assertRaises(ValueError):module.FixedRuntime.fixed()
        self.f.journal.initialize.assert_not_called()
        self.assertIn('resources_close',self.events);self.assertIn('lock_exit',self.events)
        for inbox in self.inboxes.values():inbox.read.assert_not_called()

    def test_prejournal_policy_failure_closes_resources_without_fence(self):
        self.policy_factory.side_effect=ValueError('private detail');self.f.journal.fence_external=Mock()
        with self.assertRaises(ValueError) as error:module.FixedRuntime.fixed()
        self.assertNotIn('private detail',str(error.exception));self.f.journal.fence_external.assert_not_called()
        self.assertIn('resources_close',self.events);self.assertNotIn('lock_enter',self.events)

    def test_late_policy_close_error_fences_before_unlock_and_continues_cleanup(self):
        self.f.policy.close=Mock(side_effect=ValueError('private detail'))
        self.runtime=module.FixedRuntime.fixed()
        original=self.f.journal.fence_external
        self.f.journal.fence_external=Mock(side_effect=lambda:(self.events.append('fence'),original())[1])
        with self.assertRaises(ValueError):self.runtime.close()
        self.assertLess(self.events.index('fence'),self.events.index('lock_exit'))
        self.assertIn('resources_close',self.events);self.assertIn('state_close',self.events)
        self.assertTrue(self.f.journal.snapshot()['unconfirmed'])

    def test_late_resource_close_error_fences_before_unlock(self):
        self.runtime=module.FixedRuntime.fixed()
        self.resources.close.side_effect=lambda:(_ for _ in ()).throw(ValueError('private detail'))
        original=self.f.journal.fence_external
        self.f.journal.fence_external=Mock(side_effect=lambda:(self.events.append('fence'),original())[1])
        with self.assertRaises(ValueError):self.runtime.close()
        self.assertLess(self.events.index('fence'),self.events.index('lock_exit'))
        self.assertIn('state_close',self.events)

    def test_final_release_error_closes_without_reacquisition_or_dispatch(self):
        self.runtime=module.FixedRuntime.fixed();self.lock.__exit__.side_effect=OSError('private')
        with self.assertRaises(ValueError):self.runtime.close()
        self.assertIn('state_close',self.events)
        with self.assertRaises(ValueError):self.runtime.step()
        self.f.journal.exclusive.assert_called_once()

    def test_account_change_closes_and_fences(self):
        self.runtime=module.FixedRuntime.fixed()
        self.accounts[0].pw_uid=503
        with self.assertRaises(ValueError):self.runtime.step()
        self.assertTrue(self.f.journal.snapshot()['unconfirmed'])
        self.assertIn('lock_exit',self.events)

    def test_partial_channel_admission_failure_closes_all_earlier_guards(self):
        with patch('inventory_refresh_runtime.ObservationChannel.fixed',side_effect=ValueError('private')):
            with self.assertRaises(ValueError):module.FixedRuntime.fixed()
        self.assertIsNone(self.f.publisher._directory)
        self.assertIn('resources_close',self.events);self.assertIn('state_close',self.events)
        self.assertTrue(self.f.journal.snapshot()['unconfirmed'])
        self.assertLess(self.events.index('resources_close'),self.events.index('lock_exit'))

    def test_truthy_startup_result_does_not_authorize_runtime(self):
        self.f.journal.startup_ready=Mock(return_value=1)
        with self.assertRaises(ValueError):module.FixedRuntime.fixed()
        self.assertTrue(self.f.journal.snapshot()['unconfirmed'])
        for inbox in self.inboxes.values():inbox.read.assert_not_called()

    def test_state_root_close_failure_never_retries_descriptor(self):
        # Use the unpatched fixed state opener; all OS operations are test mocks.
        opener=self.original_state
        ancestry=Mock()
        with (patch('inventory_refresh_runtime.os.open',return_value=10),
              patch('inventory_refresh_runtime._Ancestry.open',return_value=ancestry),
              patch('inventory_refresh_runtime.os.close',side_effect=OSError('private')) as close):
            with self.assertRaises(ValueError):opener()
        close.assert_called_once_with(10);ancestry.close.assert_called_once()

    def test_idle_close_permanently_prevents_step(self):
        self.runtime=module.FixedRuntime.fixed();self.runtime.close()
        with self.assertRaises(ValueError):self.runtime.step()
        self.assertFalse(self.f.journal.snapshot()['unconfirmed'])


if __name__=='__main__':unittest.main()
