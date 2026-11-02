"""Bounded inbox dispatch with real nonce files and actual observation lifecycle."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import test_inventory_refresh_observation_transaction as observation_fixture
from inventory_refresh_dispatch import RootDispatcher
from inventory_refresh_io import Inbox,IOErrorState


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.fixture=observation_fixture.ObservationTransactionTests();self.fixture.setUp();f=self.fixture
        root=f.root/'inboxes';root.mkdir(mode=0o700);self.fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
        self.inboxes={}
        for capability in ('refresh','observation','release'):
            (root/capability).mkdir(mode=0o770);(root/capability).chmod(0o770)
            self.inboxes[capability]=Inbox(self.fd,capability,os.getuid(),os.getgid(),owner=os.getuid())
        self.refresh=Mock()
        for name in ('journal','policy','resources','store','publisher','writers'):
            setattr(self.refresh,'_'+name,getattr(f.transaction,'_'+name))
        self.refresh.refresh.return_value='existing'
        self.dispatch=RootDispatcher(f.journal,self.inboxes,self.refresh,f.transaction)

    def tearDown(self):
        self.dispatch.close()
        for value in self.inboxes.values():value.close()
        os.close(self.fd);self.fixture.tearDown()

    def request(self,capability,nonce):
        p=self.fixture.root/'inboxes'/capability/'request';p.write_bytes(nonce.encode('ascii'));p.chmod(0o600)

    def test_actual_request_launches_observation_once_and_suppresses_refresh(self):
        f=self.fixture;self.request('observation',f.nonce);self.request('refresh','0000000000000002'+'a'*16)
        first=self.dispatch.step();self.assertEqual(first['observation'],'dispatched')
        self.refresh.refresh.assert_not_called();f.service.launch.assert_called_once()
        self.assertEqual(self.dispatch.step()['observation'],'existing');f.service.launch.assert_called_once()
        self.refresh.refresh.assert_not_called()

    def test_matching_release_processed_despite_malformed_peer_then_receipt_permits_refresh(self):
        f=self.fixture;self.request('observation',f.nonce);self.dispatch.step();lease=f.opened();self.dispatch.step()
        self.request('release',f.nonce);self.request('observation','bad');self.request('refresh','0000000000000002'+'a'*16)
        value=self.dispatch.step();self.assertEqual(value['release'],'releasing');self.assertEqual(value['observation'],'invalid_request')
        self.assertIsNone(f.status()['observation_lease']);self.refresh.refresh.assert_not_called()
        f.released(lease);self.assertEqual(self.dispatch.step()['poll'],'succeeded')
        self.refresh.refresh.assert_called_once();self.assertIsNotNone(f.journal.snapshot()['last_observation'])

    def test_malformed_release_does_not_starve_observation_or_fence(self):
        f=self.fixture;self.request('release','bad');self.request('observation',f.nonce)
        value=self.dispatch.step();self.assertEqual(value['release'],'invalid_request');self.assertEqual(value['observation'],'dispatched')
        self.assertFalse(f.journal.snapshot()['unconfirmed'])

    def test_reader_cleanup_error_fences_and_disables_future_steps(self):
        self.inboxes['release'].read=Mock(side_effect=IOErrorState('cleanup_unconfirmed'))
        with self.assertRaises(ValueError):self.dispatch.step()
        self.assertTrue(self.fixture.journal.snapshot()['unconfirmed'])
        self.inboxes['release'].read.reset_mock()
        self.assertEqual(self.dispatch.step()['state'],'closed');self.inboxes['release'].read.assert_not_called()

    def test_invalid_interface_tuple_cannot_dispatch(self):
        self.inboxes['release'].read=Mock(return_value=(self.fixture.nonce,True))
        with self.assertRaises(ValueError):self.dispatch.step()
        self.assertTrue(self.fixture.journal.snapshot()['unconfirmed']);self.refresh.refresh.assert_not_called()

    def test_second_dispatcher_cannot_claim_same_idle_lifecycle(self):
        with self.assertRaises(ValueError):RootDispatcher(self.fixture.journal,self.inboxes,self.refresh,self.fixture.transaction)
        self.request('observation',self.fixture.nonce)
        self.assertEqual(self.dispatch.step()['observation'],'dispatched')
        self.assertFalse(self.fixture.journal.snapshot()['unconfirmed'])
        self.fixture.service.launch.assert_called_once()

    def test_same_context_required(self):
        self.refresh._store=object()
        with self.assertRaises(ValueError):RootDispatcher(self.fixture.journal,self.inboxes,self.refresh,self.fixture.transaction)
        self.assertFalse(self.fixture.journal.snapshot()['unconfirmed'])

    def test_preexisting_scope_cannot_be_adopted(self):
        self.fixture.transaction.begin(self.fixture.nonce)
        with self.assertRaises(ValueError):RootDispatcher(self.fixture.journal,self.inboxes,self.refresh,self.fixture.transaction)
        self.fixture.service.close.assert_not_called()

    def test_idle_close_permanently_disables_without_closing_borrowed_inputs(self):
        self.dispatch.close();self.request('observation',self.fixture.nonce)
        self.assertEqual(self.dispatch.step()['state'],'closed');self.fixture.service.launch.assert_not_called()
        self.assertEqual(self.inboxes['observation'].read()[0],self.fixture.nonce)
        self.fixture.journal.snapshot();self.assertFalse(self.fixture.journal.snapshot()['unconfirmed'])

    def test_no_scope_existing_observation_does_not_starve_refresh(self):
        f=self.fixture;f.transaction.begin(f.nonce);lease=f.opened();f.transaction.poll()
        f.transaction.release(f.nonce);f.released(lease);f.transaction.poll()
        self.request('observation',f.nonce);self.request('refresh','0000000000000002'+'a'*16)
        self.assertEqual(self.dispatch.step()['observation'],'existing');self.refresh.refresh.assert_called_once()

    def test_drain_latches_and_never_admits_new_inboxes(self):
        f=self.fixture;self.request('observation',f.nonce);self.request('refresh','0000000000000002'+'a'*16)
        self.assertEqual(self.dispatch.drain()['state'],'drained')
        self.assertEqual(self.dispatch.step()['state'],'drained')
        f.service.launch.assert_not_called();self.refresh.refresh.assert_not_called()

    def test_drain_allows_only_owned_release_then_finishes_without_refresh(self):
        f=self.fixture;self.request('observation',f.nonce)
        self.assertEqual(self.dispatch.step()['observation'],'dispatched')
        lease=f.opened();self.request('refresh','0000000000000002'+'a'*16)
        self.request('release','0000000000000009'+'a'*16)
        self.assertEqual(self.dispatch.drain()['state'],'draining')
        self.assertIsNone(f.transaction._grant);self.refresh.refresh.assert_not_called()
        self.request('release',f.nonce)
        self.assertEqual(self.dispatch.drain()['release'],'releasing')
        f.released(lease)
        self.assertEqual(self.dispatch.step()['state'],'drained')
        self.refresh.refresh.assert_not_called()

    def test_drain_never_reports_drained_for_malformed_inbox_or_active_journal(self):
        f=self.fixture;self.request('refresh','bad')
        self.assertEqual(self.dispatch.drain()['state'],'draining')
        self.assertFalse(f.journal.snapshot()['unconfirmed'])
        (f.root/'inboxes/refresh/request').unlink()
        f.journal.receive('refresh','0000000000000002'+'a'*16,f.boot,200,f.policy.generation)
        self.assertEqual(self.dispatch.drain()['state'],'draining')
        self.refresh.refresh.assert_not_called();f.service.launch.assert_not_called()

    def test_drain_fences_unavailable_input_and_never_resumes(self):
        self.inboxes['release'].read=Mock(side_effect=IOErrorState('cleanup_unconfirmed'))
        with self.assertRaises(ValueError):self.dispatch.drain()
        self.assertTrue(self.fixture.journal.snapshot()['unconfirmed'])
        self.inboxes['release'].read.reset_mock()
        self.assertEqual(self.dispatch.step()['state'],'closed')
        self.inboxes['release'].read.assert_not_called();self.refresh.refresh.assert_not_called()

    def test_idle_drain_never_reports_drained_with_stale_policy(self):
        self.fixture.policy.recheck=Mock(side_effect=ValueError('stale'))
        with self.assertRaises(ValueError):self.dispatch.drain()
        self.assertTrue(self.fixture.journal.snapshot()['unconfirmed'])
        self.refresh.refresh.assert_not_called();self.fixture.service.launch.assert_not_called()

    def test_drain_rechecks_policy_after_inbox_reads(self):
        original=self.fixture.policy.recheck;calls=[]
        def changed():
            calls.append(1)
            if len(calls)>1:raise ValueError('changed')
            return original()
        self.fixture.policy.recheck=Mock(side_effect=changed)
        with self.assertRaises(ValueError):self.dispatch.drain()
        self.assertGreaterEqual(len(calls),2)
        self.assertTrue(self.fixture.journal.snapshot()['unconfirmed'])
        self.refresh.refresh.assert_not_called();self.fixture.service.launch.assert_not_called()


if __name__=='__main__':unittest.main()
