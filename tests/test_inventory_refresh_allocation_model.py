"""Abstract allocation contract; no real lock, process or durability claim."""
import unittest

from inventory_refresh_allocation_model import Model


class AllocationModelTests(unittest.TestCase):
    def locked(self):
        return Model('e'*32,'b'*36,'0'*15+'1'+'a'*16,('agent','root')).acquire('client1','agent').acquire('client1','root')

    def test_crashes_and_lost_ack_never_authorize_effect(self):
        for stage in range(5):
            model=self.locked()
            for action in ('intent','receive','submit','start')[:stage]:
                model=model.advance(action,model.epoch,model.boot,model.nonce)
            model=model.uncertain()
            self.assertTrue(model.unknown)
            self.assertFalse(model.may_effect())
            self.assertFalse(model.advance('start',model.epoch,model.boot,model.nonce).may_effect())
            self.assertTrue(model.advance('start',model.epoch,model.boot,model.nonce).unknown)

    def test_matching_durable_transitions_are_required(self):
        model=self.locked()
        self.assertFalse(model.may_effect())
        for action in ('intent','receive','submit','start'):
            model=model.advance(action,model.epoch,model.boot,model.nonce)
            self.assertEqual(model.may_effect(),action=='start')
        self.assertFalse(model.supersede().may_effect())

    def test_reverse_lock_order_and_competing_client_fail(self):
        model=Model('e'*32,'b'*36,'0'*15+'1'+'a'*16,('agent','root'))
        model=model.acquire('client1','agent')
        with self.assertRaises(ValueError):model.acquire('client2','root')
        with self.assertRaises(ValueError):Model(model.epoch,model.boot,model.nonce,model.order).acquire('client1','root').acquire('client1','agent')

    def test_identity_change_or_replay_never_advances(self):
        model=self.locked()
        self.assertTrue(model.advance('intent','f'*32,model.boot,model.nonce).unknown)
        self.assertTrue(model.advance('intent',model.epoch,'c'*36,model.nonce).unknown)
        self.assertTrue(model.advance('receive',model.epoch,model.boot,model.nonce).unknown)
        model=model.advance('intent',model.epoch,model.boot,model.nonce)
        self.assertTrue(model.advance('intent',model.epoch,model.boot,model.nonce).unknown)

    def test_missing_locks_and_reversed_hypothesis_cannot_advance(self):
        for order in (('agent','root'),('root','agent')):
            model=Model('e'*32,'b'*36,'0'*15+'1'+'a'*16,order)
            self.assertTrue(model.advance('intent',model.epoch,model.boot,model.nonce).unknown)
            model=model.acquire('client1',order[0]).acquire('client1',order[1])
            self.assertFalse(model.advance('intent',model.epoch,model.boot,model.nonce).unknown)

    def test_reboot_or_supersession_after_root_commit_prevents_submission(self):
        model=self.locked()
        for action in ('intent','receive'):
            model=model.advance(action,model.epoch,model.boot,model.nonce)
        reboot=model.advance('submit',model.epoch,'c'*36,model.nonce)
        self.assertTrue(reboot.unknown)
        self.assertFalse(reboot.may_effect())
        superseded=model.supersede()
        self.assertTrue(superseded.advance('submit',model.epoch,model.boot,model.nonce).unknown)
        self.assertFalse(superseded.may_effect())

if __name__=='__main__':unittest.main()
