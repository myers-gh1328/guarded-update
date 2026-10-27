"""Pure protocol fixtures: no filesystem, process execution, network or privilege."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def protocol():
    spec = importlib.util.spec_from_file_location('inventory_refresh_protocol', ROOT/'scripts/inventory_refresh_protocol.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class InventoryRefreshProtocolTests(unittest.TestCase):
    def setUp(self):
        self.p = protocol()
        self.nonce = '0000000000000001' + 'a'*16

    def test_correlator_is_strict_and_counter_bounded(self):
        self.assertEqual(self.p.correlator(self.nonce.encode()), (self.nonce, 1))
        self.assertEqual(self.p.correlator((self.nonce+'\n').encode()), (self.nonce, 1))
        for malformed in [self.nonce.upper(), self.nonce+'\n\n', self.nonce+'\r\n',
                          ' '+self.nonce, '0'*32, '0020000000000000'+'a'*16, '../request']:
            with self.subTest(value=malformed), self.assertRaises(ValueError):
                self.p.correlator(malformed.encode())
        with self.assertRaises(ValueError):
            self.p.correlator(b'\xff'*32)

    def test_bounded_replay_state_never_restarts_retired_operations(self):
        state = self.p.OperationState(high_water=2, active='0000000000000002'+'b'*16,
                                      terminal=self.nonce)
        self.assertEqual(state.admit(self.nonce), 'existing')
        self.assertEqual(state.admit('0000000000000002'+'b'*16), 'existing')
        self.assertEqual(state.admit('0000000000000003'+'c'*16), 'busy')
        state = self.p.OperationState(high_water=4, active=None,
                                      terminal='0000000000000004'+'d'*16)
        self.assertEqual(state.admit(self.nonce), 'stale')
        self.assertEqual(state.admit('0000000000000004'+'e'*16), 'stale')
        self.assertEqual(state.admit('0000000000000005'+'f'*16), 'new')

    def test_policy_commitment_is_keyed_framed_and_covers_private_auth(self):
        fields = {name: b'synthetic' for name in self.p.POLICY_SECTIONS}
        key = b'k'*32
        digest = self.p.policy_commitment(key, fields)
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, self.p.policy_commitment(key, dict(reversed(list(fields.items())))))
        changed = dict(fields, auth=b'synthetic-other')
        self.assertNotEqual(digest, self.p.policy_commitment(key, changed))
        self.assertNotEqual(digest, self.p.policy_commitment(b'x'*32, fields))
        with self.assertRaises(ValueError):
            self.p.policy_commitment(b'short', fields)
        with self.assertRaises(ValueError):
            self.p.policy_commitment(key, dict(fields, command=b'not-policy'))
        changed = dict(fields, sources=b'ab', trust=b'c')
        other = dict(fields, sources=b'a', trust=b'bc')
        self.assertNotEqual(self.p.policy_commitment(key, changed), self.p.policy_commitment(key, other))

    def test_request_cannot_claim_helper_started_before_its_acceptance(self):
        attempt = {'correlator': self.nonce, 'helper_sequence': 1,
                   'boot_id': '11111111-1111-4111-8111-111111111111',
                   'accepted_boottime_ms': 90, 'started_boottime_ms': 100,
                   'finished_boottime_ms': 200}
        self.assertTrue(self.p.post_acceptance_attempt(attempt, self.nonce, attempt['boot_id'], 95))
        self.assertFalse(self.p.post_acceptance_attempt(attempt, self.nonce, attempt['boot_id'], 101))
        self.assertFalse(self.p.post_acceptance_attempt(attempt, '0000000000000002'+'b'*16,
                                                      attempt['boot_id'], 95))
        self.assertFalse(self.p.post_acceptance_attempt(attempt, self.nonce,
                                                      '22222222-2222-4222-8222-222222222222', 95))
        for value in [None, True, -1, 2**53]:
            with self.subTest(start=value):
                invalid = dict(attempt, started_boottime_ms=value)
                self.assertFalse(self.p.post_acceptance_attempt(invalid, self.nonce, attempt['boot_id'], 95))


if __name__ == '__main__':
    unittest.main()
