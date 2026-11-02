"""Proof-harness control tests; no root access or host package files are used."""
import errno
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('native_inventory_refresh_observation',ROOT/'tests/native_inventory_refresh_observation.py')
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class NativeObservationHarnessTests(unittest.TestCase):
    def test_readonly_proof_never_treats_writable_probe_denial_as_writer_exclusion(self):
        boot='11111111-1111-4111-8111-111111111111'
        nonce='0000000000000001'+'a'*16
        lease={'nonce':nonce,'boot_id':boot,'cache_generation':'b'*32,'policy_generation':'c'*64,
               'lock_open_boottime_ms':101,'expires_boottime_ms':120100}
        receipt={**lease,'lock_held_until_boottime_ms':102,'released_boottime_ms':103,
                 'outcome':'released','installed_before_sha256':'d'*64,'installed_after_sha256':'d'*64}
        class Guard:
            def close(self):
                pass
        class Observation:
            def lease(self):
                return lease.copy()
            def finish(self, incoming):
                assert incoming==nonce
                return receipt.copy()
            def abort(self):
                pass
        with (patch.object(p.sys,'platform','linux'),patch.object(p.os,'geteuid',return_value=0),
              patch.dict(p.os.environ,{'GITHUB_ACTIONS':'true','GUARDED_UPDATE_NATIVE_READONLY_PROOF':'1'}),
              patch('builtins.open',return_value=io.StringIO(boot)),
              patch.object(p.time,'CLOCK_BOOTTIME',7,create=True),
              patch.object(p.time,'clock_gettime_ns',return_value=100000000),
              patch.object(p,'prepare_fixed_executor_guard'),patch.object(p.NativeReadLocks,'fixed',return_value=Guard()),
              patch.object(p.os,'open',side_effect=OSError(errno.EROFS,'synthetic readonly')),
              patch.object(p.Observation,'begin',return_value=Observation()),
              patch.object(p,'attempt',side_effect=AssertionError('Writer probe cannot run in readonly namespace')) as probes):
            proof=p.main()
        self.assertTrue(proof['read_only_filesystem_verified'])
        self.assertFalse(proof['native_package_writer_exclusion'])
        self.assertFalse(proof['actual_executor_guard_exclusion'])
        self.assertEqual(proof['receipt'],receipt)
        probes.assert_not_called()


if __name__=='__main__':
    unittest.main()
