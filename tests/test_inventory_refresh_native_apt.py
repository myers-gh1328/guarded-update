"""Regression for sequential negative cases in the disposable native proof."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_refresh_apt', ROOT/'tests/native_inventory_refresh_apt.py')
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


class NativeRefreshFixtureTests(unittest.TestCase):
    def test_fault_probe_requires_a_live_matching_nonroot_kernel_identity(self):
        valid=('Uid:\t60001\t60001\t60001\t60001\n'
               'Gid:\t60001\t60001\t60001\t60001\nGroups:\t\n'
               'CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n'
               'CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n'
               'CapAmb:\t0000000000000000\nNoNewPrivs:\t1\nState:\tS (sleeping)\n').encode()
        self.assertTrue(native.is_live_worker(valid))
        self.assertFalse(native.is_live_worker(valid.replace(b'60001\n',b'0\n',1)))
        self.assertFalse(native.is_live_worker(valid.replace(b'S (sleeping)',b'Z (zombie)')))
        self.assertFalse(native.is_live_worker(b'Uid: 60001'))

    def test_multiple_rejected_workers_do_not_reuse_a_retained_failed_unit(self):
        # systemd retains failed transient units by default. Stopping the unit and
        # proving an empty cgroup does not grant reuse of that retained name.
        retained = False
        def launch(arguments, **_):
            nonlocal retained
            if retained:
                return SimpleNamespace(returncode=1, stderr=b'Unit fixed.service already exists.')
            retained = '--collect' not in arguments
            return SimpleNamespace(returncode=75, stderr=b'')
        with TemporaryDirectory() as directory:
            root = Path(directory)
            cache, policy, runtime = root/'cache', root/'policy', root/'runtime'
            cache.mkdir(); (policy/'apt').mkdir(parents=True); runtime.mkdir()
            with patch.multiple(native, CACHE_ROOT=str(cache), POLICY_ROOT=str(policy), RUNTIME_ROOT=str(runtime)), \
                 patch.object(native, 'empty_worker') as empty, \
                 patch.object(native, 'render_policy', return_value={'apt.conf': b'synthetic'}), \
                 patch.object(native, 'policy_generation', return_value='a'*64), \
                 patch.object(native, 'write_root'), patch.object(native.os, 'chown'), \
                 patch.object(native.time, 'CLOCK_BOOTTIME', 7, create=True), \
                 patch.object(native.time, 'clock_gettime_ns', return_value=1000000000), \
                 patch.object(native.Path, 'read_text', return_value='00000000-0000-4000-8000-000000000001'), \
                 patch.object(native.subprocess, 'run', side_effect=launch):
                self.assertEqual(native.run_worker(object(), 2)[0], 75)
                self.assertEqual(native.run_worker(object(), 3)[0], 75)
                self.assertEqual(empty.call_count, 4)


if __name__ == '__main__':
    unittest.main()
