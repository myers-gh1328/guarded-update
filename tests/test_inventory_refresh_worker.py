"""Fixed low-privilege worker contract: no caller command or environment surface."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))


def module():
    spec = importlib.util.spec_from_file_location('inventory_refresh_worker', ROOT/'scripts/inventory_refresh_worker.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class RefreshWorkerTests(unittest.TestCase):
    def setUp(self):
        self.p = module()
        self.job = {'schema_version': 1, 'staging_token': 'a'*32, 'config_sha256': 'b'*64,
                    'policy_generation': 'c'*64, 'operation_nonce': '0000000000000001'+'d'*16,
                    'helper_sequence': 1, 'boot_id': '11111111-1111-4111-8111-111111111111',
                    'accepted_boottime_ms': 100, 'started_boottime_ms': 101}

    def test_job_admits_only_fixed_bounded_identifiers_and_exact_config_digest(self):
        self.assertEqual(self.p.parse_job(json.dumps(self.job).encode())['helper_sequence'], 1)
        for field, value in [('command', 'install'), ('path', '/elsewhere'), ('arguments', ['update'])]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.p.parse_job(json.dumps(dict(self.job, **{field: value})).encode())
        for field, value in [('staging_token', '../arbitrary'), ('helper_sequence', True),
                             ('boot_id', 'wrong'), ('started_boottime_ms', 99)]:
            changed = dict(self.job, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.p.parse_job(json.dumps(changed).encode())
        with self.assertRaises(ValueError):
            self.p.parse_job(b'{"schema_version":1,"schema_version":1}')

    def test_worker_environment_is_fixed_and_contains_no_inherited_secret_or_options(self):
        with patch.dict(os.environ, {'APT_CONFIG': '/untrusted', 'HTTP_PROXY': 'untrusted',
                                     'SYNTHETIC_SECRET': 'fixture'}, clear=False):
            env = self.p.worker_environment('a'*32)
        self.assertEqual(env['APT_CONFIG'], self.p.RUNTIME_ROOT+'/worker-apt.conf')
        self.assertNotIn('SYNTHETIC_SECRET', env)
        self.assertNotIn('HTTP_PROXY', env)
        self.assertTrue(env['TMPDIR'].startswith(self.p.CACHE_ROOT+'/staging-'+'a'*32+'/'))
        self.assertEqual(self.p.APT_COMMAND, ('/usr/bin/apt-get', 'update'))

    def test_worker_constants_match_the_committed_policy_template(self):
        import inventory_refresh_policy as policy
        for field in ['POLICY_ROOT', 'CACHE_ROOT', 'RUNTIME_ROOT', 'REFRESH_ACCOUNT']:
            self.assertEqual(getattr(self.p, field), getattr(policy, field))

    def test_missing_account_never_executes_apt_or_initializes_host_state(self):
        with patch.object(self.p.pwd, 'getpwnam', side_effect=KeyError), \
             patch.object(self.p.subprocess, 'run') as run:
            self.assertEqual(self.p.worker_main(), self.p.EXIT_UNSUPPORTED)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
