"""Synthetic cache relocation and rejected-claim reporting regressions."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_apt_executor import helper


class RelocationTests(unittest.TestCase):
    def test_failure_category_is_useful_without_emitting_provider_details(self):
        self.assertEqual(helper.failure_category(ValueError('Executor prerequisite command failed: guarded-update')), 'validator_rejected')
        self.assertEqual(helper.failure_category(ValueError('https://fixture.invalid?token=private')), 'ValueError')

    def test_hook_verifies_the_archive_path_apt_will_actually_unpack(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            version = {'version': '2', 'architecture': 'armhf', 'multi_arch': 'none'}
            change = {'package': 'synthetic-package', 'new': version, 'archive_sha256': 'a'*64}
            manifest = {'proposal_id': 'b'*32, 'metadata_checked_at_unix': 1000, 'metadata_valid_until_unix': 2000, 'changes': [change]}
            raw = json.dumps(manifest).encode()
            cache = '/var/cache/apt/archives/synthetic-package_2_armhf.deb'
            stream = f'VERSION 3\n\nsynthetic-package 1 armhf none < 2 armhf none {cache}\nsynthetic-package 1 armhf none < 2 armhf none **CONFIGURE**\n'
            claim = {'claim_id': '12345678-1234-1234-1234-123456789abc', 'allow_service_restarts': True}
            archive = {'package': 'synthetic-package', 'version': version, 'sha256': 'a'*64}
            with patch.dict(helper.os.environ, {'APT_HOOK_INFO_FD': '0', 'DPKG_FRONTEND_LOCKED': 'true'}), patch.object(helper.sys, 'stdin', type('Input', (), {'buffer': io.BytesIO(stream.encode())})()), patch.object(helper, 'checked', return_value=raw), patch.object(helper, 'request', return_value='request'), patch.object(helper, 'response', return_value=claim), patch.object(helper, 'package_hash', return_value='state'), patch.object(helper, 'repository_hash', return_value='repo'), patch.object(helper, 'holds', return_value=[]), patch.object(helper, 'inspect_archive', return_value=archive) as inspect, patch.object(helper, 'write_new') as writes, patch.object(helper, 'command'):
                helper.hook({'device_id': 'synthetic-fixture', 'state_dir': directory, 'validator_binary': '/usr/bin/guarded-update', 'approval_public_key_file': '/etc/fixture-public.pem'})
                validation = next(json.loads(call.args[1]) for call in writes.call_args_list if Path(call.args[0]).name.startswith('validation-'))
                self.assertIn(cache, validation['archives'])
                self.assertIn(cache, [str(call.args[0]) for call in inspect.call_args_list])

    def test_a_claimed_but_rejected_attempt_reports_without_replaying(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            for name in ('execution-attempted.json', 'execution-result.json', 'execution-claimed.json'):
                (state/name).write_text('{}')
            with patch.object(helper, 'resend_result') as report, patch.object(helper, 'execute') as execute:
                helper.cycle({'state_dir': directory}, Path('/etc/fixture.json'))
                report.assert_called_once()
                execute.assert_not_called()

    def test_substituted_cache_bytes_are_rejected(self):
        approved = {'package': 'synthetic-package', 'new': {'version': '2', 'architecture': 'armhf', 'multi_arch': 'none'}, 'archive_sha256': 'a'*64}
        archive = {'package': approved['package'], 'version': approved['new'], 'sha256': 'f'*64}
        stream = 'VERSION 3\n\nsynthetic-package 1 armhf none < 2 armhf none /var/cache/apt/archives/synthetic.deb\n'
        with patch.object(helper, 'inspect_archive', return_value=archive):
            with self.assertRaisesRegex(ValueError, 'differs'):
                helper.transaction_archives({'state_dir': '/var/lib/fixture'}, {'changes': [approved]}, stream)

    def test_claim_correlation_alone_never_reports_success(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'execution-claimed.json').write_text('{}')
            with patch.object(helper, 'checked', return_value=b'{}'):
                with self.assertRaisesRegex(ValueError, 'cannot establish'):
                    helper.attempt_claim({'state_dir': directory}, 'succeeded')
