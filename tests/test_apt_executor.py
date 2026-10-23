"""Synthetic adapter tests: no real APT, dpkg or endpoint changes."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'scripts' / 'apt_executor.py'
SPEC = importlib.util.spec_from_file_location('apt_executor', SOURCE)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class ExecutorTests(unittest.TestCase):
    def test_signed_date_bounds_metadata_without_valid_until(self):
        now = 1792700000
        with patch.object(helper.Path, 'glob', return_value=[Path('/synthetic/InRelease')]), patch.object(helper, 'checked', return_value=b'Date: Thu, 01 Oct 2026 11:51:57 UTC\n'):
            with self.assertRaisesRegex(ValueError, 'expired'):
                helper.expiry(now)
        with patch.object(helper.Path, 'glob', return_value=[Path('/synthetic/InRelease')]), patch.object(helper, 'checked', return_value=b'Origin: synthetic\n'):
            with self.assertRaisesRegex(ValueError, 'Date'):
                helper.expiry(now)

    def test_authentication_and_freshness_overrides_are_rejected(self):
        settings = ['deb [trusted=yes] https://fixture.invalid stable main',
                    'Trusted: yes', 'Trusted:\n yes', 'Allow-Insecure: true',
                    'allow-weak=1', 'allow-downgrade-to-insecure=yes',
                    'Check-Valid-Until: no', 'check-date=false']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.sources'
            path.touch()
            for setting in settings:
                with self.subTest(setting=setting), patch.object(helper, 'checked', return_value=setting.encode()):
                    with self.assertRaisesRegex(ValueError, 'bypass'):
                        helper.ensure_authenticated_sources([path])
            with patch.object(helper, 'checked', return_value=b'Types: deb\nURIs: https://fixture.invalid\nSigned-By: /usr/share/keyrings/fixture.gpg\n# trusted=yes\n'):
                helper.ensure_authenticated_sources([path])

    def test_small_batch_marks_only_selected_packages_and_includes_dependencies(self):
        selected = Mock(candidate=object(), is_upgradable=True, marked_delete=False)
        unrelated = Mock(candidate=object(), is_upgradable=True, marked_delete=False)
        dependency = Mock(candidate=object(), is_upgradable=False, marked_delete=False)
        class Cache(dict):
            def get_changes(self):
                return [selected, dependency]
        cache = Cache(selected=selected, unrelated=unrelated)
        self.assertEqual(helper.select_changes(cache, ['selected']), [selected, dependency])
        selected.mark_install.assert_called_once()
        unrelated.mark_install.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'no upgrade'):
            helper.select_changes(cache, ['missing'])
        dependency.marked_delete = True
        with self.assertRaisesRegex(ValueError, 'removals'):
            helper.select_changes(cache, ['selected'])

    def test_a_previous_execution_attempt_prevents_any_subprocess(self):
        for marker in ('execution-attempted.json', 'execution-started.json'):
            with tempfile.TemporaryDirectory() as directory:
                (Path(directory) / marker).write_text('{}')
                with patch.object(helper, 'command') as command:
                    with self.assertRaisesRegex(ValueError, 'reconciliation'):
                        helper.execute({'state_dir': directory}, Path('/etc/fixture.json'))
                    command.assert_not_called()

    def test_response_must_match_request_and_cannot_follow_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {'broker_dir': directory, 'responses_dir': directory}
            identity = 'a' * 32
            request_path = Path(directory) / (identity + '.json')
            # Use separate dirs because the queue entry is removed after the wait.
            response_dir = Path(directory) / 'responses'
            response_dir.mkdir()
            config['responses_dir'] = str(response_dir)
            request_path.write_text('{}')
            response_path = response_dir / (identity + '.json')
            response_path.write_text(json.dumps({'schema_version': 1, 'request_id': 'b' * 32, 'http_status': 200, 'body': {}}))
            with self.assertRaisesRegex(ValueError, 'rejected'):
                helper.response(config, identity)
            self.assertFalse(request_path.exists())
            response_path.unlink()
            secret = response_dir / 'other'
            secret.write_text('{}')
            response_path.symlink_to(secret)
            with self.assertRaises(OSError):
                helper.response(config, identity)

    def test_expired_wait_removes_only_its_queue_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = 'a' * 32
            target = Path(directory) / (identity + '.json')
            other = Path(directory) / ('b' * 32 + '.json')
            target.write_text('{}')
            other.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                helper.response({'broker_dir': directory, 'responses_dir': directory}, identity, timeout=0)
            self.assertFalse(target.exists())
            self.assertTrue(other.exists())

    def test_archive_identity_and_digest_come_from_content(self):
        fields = b'Package: actual-package\nVersion: 2:1.0-1\nArchitecture: arm64\nMulti-Arch: same\n'
        with patch.object(helper, 'checked', return_value=b'actual archive bytes'), patch.object(helper, 'command', return_value=fields):
            result = helper.inspect_archive(Path('/root/archives/misleading-name.deb'))
        self.assertEqual(result['package'], 'actual-package')
        self.assertEqual(result['version']['version'], '2:1.0-1')
        self.assertEqual(result['sha256'], helper.sha(b'actual archive bytes'))
        self.assertNotEqual(result['sha256'], helper.sha(b'tampered archive bytes'))


    def test_reconciliation_preserves_a_durable_terminal_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            manifest = {'changes': [{'package': 'fixture', 'new': {'version': '2', 'architecture': 'arm64'}}]}
            stored = {'manifest.json': json.dumps(manifest).encode(),
                      'execution-started.json': b'{"claim_id":"fixture-claim"}',
                      'execution-result.json': json.dumps({'status': 'interrupted', 'manifest_sha256': helper.sha(json.dumps(manifest).encode())}).encode()}
            (state / 'execution-result.json').write_bytes(stored['execution-result.json'])
            with patch.object(helper, 'checked', side_effect=lambda path, **kwargs: stored[Path(path).name]), patch.object(helper, 'package_hash', return_value='state-hash'), patch.object(helper.subprocess, 'run', return_value=Mock(returncode=1)), patch.object(helper, 'command', return_value=b'ii \t2\tarm64\n'), patch.object(helper, 'write_new'), patch.object(helper, 'request') as request:
                helper.reconcile({'state_dir': directory})
                self.assertEqual(request.call_args.args[2]['status'], 'interrupted')



    def test_repository_metadata_without_authenticated_expiry_stays_unknown(self):
        root = Mock()
        root.glob.side_effect = [[Path('/var/lib/apt/lists/fixture_InRelease')], []]
        with patch.object(helper, 'Path', return_value=root), patch.object(helper, 'checked', return_value=b'Date: Mon, 01 Jan 2024 00:00:00 UTC\n'):
            with self.assertRaises(ValueError):
                helper.expiry(2_000_000_000)



if __name__ == '__main__':
    unittest.main()
