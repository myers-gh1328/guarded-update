"""Synthetic preparation delivery tests; no APT or endpoint mutations."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('executor', Path(__file__).resolve().parents[1]/'scripts/apt_executor.py')
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def job():
    return dict(schema_version=1, kind='apt-prepare', job_id='a'*32, device_id='fixture-device', fleet='business', proposal_id='a'*32, packages=['nano'], refresh_metadata=True, issued_at_unix=1000, expires_at_unix=4600, execution_allowed=False, allow_reboot=False)


def envelope(value):
    return {'payload_json': json.dumps(value), 'signature': 'ab'*70}


class PreparationTests(unittest.TestCase):
    def test_delivery_requires_both_signed_layers_and_matching_nonce(self):
        policy = dict(device_id='fixture-device', fleet='business', allowed_packages=['nano'], allow_metadata_refresh=True)
        inner = envelope(job())
        outer = dict(schema_version=1, kind='apt-preparation-delivery', device_id='fixture-device', poll_nonce='b'*32, issued_at_unix=1000, expires_at_unix=1120, job=inner)
        with patch.object(helper, 'verify_preparation_signature') as verify:
            self.assertEqual(helper.validate_preparation_delivery(policy, envelope(outer), 'b'*32, 1001)['job_id'], 'a'*32)
            self.assertEqual(verify.call_count, 2)
            with self.assertRaises(ValueError): helper.validate_preparation_delivery(policy, envelope(outer), 'c'*32, 1001)
            with self.assertRaises(ValueError): helper.validate_preparation_delivery(policy, inner, 'b'*32, 1001)

    def test_signed_job_cannot_widen_local_policy_or_execution_authority(self):
        policy = dict(device_id='fixture-device', fleet='business', allowed_packages=['nano'], allow_metadata_refresh=True)
        variants = [dict(execution_allowed=True), dict(allow_reboot=True), dict(packages=['curl']), dict(packages=['nano','nano']), dict(packages=['z','nano']), dict(packages=['nano:armhf']), dict(proposal_id='b'*32), dict(fleet='personal'), dict(issued_at_unix=True), dict(expires_at_unix=4601), dict(extra=True)]
        for change in variants:
            value = dict(job(), **change)
            outer = dict(schema_version=1, kind='apt-preparation-delivery', device_id='fixture-device', poll_nonce='b'*32, issued_at_unix=1000, expires_at_unix=1120, job=envelope(value))
            with self.subTest(change=change), patch.object(helper, 'verify_preparation_signature'):
                with self.assertRaises(ValueError): helper.validate_preparation_delivery(policy, envelope(outer), 'b'*32, 1001)

    def test_null_delivery_is_authenticated(self):
        outer = dict(schema_version=1, kind='apt-preparation-delivery', device_id='fixture-device', poll_nonce='b'*32, issued_at_unix=1000, expires_at_unix=1120, job=None)
        with patch.object(helper, 'verify_preparation_signature', side_effect=ValueError('bad signature')):
            with self.assertRaises(ValueError): helper.validate_preparation_delivery({}, envelope(outer), 'b'*32, 1001)

class DispatcherLifecycleTests(unittest.TestCase):
    def test_uncertain_execution_blocks_all_new_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root/('a'*32)
            state.mkdir()
            (state/'job.json').write_text(json.dumps(job()))
            (state/'executor.json').write_text(json.dumps({'state_dir':str(state)}))
            (state/'execution-attempted.json').write_text('{}')
            with patch.object(helper, 'checked', side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)), patch.object(helper, 'request') as request, patch.object(helper, 'cycle') as cycle:
                helper.dispatch_preparations({'state_dir':str(root)})
                request.assert_not_called()
                cycle.assert_called_once()

    def test_preparation_crash_is_reported_without_repeating_apt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root/('a'*32)
            state.mkdir()
            (state/'job.json').write_text(json.dumps(job()))
            (state/'executor.json').write_text(json.dumps({'state_dir':str(state)}))
            (state/'received-reported.json').write_text('{}')
            (state/'preparation-started.json').write_text('{}')
            with patch.object(helper, 'checked', side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)), patch.object(helper, 'request', return_value='request'), patch.object(helper, 'response', return_value={}), patch.object(helper, 'prepare') as prepare:
                helper.dispatch_preparations({'state_dir':str(root)})
                prepare.assert_not_called()
                failure = json.loads((state/'preparation-failed.json').read_text())
                self.assertEqual(failure['reason'], 'preparation_interrupted')

class RealSignatureTests(unittest.TestCase):
    def test_system_openssl_verifies_exact_payload_and_domain(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, public = root/'private.pem', root/'public.pem'
            subprocess.run(['/usr/bin/openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(private)], check=True, capture_output=True)
            subprocess.run(['/usr/bin/openssl', 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True, capture_output=True)
            payload = json.dumps(job())
            domain = 'guarded-update-preparation-v1'
            message = (domain+'\n'+helper.sha(payload.encode())).encode()
            signature = subprocess.run(['/usr/bin/openssl','dgst','-sha256','-sign',str(private)],input=message,check=True,capture_output=True).stdout.hex()
            signed = dict(payload_json=payload,signature=signature)
            policy = dict(approval_public_key_file=str(public),state_dir=str(root))
            with patch.object(helper, 'checked', side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)):
                helper.verify_preparation_signature(policy,signed,domain)
                with self.assertRaises(ValueError): helper.verify_preparation_signature(policy,dict(signed,payload_json=payload+' '),domain)
                with self.assertRaises(ValueError): helper.verify_preparation_signature(policy,signed,'guarded-update-execution-claim-v1')
                with self.assertRaises(ValueError): helper.verify_preparation_signature(policy,dict(signed,signature='00'*70),domain)

class RejectionTests(unittest.TestCase):
    def test_authenticated_policy_rejection_is_durable_and_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = dict(state_dir=directory, device_id='fixture-device', fleet='business', allowed_packages=['nano'], allow_metadata_refresh=True)
            selected = dict(job(), packages=['curl'])
            outer = dict(schema_version=1, kind='apt-preparation-delivery', device_id='fixture-device', poll_nonce='b'*32, issued_at_unix=1000, expires_at_unix=1120, job=envelope(selected))
            with patch.object(helper, 'checked', side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)), patch.object(helper, 'verify_preparation_signature'), patch.object(helper.secrets, 'token_hex', return_value='b'*32), patch.object(helper.time, 'time', return_value=1001), patch.object(helper, 'request', return_value='r') as request, patch.object(helper, 'response', side_effect=[envelope(outer),{}]), patch.object(helper, 'prepare') as prepare:
                helper.dispatch_preparations(policy)
                prepare.assert_not_called()
                self.assertEqual(request.call_args.args[1], 'preparation-status')
                self.assertEqual(request.call_args.args[2]['reason'], 'policy_rejected')
                self.assertTrue((Path(directory)/('a'*32)/'failure-reported.json').exists())

class RolloverTests(unittest.TestCase):
    def test_rejected_manifest_closes_without_attempting_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            manifest = json.dumps({'metadata_valid_until_unix':5000,'generated_at_unix':1000,'metadata_checked_at_unix':1000}).encode()
            for name,value in [('job.json',job()),('executor.json',{'state_dir':directory}),('manifest.json',json.loads(manifest)),('received-reported.json',{}),('manifest-reported.json',{})]:
                (state/name).write_text(json.dumps(value))
            raw = (state/'manifest.json').read_bytes()
            with patch.object(helper, 'checked', side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)), patch.object(helper.time,'time',return_value=1001), patch.object(helper,'request',return_value='r'), patch.object(helper,'response',return_value={'manifest_sha256':helper.sha(raw),'status':'rejected'}), patch.object(helper,'execute') as execute:
                helper.continue_preparation({},state)
                execute.assert_not_called()
                self.assertTrue((state/'controller-closed.json').exists())

class FreshnessTests(unittest.TestCase):
    def test_unpublished_stale_manifest_fails_instead_of_retrying_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            for name,value in [('job.json',job()),('executor.json',{'state_dir':directory}),('manifest.json',{'metadata_valid_until_unix':10000,'generated_at_unix':1000,'metadata_checked_at_unix':1000}),('received-reported.json',{})]:
                (state/name).write_text(json.dumps(value))
            with patch.object(helper, 'checked', side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)), patch.object(helper.time,'time',return_value=5000), patch.object(helper,'request',return_value='r') as request, patch.object(helper,'response',return_value={'schema_version':1,'proposal_id':'a'*32,'status':'not_found','manifest_sha256':None}):
                helper.continue_preparation({},state)
                self.assertEqual(request.call_args.args[1],'preparation-status')
                self.assertTrue((state/'failure-reported.json').exists())
                self.assertTrue((state/'manifest.json').exists())

class TimeoutTests(unittest.TestCase):
    def test_preparation_deadline_kills_subprocess_before_return(self):
        import subprocess
        import sys
        import time
        helper.PREPARATION_DEADLINE = time.monotonic() + 0.05
        try:
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                helper.command([sys.executable,'-I','-c','import time; time.sleep(5)'])
            self.assertLess(time.monotonic() - started, 2)
        finally:
            helper.PREPARATION_DEADLINE = None

class SharedContractTests(unittest.TestCase):
    def test_dcc_cross_language_fixture_and_tampering(self):
        fixture = json.loads((Path(__file__).parent/'fixtures/guarded-update-preparation-v1.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)/'public.pem'
            public.write_text(fixture['public_key'])
            policy = dict(device_id='fixture-pi',fleet='business',allowed_packages=['nano'],allow_metadata_refresh=True,state_dir=directory,approval_public_key_file=str(public))
            with patch.object(helper, 'checked', side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)):
                result = helper.validate_preparation_delivery(policy,fixture['delivery'],'b'*32,1001)
                self.assertEqual(result['packages'], ['nano'])
                with self.assertRaises(ValueError): helper.validate_preparation_delivery(policy,fixture['delivery'],'c'*32,1001)
                changed = dict(fixture['delivery'],payload_json=fixture['delivery']['payload_json'].replace('fixture-pi','fixture-other'))
                with self.assertRaises(ValueError): helper.validate_preparation_delivery(policy,changed,'b'*32,1001)
                with self.assertRaises(ValueError): helper.verify_preparation_signature(policy,dict(fixture['job'],payload_json=fixture['job']['payload_json']+' '),'guarded-update-preparation-v1')


class PublicationRecoveryTests(unittest.TestCase):
    def test_lost_publication_response_reconciles_known_expired_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            for name,value in [('job.json',job()),('executor.json',{'state_dir':directory}),('manifest.json',{'metadata_valid_until_unix':10000,'generated_at_unix':1000,'metadata_checked_at_unix':1000}),('received-reported.json',{})]:
                (state/name).write_text(json.dumps(value))
            digest = helper.sha((state/'manifest.json').read_bytes())
            with patch.object(helper, 'checked', side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)), patch.object(helper.time,'time',return_value=5000), patch.object(helper,'request',return_value='r') as request, patch.object(helper,'response',return_value={'schema_version':1,'proposal_id':'a'*32,'status':'expired','manifest_sha256':digest}), patch.object(helper,'execute') as execute:
                helper.continue_preparation({},state)
                self.assertEqual(request.call_args.args[1],'status')
                self.assertTrue(request.call_args.args[2]['allow_missing'])
                self.assertTrue((state/'controller-closed.json').exists())
                self.assertFalse((state/'preparation-failed.json').exists())
                execute.assert_not_called()

class OutputBudgetTests(unittest.TestCase):
    def test_dispatcher_rejects_excess_output_before_child_finishes(self):
        import sys
        import time
        helper.PREPARATION_DEADLINE = time.monotonic()+2
        try:
            started = time.monotonic()
            with patch.object(helper,'MAX',1), self.assertRaisesRegex(ValueError,'output exceeds'):
                helper.command([sys.executable,'-I','-c','import sys,time; sys.stdout.write("x"*100); sys.stdout.flush(); time.sleep(5)'])
            self.assertLess(time.monotonic()-started,1)
        finally:
            helper.PREPARATION_DEADLINE = None

class PolicyTighteningTests(unittest.TestCase):
    def test_prepared_job_cannot_execute_after_root_removes_selected_package(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            for name,value in [('job.json',job()),('executor.json',{'state_dir':directory}),('manifest.json',{'metadata_valid_until_unix':5000,'generated_at_unix':1000,'metadata_checked_at_unix':1000}),('received-reported.json',{}),('manifest-reported.json',{})]:
                (state/name).write_text(json.dumps(value))
            raw = (state/'manifest.json').read_bytes()
            with patch.object(helper, 'checked', side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)), patch.object(helper.time,'time',return_value=1001), patch.object(helper,'request',return_value='r'), patch.object(helper,'response',return_value={'manifest_sha256':helper.sha(raw),'status':'approved'}), patch.object(helper,'execute') as execute:
                with self.assertRaises(ValueError): helper.continue_preparation({'allowed_packages':['curl']},state)
                execute.assert_not_called()

class AcceptedJobTests(unittest.TestCase):
    def test_selection_prepares_immutable_config_then_waits_for_exact_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = dict(state_dir=directory,device_id='fixture-device',fleet='business',allowed_packages=['nano'],allow_metadata_refresh=True,broker_dir='/fixture/broker',responses_dir='/fixture/responses',approval_public_key_file='/fixture/public.pem',validator_binary='/fixture/validator')
            outer = dict(schema_version=1,kind='apt-preparation-delivery',device_id='fixture-device',poll_nonce='b'*32,issued_at_unix=1000,expires_at_unix=1120,job=envelope(job()))
            raw = helper.encode(dict(metadata_valid_until_unix=4600,generated_at_unix=1000,metadata_checked_at_unix=1000))
            def prepare(config):
                (Path(config['state_dir'])/'manifest.json').write_bytes(raw)
            with patch.object(helper,'checked',side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)), patch.object(helper,'verify_preparation_signature'), patch.object(helper.secrets,'token_hex',return_value='b'*32), patch.object(helper.time,'time',return_value=1001), patch.object(helper,'request',return_value='r') as request, patch.object(helper,'response',side_effect=[envelope(outer),{},{},{'status':'pending','manifest_sha256':helper.sha(raw)}]), patch.object(helper,'prepare',side_effect=prepare) as prepare_mock, patch.object(helper,'execute') as execute:
                helper.dispatch_preparations(policy)
                self.assertEqual([call.args[1] for call in request.call_args_list],['preparation-poll','preparation-status','manifest','status'])
                config = json.loads((root/('a'*32)/'executor.json').read_text())
                self.assertEqual(config['packages'],['nano'])
                self.assertEqual(config['proposal_id'],'a'*32)
                self.assertEqual(config['state_dir'],str(root/('a'*32)))
                prepare_mock.assert_called_once()
                execute.assert_not_called()
            with patch.object(helper,'checked',side_effect=lambda p, **kw: Path(p).read_bytes() if not kw.get('directory') else Path(p)), patch.object(helper.time,'time',return_value=1001), patch.object(helper,'request',return_value='r') as request, patch.object(helper,'response',return_value={'status':'pending','manifest_sha256':helper.sha(raw)}), patch.object(helper,'prepare') as prepare_mock:
                helper.dispatch_preparations(policy)
                self.assertEqual([call.args[1] for call in request.call_args_list],['status'])
                prepare_mock.assert_not_called()


if __name__ == '__main__': unittest.main()
