"""Pure trusted-policy fixtures. No native APT, I/O, provisioning or commands."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))


def module():
    spec = importlib.util.spec_from_file_location('inventory_refresh_policy', SCRIPTS/'inventory_refresh_policy.py')
    value = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = value
    spec.loader.exec_module(value)
    return value


def fixture():
    # Structure-only public packet/certificate fixtures: native crypto validation
    # is intentionally not represented by these pure parser tests.
    public_packets = b'\xc6\x06\x04\0\0\0\0\x01\xcd\x04test'
    ca = b'-----BEGIN CERTIFICATE-----\nMAcwADAAAwEA\n-----END CERTIFICATE-----\n'
    return dict(schema_version=1, architectures=['armhf'],
                sources=[dict(id='debian', type='deb', uri='https://repo.invalid/debian',
                              suites=['trixie'], components=['main'], architectures=['armhf'], signed_by=['debian'])],
                trust=dict(keys=[dict(id='debian', format='gpg', content_base64=base64.b64encode(public_packets).decode())],
                           tls_ca_base64=base64.b64encode(ca).decode()),
                pins=[dict(package='*', match=dict(release=dict(n='trixie')), priority=500)],
                proxy=dict(http='DIRECT', https='DIRECT'),
                auth=[dict(machine='https://repo.invalid/debian', login='synthetic-user', password='synthetic-private-value')])


class TrustedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.p = module()

    def parse(self, value):
        return self.p.parse_policy(json.dumps(value).encode())

    def test_strict_policy_renders_isolated_early_configuration_and_only_reviewed_artifacts(self):
        policy = self.parse(fixture())
        files = self.p.render_policy(policy, 'a'*32)
        config = files['apt.conf'].decode()
        root = '/etc/command-center-inventory-refresh/apt'
        self.assertIn(f'Dir::Etc::parts "{root}/empty.d";', config)
        self.assertIn(f'Dir::Etc::main "{root}/empty-main.conf";', config)
        self.assertIn('/var/cache/command-center-inventory-refresh/staging-'+('a'*32)+'/lists', config)
        self.assertIn('APT::Sandbox::User "ccrefresh";', config)
        self.assertIn('APT::Update::Error-Mode "any";', config)
        self.assertIn('Acquire::https::Verify-Peer "true";', config)
        self.assertIn('Acquire::Check-Valid-Until "true";', config)
        self.assertIn('Dir::Bin::methods "/usr/lib/apt/methods";', config)
        self.assertIn(f'Acquire::https::CaInfo "{root}/ca-certificates.crt";', config)
        self.assertNotIn('/etc/apt/', config)
        self.assertNotIn('/var/lib/apt/', config)
        self.assertNotIn('/var/lib/dpkg/', config)
        self.assertIn('Signed-By: '+root+'/trust/debian.gpg', files['sources.sources'].decode())
        self.assertNotIn('synthetic-private-value', config)
        self.assertIn(b'password synthetic-private-value', files['auth.conf'])
        self.assertNotIn('synthetic-private-value', repr(policy))
        self.assertNotIn('synthetic-private-value', repr(files))
        self.assertNotIn('synthetic-private-value', repr(self.p))

    def test_unknown_fields_and_executable_policy_shapes_fail_closed_without_echoing_values(self):
        for change in [dict(options={'APT::Update::Post-Invoke':'synthetic-private-value'}),
                       dict(methods='/tmp/custom'), dict(proxy_command='synthetic-private-value'),
                       dict(schema_version=True),dict(schema_version='1')]:
            value=fixture();value.update(change)
            with self.subTest(change=list(change)), self.assertRaises(ValueError) as rejected:
                self.parse(value)
            self.assertNotIn('synthetic-private-value',str(rejected.exception))
        raw=json.dumps(fixture()).encode()
        with self.assertRaises(ValueError):self.p.parse_policy(raw[:-1]+b',"auth":[]}')
        for raw in [b'[]',b'null',b'\xff',b'{"auth":NaN}',b' '* (8*1024*1024+1)]:
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):self.p.parse_policy(raw)

    def test_hooks_custom_methods_unsafe_sources_and_source_options_are_not_imported(self):
        variants=[dict(uri='file:/tmp/repository'),dict(uri='mirror+http://repo.invalid'),
                  dict(uri='https://user:synthetic-private-value@repo.invalid'),
                  dict(uri='https://repo.invalid/?token=synthetic-private-value'),dict(type='deb-src'),
                  dict(options={'trusted':True}),dict(suites=['trixie\nTrusted: yes']),
                  dict(signed_by=['../../private-key']),dict(architectures=['unknown'])]
        for variant in variants:
            value=fixture();value['sources'][0].update(variant)
            with self.subTest(fields=list(variant)),self.assertRaises(ValueError) as rejected:self.parse(value)
            self.assertNotIn('synthetic-private-value',str(rejected.exception))
        for proxy in [dict(http='DIRECT',https='auto-detect:/bin/tool'),
                      dict(http='http://user:synthetic-private-value@proxy.invalid',https='DIRECT'),
                      dict(http='DIRECT',https='DIRECT',command='arbitrary')]:
            value=fixture();value['proxy']=proxy
            with self.assertRaises(ValueError):self.parse(value)

    def test_commitment_covers_exact_private_auth_trust_pins_arch_proxy_and_fixed_template(self):
        value=fixture();policy=self.parse(value);key=b'k'*32
        digest=self.p.policy_generation(key,policy)
        self.assertEqual(len(digest),64)
        self.assertEqual(digest,self.p.policy_generation(key,self.p.parse_policy(json.dumps(value,indent=2).encode())))
        for field in ['sources','auth','trust','pins','architectures','proxy']:
            changed=fixture()
            if field=='sources':changed['sources'][0]['suites']=['trixie-updates']
            if field=='auth':changed['auth'][0]['password']='another-private-value'
            if field=='trust':changed['trust']['keys'][0]['content_base64']=base64.b64encode(b'\xc6\x06\x04\0\0\0\0\x02').decode()
            if field=='pins':changed['pins'][0]['priority']=501
            if field=='architectures':changed['architectures'].append('arm64')
            if field=='proxy':changed['proxy']['https']='https://proxy.invalid:8443/'
            with self.subTest(field=field):self.assertNotEqual(digest,self.p.policy_generation(key,self.parse(changed)))
        self.assertNotEqual(digest,self.p.policy_generation(b'x'*32,policy))
        # Dynamic staging location is not repository-policy identity.
        self.assertNotEqual(self.p.render_policy(policy,'a'*32)['apt.conf'],self.p.render_policy(policy,'b'*32)['apt.conf'])
        self.assertEqual(digest,self.p.policy_generation(key,policy))
        for bad in [b'',b'k'*31,b'k'*33,'k'*32]:
            with self.assertRaises(ValueError):self.p.policy_generation(bad,policy)

    def test_public_trust_only_and_auth_cannot_escape_reviewed_tls_sources(self):
        for material in [b'\xc5\x01x',b'\xc8\x01x',b'\xc6\xe0x',b'not-openpgp']:
            value=fixture();value['trust']['keys'][0]['content_base64']=base64.b64encode(material).decode()
            with self.assertRaises(ValueError):self.parse(value)
        for ca in [b'-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----',b'not-a-certificate']:
            value=fixture();value['trust']['tls_ca_base64']=base64.b64encode(ca).decode()
            with self.assertRaises(ValueError):self.parse(value)
        for auth_change in [dict(machine='http://repo.invalid/debian'),dict(machine='https://elsewhere.invalid'),
                            dict(password='contains whitespace'),dict(password='x\nmachine attacker.invalid')]:
            value=fixture();value['auth'][0].update(auth_change)
            with self.assertRaises(ValueError):self.parse(value)
        for token in ['../staging','A'*32,'a'*31,'a'*33,'a'*32+'\n']:
            with self.assertRaises(ValueError):self.p.render_policy(self.parse(fixture()),token)

    def test_fixed_profile_is_committed_and_certificate_label_cannot_hide_private_key_der(self):
        policy=self.parse(fixture()); before=self.p.policy_generation(b'k'*32,policy)
        original=self.p.CACHE_ROOT
        try:
            self.p.CACHE_ROOT='/var/cache/synthetic-other-profile'
            changed=self.parse(fixture())
            self.assertNotEqual(before,self.p.policy_generation(b'k'*32,changed))
            self.assertIn(original.encode(),self.p.render_policy(policy,'a'*32)['apt.conf'])
            self.assertIn(self.p.CACHE_ROOT.encode(),self.p.render_policy(changed,'a'*32)['apt.conf'])
        finally:self.p.CACHE_ROOT=original
        value=fixture()
        value['trust']['tls_ca_base64']=base64.b64encode(b'-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n').decode()
        with self.assertRaises(ValueError):self.parse(value)

    def test_cleared_native_defaults_restore_binary_indexes_without_forcing_untrusted(self):
        files=self.p.render_policy(self.parse(fixture()),'a'*32)
        self.assertIn(b'Acquire::IndexTargets::deb::Packages::MetaKey "$(COMPONENT)/binary-$(ARCHITECTURE)/Packages";',files['apt.conf'])
        self.assertIn(b'Acquire::IndexTargets::deb::Packages::Optional "false";',files['apt.conf'])
        self.assertNotIn(b'Trusted:',files['sources.sources'])
        for flag in [b'Allow-Insecure: no',b'Allow-Weak: no',b'Allow-Downgrade-To-Insecure: no']:
            self.assertIn(flag,files['sources.sources'])

    def test_hostile_types_and_noncanonical_acquisition_names_are_static_errors(self):
        for name in fixture():
            for hostile in [None,True,12,[],{}]:
                value=fixture();value[name]=hostile
                if name in ('pins','auth') and hostile == []:continue
                with self.subTest(field=name,kind=type(hostile).__name__),self.assertRaises(ValueError) as rejected:self.parse(value)
                self.assertEqual(str(rejected.exception),'Unsupported trusted APT policy')
        value=fixture();value['sources'][0]['uri']='HTTPS://repo.invalid/debian'
        with self.assertRaises(ValueError):self.parse(value)
        packets=base64.b64decode(fixture()['trust']['keys'][0]['content_base64'])
        armor=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: Synthetic\n\n'+base64.b64encode(packets)+b'\n-----END PGP PUBLIC KEY BLOCK-----\n'
        value=fixture();value['trust']['keys'][0].update(format='asc',content_base64=base64.b64encode(armor).decode())
        rendered=self.p.render_policy(self.parse(value),'a'*32)
        self.assertEqual(rendered['trust/debian.asc'],armor)
        self.assertIn(b'/trust/debian.asc',rendered['sources.sources'])


if __name__ == '__main__':unittest.main()
