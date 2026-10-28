"""Noncredential generation-bound reader policy and actual descriptor publication."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_inventory_refresh_policy import fixture
import inventory_refresh_policy as policy
import inventory_refresh_storage as storage
from inventory_refresh_policy_admission import PolicyGuard
from inventory_refresh_storage import ReaderProjection


class ReaderPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy=policy.parse_policy(json.dumps(fixture()).encode());self.generation='b'*32
        self.commitment=policy.policy_generation(b'k'*32,self.policy)
    def projection(self):return policy.render_reader_policy(self.policy,self.generation,self.commitment)
    def test_exact_generation_policy_arch_sources_and_pins_without_credentials(self):
        projection=self.projection();self.assertIs(type(projection),ReaderProjection)
        self.assertEqual(projection.cache_generation,self.generation);self.assertEqual(projection.policy_generation,self.commitment)
        files=dict(projection.files);config=files['apt.conf'].decode();root='/var/cache/command-center-inventory-refresh/generation-'+self.generation
        self.assertIn('Dir::State::lists "'+root+'";',config)
        self.assertIn('Dir::State::status "/var/lib/dpkg/status";',config)
        self.assertIn('Dir::Etc::parts "'+root+'/_inventory-reader/empty.d";',config)
        self.assertIn('Dir::Etc::main "'+root+'/_inventory-reader/empty-main.conf";',config)
        self.assertIn('#clear Binary;',config);self.assertIn('APT::Architecture "armhf";',config)
        self.assertIn('Dir::Cache::pkgcache "";',config);self.assertIn('Dir::Cache::srcpkgcache "";',config)
        self.assertNotIn('/etc/apt/',config);self.assertNotIn('/var/lib/apt/',config)
        self.assertEqual(files['sources.sources'],dict(self.policy._files)['sources.sources'])
        self.assertEqual(files['preferences'],dict(self.policy._files)['preferences'])
        for secret in (b'synthetic-private-value',b'synthetic-user',b'password ',b'Proxy '):
            self.assertNotIn(secret,b''.join(files.values()))
        self.assertNotIn('synthetic-private-value',repr(projection))
        with self.assertRaises(AttributeError):projection.cache_generation='c'*32
    def test_auth_and_proxy_change_private_commitment_without_disclosing_values(self):
        baseline=dict(self.projection().files)
        for field in ('auth','proxy'):
            value=fixture()
            if field=='auth':value['auth'][0]['password']='different-secret'
            else:value['proxy']['https']='https://proxy.invalid/'
            admitted=policy.parse_policy(json.dumps(value).encode());commitment=policy.policy_generation(b'k'*32,admitted)
            self.assertNotEqual(commitment,self.commitment)
            projected=policy.render_reader_policy(admitted,self.generation,commitment)
            self.assertEqual(dict(projected.files),baseline)
    def test_template_is_committed_statically_and_frozen_in_admitted_policy(self):
        before=dict(self.projection().files)
        with patch.object(policy,'_READER_CONFIG_TEMPLATE',policy._READER_CONFIG_TEMPLATE+'\n# changed-reader-template\n'):
            admitted=policy.parse_policy(json.dumps(fixture()).encode())
            self.assertNotEqual(policy.policy_generation(b'k'*32,admitted),self.commitment)
            self.assertEqual(dict(self.projection().files),before)
            self.assertIn(b'changed-reader-template',dict(policy.render_reader_policy(admitted,self.generation,policy.policy_generation(b'k'*32,admitted)).files)['apt.conf'])
    def test_no_caller_paths_or_unbound_projection_shapes(self):
        for token in ('../reader','a'*31,'A'*32,'a'*32+'\n'):
            with self.assertRaises(ValueError):policy.render_reader_policy(self.policy,token,self.commitment)
        for commitment in ('', 'a'*63, 'A'*64):
            with self.assertRaises(ValueError):policy.render_reader_policy(self.policy,self.generation,commitment)
        with self.assertRaises(TypeError):ReaderProjection()


class ReaderPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        self.store=storage.Store(self.fd,os.getuid(),os.getgid(),os.getuid())
        self.policy=policy.parse_policy(json.dumps(fixture()).encode());self.commitment=policy.policy_generation(b'k'*32,self.policy)
        self.stage='a'*32;self.generation='b'*32
        self.directory=self.root/('staging-'+self.stage)/'lists';self.directory.mkdir(parents=True)
        (self.directory/'synthetic_Packages').write_bytes(b'synthetic metadata')
    def tearDown(self):os.close(self.fd);self.temp.cleanup()
    def projection(self,gen=None,commitment=None):return policy.render_reader_policy(self.policy,gen or self.generation,commitment or self.commitment)
    def publish(self,projection):return self.store.publish(self.stage,self.generation,self.commitment,'2026-10-28T00:00:00Z',reader_projection=projection)
    def test_root_reader_files_are_immutable_manifest_bound_and_same_generation(self):
        projection=self.projection();manifest=self.publish(projection)
        with self.store.lease_current() as lease:
            self.assertEqual(lease.manifest,manifest)
            for name,data in projection.files:
                relative=storage.READER_DIRECTORY+'/'+name;self.assertEqual(lease.read_index(relative),data)
                path=self.root/('generation-'+self.generation)/relative;info=path.stat()
                self.assertEqual(info.st_uid,os.getuid());self.assertEqual(info.st_gid,os.getgid());self.assertEqual(info.st_mode&0o777,0o440)
            reader=self.root/('generation-'+self.generation)/storage.READER_DIRECTORY
            self.assertEqual(reader.stat().st_mode&0o777,0o550);self.assertEqual(list((reader/'empty.d').iterdir()),[])
    def test_cross_generation_cross_policy_and_raw_dict_rejected_before_seal(self):
        before=(self.directory/'synthetic_Packages').stat().st_mode
        for projection in (self.projection(gen='c'*32),self.projection(commitment='d'*64),{}):
            with self.assertRaises(ValueError):self.publish(projection)
            self.assertFalse((self.root/'current.json').exists());self.assertEqual((self.directory/'synthetic_Packages').stat().st_mode,before)
    def test_worker_supplied_reserved_directory_is_not_repurposed(self):
        reserved=self.directory/storage.READER_DIRECTORY;reserved.mkdir();(reserved/'apt.conf').write_bytes(b'worker controlled')
        with self.assertRaises(ValueError):self.publish(self.projection())
        self.assertEqual((reserved/'apt.conf').read_bytes(),b'worker controlled');self.assertFalse((self.root/'current.json').exists())
    def test_projection_counts_inside_existing_generation_bounds(self):
        with patch.object(storage,'MAX_FILES',3):
            with self.assertRaises(ValueError):self.publish(self.projection())
        self.assertFalse((self.root/'current.json').exists())
    def test_projection_payload_counts_inside_existing_byte_limit(self):
        size=len((self.directory/'synthetic_Packages').read_bytes())
        with patch.object(storage,'MAX_GENERATION',size+1):
            with self.assertRaises(ValueError):self.publish(self.projection())
        self.assertFalse((self.root/'current.json').exists())

    def test_guard_renders_only_its_current_admitted_commitment(self):
        root=self.root/'policy';root.mkdir(mode=0o700)
        for name,data in [('policy.json',json.dumps(fixture()).encode()),('policy-commitment.key',b'k'*32)]:
            path=root/name;path.write_bytes(data);path.chmod(0o600)
        fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
        try:
            with PolicyGuard(fd,owner=os.getuid(),group=os.getgid()) as guard:
                projection=guard.reader_projection(self.generation)
                self.assertEqual(projection.policy_generation,guard.generation)
                self.publish(projection)
        finally:os.close(fd)


if __name__=='__main__':unittest.main()
