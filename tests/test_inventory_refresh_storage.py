"""Descriptor publication fixtures; native cross-UID/cgroup proof belongs in CI."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def storage():
    spec = importlib.util.spec_from_file_location('inventory_refresh_storage', ROOT/'scripts/inventory_refresh_storage.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RefreshStorageTests(unittest.TestCase):
    def setUp(self):
        self.module = storage()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.store = self.module.Store(self.fd, os.getuid(), os.getgid(), os.getuid())
        self.stage = '1'*32
        self.generation = '2'*32
        self.policy = 'a'*64

    def tearDown(self):
        os.close(self.fd)
        self.temp.cleanup()

    def stage_lists(self, token=None):
        directory = self.root/('staging-'+(token or self.stage))/'lists'
        directory.mkdir(parents=True, mode=0o700)
        directory.parent.chmod(0o700)
        (directory/'synthetic_Packages').write_bytes(b'synthetic-package-index')
        return directory

    def publish(self, stage=None, generation=None):
        return self.store.publish(stage or self.stage, generation or self.generation,
                                  self.policy, '2026-01-01T00:00:00Z')

    def test_reader_leases_without_worker_identity_or_mutation_methods(self):
        self.stage_lists()
        self.publish()
        reader = self.module.CacheReader(self.fd, owner=os.getuid())
        with reader.lease_current() as lease:
            self.assertEqual(lease.read_index('synthetic_Packages'), b'synthetic-package-index')
        for method in ('publish', 'retire', '_new_file', '_seal', '_remove'):
            self.assertFalse(hasattr(reader, method), method)
        self.assertFalse(hasattr(reader, 'worker'))

    def test_reader_rejects_writable_cache_and_wrong_owner(self):
        with self.assertRaises(ValueError):
            self.module.CacheReader(self.fd, owner=os.getuid()+1)
        self.root.chmod(0o770)
        with self.assertRaises(ValueError):
            self.module.CacheReader(self.fd, owner=os.getuid())

    def test_publish_seals_exact_opened_index_objects_and_current_reference(self):
        self.stage_lists()
        self.publish()
        pointer = json.loads((self.root/'current.json').read_text())
        self.assertEqual(pointer['cache_generation'], self.generation)
        with self.store.lease_current() as lease:
            self.assertEqual(lease.manifest['policy_generation'], self.policy)
            self.assertEqual(lease.verify_index('synthetic_Packages')[0], 23)
            self.assertEqual(lease.read_index('synthetic_Packages'), b'synthetic-package-index')
        published = self.root/('generation-'+self.generation)
        self.assertEqual((published/'synthetic_Packages').stat().st_mode & 0o777, 0o440)
        self.assertFalse((self.root/('staging-'+self.stage)/'lists').exists())

    def test_native_apt_index_names_with_explicit_repository_ports_are_supported(self):
        directory = self.stage_lists()
        entry = "repo.invalid:8443_repo_dists_proof_main_binary-arm64_Packages.lz4"
        (directory/'synthetic_Packages').rename(directory/entry)
        self.publish()
        with self.store.lease_current() as lease:
            self.assertEqual(lease.read_index(entry), b'synthetic-package-index')
        for unsafe in ['../outside', '/outside', '..', '.', 'line\nfeed', 'back\\slash']:
            with self.subTest(entry=unsafe), self.assertRaises(ValueError):
                self.module.name(unsafe)

    def test_symlink_hardlink_and_special_files_cannot_be_published(self):
        for kind in ['symlink', 'hardlink', 'fifo']:
            with self.subTest(kind=kind):
                token = {'symlink':'3', 'hardlink':'4', 'fifo':'5'}[kind]*32
                directory = self.stage_lists(token)
                if kind == 'symlink':
                    (directory/'alias').symlink_to('synthetic_Packages')
                elif kind == 'hardlink':
                    os.link(directory/'synthetic_Packages', directory/'alias')
                else:
                    os.mkfifo(directory/'alias')
                with self.assertRaises(ValueError):
                    self.publish(token, token)
                self.assertFalse((self.root/'current.json').exists())

    def test_failed_new_generation_preserves_previous_current(self):
        self.stage_lists()
        self.publish()
        before = (self.root/'current.json').read_bytes()
        bad = self.stage_lists('6'*32)
        (bad/'alias').symlink_to('/does-not-exist')
        with self.assertRaises(ValueError):
            self.publish('6'*32, '7'*32)
        self.assertEqual((self.root/'current.json').read_bytes(), before)
        with self.store.lease_current() as lease:
            self.assertEqual(lease.read_index('synthetic_Packages'), b'synthetic-package-index')

    def test_current_and_leased_generations_are_never_retired(self):
        self.stage_lists()
        self.publish()
        self.assertFalse(self.store.retire(self.generation))
        with self.store.lease_current() as lease:
            self.stage_lists('8'*32)
            self.publish('8'*32, '9'*32)
            self.assertFalse(self.store.retire(self.generation))
            self.assertEqual(lease.read_index('synthetic_Packages'), b'synthetic-package-index')
        self.assertTrue(self.store.retire(self.generation))
        self.assertFalse((self.root/('generation-'+self.generation)).exists())
        self.assertFalse(self.store.retire('9'*32))


if __name__ == '__main__':
    unittest.main()
