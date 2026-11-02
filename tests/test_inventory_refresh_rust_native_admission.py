"""Unprivileged synthetic tests for Root fixture admission, no live staging."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from inventory_refresh_rust_native_admission import RunnerArtifact
import inventory_refresh_rust_native_admission as admission


class RunnerArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.out=self.root/'inventory-rust-parent';self.deps=self.out/'target/debug/deps';self.deps.mkdir(parents=True);self.out.chmod(0o700)
        self.name='command_center_inventory-0123456789abcdef';self.binary=self.deps/self.name;self.binary.write_bytes(b'fixture');self.binary.chmod(0o555)
        self.manifest={'schema_version':1,'source_commit':'a'*40,'tree':'b'*40,'binary_name':self.name,'binary_sha256':hashlib.sha256(b'fixture').hexdigest(),'binary_size':7}
        self.path=self.out/'manifest.json';self.write_manifest();self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.value=None
    def tearDown(self):
        if self.value is not None:self.value.close()
        os.close(self.fd);self.temp.cleanup()
    def write_manifest(self):self.path.write_bytes((json.dumps(self.manifest)+'\n').encode());self.path.chmod(0o600)
    def admit(self,owner=None,group=None,commit='a'*40,tree='b'*40):
        self.value=RunnerArtifact.from_root(self.fd,('inventory-rust-parent','target','debug','deps'),os.getuid() if owner is None else owner,os.getgid() if group is None else group,commit,tree,time.monotonic()+10)
        return self.value
    def test_valid_fixed_runner_manifest_opens_only_owned_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);out=root/'inventory-rust-parent';deps=out/'target/debug/deps';deps.mkdir(parents=True)
            out.chmod(0o700);name='command_center_inventory-0123456789abcdef';binary=deps/name;binary.write_bytes(b'fixture');binary.chmod(0o555)
            manifest={'schema_version':1,'source_commit':'a'*40,'tree':'b'*40,'binary_name':name,'binary_sha256':hashlib.sha256(b'fixture').hexdigest(),'binary_size':7}
            path=out/'manifest.json';path.write_bytes((json.dumps(manifest)+'\n').encode());path.chmod(0o600)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                value=RunnerArtifact.from_root(fd,('inventory-rust-parent','target','debug','deps'),os.getuid(),os.getgid(),'a'*40,'b'*40,time.monotonic()+10)
                self.assertEqual(value.name,name);self.assertEqual(value.size,7);value.close()
            finally:os.close(fd)

    def test_manifest_identity_shape_and_head_tree_are_strict(self):
        for field,bad in [('source_commit','d'*40),('tree','e'*40),('binary_name','../escape'),('binary_size',True),('binary_sha256','invalid')]:
            old=self.manifest[field];self.manifest[field]=bad;self.write_manifest()
            with self.assertRaises(ValueError,msg=field):self.admit()
            self.manifest[field]=old
        self.path.write_bytes(b'{"schema_version":1,"schema_version":1}\n');self.path.chmod(0o600)
        with self.assertRaises(ValueError):self.admit()
        self.write_manifest()
        with self.assertRaises(ValueError):self.admit(commit='d'*40)
        with self.assertRaises(ValueError):self.admit(tree='e'*40)
        with self.assertRaises(ValueError):self.admit(owner=os.getuid()+1)
        with self.assertRaises(ValueError):self.admit(group=os.getgid()+1)

    def test_symlink_hardlink_and_writable_files_are_rejected(self):
        self.path.chmod(0o666)
        with self.assertRaises(ValueError):self.admit()
        self.path.chmod(0o600);alias=self.out/'alias';os.link(self.path,alias)
        with self.assertRaises(ValueError):self.admit()
        alias.unlink();self.binary.chmod(0o775)
        with self.assertRaises(ValueError):self.admit()
        self.binary.chmod(0o555);target=self.deps/'original';self.binary.rename(target);self.binary.symlink_to(target)
        with self.assertRaises(ValueError):self.admit()

    def test_source_manifest_or_ancestor_replacement_invalidates_held_admission(self):
        value=self.admit();self.binary.chmod(0o755);self.binary.write_bytes(b'changed');self.binary.chmod(0o555)
        with self.assertRaises(ValueError):value.verify()
        value.close();self.value=None
        self.binary.chmod(0o755);self.binary.write_bytes(b'fixture');self.binary.chmod(0o555)
        value=self.admit();old=self.out/'old-manifest';self.path.rename(old);self.write_manifest()
        with self.assertRaises(ValueError):value.verify()
        value.close();self.value=None
        old.unlink();self.path.unlink();self.write_manifest();value=self.admit()
        moved=self.out/'old-target';(self.out/'target').rename(moved);(self.out/'target').symlink_to(moved,target_is_directory=True)
        with self.assertRaises(ValueError):value.verify()

    def test_close_failure_attempts_every_owned_descriptor_and_is_not_retried(self):
        value=self.admit();actual=os.close;seen=[]
        def uncertain(fd):
            seen.append(fd);actual(fd)
            if len(seen)==1:raise OSError('synthetic close failure')
        with patch.object(admission.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):value.close()
        self.assertEqual(len(seen),7)
        with self.assertRaises(ValueError):value.close()
        self.value=None
