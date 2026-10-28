"""Synthetic materialized-policy byte binding; no APT or private endpoint data."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_inventory_refresh_policy import fixture
from inventory_refresh_policy import parse_policy,render_policy
from inventory_refresh_materialized_policy import MaterializedPolicy
import json

class MaterializedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.apt=self.root/'apt';self.runtime=self.root/'run'
        for path in (self.apt,self.runtime):path.mkdir(mode=0o750);path.chmod(0o750)
        self.rendered=render_policy(parse_policy(json.dumps(fixture()).encode()),'a'*32)
        for name,raw in self.rendered.items():
            target=self.runtime/'worker-apt.conf' if name=='apt.conf' else self.apt/name
            target.parent.mkdir(parents=True,exist_ok=True,mode=0o750)
            target.write_bytes(raw);target.chmod(0o640)
        (self.apt/'empty.d').mkdir(mode=0o550)
        self.fds=[os.open(path,os.O_RDONLY|os.O_DIRECTORY) for path in (self.apt,self.runtime)]
        self.guard=None

    def tearDown(self):
        if self.guard is not None:self.guard.close()
        for fd in self.fds:os.close(fd)
        self.temp.cleanup()

    def admit(self):
        self.guard=MaterializedPolicy(*self.fds,self.rendered,os.getgid(),owner=os.getuid());return self.guard

    def test_exact_all_artifacts_and_declared_config_hash_match(self):
        guard=self.admit();guard.recheck()
        guard.verify_config_hash(hashlib.sha256(self.rendered['apt.conf']).hexdigest())
        self.assertNotIn('synthetic-private-value',repr(guard))
        guard.close()
        for fd in self.fds:os.fstat(fd)
        with self.assertRaises(ValueError):guard.recheck()

    def test_coherently_stale_config_and_declared_hash_do_not_match_current_policy(self):
        stale=b'consistently-stale-config'
        (self.runtime/'worker-apt.conf').write_bytes(stale)
        with self.assertRaises(ValueError):
            guard=self.admit();guard.verify_config_hash(hashlib.sha256(stale).hexdigest())

    def test_wrong_declared_hash_cannot_claim_current_materialization(self):
        guard=self.admit()
        with self.assertRaises(ValueError):guard.verify_config_hash('f'*64)
        with self.assertRaises(ValueError):guard.recheck()

    def test_stale_auxiliary_artifacts_rejected_without_secret_error(self):
        for name in ('sources.sources','auth.conf','preferences','trust/debian.gpg'):
            target=self.apt/name;original=target.read_bytes()
            try:
                target.write_bytes(b'synthetic-private-value')
                with self.subTest(name=name),self.assertRaises(ValueError) as caught:self.admit()
                self.assertNotIn('synthetic-private-value',str(caught.exception))
            finally:target.write_bytes(original)

    def test_empty_parts_injection_and_add_remove_after_admission_rejected(self):
        guard=self.admit();directory=self.apt/'empty.d';directory.chmod(0o750)
        (directory/'injected.conf').write_bytes(b'synthetic-hook')
        (directory/'injected.conf').unlink();directory.chmod(0o550)
        with self.assertRaises(ValueError):guard.recheck()

    def test_nonempty_parts_stops_after_one_lazy_entry_and_closes_iterator(self):
        guard=self.admit()
        class Entries:
            count=0;closed=False
            def __enter__(self):return self
            def __exit__(self,*_):self.closed=True
            def __iter__(self):return self
            def __next__(self):
                self.count+=1
                if self.count>1:raise AssertionError('unbounded directory enumeration')
                return object()
        entries=Entries()
        with patch('os.scandir',return_value=entries):
            with self.assertRaises(ValueError):guard.recheck()
        self.assertEqual(entries.count,1);self.assertTrue(entries.closed)

    def test_atomic_same_content_replacement_poisoned_not_reattached(self):
        guard=self.admit();target=self.apt/'auth.conf';replacement=self.apt/'replacement'
        replacement.write_bytes(target.read_bytes());replacement.chmod(0o640);replacement.replace(target)
        with self.assertRaises(ValueError):guard.recheck()
        with self.assertRaises(ValueError):guard.verify_config_hash(hashlib.sha256(self.rendered['apt.conf']).hexdigest())

    def test_symlink_hardlink_or_group_write_rejected(self):
        target=self.apt/'auth.conf';raw=target.read_bytes();extra=self.apt/'extra'
        for kind in ('symlink','hardlink','writable'):
            target.unlink();target.write_bytes(raw);target.chmod(0o640)
            if extra.exists():extra.unlink()
            if kind=='symlink':target.rename(extra);target.symlink_to(extra)
            elif kind=='hardlink':os.link(target,extra)
            else:target.chmod(0o660)
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.admit()

    def test_nested_trust_directory_replaced_during_recheck_is_not_followed(self):
        guard=self.admit();original=os.read;changed=False
        old_key=(self.apt/'trust/debian.gpg').read_bytes()
        def read(fd,size):
            nonlocal changed
            raw=original(fd,size)
            if raw==old_key and not changed:
                changed=True;(self.apt/'trust').rename(self.apt/'old-trust')
                (self.apt/'trust').mkdir(mode=0o750)
                (self.apt/'trust/debian.gpg').write_bytes(b'synthetic-other-key')
                (self.apt/'trust/debian.gpg').chmod(0o640)
            return raw
        with patch('os.read',side_effect=read):
            with self.assertRaises(ValueError):guard.recheck()

    def test_earlier_reference_replaced_while_later_auth_is_read_rejected(self):
        original=os.read;changed=False;target=self.apt/'sources.sources'
        def read(fd,size):
            nonlocal changed
            raw=original(fd,size)
            if b'synthetic-private-value' in raw and not changed:
                changed=True;replacement=self.apt/'replacement'
                replacement.write_bytes(target.read_bytes());replacement.chmod(0o640);replacement.replace(target)
            return raw
        with patch('os.read',side_effect=read):
            with self.assertRaises(ValueError):self.admit()

if __name__=='__main__':unittest.main()
