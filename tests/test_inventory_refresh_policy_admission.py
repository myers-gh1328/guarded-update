"""Synthetic private-policy descriptor admission; no real keys or native commands."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_inventory_refresh_policy import fixture
from inventory_refresh_policy import parse_policy,policy_generation,MAX_POLICY
from inventory_refresh_policy_admission import PolicyGuard

class PolicyAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.policy=self.root/'policy.json';self.key=self.root/'policy-commitment.key'
        self.policy.write_bytes(json.dumps(fixture()).encode());self.key.write_bytes(b'k'*32)
        for path in (self.policy,self.key):path.chmod(0o600)
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.guard=None

    def tearDown(self):
        if self.guard is not None:self.guard.close()
        os.close(self.fd);self.temp.cleanup()

    def admit(self):
        self.guard=PolicyGuard(self.fd,owner=os.getuid(),group=os.getgid());return self.guard

    def replace(self,path,raw):
        temporary=self.root/'replacement';temporary.write_bytes(raw);temporary.chmod(0o600);temporary.replace(path)

    def test_admits_fixed_pair_hmac_render_and_no_secret_repr(self):
        guard=self.admit();expected=policy_generation(b'k'*32,parse_policy(self.policy.read_bytes()))
        self.assertEqual(guard.generation,expected);guard.recheck()
        self.assertIn(b'password synthetic-private-value',guard.render('a'*32)['auth.conf'])
        self.assertNotIn('synthetic-private-value',repr(guard));self.assertNotIn('kkkk',repr(guard))

    def test_private_permissions_symlink_hardlink_and_short_key_rejected(self):
        for kind in ('group_read','group_write','symlink','hardlink','short'):
            with self.subTest(kind=kind):
                self.key.unlink();self.key.write_bytes(b'k'*32);self.key.chmod(0o600)
                extra=self.root/'extra'
                if extra.exists():extra.unlink()
                if kind=='group_read':self.key.chmod(0o640)
                elif kind=='group_write':self.key.chmod(0o620)
                elif kind=='symlink':self.key.rename(extra);self.key.symlink_to(extra)
                elif kind=='hardlink':os.link(self.key,extra)
                else:self.key.write_bytes(b'k'*31)
                with self.assertRaises(ValueError):self.admit()

    def test_first_input_metadata_failure_closes_just_opened_descriptor(self):
        real_open=os.open;real_stat=os.fstat;opened=[];failed=False
        def tracked_open(name,*args,**kwargs):
            fd=real_open(name,*args,**kwargs)
            if name=='policy.json':opened.append(fd)
            return fd
        def metadata(fd):
            nonlocal failed
            if opened and fd==opened[-1] and not failed:
                failed=True;raise OSError('synthetic-private-value')
            return real_stat(fd)
        with patch('os.open',side_effect=tracked_open),patch('os.fstat',side_effect=metadata):
            with self.assertRaises(ValueError) as caught:self.admit()
        self.assertNotIn('synthetic-private-value',str(caught.exception))
        self.assertEqual(len(opened),1)
        try:
            with self.assertRaises(OSError):real_stat(opened[0])
        finally:
            try:os.close(opened[0])
            except OSError:pass

    def test_read_only_private_modes_are_valid(self):
        self.policy.chmod(0o400);self.key.chmod(0o400)
        self.admit().recheck()

    def test_oversize_policy_rejected_before_any_input_read(self):
        os.truncate(self.policy,MAX_POLICY+1)
        with patch('os.read') as read:
            with self.assertRaises(ValueError):self.admit()
            read.assert_not_called()

    def test_nonregular_policy_rejected_without_reading(self):
        self.policy.unlink();self.policy.mkdir(mode=0o700)
        with patch('os.read') as read:
            with self.assertRaises(ValueError):self.admit()
            read.assert_not_called()

    def test_foreign_owner_or_group_rejected(self):
        for owner,group in ((os.getuid()+1,os.getgid()),(os.getuid(),os.getgid()+1)):
            with self.assertRaises(ValueError):PolicyGuard(self.fd,owner=owner,group=group)

    def test_named_policy_replaced_while_key_is_read_rejects_mixed_pair(self):
        original=os.read;changed=False
        def read(fd,size):
            nonlocal changed
            raw=original(fd,size)
            if raw==b'k'*32 and not changed:
                changed=True;self.replace(self.policy,self.policy.read_bytes())
            return raw
        with patch('os.read',side_effect=read):
            with self.assertRaises(ValueError):self.admit()

    def test_changed_auth_and_key_rotation_loss_poison_guard_no_retained_fallback(self):
        for kind in ('auth','rotate','lost'):
            with self.subTest(kind=kind):
                self.policy.write_bytes(json.dumps(fixture()).encode());self.key.write_bytes(b'k'*32)
                guard=self.admit()
                if kind=='auth':
                    value=fixture();value['auth'][0]['password']='synthetic-new-password'
                    self.replace(self.policy,json.dumps(value).encode())
                elif kind=='rotate':self.replace(self.key,b'r'*32)
                else:self.key.unlink()
                with self.assertRaises(ValueError):guard.recheck()
                with self.assertRaises(ValueError):guard.render('a'*32)
                with self.assertRaises(ValueError):_ = guard.generation
                guard.close();self.guard=None
                if not self.key.exists():self.key.write_bytes(b'k'*32);self.key.chmod(0o600)

    def test_equivalent_canonical_policy_replacement_keeps_same_commitment(self):
        guard=self.admit();generation=guard.generation
        self.replace(self.policy,json.dumps(fixture(),indent=2,sort_keys=True).encode())
        guard.recheck();self.assertEqual(guard.generation,generation)

    def test_invalid_json_static_error_and_closed_guard_cannot_render(self):
        self.policy.write_bytes(b'{"secret":"synthetic-private-value","secret":true}')
        with self.assertRaises(ValueError) as caught:self.admit()
        self.assertNotIn('synthetic-private-value',str(caught.exception))
        self.policy.write_bytes(json.dumps(fixture()).encode())
        guard=self.admit();guard.close()
        for operation in (guard.recheck,lambda:guard.render('a'*32),lambda:guard.generation):
            with self.assertRaises(ValueError):operation()

if __name__=='__main__':unittest.main()
