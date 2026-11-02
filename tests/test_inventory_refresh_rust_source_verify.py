"""Private source verification tests; no compiler or production admission."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from inventory_refresh_rust_source_copy import materialize
from inventory_refresh_rust_source_verify import verify
import inventory_refresh_rust_source_verify as source_verify


class SourceVerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        files={'Cargo.toml':b'package','Cargo.lock':b'lock','rust-toolchain.toml':b'tool','src/inventory_main.rs':b'fn main() {}'}
        self.snapshot={'source_commit':'a'*40,'tree':'b'*40,'files':files,'modes':{name:'100644' for name in files}}
        materialize(self.snapshot,self.root,self.fd,os.getuid());self.copied=self.root/('source-'+'a'*40)
    def tearDown(self):os.close(self.fd);self.temp.cleanup()
    def check(self):return verify(self.snapshot,self.root,self.fd,os.getuid())
    def test_exact_private_tree_is_readable_but_extra_file_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            files={'Cargo.toml':b'package','Cargo.lock':b'lock','rust-toolchain.toml':b'tool','src/inventory_main.rs':b'fn main() {}'}
            snapshot={'source_commit':'a'*40,'tree':'b'*40,'files':files,'modes':{name:'100644' for name in files}}
            try:
                materialize(snapshot,root,fd,os.getuid())
                verify(snapshot,root,fd,os.getuid())
                extra=root/('source-'+'a'*40)/'unexpected';extra.write_bytes(b'foreign')
                with self.assertRaises(ValueError):verify(snapshot,root,fd,os.getuid())
                self.assertEqual(extra.read_bytes(),b'foreign')
            finally:os.close(fd)

    def test_changed_missing_symlink_hardlink_and_mode_rejected(self):
        path=self.copied/'Cargo.lock';original=path.read_bytes()
        path.write_bytes(b'wrong')
        with self.assertRaises(ValueError):self.check()
        path.write_bytes(original);path.chmod(0o666)
        with self.assertRaises(ValueError):self.check()
        path.chmod(0o600);extra=self.copied/'link';os.link(path,extra)
        with self.assertRaises(ValueError):self.check()
        extra.unlink();path.unlink();path.symlink_to(self.copied/'Cargo.toml')
        with self.assertRaises(ValueError):self.check()
        path.unlink()
        with self.assertRaises(ValueError):self.check()

    def test_changed_ancestry_and_mutation_during_read_are_rejected(self):
        path=self.copied/'Cargo.lock';actual=os.read;changed=[]
        def mutate(fd,size):
            data=actual(fd,size)
            if data and not changed:changed.append(True);path.write_bytes(b'evil')
            return data
        with patch.object(source_verify.os,'read',side_effect=mutate):
            with self.assertRaises(ValueError):self.check()
        path.write_bytes(b'lock');old=self.root/'old';self.copied.rename(old);self.copied.symlink_to(old)
        with self.assertRaises(ValueError):self.check()

    def test_uncertain_close_and_extra_directory_never_succeed(self):
        extra=self.copied/'foreign-dir';extra.mkdir()
        with self.assertRaises(ValueError):self.check()
        extra.rmdir();actual=os.close;calls=[]
        def uncertain(fd):
            calls.append(fd);actual(fd)
            if len(calls)==1:raise OSError('synthetic close failure')
        with patch.object(source_verify.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):self.check()
        self.assertGreaterEqual(len(calls),3)
