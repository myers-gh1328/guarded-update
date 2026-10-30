"""Private temporary source copy mechanics, never production installation."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from inventory_refresh_rust_source_copy import materialize
import inventory_refresh_rust_source_copy as source_copy


class SourceCopyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        files={'Cargo.toml':b'package','Cargo.lock':b'lock','rust-toolchain.toml':b'tool','src/inventory_main.rs':b'fn main() {}'}
        self.snapshot={'source_commit':'a'*40,'tree':'b'*40,'files':files,'modes':{name:'100644' for name in files}}
    def tearDown(self):os.close(self.fd);self.temp.cleanup()
    def copy(self):return materialize(self.snapshot,self.root,self.fd,os.getuid())
    def test_materializes_exact_private_tree_without_touching_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            files={'Cargo.toml':b'package','Cargo.lock':b'lock','rust-toolchain.toml':b'tool',
                'src/inventory_main.rs':b'fn main() {}','scripts/tool.sh':b'#!/bin/sh\n'}
            modes={name:'100644' for name in files};modes['scripts/tool.sh']='100755'
            snapshot={'source_commit':'a'*40,'tree':'b'*40,'files':files,'modes':modes}
            try:
                result=materialize(snapshot,root,fd,os.getuid())
                copied=root/('source-'+'a'*40)
                self.assertEqual(result['source_commit'],'a'*40)
                for name,raw in files.items():self.assertEqual((copied/name).read_bytes(),raw)
                self.assertEqual((copied/'scripts/tool.sh').stat().st_mode&0o777,0o700)
                self.assertEqual((copied/'Cargo.toml').stat().st_mode&0o777,0o600)
            finally:os.close(fd)

    def test_preexisting_tree_and_bad_layout_are_never_mutated(self):
        existing=self.root/('source-'+'a'*40);existing.mkdir();marker=existing/'foreign';marker.write_bytes(b'keep')
        with self.assertRaises(ValueError):self.copy()
        self.assertEqual(marker.read_bytes(),b'keep');marker.unlink();existing.rmdir()
        for path in ['../escape','.cargo/config','src/build.rs','src/inventory_main.rs/subfile']:
            self.snapshot['files'][path]=b'x';self.snapshot['modes'][path]='100644'
            with self.assertRaises(ValueError,msg=path):self.copy()
            self.assertFalse(existing.exists())
            del self.snapshot['files'][path];del self.snapshot['modes'][path]

    def test_fsync_failure_and_uncertain_close_preserve_partial_tree(self):
        with patch.object(source_copy.os,'fsync',side_effect=OSError('synthetic fsync failure')):
            with self.assertRaises(ValueError):self.copy()
        copied=self.root/('source-'+'a'*40);self.assertTrue(copied.is_dir());copied.rmdir()
        actual=os.close;calls=[]
        def close_once(fd):
            calls.append(fd);actual(fd)
            if len(calls)==1:raise OSError('synthetic close uncertainty')
        with patch.object(source_copy.os,'close',side_effect=close_once):
            with self.assertRaises(ValueError):self.copy()
        self.assertGreaterEqual(len(calls),3);self.assertTrue(copied.is_dir())

    def test_replacement_during_write_is_never_admitted(self):
        actual=os.fsync;changed=[];copied=self.root/('source-'+'a'*40);path=copied/'Cargo.lock'
        def replace(fd):
            actual(fd)
            if not changed and path.exists() and os.path.isfile(path):
                changed.append(True);path.rename(copied/'foreign-original');path.write_bytes(b'foreign')
        with patch.object(source_copy.os,'fsync',side_effect=replace):
            with self.assertRaises(ValueError):self.copy()
        self.assertEqual(path.read_bytes(),b'foreign');self.assertEqual((copied/'foreign-original').read_bytes(),b'lock')

    def test_short_writes_are_completed_and_bad_snapshot_has_no_effect(self):
        self.snapshot['modes'].pop('Cargo.lock')
        with self.assertRaises(ValueError):self.copy()
        self.assertEqual(list(self.root.iterdir()),[])
        self.snapshot['modes']['Cargo.lock']='100644';actual=os.write
        def short(fd,data):return actual(fd,data[:max(1,len(data)//2)])
        with patch.object(source_copy.os,'write',side_effect=short):self.copy()
        self.assertEqual((self.root/('source-'+'a'*40)/'Cargo.lock').read_bytes(),b'lock')
