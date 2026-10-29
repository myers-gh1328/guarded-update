"""Private source/target fixture mechanics; no Root or provenance claim."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from inventory_refresh_rust_parent_fixture import FixtureBinary
import inventory_refresh_rust_parent_fixture as staging


class FixtureBinaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.src=self.root/'src';self.dst=self.root/'dst';self.src.mkdir();self.dst.mkdir()
        self.name='command_center_inventory-0123456789abcdef';self.raw=b'synthetic binary payload';self.source=self.src/self.name;self.source.write_bytes(self.raw);self.source.chmod(0o555)
        self.sf=os.open(self.src,os.O_RDONLY|os.O_DIRECTORY);self.df=os.open(self.dst,os.O_RDONLY|os.O_DIRECTORY);self.value=None
    def tearDown(self):
        if self.value is not None:self.value.close()
        os.close(self.sf);os.close(self.df);self.temp.cleanup()
    def admit(self):
        self.value=FixtureBinary.from_directory(self.sf,self.name,self.df,hashlib.sha256(self.raw).hexdigest(),len(self.raw),os.getuid(),(os.getuid(),os.getgid()))
        return self.value
    def test_publish_and_retire_only_after_confirmed_empty(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);src=root/'src';dst=root/'dst';src.mkdir();dst.mkdir()
            name='command_center_inventory-0123456789abcdef';source=src/name;raw=b'synthetic binary';source.write_bytes(raw);source.chmod(0o555)
            sf=os.open(src,os.O_RDONLY|os.O_DIRECTORY);df=os.open(dst,os.O_RDONLY|os.O_DIRECTORY)
            try:
                value=FixtureBinary.from_directory(sf,name,df,hashlib.sha256(raw).hexdigest(),len(raw),os.getuid(),(os.getuid(),os.getgid()))
                value.publish();target=dst/'command-center-inventory'
                self.assertEqual(target.read_bytes(),raw);self.assertEqual(target.stat().st_mode&0o777,0o555)
                value.retire(True);self.assertFalse(target.exists())
            finally:os.close(sf);os.close(df)

    def test_preexisting_foreign_target_and_unsafe_source_never_publish(self):
        target=self.dst/'command-center-inventory';target.write_bytes(b'foreign')
        with self.assertRaises(ValueError):self.admit()
        self.assertEqual(target.read_bytes(),b'foreign');target.unlink()
        self.source.chmod(0o775)
        with self.assertRaises(ValueError):self.admit()
        self.source.chmod(0o555);link=self.src/'extra';os.link(self.source,link)
        with self.assertRaises(ValueError):self.admit()
        link.unlink();other=self.src/'original';self.source.rename(other);self.source.symlink_to(other)
        with self.assertRaises(ValueError):self.admit()

    def test_unknown_cleanup_is_absorbing_and_preserves_target(self):
        value=self.admit();value.publish();target=self.dst/'command-center-inventory'
        with self.assertRaises(ValueError):value.retire(False)
        with self.assertRaises(ValueError):value.retire(True)
        self.assertEqual(target.read_bytes(),self.raw)

    def test_partial_write_or_fsync_failure_preserves_nonexecutable_file(self):
        for kind in ('write','fsync'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);src=root/'src';dst=root/'dst';src.mkdir();dst.mkdir();source=src/self.name;source.write_bytes(self.raw);source.chmod(0o555)
                sf=os.open(src,os.O_RDONLY|os.O_DIRECTORY);df=os.open(dst,os.O_RDONLY|os.O_DIRECTORY)
                value=FixtureBinary.from_directory(sf,self.name,df,hashlib.sha256(self.raw).hexdigest(),len(self.raw),os.getuid(),(os.getuid(),os.getgid()))
                actual=os.write;calls=[]
                def broken(fd,data):
                    calls.append(True)
                    if len(calls)>1:raise OSError('synthetic write failure')
                    return actual(fd,data[:3])
                try:
                    if kind=='write':mock=patch.object(staging.os,'write',side_effect=broken)
                    else:mock=patch.object(staging.os,'fsync',side_effect=OSError('synthetic fsync failure'))
                    with mock:
                        with self.assertRaises(ValueError):value.publish()
                    target=dst/'command-center-inventory';self.assertTrue(target.exists());self.assertEqual(target.stat().st_mode&0o111,0)
                    with self.assertRaises(ValueError):value.retire(True)
                    self.assertTrue(target.exists())
                finally:value.close();os.close(sf);os.close(df)

    def test_source_mutation_during_copy_preserves_nonexecutable_target(self):
        value=self.admit();actual=os.read;calls=[]
        def change(fd,size):
            data=actual(fd,size);calls.append(True)
            if len(calls)==3 and data:self.source.chmod(0o755);self.source.write_bytes(b'foreign changed');self.source.chmod(0o555)
            return data
        with patch.object(staging.os,'read',side_effect=change):
            with self.assertRaises(ValueError):value.publish()
        target=self.dst/'command-center-inventory';self.assertTrue(target.exists());self.assertEqual(target.stat().st_mode&0o111,0)
        with self.assertRaises(ValueError):value.retire(True)
        self.assertTrue(target.exists())

    def test_replaced_or_modified_target_is_never_retired(self):
        value=self.admit();value.publish();target=self.dst/'command-center-inventory';target.unlink();target.write_bytes(self.raw);target.chmod(0o555)
        with self.assertRaises(ValueError):value.retire(True)
        self.assertEqual(target.read_bytes(),self.raw)

    def test_unknown_close_is_absorbing_and_all_owned_closes_are_attempted(self):
        value=self.admit();actual=os.close;calls=[]
        def uncertain(fd):calls.append(fd);actual(fd);raise OSError('synthetic close uncertainty')
        with patch.object(staging.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):value.publish()
        target=self.dst/'command-center-inventory';self.assertTrue(target.exists())
        calls.clear()
        with patch.object(staging.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):value.retire(True)
        self.assertEqual(len(calls),3);self.assertTrue(target.exists())
        with self.assertRaises(ValueError):value.retire(True)

    def test_non_boolean_cleanup_confirmation_never_retires(self):
        value=self.admit();value.publish();target=self.dst/'command-center-inventory'
        with self.assertRaises(ValueError):value.retire(1)
        self.assertTrue(target.exists())
