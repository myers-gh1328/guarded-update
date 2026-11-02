"""Fixed-source bootstrap tests; no privileged entry execution."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]

class EntryTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('entry_fixture',ROOT/'scripts/inventory_refresh_entry.py')
        self.entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.entry)
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.root.chmod(0o700)
        for _,filename in self.entry.SOURCES:
            (self.root/filename).write_text('sentinel = 1\n')
            (self.root/filename).chmod(0o400)
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)

    def tearDown(self):
        os.close(self.fd);self.temp.cleanup()

    def test_full_fixed_bundle_admitted_without_executing_any_bytes(self):
        sources=self.entry.read_sources(self.fd,owner=os.getuid())
        self.assertEqual(tuple(sources),tuple(name for name,_ in self.entry.SOURCES))
        self.assertTrue(all(raw==b'sentinel = 1\n' for raw in sources.values()))

    def test_rejects_symlink_hardlink_write_permission_and_oversize(self):
        target=self.root/self.entry.SOURCES[-1][1]
        for kind in ('symlink','hardlink','write','oversize'):
            with self.subTest(kind=kind):
                target.unlink();target.write_text('sentinel = 1\n');target.chmod(0o400)
                extra=self.root/'extra'
                if extra.exists() or extra.is_symlink():extra.unlink()
                if kind=='symlink':
                    target.rename(extra);target.symlink_to(extra)
                elif kind=='hardlink':os.link(target,extra)
                elif kind=='write':target.chmod(0o460)
                else:
                    target.chmod(0o600);target.write_bytes(b'x'*65537);target.chmod(0o400)
                with self.assertRaises(ValueError):self.entry.read_sources(self.fd,owner=os.getuid())

    def test_rejects_foreign_owner_and_writable_directory(self):
        with self.assertRaises(ValueError):self.entry.read_sources(self.fd,owner=os.getuid()+1)
        self.root.chmod(0o770)
        with self.assertRaises(ValueError):self.entry.read_sources(self.fd,owner=os.getuid())

    def test_named_replacement_during_read_fails(self):
        original=os.read;changed=False;target=self.root/self.entry.SOURCES[0][1]
        def read(fd,size):
            nonlocal changed
            data=original(fd,size)
            if not changed:
                changed=True;target.unlink();target.write_text('changed = 1\n');target.chmod(0o400)
            return data
        with patch.object(self.entry.os,'read',side_effect=read):
            with self.assertRaises(ValueError):self.entry.read_sources(self.fd,owner=os.getuid())

    def test_fixed_exec_ignores_sibling_packages_and_does_not_change_search_path(self):
        (self.root/'json.py').write_text('raise RuntimeError("shadow")')
        before=list(sys.path)
        with patch.dict(sys.modules):
            for name,_ in self.entry.SOURCES:sys.modules.pop(name,None)
            modules=self.entry.execute_sources(self.entry.read_sources(self.fd,owner=os.getuid()))
            self.assertTrue(all(module.sentinel==1 for module in modules.values()))
        self.assertEqual(sys.path,before)

    def test_module_collision_rejected_before_any_exec(self):
        sources=self.entry.read_sources(self.fd,owner=os.getuid())
        with patch.dict(sys.modules,{self.entry.SOURCES[-1][0]:object()}):
            with patch('builtins.exec') as execute:
                with self.assertRaises(ValueError):self.entry.execute_sources(sources)
                execute.assert_not_called()

if __name__=='__main__':unittest.main()
