"""Actual descriptor tests; admission proves no compiler or source provenance."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from inventory_refresh_rust_binary_selection import admit
import inventory_refresh_rust_binary_selection as selection


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.target=self.root/'target';self.deps=self.target/'debug'/'deps';self.deps.mkdir(parents=True)
        self.binary=self.deps/'command_center_inventory-0123456789abcdef';self.binary.write_bytes(b'synthetic test binary');self.binary.chmod(0o555)
        self.repo=self.root/'source';self.repo.mkdir();self.fd=os.open(self.target,os.O_RDONLY|os.O_DIRECTORY)
        self.event={'reason':'compiler-artifact','package_id':'path+'+self.repo.as_uri()+'#guarded-update@0.1.9',
            'manifest_path':str(self.repo/'Cargo.toml'),'target':{'name':'command-center-inventory','kind':['bin'],
            'src_path':str(self.repo/'src/inventory_main.rs')},'profile':{'test':True},'features':['inventory-agent'],
            'executable':str(self.binary),'fresh':False}
    def tearDown(self):os.close(self.fd);self.temp.cleanup()
    def lines(self,*events):return b''.join((json.dumps(event)+'\n').encode() for event in events)
    def check(self,raw):return admit(raw,self.repo,self.target,self.fd,os.getuid())

    def test_admits_one_fresh_fixed_test_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);target=root/'target';deps=target/'debug'/'deps';deps.mkdir(parents=True)
            binary=deps/'command_center_inventory-0123456789abcdef';binary.write_bytes(b'synthetic test binary');binary.chmod(0o555)
            repo=root/'source';repo.mkdir()
            event={'reason':'compiler-artifact','package_id':repo.as_uri()+'#guarded-update@0.1.9',
                'manifest_path':str(repo/'Cargo.toml'),'target':{'name':'command-center-inventory','kind':['bin'],
                'src_path':str(repo/'src/inventory_main.rs')},'profile':{'test':True},'features':['inventory-agent'],
                'executable':str(binary),'fresh':False}
            # cargo emits a path+ prefix on package IDs.
            event['package_id']='path+'+event['package_id']
            lines=(json.dumps(event)+'\n'+json.dumps({'reason':'build-finished','success':True})+'\n').encode()
            fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY)
            try:
                result=admit(lines,repo,target,fd,os.getuid())
                self.assertEqual(result['sha256'],hashlib.sha256(binary.read_bytes()).hexdigest())
                self.assertEqual(result['size'],len(binary.read_bytes()))
            finally:os.close(fd)

    def test_selection_rejects_ambiguous_inexact_or_unfinished_cargo_output(self):
        done={'reason':'build-finished','success':True}
        for field,value in [('fresh',True),('package_id','different'),('features',['default','inventory-agent']),
                ('profile',{'test':1}),('executable',str(self.deps/'..'/'other'))]:
            candidate=dict(self.event);candidate[field]=value
            with self.assertRaises(ValueError,msg=field):self.check(self.lines(candidate,done))
        for raw in [self.lines(self.event,self.event,done),self.lines(self.event),self.lines(done,self.event),
            self.lines(self.event,{'reason':'build-finished','success':False}),
            b'{"reason":"compiler-artifact","reason":"compiler-artifact"}\n'+self.lines(done),
            b'x'*(8*1024*1024+1)]:
            with self.assertRaises(ValueError):self.check(raw)

    def test_symlink_hardlink_wrong_modes_and_replaced_ancestry_are_rejected(self):
        log=self.lines(self.event,{'reason':'build-finished','success':True})
        self.binary.chmod(0o775)
        with self.assertRaises(ValueError):self.check(log)
        self.binary.chmod(0o555)
        link=self.deps/'other';os.link(self.binary,link)
        with self.assertRaises(ValueError):self.check(log)
        link.unlink();actual=self.deps/'original';self.binary.rename(actual);self.binary.symlink_to(actual)
        with self.assertRaises(ValueError):self.check(log)
        self.binary.unlink();actual.rename(self.binary)
        old=self.target/'old-debug';(self.target/'debug').rename(old)
        (self.target/'debug').symlink_to(old)
        with self.assertRaises(ValueError):self.check(log)

    def test_changed_file_or_uncertain_close_never_returns_digest(self):
        log=self.lines(self.event,{'reason':'build-finished','success':True})
        real_read=os.read;changed=[]
        def mutate(fd,size):
            data=real_read(fd,size)
            if data and not changed:
                changed.append(True);self.binary.chmod(0o755);self.binary.write_bytes(b'different');self.binary.chmod(0o555)
            return data
        with patch.object(selection.os,'read',side_effect=mutate):
            with self.assertRaises(ValueError):self.check(log)
        real_close=os.close;closed=[]
        def uncertain(fd):
            closed.append(fd);real_close(fd)
            if len(closed)==1:raise OSError('synthetic close uncertainty')
        with patch.object(selection.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):self.check(log)
        self.assertEqual(len(closed),4)

    def test_empty_oversized_and_io_failure_never_return_digest(self):
        log=self.lines(self.event,{'reason':'build-finished','success':True})
        self.binary.chmod(0o755);self.binary.write_bytes(b'');self.binary.chmod(0o555)
        with self.assertRaises(ValueError):self.check(log)
        self.binary.chmod(0o755)
        with self.binary.open('wb') as output:output.truncate(128*1024*1024+1)
        self.binary.chmod(0o555)
        with self.assertRaises(ValueError):self.check(log)
        self.binary.chmod(0o755);self.binary.write_bytes(b'abc');self.binary.chmod(0o555)
        with patch.object(selection.os,'read',side_effect=OSError('synthetic read failure')):
            with self.assertRaises(ValueError):self.check(log)
