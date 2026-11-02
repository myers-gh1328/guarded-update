"""Private CI build wrapper tests; no Root staging or provenance claim."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import native_inventory_refresh_rust_build as wrapper


class OsProxy:
    def __init__(self,**overrides):self.overrides=overrides
    def __getattr__(self,name):return self.overrides.get(name,getattr(os,name))


class RustBuildWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.repo=self.root/'repo';self.repo.mkdir();self.runner=self.root/'runner';self.runner.mkdir(mode=0o700)
        subprocess.run(['/usr/bin/git','init','-q',str(self.repo)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (self.repo/'file').write_bytes(b'fixture');subprocess.run(['/usr/bin/git','-C',str(self.repo),'add','file'],check=True)
        subprocess.run(['/usr/bin/git','-C',str(self.repo),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','fixture'],check=True)
        self.commit=subprocess.check_output(['/usr/bin/git','-C',str(self.repo),'rev-parse','HEAD']).decode().strip()
    def tearDown(self):self.temp.cleanup()
    def result(self,repo,output,fd,owner):
        return {'source_commit':self.commit,'tree':'b'*40,'binary_sha256':'c'*64,'binary_size':12,
            'binary_path':str(output/'target/debug/deps/command_center_inventory-0123456789abcdef')}
    def test_writes_only_bounded_private_manifest_for_exact_commit(self):
        with patch.object(wrapper,'build',side_effect=self.result):result=wrapper.execute(self.repo,self.runner,'true')
        manifest=self.runner/'inventory-rust-parent'/'manifest.json'
        self.assertEqual(result,self.commit);self.assertTrue(manifest.is_file());self.assertEqual(manifest.stat().st_mode&0o777,0o600)
        self.assertNotIn(str(self.root).encode(),manifest.read_bytes())

    def test_wrong_identity_or_marker_never_creates_anything(self):
        for marker in ('false',None,'1'):
            with self.assertRaises(ValueError):wrapper.execute(self.repo,self.runner,marker)
            self.assertEqual(list(self.runner.iterdir()),[])
        with patch.object(wrapper,'os',OsProxy(geteuid=lambda:0)):
            with self.assertRaises(ValueError):wrapper.execute(self.repo,self.runner,'true')
        self.assertEqual(list(self.runner.iterdir()),[])

    def test_unsafe_ancestor_or_symlinked_runner_is_rejected_before_build(self):
        self.root.chmod(0o777)
        try:
            with patch.object(wrapper,'build') as build:
                with self.assertRaises(ValueError):wrapper.execute(self.repo,self.runner,'true')
                build.assert_not_called()
        finally:self.root.chmod(0o700)
        link=self.root/'runner-link';link.symlink_to(self.runner,target_is_directory=True)
        with patch.object(wrapper,'build') as build:
            with self.assertRaises(ValueError):wrapper.execute(self.repo,link,'true')
            build.assert_not_called()
        self.assertEqual(list(self.runner.iterdir()),[])

    def test_preexisting_output_and_manifest_symlink_are_preserved(self):
        target=self.runner/'inventory-rust-parent';target.mkdir();marker=target/'foreign';marker.write_bytes(b'foreign')
        with self.assertRaises(ValueError):wrapper.execute(self.repo,self.runner,'true')
        self.assertEqual(marker.read_bytes(),b'foreign');marker.unlink();target.rmdir()
        outside=self.runner/'outside';outside.write_bytes(b'untouched')
        def fake(repo,output,fd,owner):
            (output/'manifest.json').symlink_to(outside);return self.result(repo,output,fd,owner)
        with patch.object(wrapper,'build',side_effect=fake):
            with self.assertRaises(ValueError):wrapper.execute(self.repo,self.runner,'true')
        self.assertTrue((target/'manifest.json').is_symlink());self.assertEqual(outside.read_bytes(),b'untouched')

    def test_invalid_build_metadata_never_writes_manifest(self):
        for key,bad in [('source_commit','d'*40),('binary_sha256','not-a-digest'),('binary_size',True),('binary_path','/tmp/not-a-binary')]:
            with self.subTest(key=key),tempfile.TemporaryDirectory() as temporary:
                runner=Path(temporary).resolve()
                def fake(repo,output,fd,owner):
                    value=self.result(repo,output,fd,owner);value[key]=bad;return value
                with patch.object(wrapper,'build',side_effect=fake):
                    with self.assertRaises(ValueError):wrapper.execute(self.repo,runner,'true')
                self.assertFalse((runner/'inventory-rust-parent'/'manifest.json').exists())

    def test_partial_write_and_uncertain_close_never_report_success(self):
        target=self.runner/'inventory-rust-parent';actual=os.write;calls=[]
        def fail_write(fd,raw):
            calls.append(fd)
            if len(calls)>1:raise OSError('synthetic partial write failure')
            return actual(fd,raw[:3])
        with patch.object(wrapper,'build',side_effect=self.result),patch.object(wrapper,'os',OsProxy(write=fail_write)):
            with self.assertRaises(ValueError):wrapper.execute(self.repo,self.runner,'true')
        self.assertTrue((target/'manifest.json').exists());self.assertLess((target/'manifest.json').stat().st_size,20)
        with tempfile.TemporaryDirectory() as temporary:
            runner=Path(temporary).resolve();actual_close=os.close;closed=[]
            def uncertain(fd):
                closed.append(fd);actual_close(fd)
                if len(closed)==1:raise OSError('synthetic close uncertainty')
            with patch.object(wrapper,'build',side_effect=self.result),patch.object(wrapper,'os',OsProxy(close=uncertain)):
                with self.assertRaises(ValueError):wrapper.execute(self.repo,runner,'true')
            self.assertGreaterEqual(len(closed),3)
