"""Synthetic builder seam; no compiler or production provenance claim."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import inventory_refresh_rust_build as build


class RustBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir()));self.root=Path(self.temp.name);self.repo=self.root/'repo';self.repo.mkdir();self.output=self.root/'output';self.output.mkdir(mode=0o700)
        subprocess.run(['/usr/bin/git','init','-q',str(self.repo)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for name,raw in {'Cargo.toml':b'package','Cargo.lock':b'lock','rust-toolchain.toml':b'tool','src/inventory_main.rs':b'fn main() {}'}.items():
            path=self.repo/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        subprocess.run(['/usr/bin/git','-C',str(self.repo),'add','.'],check=True)
        subprocess.run(['/usr/bin/git','-C',str(self.repo),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','fixture'],check=True)
        self.fd=os.open(self.output,os.O_RDONLY|os.O_DIRECTORY)
    def tearDown(self):os.close(self.fd);self.temp.cleanup()
    def run_build(self):return build.build(self.repo,self.output,self.fd,os.getuid())
    def test_fixed_isolated_build_accepts_only_revalidated_test_binary(self):
        with tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir())) as temporary:
            root=Path(temporary);repo=root/'repo';repo.mkdir();output=root/'output';output.mkdir(mode=0o700)
            subprocess.run(['/usr/bin/git','init','-q',str(repo)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for name,raw in {'Cargo.toml':b'package','Cargo.lock':b'lock','rust-toolchain.toml':b'tool','src/inventory_main.rs':b'fn main() {}'}.items():
                path=repo/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            subprocess.run(['/usr/bin/git','-C',str(repo),'add','.'],check=True)
            subprocess.run(['/usr/bin/git','-C',str(repo),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','fixture'],check=True)
            fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY)
            def fake_cargo(cwd,target,env,deadline):
                self.assertNotIn('RUSTC_WRAPPER',env);self.assertNotIn('GITHUB_TOKEN',env)
                deps=target/'debug'/'deps';deps.mkdir(parents=True);binary=deps/'command_center_inventory-0123456789abcdef';binary.write_bytes(b'compiler fixture');binary.chmod(0o555)
                event={'reason':'compiler-artifact','package_id':'path+'+cwd.as_uri()+'#guarded-update@0.1.9','manifest_path':str(cwd/'Cargo.toml'),
                    'target':{'name':'command-center-inventory','kind':['bin'],'src_path':str(cwd/'src/inventory_main.rs')},
                    'profile':{'test':True},'features':['inventory-agent'],'executable':str(binary),'fresh':False}
                return (json.dumps(event)+'\n'+json.dumps({'reason':'build-finished','success':True})+'\n').encode()
            try:
                with patch.dict(os.environ,{'RUSTC_WRAPPER':'unsafe-wrapper','GITHUB_TOKEN':'synthetic-secret'}):
                    with patch.object(build,'_capture',side_effect=fake_cargo):result=build.build(repo,output,fd,os.getuid())
                self.assertEqual(result['binary_size'],len(b'compiler fixture'))
                self.assertTrue((Path(result['binary_path'])).is_file())
            finally:os.close(fd)

    def test_ancestor_config_rejected_before_cargo(self):
        config=self.root/'.cargo';config.mkdir();(config/'config.toml').write_bytes(b'[build]\n')
        with patch.object(build,'_capture') as capture:
            with self.assertRaises(ValueError):self.run_build()
            capture.assert_not_called()
        self.assertEqual((config/'config.toml').read_bytes(),b'[build]\n')

    def test_postbuild_source_change_and_extra_entry_fail_closed(self):
        for fault in ('changed','extra'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir())) as temporary:
                output=Path(temporary);fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY)
                def change(cwd,target,env,deadline):
                    if fault=='changed':(cwd/'Cargo.lock').write_bytes(b'altered')
                    else:(cwd/'unknown').write_bytes(b'unexpected')
                    return b'{}\n'
                try:
                    with patch.object(build,'_capture',side_effect=change):
                        with self.assertRaises(ValueError):build.build(self.repo,output,fd,os.getuid())
                    self.assertTrue((output/'target').is_dir())
                finally:os.close(fd)

    def test_capture_times_out_or_rejects_oversized_output_without_success(self):
        real=subprocess.Popen
        for program,seconds in [('import time;time.sleep(0.4)',0.05),('import sys;sys.stdout.buffer.write(b"x"*(9*1024*1024));sys.stdout.buffer.flush()',3)]:
            owned=[]
            def child(_args,**kwargs):
                result=real(['/usr/bin/python3','-I','-c',program],**kwargs);owned.append(result);return result
            with patch.object(build.subprocess,'Popen',side_effect=child):
                with self.assertRaises(ValueError):build._capture(self.repo,self.output,{'PATH':'/usr/bin:/bin'},time.monotonic()+seconds)
            self.assertEqual(len(owned),1);self.assertIsNotNone(owned[0].poll())

    def test_capture_close_uncertainty_never_returns_output(self):
        real=subprocess.Popen;selector=build.selectors.DefaultSelector();close=selector.close
        def uncertain():close();raise OSError('synthetic close uncertainty')
        def child(_args,**kwargs):return real(['/usr/bin/python3','-I','-c','print("{}")'],**kwargs)
        with patch.object(selector,'close',side_effect=uncertain),patch.object(build.selectors,'DefaultSelector',return_value=selector),patch.object(build.subprocess,'Popen',side_effect=child):
            with self.assertRaises(ValueError):build._capture(self.repo,self.output,{'PATH':'/usr/bin:/bin'},time.monotonic()+3)

    def test_expired_capture_never_spawns(self):
        with patch.object(build.subprocess,'Popen') as child:
            with self.assertRaises(ValueError):build._capture(self.repo,self.output,{},time.monotonic()-1)
            child.assert_not_called()
