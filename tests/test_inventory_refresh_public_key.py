"""Synthetic device-key derivation; no enrollment authority."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_public_key as derive


class PublicKeyTests(unittest.TestCase):
    def fixture(self,root,curve='prime256v1'):
        directory=root/'var'/'lib'/'command-center-inventory'/'keys'/'inventory-v1'
        directory.mkdir(parents=True);directory.chmod(0o700)
        path=directory/'private.pem'
        subprocess.run(['/usr/bin/openssl','ecparam','-name',curve,'-genkey','-noout','-out',str(path)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        path.chmod(0o600)
        return path

    def test_fixed_descriptor_derivation_matches_public_spki_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);directory=root/'var'/'lib'/'command-center-inventory'/'keys'/'inventory-v1'
            directory.mkdir(parents=True);directory.chmod(0o700)
            path=directory/'private.pem'
            subprocess.run(['/usr/bin/openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',str(path)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            path.chmod(0o600)
            public=subprocess.run(['/usr/bin/openssl','pkey','-in',str(path),'-pubout','-outform','DER'],check=True,capture_output=True).stdout
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                self.assertEqual(derive._derive_from(fd,os.getuid(),os.getgid(),time.monotonic()+5,ancestor_owner=os.getuid()),hashlib.sha256(public).hexdigest())
            finally:os.close(fd)

    def test_rejects_bad_path_modes_links_key_and_expiry(self):
        for fault in ('mode','directory','symlink','hardlink','wrong_curve','malformed','oversize','expired','wrong_owner','wrong_group'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);path=self.fixture(root,'secp384r1' if fault=='wrong_curve' else 'prime256v1')
                if fault=='mode':path.chmod(0o644)
                elif fault=='directory':path.parent.chmod(0o755)
                elif fault=='symlink':path.unlink();path.symlink_to('missing')
                elif fault=='hardlink':os.link(path,path.with_name('other'))
                elif fault=='malformed':path.write_bytes(b'synthetic invalid key')
                elif fault=='oversize':path.write_bytes(b'x'*4097)
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    uid=os.getuid()+int(fault=='wrong_owner');gid=os.getgid()+int(fault=='wrong_group')
                    with self.assertRaises(derive.KeyErrorState):
                        derive._derive_from(fd,uid,gid,time.monotonic()+(-1 if fault=='expired' else 5),ancestor_owner=os.getuid())
                finally:os.close(fd)

    def test_timeout_and_uncertain_output_close_never_return_a_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);popen=subprocess.Popen;children=[]
            def stall(*args,**kwargs):
                child=popen([sys.executable,'-c','import time;time.sleep(0.2)'],**kwargs)
                children.append(child);return child
            try:
                with patch.object(derive.subprocess,'Popen',side_effect=stall):
                    with self.assertRaises(derive.KeyErrorState):derive._derive_from(fd,os.getuid(),os.getgid(),time.monotonic()+0.05,ancestor_owner=os.getuid())
                for child in children:child.wait(timeout=2)
                class UncertainStream:
                    def __init__(self,stream):self.stream=stream
                    def fileno(self):return self.stream.fileno()
                    def close(self):self.stream.close();raise OSError('synthetic close uncertainty')
                def uncertain(*args,**kwargs):
                    child=popen(*args,**kwargs);child.stdout=UncertainStream(child.stdout);return child
                with patch.object(derive.subprocess,'Popen',side_effect=uncertain):
                    with self.assertRaises(derive.KeyErrorState):derive._derive_from(fd,os.getuid(),os.getgid(),time.monotonic()+5,ancestor_owner=os.getuid())
            finally:os.close(fd)

    def test_replaced_key_and_malformed_public_output_never_return_a_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=self.fixture(root);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            popen=subprocess.Popen;children=[]
            def replace_key(*args,**kwargs):
                child=popen(*args,**kwargs);children.append(child)
                replacement=path.with_name('replacement');replacement.write_bytes(path.read_bytes());replacement.chmod(0o600)
                os.replace(replacement,path)
                return child
            try:
                with patch.object(derive.subprocess,'Popen',side_effect=replace_key):
                    with self.assertRaises(derive.KeyErrorState):derive._derive_from(fd,os.getuid(),os.getgid(),time.monotonic()+5,ancestor_owner=os.getuid())
                for payload in ('b"x"*513','b"short"'):
                    def malformed(*args,**kwargs):
                        child=popen([sys.executable,'-c','import os;os.write(1,'+payload+')'],**kwargs);children.append(child);return child
                    with patch.object(derive.subprocess,'Popen',side_effect=malformed):
                        with self.assertRaises(derive.KeyErrorState):derive._derive_from(fd,os.getuid(),os.getgid(),time.monotonic()+5,ancestor_owner=os.getuid())
            finally:
                for child in children:child.wait(timeout=2)
                os.close(fd)

if __name__=='__main__':unittest.main()
