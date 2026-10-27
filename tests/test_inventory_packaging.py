"""Synthetic package fixture; never builds or activates a host agent."""
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
class InventoryPackagingTests(unittest.TestCase):
    def test_linux_archives_have_separate_binary_and_inactive_linux_examples(self):
        for target in ['arm-unknown-linux-musleabihf','aarch64-unknown-linux-musl','x86_64-unknown-linux-musl']:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);tools=root/'tools';tools.mkdir()
                cargo=tools/'cargo';cargo.write_text('#!/bin/sh\nexit 0\n');cargo.chmod(0o700)
                binary=root/'build'/target/'release'/'command-center-inventory';binary.parent.mkdir(parents=True);binary.write_bytes(b'synthetic-build-artifact')
                env={**os.environ,'PATH':str(tools)+os.pathsep+os.environ['PATH'],'CARGO_TARGET_DIR':str(root/'build')}
                result=subprocess.run(['bash','scripts/package-inventory.sh',target,str(root/'dist')],cwd=ROOT,env=env,capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,'Synthetic inventory packaging failed')
                archive=next((root/'dist').glob('*.tar.gz'))
                with tarfile.open(archive) as package:
                    names=package.getnames()
                self.assertTrue(any(name.endswith('/command-center-inventory') for name in names))
                self.assertFalse(any(name.endswith('/guarded-update') or name.endswith('.plist') for name in names))
                self.assertTrue(any(name.endswith('/command-center-inventory.service') for name in names))
                self.assertTrue(any(name.endswith('/command-center-inventory.timer') for name in names))
                self.assertTrue(Path(str(archive)+'.sha256').is_file())
if __name__=='__main__':unittest.main()
