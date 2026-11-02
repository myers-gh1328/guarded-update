"""Synthetic packaging contract; does not activate any host service."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Armv6ExecutorPackaging(unittest.TestCase):
    def test_executor_accepts_armv6_with_conventional_armhf_package_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools = root / 'tools'
            tools.mkdir()
            cargo = tools / 'cargo'
            cargo.write_text('#!/bin/sh\ncase "$RUSTFLAGS" in *"target-feature=+crt-static"*) ;; *) exit 9;; esac\ntest "$CARGO_TARGET_ARM_UNKNOWN_LINUX_MUSLEABIHF_LINKER" = rust-lld\n')
            cargo.chmod(0o700)
            dpkg = tools / 'dpkg-deb'
            dpkg.write_text('#!/bin/sh\ncp "$3/DEBIAN/control" "$4"\n')
            dpkg.chmod(0o700)
            target = 'arm-unknown-linux-musleabihf'
            binary = root / 'build' / target / 'release' / 'guarded-update'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'synthetic')
            env = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH'], 'CARGO_TARGET_DIR': str(root / 'build')}
            result = subprocess.run(['bash', 'scripts/package-apt.sh', 'apt-executor', target, str(root / 'dist')], cwd=ROOT, env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            packages = list((root / 'dist').glob('guarded-update-apt-executor_*_armhf.deb'))
            self.assertEqual(len(packages), 1)
            package = packages[0]
            self.assertIn('Architecture: armhf', package.read_text())


if __name__ == '__main__':
    unittest.main()
