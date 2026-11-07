"""The existing Linux job must publish distinct executor architectures."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ExecutorMultiarchPipeline(unittest.TestCase):
    def test_linux_job_publishes_checked_arm64_and_amd64_packages(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        job = ci.split('  armv7:\n', 1)[1].split('\n  apt-hook:', 1)[0]
        for target, arch in [('aarch64-unknown-linux-gnu', 'arm64'), ('x86_64-unknown-linux-gnu', 'amd64')]:
            self.assertIn(f'scripts/package-apt.sh apt-executor {target}', job)
            self.assertIn(f'guarded-update-{arch}-executor', job)
        self.assertIn('scripts/test-executor-multiarch.sh', job)

if __name__ == '__main__': unittest.main()

class ExecutorPackageVerification(unittest.TestCase):
    def test_accepts_complete_amd64_fixture(self):
        import os
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); tools = root / 'tools'; tools.mkdir()
            dist = root / 'dist'; dist.mkdir()
            (dist / 'guarded-update-apt-executor_0.1.10_amd64.deb').write_bytes(b'fixture')
            version = next(line.split('"')[1] for line in (ROOT / 'Cargo.toml').read_text().splitlines() if line.startswith('version = '))
            dpkg = tools / 'dpkg-deb'
            dpkg.write_text("""#!/bin/sh
case "$1" in
-f) case "$3" in Package) echo guarded-update-apt-executor;; Architecture) echo amd64;; Version) echo "$TEST_VERSION";; esac;;
--ctrl-tarfile) echo fixture;;
-c) echo safe;;
-x) mkdir -p "$3/usr/bin" "$3/usr/lib/guarded-update" "$3/usr/lib/systemd/system"
    printf '#!/bin/sh\necho fixture\n' > "$3/usr/bin/guarded-update"
    printf '#!/bin/sh\n' > "$3/usr/lib/guarded-update/apt_executor.py"
    chmod +x "$3/usr/bin/guarded-update" "$3/usr/lib/guarded-update/apt_executor.py"
    for unit in guarded-update-remote guarded-update-executor guarded-update-broker; do
      touch "$3/usr/lib/systemd/system/$unit.service" "$3/usr/lib/systemd/system/$unit.timer"
    done;;
esac
""")
            dpkg.chmod(0o700)
            for name, body in [('tar', 'echo ./control'), ('readelf', "case \"$1\" in -h) echo 'Machine: Advanced Micro Devices X86-64';; -l) echo 'Requesting program interpreter';; -d) echo 'NEEDED [libc.so.6]';; --version-info) echo GLIBC_2.39;; esac")]:
                tool = tools / name; tool.write_text('#!/bin/sh\n' + body + '\n'); tool.chmod(0o700)
            env = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH'],
                   'TMPDIR': directory, 'TEST_VERSION': version}
            result = subprocess.run(['bash', 'scripts/test-executor-multiarch.sh', str(dist), 'amd64'],
                                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            readelf = tools / 'readelf'
            readelf.write_text(readelf.read_text().replace('GLIBC_2.39', 'GLIBC_2.40'))
            result = subprocess.run(['bash', 'scripts/test-executor-multiarch.sh', str(dist), 'amd64'],
                                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)

    def test_rejects_wrong_metadata_with_fake_package_tools(self):
        import os
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / 'tools'; tools.mkdir()
            dist = root / 'dist'; dist.mkdir()
            (dist / 'guarded-update-apt-executor_0.1.10_amd64.deb').write_bytes(b'fixture')
            dpkg = tools / 'dpkg-deb'
            dpkg.write_text('#!/bin/sh\ncase "$3" in Package) echo guarded-update-apt-executor;; Architecture) echo arm64;; esac\n')
            dpkg.chmod(0o700)
            env = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH'], 'TMPDIR': directory}
            result = subprocess.run(['bash', 'scripts/test-executor-multiarch.sh', str(dist), 'amd64'],
                                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
