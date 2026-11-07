#!/usr/bin/env python3
"""Disposable hosted-Linux proof of memfd, isolated dpkg, and transient systemd.

This tests kernel/runner primitives, not any external controller, installer,
production service, authorization, crash recovery or device configuration.
"""
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import uuid


def run(args, *, pass_fds=(), capture=False):
    return subprocess.run(args, check=True, timeout=45, pass_fds=pass_fds,
                          stdin=subprocess.DEVNULL, capture_output=capture, text=True,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})


def main():
    if (os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or
            not Path('/run/systemd/system').is_dir()):
        raise SystemExit('Requires an ephemeral GitHub-hosted Linux runner')
    unit = 'guarded-update-fixture-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='guarded-update-proof-') as directory:
        root = Path(directory)
        package = root / 'package'; (package / 'DEBIAN').mkdir(parents=True)
        (package / 'DEBIAN/control').write_text('Package: guarded-update-fixture\nVersion: 1.0\nArchitecture: all\nMaintainer: fixture <fixture@example.invalid>\nDescription: disposable test\n')
        payload = package / 'usr/share/guarded-update-fixture'; payload.mkdir(parents=True)
        (payload / 'evidence').write_text('synthetic\n')
        deb = root / 'fixture.deb'
        run(['/usr/bin/dpkg-deb', '--build', '--root-owner-group', str(package), str(deb)])
        raw = deb.read_bytes(); digest = hashlib.sha256(raw).digest()
        fd = os.memfd_create('fixture-package', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        try:
            view = memoryview(raw)
            while view: view = view[os.write(fd, view):]
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals != seals:
                raise RuntimeError('memfd seal verification failed')
            try: os.write(fd, b'x')
            except OSError as error:
                if error.errno != errno.EPERM: raise
            else: raise RuntimeError('sealed memfd was writable')
            os.lseek(fd, 0, os.SEEK_SET)
            if hashlib.sha256(os.read(fd, len(raw) + 1)).digest() != digest:
                raise RuntimeError('sealed bytes differ')
            target = root / 'root'; target.mkdir()
            admin = target / 'var/lib/dpkg'
            (admin / 'info').mkdir(parents=True)
            (admin / 'updates').mkdir()
            (admin / 'status').write_text('')
            run(['/usr/bin/dpkg', '--root=' + str(target), '--install', '/proc/self/fd/' + str(fd)], pass_fds=(fd,))
            if (target / 'usr/share/guarded-update-fixture/evidence').read_text() != 'synthetic\n':
                raise RuntimeError('isolated fixture payload missing')
        finally:
            os.close(fd)
        try:
            run(['/usr/bin/systemd-run', '--unit=' + unit, '--property=PrivateNetwork=yes',
                 '--property=RuntimeMaxSec=90', '--', '/usr/bin/sleep', '90'])
            run(['/usr/bin/systemctl', 'is-active', '--quiet', unit + '.service'])
            run(['/usr/bin/systemctl', 'stop', unit + '.service'])
            state = subprocess.run(['/usr/bin/systemctl', 'is-active', unit + '.service'],
                                   check=False, timeout=15, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
            if state.returncode not in (3, 4):
                raise RuntimeError('stopped synthetic unit unexpectedly active')
        finally:
            subprocess.run(['/usr/bin/systemctl', 'stop', unit + '.service'], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    print('Synthetic sealed-fd dpkg and isolated transient-unit proof passed.')


if __name__ == '__main__': main()
