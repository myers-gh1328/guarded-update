#!/usr/bin/env python3
"""Hosted disposable Linux proof only. Never packaged or installed on endpoints."""
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import shutil
import subprocess
import sys
import time

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
WORKER = 60001
READER = 60002
MIB = 1024 * 1024
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
       'PYTHONDONTWRITEBYTECODE': '1'}


def command(argv, **kwargs):
    try:
        return subprocess.run(argv, check=True, env=ENV, timeout=kwargs.pop('timeout', 60),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    except subprocess.CalledProcessError as error:
        # Fixture-only proof commands never handle repository credentials or keys.
        detail = error.stderr.decode('utf-8', errors='replace')[-8000:]
        raise RuntimeError('Disposable proof command failed: '+detail) from None


def module():
    spec = importlib.util.spec_from_file_location('inventory_refresh_storage', ROOT/'scripts/inventory_refresh_storage.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def write_data(path, count):
    with open(path, 'xb', buffering=0) as output:
        chunk = b'x' * MIB
        for _ in range(count):
            output.write(chunk)
        os.fsync(output.fileno())


def fingerprint(paths):
    digest = hashlib.sha256()
    for base in paths:
        base = Path(base)
        entries = sorted(base.rglob('*')) if base.is_dir() else [base]
        for entry in entries:
            if entry.is_symlink():
                digest.update(str(entry).encode()+b'link'+os.readlink(entry).encode())
            elif entry.is_file():
                digest.update(str(entry).encode())
                with open(entry, 'rb') as stream:
                    while chunk := stream.read(65536):
                        digest.update(chunk)
    return digest.digest()


def drop(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def identity_check(cache, uid):
    script = '''import os,sys
try:
 os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND)
except PermissionError:
 sys.exit(0)
sys.exit(1)
'''
    path = cache/('generation-'+'2'*32)/'synthetic_Packages'
    result = subprocess.run([sys.executable, '-c', script, str(path)], env=ENV,
                            preexec_fn=lambda: drop(uid), timeout=10,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert result.returncode == 0, 'Published indexes must not be writable by endpoint UIDs'


def child_reader(cache):
    drop(READER)
    storage = module()
    fd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY)
    try:
        store = storage.Store(fd, 0, READER, WORKER)
        with store.lease_current() as lease:
            assert lease.verify_index('synthetic_Packages')[0] == 40*MIB
            print('ready', flush=True)
            assert sys.stdin.readline() == 'release\n'
            assert lease.verify_index('synthetic_Packages')[0] == 40*MIB
    finally:
        os.close(fd)


def metrics(path):
    return {key: int(value) for key, value in
            (line.split() for line in path.read_text().splitlines())}


def workload(base, slice_name):
    cache = base/'cache'
    storage = module()
    fd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY)
    store = storage.Store(fd, 0, READER, WORKER)
    cgroup = Path('/sys/fs/cgroup')/slice_name
    assert int((cgroup/'memory.max').read_text()) == 256*MIB
    assert int((cgroup/'memory.swap.max').read_text()) == 0
    assert int((cgroup/'pids.max').read_text()) == 64
    limits = os.statvfs(cache)
    assert limits.f_blocks*limits.f_frsize == 128*MIB
    assert limits.f_files == 32768
    def stage(number, size):
        path = cache/('staging-'+str(number)*32)/'lists'
        path.mkdir(parents=True, mode=0o700)
        path.parent.chmod(0o700)
        write_data(path/'synthetic_Packages', size)
        os.chown(path/'synthetic_Packages', WORKER, WORKER)
        os.chown(path, WORKER, WORKER)
        os.chown(path.parent, WORKER, WORKER)
    reader = None
    try:
        stage(1, 40)
        store.publish('1'*32, '2'*32, 'a'*64, '2026-01-01T00:00:00Z')
        identity_check(cache, WORKER)
        identity_check(cache, READER)
        reader = subprocess.Popen([sys.executable, '-B', str(SCRIPT), '--reader', str(cache)],
                                  env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        with selectors.DefaultSelector() as selector:
            selector.register(reader.stdout, selectors.EVENT_READ)
            assert selector.select(15), 'Native reader lease failed to start'
        ready = reader.stdout.readline()
        if ready != 'ready\n':
            reader.wait(timeout=10)
            raise AssertionError('Native reader failed: '+reader.stderr.read(8000))
        stage(3, 40)
        store.publish('3'*32, '4'*32, 'a'*64, '2026-01-01T00:00:01Z')
        assert not store.retire('2'*32), 'Leased old generation must be retained'
        before = (cache/'current.json').read_bytes()
        try:
            write_data(cache/'oversize-staging', 60)
        except OSError as error:
            assert error.errno == errno.ENOSPC, 'Expected tmpfs hard byte limit'
        else:
            raise AssertionError('Aggregate cache byte limit was not enforced')
        assert (cache/'current.json').read_bytes() == before
        (cache/'oversize-staging').unlink()
        with store.lease_current() as lease:
            assert lease.verify_index('synthetic_Packages')[0] == 40*MIB
        reader.stdin.write('release\n')
        reader.stdin.flush()
        assert reader.wait(timeout=15) == 0
        reader = None
        assert store.retire('2'*32)
        # Unlinked open index pages/inodes must remain charged until the FD closes.
        write_data(cache/'held-open', 16)
        held = os.open(cache/'held-open', os.O_RDONLY)
        allocated = os.statvfs(cache).f_bavail
        allocated_inodes = os.statvfs(cache).f_favail
        (cache/'held-open').unlink()
        assert os.statvfs(cache).f_bavail == allocated
        assert os.statvfs(cache).f_favail == allocated_inodes
        os.close(held)
        assert os.statvfs(cache).f_bavail > allocated
        assert os.statvfs(cache).f_favail > allocated_inodes
        # Exhaust inode quota without filling bytes or crossing the cgroup ceiling.
        saturation = cache/'inodes'
        saturation.mkdir()
        count = 0
        try:
            while count <= 32768:
                created = os.open(saturation/str(count), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(created)
                count += 1
        except OSError as error:
            assert error.errno == errno.ENOSPC, 'Expected tmpfs hard inode limit'
        else:
            raise AssertionError('Aggregate cache inode limit was not enforced')
        assert os.statvfs(cache).f_favail == 0
        for entry in saturation.iterdir():
            entry.unlink()
        saturation.rmdir()
        # Prove the aggregate memory controller actually kills only its owned child.
        previous = metrics(cgroup/'memory.events').get('oom_kill', 0)
        bomb = subprocess.Popen([sys.executable, '-c',
            "open('/proc/self/oom_score_adj','w').write('1000')\nchunks=[]\nwhile True: chunks.append(bytearray(1024*1024))"], env=ENV,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            assert bomb.wait(timeout=45) == -9, 'Expected cgroup OOM termination'
        finally:
            if bomb.poll() is None:
                bomb.kill()
                bomb.wait(timeout=10)
        assert metrics(cgroup/'memory.events')['oom_kill'] > previous
        with store.lease_current() as lease:
            assert lease.verify_index('synthetic_Packages')[0] == 40*MIB
        print(json.dumps({'schema_version': 1, 'tmpfs_bytes': 128*MIB,
            'tmpfs_inodes': 32768, 'memory_max': 256*MIB,
            'memory_peak': int((cgroup/'memory.peak').read_text()),
            'byte_limit_enforced': True, 'inode_limit_enforced': True,
            'memory_limit_enforced': True, 'old_reader_retained': True,
            'unlinked_open_charged': True, 'unlinked_open_inode_charged': True,
            'cross_uid_immutable': True,
            'previous_current_preserved_after_resource_failure': True}))
    finally:
        if reader is not None:
            reader.kill()
            reader.wait(timeout=10)
        os.close(fd)


def hosted():
    if sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('This proof requires an isolated hosted Linux runner as root')
    assert Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'cgroup v2 required'
    prefix = 'inventoryproof'+secrets.token_hex(6)
    base = Path('/run')/prefix
    base.mkdir(mode=0o755)
    cache = base/'cache'
    cache.mkdir()
    fixture = base/'executor-fixture'
    fixture.mkdir(mode=0o700)
    for entry in ['binary', 'unit', 'config', 'key', 'state']:
        (fixture/entry).write_bytes(b'synthetic-prepared-executor-continuity')
    unchanged = ['/var/lib/dpkg/status', '/var/lib/apt/lists', '/etc/apt', fixture]
    before = fingerprint(unchanged)
    slice_name = prefix+'.slice'
    unit_name = prefix+'-workload.service'
    unit_file = Path('/run/systemd/system')/slice_name
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit('Proof interrupted')))
    unit_file.write_text('[Unit]\nDescription=Disposable inventory containment proof\n'
                         '[Slice]\nMemoryAccounting=yes\nMemoryMax=256M\n'
                         'MemorySwapMax=0\nTasksMax=64\n')
    mounted = False
    try:
        command(['/bin/systemctl', 'daemon-reload'])
        command(['/bin/systemctl', 'start', slice_name])
        command(['/bin/mount', '-t', 'tmpfs', '-o', 'size=128m,nr_inodes=32768,mode=0755',
                 'inventory-proof', str(cache)])
        mounted = True
        result = command(['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe',
            '--unit='+unit_name, '--slice='+slice_name, '-p', 'OOMPolicy=continue',
            '-p', 'RuntimeMaxSec=240', '-p', 'TimeoutStopSec=10',
            '-p', 'NoNewPrivileges=yes', '-p', 'ProtectSystem=strict',
            '-p', 'ProtectControlGroups=yes', '-p', 'PrivateTmp=yes',
            '-p', 'ReadWritePaths='+str(base),
            sys.executable, '-B', str(SCRIPT), '--workload', str(base), slice_name], timeout=300)
        proof = json.loads(result.stdout)
        assert fingerprint(unchanged) == before, 'Host/executor state changed during proof'
        proof['host_apt_and_executor_state_unchanged'] = True
    finally:
        command(['/bin/systemctl', 'stop', unit_name])
        cgroup = Path('/sys/fs/cgroup')/slice_name
        assert metrics(cgroup/'cgroup.events')['populated'] == 0, 'Owned cgroup cleanup unconfirmed'
        if mounted:
            command(['/bin/umount', str(cache)])
        command(['/bin/systemctl', 'stop', slice_name])
        unit_file.unlink()
        command(['/bin/systemctl', 'daemon-reload'])
        shutil.rmtree(base)
    proof['owned_cgroup_empty_before_unmount'] = True
    proof['scope'] = 'storage_and_resource_containment'
    proof['apt_refresh_exercised'] = False
    print(json.dumps(proof, sort_keys=True))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--reader':
        child_reader(Path(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == '--workload':
        workload(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 1:
        hosted()
    else:
        raise SystemExit('Invalid disposable proof invocation')
