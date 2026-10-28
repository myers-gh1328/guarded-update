#!/usr/bin/python3
"""Disposable hosted-Linux proof of native observation primitives only.

No refresh, installation, update execution or cache-coherence claim is made.
The receipt's cache/policy identities are synthetic; the native locks, installed
state fingerprint, monotonic clock and release evidence are actual runner data.
"""
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_observation import NativeReadLocks, Observation, prepare_fixed_executor_guard
from inventory_refresh_status import PublicStatus

TRY_LOCK = '''import fcntl, os, sys
fd=os.open(sys.argv[1],os.O_RDWR|os.O_NOFOLLOW)
try:
 if sys.argv[2]=='native': fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 else: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:
 sys.exit(75)
sys.exit(0)
'''
LOCKS = (('/var/lib/dpkg/lock-frontend', 'native'),
         ('/var/lib/dpkg/lock', 'native'),
         ('/run/guarded-update-executor.lock', 'executor'))


def attempt(path, namespace):
    return subprocess.run([sys.executable, '-I', '-c', TRY_LOCK, path, namespace],
                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=5, check=False).returncode


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Disposable hosted Linux root runner required')
    with open('/proc/sys/kernel/random/boot_id', 'r', encoding='ascii') as source:
        boot = source.read(64).strip()
    def clock():
        return boot, time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
    accepted = clock()[1]
    prepare_fixed_executor_guard()
    read_only=os.environ.get('GUARDED_UPDATE_NATIVE_READONLY_PROOF')=='1'
    if read_only:
        try:
            writable=os.open('/run/guarded-update-executor.lock',os.O_WRONLY|os.O_NOFOLLOW)
        except OSError as error:
            assert error.errno==errno.EROFS, 'Expected actual read-only filesystem denial'
        else:
            os.close(writable)
            raise AssertionError('Observation sandbox unexpectedly allows writable guard access')
    deadline=accepted+120000
    guard = NativeReadLocks.fixed(deadline_ms=deadline,now=lambda:clock()[1])
    observation = None
    try:
        observation = Observation.begin(guard, '0000000000000001'+'a'*16, boot,
                                        'b'*32, 'c'*64, accepted, clock, deadline_ms=deadline)
        active=observation.lease()
        assert active['expires_boottime_ms']==deadline
        if not read_only:
            for path, namespace in LOCKS:
                assert attempt(path, namespace) == 75, 'Native writer exclusion failed'
        receipt = observation.finish('0000000000000001'+'a'*16)
        assert receipt['outcome'] == 'released'
        assert all(receipt[field]==value for field,value in active.items())
        document={'schema_version':1,'operation_nonce':None,'phase':'unconfirmed','reason':'cache_unavailable',
                  'policy_generation':None,'cache_generation':None,'successful_checked_at':None,
                  'started_at':None,'finished_at':None,'attempt':None,'observation_lease':None,
                  'observation_receipt':receipt}
        assert json.loads(PublicStatus.create(document).encoded())['observation_receipt']==receipt
        assert receipt['installed_before_sha256'] == receipt['installed_after_sha256']
        if not read_only:
            for path, namespace in LOCKS:
                assert attempt(path, namespace) == 0, 'Owned lock release failed'
        return {'schema_version': 1, 'scope': 'native_observation_primitives',
                'cache_policy_identities': 'synthetic', 'native_package_writer_exclusion': not read_only,
                'actual_executor_guard_exclusion': not read_only, 'fixed_ancestry_verified': True,
                'active_open_matches_released_receipt': True, 'typed_public_status_validated': True,
                'read_only_filesystem_verified': read_only, 'root_job_deadline_bound': True,
                'installed_state_unchanged_during_observation': True, 'receipt': receipt,
                'independent_deadline_enforcement_verified': False,
                'durable_coordinator_verified': False, 'cache_pin_verified': False}
    finally:
        if observation is not None:
            observation.abort()
        else:
            guard.close()


if __name__ == '__main__':
    print(json.dumps(main(), sort_keys=True))
