"""Real child-process locks on synthetic native state; never touches host APT."""
import importlib.util
from contextlib import contextmanager
import select
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
spec = importlib.util.spec_from_file_location('inventory_refresh_observation', ROOT/'scripts/inventory_refresh_observation.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

# The child uses the exact lock namespaces used by native APT/dpkg and executor.
TRY_LOCK = '''import fcntl, os, sys
fd=os.open(sys.argv[1],os.O_RDWR)
try:
 if sys.argv[2]=='native': fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 else: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:
 sys.exit(75)
sys.exit(0)
'''

HOLD_LOCK = TRY_LOCK[:TRY_LOCK.index('sys.exit(0)')] + "os.write(1,b'R')\nsys.stdin.buffer.read(1)\n"


class NativeObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dpkg = self.root/'dpkg'
        self.runtime = self.root/'run'
        self.dpkg.mkdir(mode=0o700)
        self.runtime.mkdir(mode=0o700)
        for directory, name in [(self.dpkg, 'lock-frontend'), (self.dpkg, 'lock'),
                                (self.runtime, 'guarded-update-executor.lock')]:
            (directory/name).write_bytes(b'')
            (directory/name).chmod(0o600)
        (self.dpkg/'status').write_bytes(b'Package: synthetic\nVersion: 1\n')
        (self.dpkg/'updates').mkdir(mode=0o700)
        self.dpkg_fd = os.open(self.dpkg, os.O_RDONLY | os.O_DIRECTORY)
        self.runtime_fd = os.open(self.runtime, os.O_RDONLY | os.O_DIRECTORY)

    def tearDown(self):
        os.close(self.dpkg_fd)
        os.close(self.runtime_fd)
        self.temp.cleanup()

    def attempt(self, path, namespace):
        return subprocess.run([sys.executable, '-I', '-c', TRY_LOCK, str(path), namespace],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=5, check=False).returncode

    @contextmanager
    def held(self, path, namespace):
        child = subprocess.Popen([sys.executable, '-I', '-c', HOLD_LOCK, str(path), namespace],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            self.assertTrue(select.select([child.stdout], [], [], 3)[0])
            self.assertEqual(child.stdout.read(1), b'R')
            yield
        finally:
            child.stdin.close()
            child.wait(timeout=5)
            child.stdout.close()

    def test_busy_each_native_or_executor_lock_unwinds_every_partial_acquisition(self):
        locks = [(self.runtime/'guarded-update-executor.lock', 'executor'),
                 (self.dpkg/'lock-frontend', 'native'), (self.dpkg/'lock', 'native')]
        for path, namespace in locks:
            with self.subTest(held=path.name), self.held(path, namespace):
                with self.assertRaises(p.ObservationError) as caught:
                    p.NativeReadLocks.acquire(self.dpkg_fd, self.runtime_fd, owner=os.getuid())
                self.assertEqual(caught.exception.reason, 'executor_busy' if namespace=='executor' else 'package_manager_busy')
                for other, kind in locks:
                    if other != path:
                        self.assertEqual(self.attempt(other, kind), 0)
            for other, kind in locks:
                self.assertEqual(self.attempt(other, kind), 0)

    def test_fingerprint_rejects_unsafe_files_links_and_update_entries(self):
        guard = p.NativeReadLocks.acquire(self.dpkg_fd, self.runtime_fd, owner=os.getuid())
        status = self.dpkg/'status'
        try:
            status.chmod(0o666)
            with self.assertRaises(p.ObservationError):
                guard.fingerprint(1000, lambda: 100)
            status.chmod(0o644)
            alias = self.root/'status-alias'
            os.link(status, alias)
            with self.assertRaises(p.ObservationError):
                guard.fingerprint(1000, lambda: 100)
            alias.unlink()
            original = self.dpkg/'original'
            status.rename(original)
            status.symlink_to(original)
            with self.assertRaises(p.ObservationError):
                guard.fingerprint(1000, lambda: 100)
            status.unlink()
            original.rename(status)
            (self.dpkg/'arch').mkdir()
            with self.assertRaises(p.ObservationError):
                guard.fingerprint(1000, lambda: 100)
            (self.dpkg/'arch').rmdir()
            (self.dpkg/'updates'/'unexpected').write_bytes(b'synthetic')
            with self.assertRaises(p.ObservationError):
                guard.fingerprint(1000, lambda: 100)
        finally:
            guard.close()

    def test_fingerprint_checks_deadline_inside_reads_and_bounds_state_bytes(self):
        guard = p.NativeReadLocks.acquire(self.dpkg_fd, self.runtime_fd, owner=os.getuid())
        try:
            ticks = [0]
            def advancing():
                ticks[0] += 1
                return ticks[0]
            with self.assertRaises(p.ObservationError) as expired:
                guard.fingerprint(3, advancing)
            self.assertEqual(expired.exception.reason, 'lease_expired')
            with patch.object(p, 'MAX_STATE_BYTES', 3):
                with self.assertRaises(p.ObservationError) as bounded:
                    guard.fingerprint(1000, lambda: 100)
            self.assertEqual(bounded.exception.reason, 'resource_limit')
            self.assertEqual(self.attempt(self.dpkg/'lock', 'native'), 75)
        finally:
            guard.close()

    def test_updates_enumeration_has_a_hard_entry_bound(self):
        guard = p.NativeReadLocks.acquire(self.dpkg_fd, self.runtime_fd, owner=os.getuid())
        try:
            for name in ['0001', '0002']:
                (self.dpkg/'updates'/name).write_bytes(b'')
            with patch.object(p, 'MAX_STATE_FILES', 1):
                with self.assertRaises(p.ObservationError) as caught:
                    guard.fingerprint(1000, lambda: 100)
            self.assertEqual(caught.exception.reason, 'resource_limit')
        finally:
            guard.close()

    def test_fixed_ancestry_replacement_is_detected_even_when_pinned_directory_remains_valid(self):
        root = os.open(self.root, os.O_RDONLY|os.O_DIRECTORY)
        ancestry = p._Ancestry.open(root, ('dpkg',), owner=os.getuid())
        os.close(root)
        try:
            ancestry.verify()
            self.dpkg.rename(self.root/'old-dpkg')
            self.dpkg.mkdir(mode=0o700)
            with self.assertRaises(p.ObservationError):
                ancestry.verify()
        finally:
            ancestry.close()

    def test_exact_release_emits_one_bounded_receipt_after_unlock_with_equal_fingerprints(self):
        guard = p.NativeReadLocks.acquire(self.dpkg_fd, self.runtime_fd, owner=os.getuid())
        nonce='0000000000000001'+'a'*16
        boot='11111111-1111-4111-8111-111111111111'
        ticks=[100]
        def clock():
            ticks[0]+=1
            return boot,ticks[0]
        observation=p.Observation.begin(guard,nonce,boot,'b'*32,'c'*64,99,clock)
        try:
            receipt=observation.finish(nonce)
            self.assertEqual(receipt['outcome'],'released')
            self.assertEqual(receipt['nonce'],nonce)
            self.assertEqual(receipt['boot_id'],boot)
            self.assertEqual(receipt['cache_generation'],'b'*32)
            self.assertEqual(receipt['policy_generation'],'c'*64)
            self.assertLessEqual(99,receipt['lock_open_boottime_ms'])
            self.assertLessEqual(receipt['lock_open_boottime_ms'],receipt['lock_held_until_boottime_ms'])
            self.assertLessEqual(receipt['lock_held_until_boottime_ms'],receipt['released_boottime_ms'])
            self.assertLessEqual(receipt['released_boottime_ms'],receipt['expires_boottime_ms'])
            self.assertEqual(receipt['installed_before_sha256'],receipt['installed_after_sha256'])
            self.assertEqual(self.attempt(self.dpkg/'lock','native'),0)
            with self.assertRaises(p.ObservationError):
                observation.finish(nonce)
        finally:
            guard.close()

    def test_wrong_release_preserves_active_guard_and_failed_exact_release_is_consumed(self):
        nonce='0000000000000001'+'a'*16
        boot='11111111-1111-4111-8111-111111111111'
        guard=p.NativeReadLocks.acquire(self.dpkg_fd,self.runtime_fd,owner=os.getuid())
        observation=p.Observation.begin(guard,nonce,boot,'b'*32,'c'*64,99,lambda:(boot,100))
        try:
            with self.assertRaises(p.ObservationError) as wrong:
                observation.finish('0000000000000002'+'d'*16)
            self.assertEqual(wrong.exception.reason,'invalid_request')
            self.assertEqual(self.attempt(self.dpkg/'lock','native'),75)
            (self.dpkg/'status').write_bytes(b'synthetic changed state')
            with self.assertRaises(p.ObservationError) as changed:
                observation.finish(nonce)
            self.assertEqual(changed.exception.reason,'state_inconsistent')
            self.assertEqual(self.attempt(self.dpkg/'lock','native'),0)
            with self.assertRaises(p.ObservationError):
                observation.finish(nonce)
        finally:
            observation.abort()

    def test_expiry_or_boot_change_cannot_emit_a_receipt_and_releases_only_owned_locks(self):
        nonce='0000000000000001'+'a'*16
        boot='11111111-1111-4111-8111-111111111111'
        for failure in ['expired_before','expired_after','changed_boot','rewound_clock']:
            guard=p.NativeReadLocks.acquire(self.dpkg_fd,self.runtime_fd,owner=os.getuid())
            phase=['begin']
            def clock():
                if phase[0]=='finish':
                    if failure=='expired_before' or failure=='expired_after' and guard._closed:
                        return boot,120101
                    if failure=='changed_boot':
                        return '22222222-2222-4222-8222-222222222222',101
                    if failure=='rewound_clock':
                        return boot,99
                return boot,100
            observation=p.Observation.begin(guard,nonce,boot,'b'*32,'c'*64,99,clock)
            try:
                phase[0]='finish'
                with self.subTest(failure=failure),self.assertRaises(p.ObservationError):
                    observation.finish(nonce)
                self.assertEqual(self.attempt(self.dpkg/'lock','native'),0)
                with self.assertRaises(p.ObservationError):
                    observation.finish(nonce)
            finally:
                observation.abort()

    def test_native_reference_replacement_is_a_static_failure(self):
        guard=p.NativeReadLocks.acquire(self.dpkg_fd,self.runtime_fd,owner=os.getuid())
        try:
            (self.dpkg/'lock').rename(self.dpkg/'retired-lock')
            with self.assertRaises(p.ObservationError):
                guard.verify()
        finally:
            guard.close()

    def test_installed_fingerprint_is_stable_and_distinguishes_missing_empty_and_changed_state(self):
        guard = p.NativeReadLocks.acquire(self.dpkg_fd, self.runtime_fd, owner=os.getuid())
        try:
            original = guard.fingerprint(1000, lambda: 100)
            self.assertEqual(guard.fingerprint(1000, lambda: 100), original)
            (self.dpkg/'arch').write_bytes(b'')
            empty = guard.fingerprint(1000, lambda: 100)
            self.assertNotEqual(original, empty)
            (self.dpkg/'arch').write_bytes(b'synthetic-arch\n')
            arch = guard.fingerprint(1000, lambda: 100)
            self.assertNotEqual(empty, arch)
            (self.dpkg/'updates'/'0001').write_bytes(b'synthetic pending state')
            updates = guard.fingerprint(1000, lambda: 100)
            self.assertNotEqual(arch, updates)
            (self.dpkg/'status').write_bytes(b'Package: synthetic\nVersion: 2\n')
            self.assertNotEqual(updates, guard.fingerprint(1000, lambda: 100))
        finally:
            guard.close()

    def test_second_handle_cannot_drop_process_owned_native_locks(self):
        guard = p.NativeReadLocks.acquire(self.dpkg_fd, self.runtime_fd, owner=os.getuid())
        second = None
        try:
            with self.assertRaises(p.ObservationError):
                second = p.NativeReadLocks.acquire(self.dpkg_fd, self.runtime_fd, owner=os.getuid())
            for name in ['lock-frontend', 'lock']:
                self.assertEqual(self.attempt(self.dpkg/name, 'native'), 75)
        finally:
            if second is not None:
                second.close()
            guard.close()

    def test_guard_blocks_real_native_writers_and_executor_until_closed(self):
        guard = p.NativeReadLocks.acquire(self.dpkg_fd, self.runtime_fd, owner=os.getuid())
        try:
            for name in ['lock-frontend', 'lock']:
                with self.subTest(native=name):
                    self.assertEqual(self.attempt(self.dpkg/name, 'native'), 75)
            self.assertEqual(self.attempt(self.runtime/'guarded-update-executor.lock', 'executor'), 75)
        finally:
            guard.close()
        for name in ['lock-frontend', 'lock']:
            self.assertEqual(self.attempt(self.dpkg/name, 'native'), 0)
        self.assertEqual(self.attempt(self.runtime/'guarded-update-executor.lock', 'executor'), 0)


if __name__ == '__main__':
    unittest.main()
