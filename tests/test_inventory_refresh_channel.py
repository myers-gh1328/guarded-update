"""Real descriptor channel fixtures; no service starts or device mutations."""
import json
import os
from pathlib import Path
from dataclasses import replace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_state import Journal
from inventory_refresh_cached_observation import ObservationJob, ObservationResult, ReleaseGrant
from inventory_refresh_channel import ObservationChannel, ChannelError

BOOT='11111111-1111-4111-8111-111111111111'
NONCE='0000000000000001'+'a'*16
POLICY='b'*64


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.fds=[]
        for name in ['state','control','results']:
            path=self.root/name;path.mkdir(mode=0o700)
            self.fds.append(os.open(path,os.O_RDONLY|os.O_DIRECTORY))
        self.journal=Journal(self.fds[0],owner=os.getuid())
        with self.journal.exclusive():
            self.journal.initialize('a'*32)
        self.parent=ObservationChannel(self.fds[1],self.fds[2],journal=self.journal,owner=os.getuid())
        self.child=ObservationChannel(self.fds[1],self.fds[2],owner=os.getuid())
        self.job=ObservationJob(1,'c'*32,NONCE,1,BOOT,'d'*32,POLICY,'2026-10-28T07:00:00Z',100,101,1000)
        self.lease={'nonce':NONCE,'boot_id':BOOT,'cache_generation':'d'*32,'policy_generation':POLICY,
                    'lock_open_boottime_ms':110,'expires_boottime_ms':1000}
        self.receipt=dict(self.lease,lock_held_until_boottime_ms=125,released_boottime_ms=126,
                          outcome='released',installed_before_sha256='f'*64,installed_after_sha256='f'*64)

    def tearDown(self):
        self.parent.close();self.child.close()
        for fd in self.fds:os.close(fd)
        self.temp.cleanup()

    def admit(self,job=None):
        job=self.job if job is None else job
        self.journal.receive('observation',job.operation_nonce,job.boot_id,job.accepted_boottime_ms,job.policy_generation)
        self.assertTrue(self.journal.start('observation',job.operation_nonce,job.boot_id,job.started_boottime_ms,policy=job.policy_generation))
        self.parent.write_job(job)

    def opened(self):
        result=ObservationResult.create(self.job,'opened',lease=self.lease)
        self.child.write_result(result)
        self.parent.read_result(expected_job=self.job)
        return result

    def grant(self,when=120):
        self.journal.receive('release',NONCE,BOOT,when,POLICY)
        self.assertTrue(self.journal.start('release',NONCE,BOOT,when,policy=POLICY))
        value=ReleaseGrant(self.job,when)
        self.parent.write_release(value)
        return value

    def test_readonly_control_and_writable_results_cannot_alias_same_directory(self):
        with self.assertRaises(ValueError):
            channel=ObservationChannel(self.fds[1],self.fds[1],owner=os.getuid())
            channel.close()

    def test_close_attempts_both_owned_descriptors_after_one_uncertain_close(self):
        first,second=self.child._control,self.child._results
        real=os.close;seen=[]
        def close(fd):
            seen.append(fd)
            if fd==first:raise OSError('synthetic close failure')
            return real(fd)
        try:
            with patch('inventory_refresh_channel.os.close',side_effect=close):
                with self.assertRaises((OSError,ValueError)):
                    self.child.close()
            self.assertIn(second,seen)
        finally:
            # The fixture knows its injected first close did not actually run.
            real(first)
            if second not in seen:real(second)

    def test_parent_writes_require_held_durable_running_records(self):
        with self.assertRaises(ValueError):self.parent.write_job(self.job)
        with self.journal.exclusive():
            with self.assertRaises(ValueError):self.parent.write_job(self.job)
            self.admit()
            with self.assertRaises(ValueError):self.child.write_job(self.job)
            before=(self.root/'control/job.json').read_bytes()
            for job in [replace(self.job,job_id='e'*32),replace(self.job,cache_generation='e'*32),
                        replace(self.job,deadline_boottime_ms=900)]:
                with self.subTest(job=job),self.assertRaises(ValueError):self.parent.write_job(job)
            self.assertEqual((self.root/'control/job.json').read_bytes(),before)

    def test_release_requires_opened_result_and_exact_frozen_release_start(self):
        with self.journal.exclusive():
            self.admit()
            with self.assertRaises(ValueError):self.parent.write_release(ReleaseGrant(self.job,120))
            self.opened()
            with self.assertRaises(ValueError):self.parent.write_release(ReleaseGrant(self.job,120))
            self.journal.receive('release',NONCE,BOOT,121,POLICY)
            self.journal.start('release',NONCE,BOOT,121,policy=POLICY)
            with self.assertRaises(ValueError):self.parent.write_release(ReleaseGrant(self.job,120))
            self.parent.write_release(ReleaseGrant(self.job,121))
            before=(self.root/'control/release.json').read_bytes()
            with patch('inventory_refresh_channel.os.fsync',wraps=os.fsync) as sync:
                self.parent.write_release(ReleaseGrant(self.job,121))
                self.assertGreaterEqual(sync.call_count,2)
            self.assertEqual((self.root/'control/release.json').read_bytes(),before)

    def test_parent_rejects_raw_released_result_without_exact_root_grant(self):
        with self.journal.exclusive():
            self.admit();self.opened()
            released=ObservationResult.create(self.job,'released',receipt=self.receipt)
            (self.root/'results/result.json').write_bytes(released.encoded())
            with self.assertRaises(ValueError):
                self.parent.read_result(expected_job=self.job)

    def test_released_result_needs_grant_and_opened_lease_cannot_be_rewritten(self):
        with self.journal.exclusive():
            self.admit();opened=self.opened()
            released=ObservationResult.create(self.job,'released',receipt=self.receipt)
            with self.assertRaises(ValueError):self.child.write_result(released)
            self.grant()
            changed=ObservationResult.create(self.job,'released',receipt=dict(self.receipt,expires_boottime_ms=999))
            with self.assertRaises(ValueError):self.child.write_result(changed)
            self.child.write_result(released)
            self.parent.read_result(expected_job=self.job)
            with self.assertRaises(ValueError):self.child.write_result(opened)
            # A raw stale-file replacement also cannot roll this parent's tracker back.
            (self.root/'results/result.json').write_bytes(opened.encoded())
            with self.assertRaises(ValueError):self.parent.read_result(expected_job=self.job)

    def test_lower_job_residue_is_ignored_but_old_child_cannot_overwrite_new_job(self):
        with self.journal.exclusive():
            self.admit();old=self.opened();self.grant()
            self.journal.finish('release',NONCE,BOOT,130,'failed',reason='internal_error')
            self.journal.finish('observation',NONCE,BOOT,130,'failed',reason='internal_error')
            newer=replace(self.job,job_id='e'*32,operation_nonce='0000000000000002'+'e'*16,
                          helper_sequence=2,accepted_boottime_ms=200,started_boottime_ms=201,deadline_boottime_ms=1100)
            self.admit(newer)
            self.assertIsNone(self.child.read_release(expected_job=newer))
            self.assertIsNone(self.parent.read_result(expected_job=newer))
            with self.assertRaises(ValueError):self.child.write_result(old)

    def test_root_channel_rejects_unsafe_file_modes_and_links_without_repair(self):
        with self.journal.exclusive():self.admit()
        job=self.root/'control/job.json'
        job.chmod(0o644)
        with self.assertRaises(ValueError):self.child.read_job()
        self.assertEqual(job.stat().st_mode&0o777,0o644)
        job.chmod(0o400)
        alias=self.root/'alias';os.link(job,alias)
        with self.assertRaises(ValueError):self.child.read_job()
        alias.unlink()
        original=job.read_bytes();job.unlink();alias.write_bytes(original);alias.chmod(0o400)
        job.symlink_to(alias)
        with self.assertRaises((OSError,ValueError)):self.child.read_job()
        self.assertTrue(job.is_symlink())

    def test_temp_collision_is_not_deleted_and_zero_progress_cannot_acknowledge(self):
        with self.journal.exclusive():
            self.journal.receive('observation',NONCE,BOOT,100,POLICY)
            self.journal.start('observation',NONCE,BOOT,101,policy=POLICY)
            collision=self.root/'control'/('.observation-'+'a'*32)
            collision.write_bytes(b'synthetic existing temp')
            with patch('inventory_refresh_channel.secrets.token_hex',return_value='a'*32):
                with self.assertRaises(ChannelError) as raised:self.parent.write_job(self.job)
                self.assertFalse(raised.exception.may_be_visible)
            self.assertEqual(collision.read_bytes(),b'synthetic existing temp')
            with patch('inventory_refresh_channel.os.write',return_value=0):
                with self.assertRaises(ChannelError) as raised:self.parent.write_job(self.job)
                self.assertFalse(raised.exception.may_be_visible)
            self.assertFalse((self.root/'control/job.json').exists())

    def test_read_growth_is_bounded_and_parent_result_requires_sync_barrier(self):
        with self.journal.exclusive():
            self.admit()
            calls=[]
            def growing(fd,size):
                calls.append(size)
                return b'x'*size
            with patch('inventory_refresh_channel.os.read',side_effect=growing):
                with self.assertRaises(ValueError):self.child.read_job()
            self.assertEqual(sum(calls),65537)
            self.opened()
            before=self.parent._last_result
            with patch('inventory_refresh_channel.os.fsync',side_effect=OSError('synthetic barrier failure')):
                with self.assertRaises(ChannelError):self.parent.read_result(expected_job=self.job)
            self.assertIs(self.parent._last_result,before)

    def test_cleanup_error_cannot_hide_postrename_visibility_uncertainty(self):
        renamed=False
        replace=os.replace;stat_call=os.stat;sync=os.fsync
        def rename(*args,**kwargs):
            nonlocal renamed
            result=replace(*args,**kwargs);renamed=True
            return result
        def metadata(path,*args,**kwargs):
            if renamed and isinstance(path,str) and path.startswith('.observation-'):
                raise OSError('synthetic cleanup metadata error')
            return stat_call(path,*args,**kwargs)
        def fail_sync(fd):
            if renamed and fd==self.parent._control:
                raise OSError('synthetic directory sync error')
            return sync(fd)
        with self.journal.exclusive():
            self.journal.receive('observation',NONCE,BOOT,100,POLICY)
            self.journal.start('observation',NONCE,BOOT,101,policy=POLICY)
            with patch('inventory_refresh_channel.os.replace',side_effect=rename), \
                 patch('inventory_refresh_channel.os.stat',side_effect=metadata), \
                 patch('inventory_refresh_channel.os.fsync',side_effect=fail_sync):
                with self.assertRaises(ChannelError) as raised:
                    self.parent.write_job(self.job)
                self.assertTrue(raised.exception.may_be_visible)

    def test_identical_job_acknowledgement_rechecks_file_and_directory_durability(self):
        with self.journal.exclusive():
            self.admit()
            before=(self.root/'control/job.json').read_bytes()
            real=os.fsync
            with patch('inventory_refresh_channel.os.fsync',wraps=real) as sync:
                self.parent.write_job(self.job)
                self.assertGreaterEqual(sync.call_count,2)
            self.assertEqual((self.root/'control/job.json').read_bytes(),before)

    def test_root_job_open_grant_release_roundtrip_has_exact_modes_and_frozen_fields(self):
        with self.journal.exclusive():
            self.admit()
            self.assertEqual(self.child.read_job(),self.job)
            opened=ObservationResult.create(self.job,'opened',lease=self.lease)
            self.child.write_result(opened)
            self.assertEqual(self.parent.read_result(expected_job=self.job).encoded(),opened.encoded())
            self.journal.receive('release',NONCE,BOOT,120,POLICY)
            self.assertTrue(self.journal.start('release',NONCE,BOOT,120,policy=POLICY))
            grant=ReleaseGrant(self.job,120)
            self.parent.write_release(grant)
            self.assertEqual(self.child.read_release(expected_job=self.job),grant)
            released=ObservationResult.create(self.job,'released',receipt=self.receipt)
            self.child.write_result(released)
            self.assertEqual(self.parent.read_result(expected_job=self.job).encoded(),released.encoded())
        for path,mode in [('control/job.json',0o400),('control/release.json',0o400),('results/result.json',0o600)]:
            self.assertEqual((self.root/path).stat().st_mode&0o777,mode)
            self.assertEqual((self.root/path).stat().st_nlink,1)


if __name__=='__main__':
    unittest.main()
