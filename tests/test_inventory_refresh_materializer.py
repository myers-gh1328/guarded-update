"""Real-FD synthetic input preparation; no service/remote commands."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_inventory_refresh_policy import fixture
from inventory_refresh_state import Journal
from inventory_refresh_policy_admission import PolicyGuard
from inventory_refresh_materialized_policy import MaterializedPolicy
from inventory_refresh_worker import parse_job
from inventory_refresh_materializer import RefreshMaterializer


class RefreshMaterializerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        for name in ('apt','run','cache','state','policy'):
            path=self.root/name;path.mkdir(mode=0o750);path.chmod(0o750)
        (self.root/'state').chmod(0o700)
        for name,raw in [('policy.json',json.dumps(fixture()).encode()),('policy-commitment.key',b'k'*32)]:
            path=self.root/'policy'/name;path.write_bytes(raw);path.chmod(0o600)
        self.fds={name:os.open(self.root/name,os.O_RDONLY|os.O_DIRECTORY) for name in ('apt','run','cache','state','policy')}
        self.policy=PolicyGuard(self.fds['policy'],owner=os.getuid(),group=os.getgid())
        self.journal=Journal(self.fds['state'],owner=os.getuid());self.lock=self.journal.exclusive();self.lock.__enter__()
        self.journal.initialize('a'*32)
        self.nonce='0000000000000001'+'a'*16;self.boot='11111111-1111-4111-8111-111111111111'
        self.journal.receive('refresh',self.nonce,self.boot,100,self.policy.generation)
        self.journal.start('refresh',self.nonce,self.boot,101,policy=self.policy.generation)
        self.preparer=None

    def tearDown(self):
        if self.preparer is not None:self.preparer.close()
        self.lock.__exit__(None,None,None);self.policy.close()
        for fd in self.fds.values():os.close(fd)
        self.temp.cleanup()

    def prepare(self):
        self.preparer=RefreshMaterializer(self.fds['apt'],self.fds['run'],self.fds['cache'],
            worker_uid=os.getuid(),worker_gid=os.getgid(),owner=os.getuid())
        return self.preparer.prepare(self.journal,self.policy)

    def test_actual_rendered_files_job_and_private_stage_match_new_durable_start(self):
        job=self.prepare()
        self.assertEqual(parse_job((self.root/'run/job.json').read_bytes()),job)
        self.assertEqual(job['operation_nonce'],self.nonce);self.assertEqual(job['helper_sequence'],1)
        self.assertEqual((job['accepted_boottime_ms'],job['started_boottime_ms'],job['deadline_boottime_ms']),(100,101,600101))
        self.assertEqual(job['policy_generation'],self.policy.generation)
        self.assertEqual(job['config_sha256'],hashlib.sha256((self.root/'run/worker-apt.conf').read_bytes()).hexdigest())
        with MaterializedPolicy(self.fds['apt'],self.fds['run'],self.policy.render(job['staging_token']),os.getgid(),owner=os.getuid()) as bound:
            bound.recheck()
        for name in ('sources.sources','auth.conf','trust/debian.gpg'):
            info=(self.root/'apt'/name).lstat();self.assertEqual(info.st_mode&0o777,0o640)
        stage=self.root/'cache'/('staging-'+job['staging_token'])
        for name in ('','lists','lists/partial','cache','archives','log','tmp'):
            info=(stage/name).lstat();self.assertEqual(info.st_mode&0o777,0o700)
        self.assertNotIn('synthetic-private-value',repr(self.preparer))
        with self.assertRaises(ValueError):self.preparer.prepare(self.journal,self.policy)

    def test_all_stage_chmods_precede_worker_ownership_transfer(self):
        real_chmod=os.fchmod;real_chown=os.fchown;transferred=set()
        def chmod(fd,mode):
            info=os.fstat(fd)
            self.assertNotIn((info.st_dev,info.st_ino),transferred,'CAP3 cannot chmod after worker ownership transfer')
            return real_chmod(fd,mode)
        def chown(fd,uid,gid):
            info=os.fstat(fd)
            if info.st_mode&0o170000==0o040000 and info.st_mode&0o777==0o700:
                transferred.add((info.st_dev,info.st_ino))
            return real_chown(fd,uid,gid)
        with patch('inventory_refresh_materializer.os.fchmod',side_effect=chmod),patch('inventory_refresh_materializer.os.fchown',side_effect=chown):self.prepare()
        self.assertEqual(len(transferred),7)

    def test_unsafe_existing_files_and_symlink_directories_are_not_repaired(self):
        target=self.root/'apt/auth.conf';target.symlink_to(self.root/'outside')
        with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(target.is_symlink());self.assertFalse((self.root/'outside').exists())
        self.assertTrue(self.journal.snapshot()['unconfirmed'])

    def test_nonempty_parts_is_not_cleared_or_followed(self):
        empty=self.root/'apt/empty.d';empty.mkdir(mode=0o750)
        sentinel=empty/'injected';sentinel.write_bytes(b'synthetic')
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(sentinel.read_bytes(),b'synthetic')
        self.assertTrue(self.journal.snapshot()['unconfirmed'])

    def test_short_writes_are_completed_and_fsync_uncertainty_fences_work(self):
        original=os.write
        with patch('inventory_refresh_materializer.os.write',side_effect=lambda fd,raw:original(fd,raw[:max(1,len(raw)//2)])):
            job=self.prepare()
        self.assertEqual(parse_job((self.root/'run/job.json').read_bytes()),job)

    def test_failed_output_fsync_blocks_further_work_and_never_creates_job(self):
        with patch('inventory_refresh_materializer.os.fsync',side_effect=OSError('synthetic private detail')):
            with self.assertRaises(ValueError) as error:self.prepare()
        self.assertNotIn('synthetic private detail',str(error.exception))
        with self.assertRaises(ValueError):self.journal.snapshot()
        self.assertFalse((self.root/'run/job.json').exists())

    def test_close_failure_after_preparation_revokes_launch_permission(self):
        self.prepare();real_close=os.close;failed=False;failed_fd=[]
        def close(fd):
            nonlocal failed
            if not failed:
                failed=True;failed_fd.append(fd);raise OSError('synthetic close uncertainty')
            return real_close(fd)
        with patch('inventory_refresh_materializer.os.close',side_effect=close):
            with self.assertRaises(ValueError):self.preparer.close()
        for fd in failed_fd:real_close(fd)
        self.assertTrue(self.journal.snapshot()['unconfirmed'])
        self.assertFalse(self.journal._launch_permits)

    def test_temporary_replacement_is_never_published_or_deleted(self):
        original=os.fsync;substituted=[]
        def fsync(fd):
            result=original(fd)
            for directory in (self.root/'apt',self.root/'run'):
                for path in directory.glob('.materialize-*'):
                    if path not in substituted:
                        info=path.stat()
                        if info.st_size:
                            replacement=directory/'synthetic-foreign-temp'
                            replacement.write_bytes(b'foreign');replacement.chmod(0o640)
                            replacement.replace(path);substituted.append(path)
            return result
        with patch('inventory_refresh_materializer.os.fsync',side_effect=fsync):
            with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(substituted)
        self.assertEqual(substituted[0].read_bytes(),b'foreign')
        self.assertFalse((self.root/'run/job.json').exists())

    def test_old_running_metadata_without_process_start_permission_cannot_prepare(self):
        self.journal._launch_permits.clear()
        with self.assertRaises(ValueError):self.prepare()
        self.assertFalse(any((self.root/'cache').iterdir()))
        self.assertFalse((self.root/'run/job.json').exists())

    def test_policy_change_fences_without_writing_new_job(self):
        (self.root/'policy/policy-commitment.key').write_bytes(b'x'*32)
        with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(self.journal.snapshot()['unconfirmed'])
        self.assertFalse((self.root/'run/job.json').exists())


if __name__=='__main__':unittest.main()
