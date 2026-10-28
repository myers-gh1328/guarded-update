"""Coordinator status through actual journal and public-file fixture boundaries."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_state import Journal
from inventory_refresh_io import StatusPublisher
from inventory_refresh_coordinator import publish_current_status

BOOT='11111111-1111-4111-8111-111111111111'
POLICY='b'*64
CHECKED='2026-10-28T07:00:00Z'
NONCE='0000000000000001'+'a'*16


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        private=self.root/'private';private.mkdir(mode=0o700)
        public=self.root/'public';public.mkdir(mode=0o750);public.chmod(0o750)
        self.private_fd=os.open(private,os.O_RDONLY|os.O_DIRECTORY)
        self.public_fd=os.open(public,os.O_RDONLY|os.O_DIRECTORY)
        self.journal=Journal(self.private_fd,owner=os.getuid())
        with self.journal.exclusive():
            self.journal.initialize('a'*32)
        self.publisher=StatusPublisher(self.public_fd,self.journal,os.getgid(),owner=os.getuid())
        self.manifest={'schema_version':1,'cache_generation':'c'*32,'policy_generation':POLICY,
                       'successful_checked_at':CHECKED,'files':[]}

    def tearDown(self):
        self.publisher.close()
        os.close(self.public_fd);os.close(self.private_fd)
        self.temp.cleanup()

    def success(self):
        self.journal.receive('refresh',NONCE,BOOT,100,POLICY)
        self.journal.start('refresh',NONCE,BOOT,101,policy=POLICY)
        self.journal.finish('refresh',NONCE,BOOT,102,'succeeded',cache='c'*32,policy=POLICY,
                            successful_checked_at=CHECKED)

    def publish(self,*,boot=BOOT,policy=POLICY,manifest='current',**kwargs):
        publish_current_status(self.journal,self.publisher,boot_id=boot,current_policy=policy,
                               manifest=self.manifest if manifest=='current' else manifest,**kwargs)
        return json.loads((self.root/'public/status.json').read_bytes())

    def accept_observation(self):
        nonce='0000000000000002'+'a'*16
        self.journal.receive('observation',nonce,BOOT,110,POLICY)
        self.journal.start('observation',nonce,BOOT,111,policy=POLICY)
        self.journal.receive('release',nonce,BOOT,120,POLICY)
        self.journal.start('release',nonce,BOOT,121,policy=POLICY)
        receipt={'nonce':nonce,'boot_id':BOOT,'cache_generation':'c'*32,'policy_generation':POLICY,
                 'lock_open_boottime_ms':115,'expires_boottime_ms':1000,'lock_held_until_boottime_ms':125,
                 'released_boottime_ms':126,'outcome':'released','installed_before_sha256':'d'*64,'installed_after_sha256':'d'*64}
        self.journal.finish_observation(receipt)
        return receipt

    def test_accepted_historical_receipt_survives_policy_cache_loss_and_reboot(self):
        with self.journal.exclusive():
            self.success();receipt=self.accept_observation()
            for kwargs in ({},{'policy':'e'*64},{'manifest':None},{'boot':'22222222-2222-4222-8222-222222222222'}):
                with self.subTest(kwargs=kwargs):
                    self.assertEqual(self.publish(**kwargs)['observation_receipt'],receipt)
            self.assertEqual(self.publish(observation_receipt=None)['observation_receipt'],receipt)
            self.assertEqual(self.publish(observation_receipt=dict(receipt))['observation_receipt'],receipt)
            with self.assertRaises(ValueError):self.publish(observation_receipt=dict(receipt,released_boottime_ms=127))

    def test_unaccepted_child_receipt_cannot_be_projected(self):
        with self.journal.exclusive():
            self.success()
            receipt={'nonce':NONCE,'boot_id':BOOT,'cache_generation':'c'*32,'policy_generation':POLICY,
                     'lock_open_boottime_ms':115,'expires_boottime_ms':1000,'lock_held_until_boottime_ms':125,
                     'released_boottime_ms':126,'outcome':'released','installed_before_sha256':'d'*64,'installed_after_sha256':'d'*64}
            with self.assertRaises(ValueError):self.publish(observation_receipt=receipt)

    def test_current_policy_change_never_relabels_any_correlated_attempt(self):
        newer='0000000000000002'+'b'*16
        with self.journal.exclusive():
            transitions=[('received',lambda:self.journal.receive('refresh',NONCE,BOOT,100,POLICY)),
                         ('running',lambda:self.journal.start('refresh',NONCE,BOOT,101,policy=POLICY)),
                         ('failed',lambda:self.journal.finish('refresh',NONCE,BOOT,102,'failed',reason='repository_failed')),
                         ('deferred',lambda:(self.journal.receive('refresh',newer,BOOT,103,POLICY),
                                             self.journal.defer('refresh',newer,BOOT,'minimum_interval',now=104)))]
            for phase,transition in transitions:
                transition()
                before=self.journal.snapshot()
                original=self.publish()
                self.assertEqual(original['phase'],phase)
                changed=self.publish(policy='d'*64)
                with self.subTest(phase=phase):
                    self.assertEqual(changed['phase'],'unconfirmed')
                    self.assertEqual(changed['reason'],'policy_changed')
                    self.assertIsNone(changed['operation_nonce'])
                    self.assertIsNone(changed['attempt'])
                    self.assertEqual(self.journal.snapshot(),before)

    def test_manifest_alone_never_becomes_correlated_refresh_success(self):
        with self.journal.exclusive():
            status=self.publish()
        self.assertEqual(status['phase'],'unconfirmed')
        for field in ['operation_nonce','attempt','cache_generation','successful_checked_at']:
            self.assertIsNone(status[field])

    def test_policy_change_cache_loss_and_reboot_do_not_rewrite_frozen_success(self):
        with self.journal.exclusive():
            self.success()
            before=self.journal.snapshot()
            first=self.publish()
            self.assertEqual(first['phase'],'succeeded')
            for arguments in [dict(manifest=None),dict(policy='d'*64),dict(policy=None),
                              dict(boot='22222222-2222-4222-8222-222222222222'),
                              dict(manifest=dict(self.manifest,cache_generation='d'*32))]:
                with self.subTest(arguments=arguments):
                    status=self.publish(**arguments)
                    self.assertEqual(status['phase'],'unconfirmed')
                    for field in ['operation_nonce','attempt','cache_generation','successful_checked_at']:
                        self.assertIsNone(status[field])
                    self.assertEqual(self.journal.snapshot(),before)

    def test_frozen_no_work_endpoint_survives_observation_uncertainty(self):
        newer='0000000000000002'+'b'*16
        observe='0000000000000001'+'d'*16
        with self.journal.exclusive():
            self.success()
            self.journal.receive('refresh',newer,BOOT,103,POLICY)
            self.journal.defer('refresh',newer,BOOT,'minimum_interval',now=104)
            first=self.publish()
            frozen=self.journal.snapshot()['capabilities']['refresh']
            self.assertEqual(first['phase'],'deferred')
            self.assertEqual(first['attempt']['finished_boottime_ms'],104)
            self.assertEqual(self.publish(),first)
            self.journal.receive('observation',observe,BOOT,105,POLICY)
            self.journal.start('observation',observe,BOOT,106,policy=POLICY)
            self.assertFalse(self.journal.startup_ready())
            status=self.publish()
            self.assertEqual(status['phase'],'unconfirmed')
            self.assertEqual(status['reason'],'cleanup_unconfirmed')
            self.assertIsNone(status['operation_nonce'])
            self.assertIsNone(status['attempt'])
            self.assertEqual(self.journal.snapshot()['capabilities']['refresh'],frozen)

    def test_failed_success_sync_cannot_publish_visible_but_unreconciled_bytes(self):
        with self.journal.exclusive():
            self.journal.receive('refresh',NONCE,BOOT,100,POLICY)
            self.journal.start('refresh',NONCE,BOOT,101,policy=POLICY)
            self.publish()
            before=(self.root/'public/status.json').read_bytes()
            real=os.fsync
            def fail_directory(fd):
                if fd==self.private_fd:
                    raise OSError('synthetic directory sync failure')
                return real(fd)
            with patch('inventory_refresh_state.os.fsync',side_effect=fail_directory):
                with self.assertRaises(OSError):
                    self.journal.finish('refresh',NONCE,BOOT,102,'succeeded',cache='c'*32,
                                        policy=POLICY,successful_checked_at=CHECKED)
            with self.assertRaises(ValueError):
                self.publish()
            self.assertEqual((self.root/'public/status.json').read_bytes(),before)
            self.assertTrue(self.journal.startup_ready())
            self.assertEqual(self.publish()['phase'],'succeeded')

    def test_projection_requires_held_lock_and_rejects_foreign_boot_lease(self):
        with self.assertRaises(ValueError):
            self.publish()
        with self.journal.exclusive():
            self.success()
            lease={'nonce':'0000000000000001'+'d'*16,'boot_id':'22222222-2222-4222-8222-222222222222',
                   'cache_generation':'c'*32,'policy_generation':POLICY,
                   'lock_open_boottime_ms':200,'expires_boottime_ms':300}
            with self.assertRaises(ValueError):
                self.publish(observation_lease=lease)

    def test_later_failure_keeps_verified_prior_cache_and_actual_attempt_times(self):
        newer='0000000000000002'+'b'*16
        with self.journal.exclusive():
            self.success()
            self.journal.receive('refresh',newer,BOOT,1000000,POLICY)
            self.journal.start('refresh',newer,BOOT,1000001,policy=POLICY)
            self.journal.finish('refresh',newer,BOOT,1000002,'failed',reason='repository_failed')
            status=self.publish()
        self.assertEqual(status['phase'],'failed')
        self.assertEqual(status['operation_nonce'],newer)
        self.assertEqual(status['reason'],'repository_failed')
        self.assertEqual(status['cache_generation'],'c'*32)
        self.assertEqual(status['successful_checked_at'],CHECKED)
        self.assertEqual(status['attempt']['started_boottime_ms'],1000001)
        self.assertEqual(status['attempt']['finished_boottime_ms'],1000002)
        self.assertIsNone(status['started_at'])
        self.assertIsNone(status['finished_at'])


if __name__=='__main__':
    unittest.main()
