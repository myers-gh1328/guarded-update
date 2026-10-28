"""Fixed refresh launch/ownership contracts; no actual services on this host."""
from pathlib import Path
from contextlib import ExitStack
from types import SimpleNamespace
import json
import os
import tempfile
import sys
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_worker_service as service
import inventory_refresh_worker as worker
from inventory_refresh_state import Journal

class WorkerServiceTests(unittest.TestCase):
    def owned(self):
        value=object.__new__(service.RefreshService)
        value._closed=False;value._wrapper=Mock();value._wrapper.poll.return_value=None
        value._invocation='a'*32;value._cgroup=(1,2);value._cgroup_fd=None
        value._marker='Command Center inventory refresh '+'b'*32
        value._sources=Mock();value._input=Mock();value._binding=Mock()
        value.owned_inputs=(value._sources,value._input,value._binding)
        return value

    def properties(self,value,**changes):
        result={'LoadState':'loaded','ActiveState':'active','Transient':'yes','Description':value._marker,
                'InvocationID':value._invocation,'ControlGroup':service.CGROUP,'MainPID':'100'}
        result.update(changes);return result

    def test_new_start_permit_consumed_once_and_old_lock_handle_cannot_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);first=None
            nonce='0000000000000001'+'a'*16;boot='11111111-1111-4111-8111-111111111111'
            job={'schema_version':1,'staging_token':'c'*32,'config_sha256':'d'*64,'policy_generation':'b'*64,
                 'operation_nonce':nonce,'helper_sequence':1,'boot_id':boot,'accepted_boottime_ms':100,
                 'started_boottime_ms':101,'deadline_boottime_ms':600101}
            policy=Mock();policy.generation='b'*64
            user=SimpleNamespace(pw_uid=60001,pw_gid=60001);reporter=SimpleNamespace(pw_uid=60002,pw_gid=60002)
            try:
                journal=Journal(fd,owner=os.getuid())
                with patch.object(service,'_WorkerSources') as sources,patch.object(service,'_JobInput') as input_file,patch.object(service,'_accounts',return_value=(user,reporter)):
                    sources.return_value.worker.return_value=worker
                    input_file.return_value.read.return_value=json.dumps(job).encode()
                    with journal.exclusive():
                        journal.initialize('a'*32);journal.receive('refresh',nonce,boot,100,'b'*64)
                        journal.start('refresh',nonce,boot,101,policy='b'*64)
                        first=service.RefreshService(journal,policy)
                        with self.assertRaises(ValueError):service.RefreshService(journal,policy)
                    with journal.exclusive(),patch.object(service,'MaterializedPolicy') as binding,patch.object(service.subprocess,'Popen') as spawn:
                        with self.assertRaises(ValueError):first.launch()
                        binding.fixed.assert_not_called();spawn.assert_not_called()
                policy.close.assert_not_called()
            finally:
                if first is not None:first.close()
                os.close(fd)

    def test_fixed_worker_profile_only_accepts_strict_staging_token(self):
        args=service.refresh_argv('a'*32)
        self.assertEqual(args[0],'/usr/bin/systemd-run');self.assertIn('--unit='+service.UNIT,args)
        self.assertEqual(args[-4:],('/usr/bin/python3','-I','-B',service.LIB_ROOT+'/guardian.py'))
        for prop in ('User=0','Group=0','CapabilityBoundingSet=CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP',
                     'AmbientCapabilities=CAP_SETUID','ReadWritePaths='+service.CACHE_ROOT+'/staging-'+'a'*32,
                     'KillMode=control-group','RuntimeMaxSec=610','TasksMax=64'):
            self.assertIn(prop,args)
        for bad in ('/tmp','..','A'*32,'a'*33):
            with self.subTest(bad=bad),self.assertRaises(ValueError):service.refresh_argv(bad)

    def launchable(self):
        value=self.owned();value._invocation=None;value._wrapper=None;value._attempted=False
        value._journal=Mock();value._generation=value._journal._launch_epoch
        value._job={'boot_id':'11111111-1111-4111-8111-111111111111','started_boottime_ms':100,
                    'deadline_boottime_ms':1000,'staging_token':'b'*32,'config_sha256':'d'*64}
        value._policy=Mock();value._user=SimpleNamespace(pw_gid=60001);value._worker=Mock()
        value.verify_current_inputs=Mock()
        return value

    def root_context(self,value):
        stack=ExitStack()
        stack.enter_context(patch.object(service.sys,'platform','linux'))
        stack.enter_context(patch.object(service.os,'getresuid',return_value=(0,0,0),create=True))
        stack.enter_context(patch.object(service.os,'getresgid',return_value=(0,0,0),create=True))
        return stack

    def test_preexisting_unit_cannot_be_started_or_stopped(self):
        value=self.launchable()
        with self.root_context(value),patch.object(service,'kernel_clock',return_value=(value._job['boot_id'],105)),patch.object(service,'MaterializedPolicy'),patch.object(service,'show_unit',return_value={'LoadState':'loaded'}),patch.object(service.subprocess,'Popen') as spawn,patch.object(service,'stop_unit') as stop:
            with self.assertRaises(ValueError):value.launch()
            spawn.assert_not_called();stop.assert_not_called()

    def test_expiry_during_policy_checks_rejected_immediately_before_spawn(self):
        value=self.launchable();boot=value._job['boot_id']
        with self.root_context(value),patch.object(service,'kernel_clock',side_effect=[(boot,105),(boot,1000)]),patch.object(service,'MaterializedPolicy'),patch.object(service,'show_unit',return_value={'LoadState':'not-found'}),patch.object(service.subprocess,'Popen') as spawn:
            with self.assertRaises(ValueError):value.launch()
            spawn.assert_not_called()

    def test_worker_filesystem_whitelist_excludes_parent_inputs_and_control_sockets(self):
        args=service.refresh_argv('a'*32)
        self.assertIn('TemporaryFileSystem=/etc:ro /var/lib:ro /run:ro',args)
        binds=next(value for value in args if value.startswith('BindReadOnlyPaths=')).split('=',1)[1].split()
        self.assertIn('/etc/command-center-inventory-refresh/apt',binds)
        self.assertIn('/run/command-center-inventory-refresh/job.json',binds)
        self.assertIn('/run/command-center-inventory-refresh/worker-apt.conf',binds)
        for path in ('/etc/passwd','/etc/group','/etc/nsswitch.conf','/etc/hosts','/etc/resolv.conf'):
            self.assertIn(path,binds)
        for forbidden in ('/etc/command-center-inventory-refresh','/var/lib','/run','/run/systemd/private',
                          '/etc/command-center-inventory-refresh/policy.json','/etc/command-center-inventory-refresh/policy-commitment.key'):
            self.assertNotIn(forbidden,binds)

    def test_same_name_replacement_cannot_be_stopped(self):
        value=self.owned()
        with patch.object(service,'show_unit',return_value=self.properties(value,InvocationID='c'*32)),patch.object(service,'stop_unit') as stop:
            with self.assertRaises(ValueError):value.close()
            stop.assert_not_called();value._wrapper.kill.assert_called_once();value._wrapper.wait.assert_called_once()
        [resource.close.assert_called_once() for resource in value.owned_inputs]

    def test_unknown_creation_reaps_only_wrapper(self):
        value=self.owned();value._invocation=None
        with patch.object(service,'show_unit') as show,patch.object(service,'stop_unit') as stop:
            value.close();show.assert_not_called();stop.assert_not_called()
            value._wrapper.kill.assert_called_once();value._wrapper.wait.assert_called_once()

    def test_binding_cleanup_failure_still_closes_other_owned_inputs(self):
        value=self.owned();value._invocation=None
        value._binding.close.side_effect=ValueError('uncertain binding close')
        with self.assertRaises(ValueError):value.close()
        [resource.close.assert_called_once() for resource in value.owned_inputs[:2]]
        value._wrapper.wait.assert_called_once()

    def test_stop_failure_still_reaps_and_closes_inputs(self):
        value=self.owned()
        with patch.object(service,'show_unit',return_value=self.properties(value)),patch.object(service,'cgroup_identity',return_value=(1,2)),patch.object(service,'stop_unit',side_effect=OSError('stop failed')):
            with self.assertRaises(OSError):value.close()
            value._wrapper.kill.assert_called_once();value._wrapper.wait.assert_called_once()
        value.owned_inputs[2].close.assert_called_once()

if __name__=='__main__':unittest.main()
