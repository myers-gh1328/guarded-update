"""Fixed service profile/ownership contracts; no service starts on this host."""
from pathlib import Path
from contextlib import ExitStack
from types import SimpleNamespace
import os
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_service as service
from inventory_refresh_state import Journal
from inventory_refresh_channel import ObservationChannel
from inventory_refresh_cached_observation import ObservationJob

class ServiceTests(unittest.TestCase):
    def owned(self):
        value=object.__new__(service.ObservationService)
        value._closed=False;value._wrapper=Mock();value._wrapper.poll.return_value=None
        value._invocation='a'*32;value._cgroup=(1,2);value._cgroup_fd=None
        value._marker='Command Center inventory observation '+'b'*32
        return value

    def properties(self,value,**changes):
        result={'LoadState':'loaded','ActiveState':'active','Transient':'yes','Description':value._marker,
                'InvocationID':value._invocation,'ControlGroup':service.CGROUP,'MainPID':'100'}
        result.update(changes);return result

    def test_fresh_adapter_object_cannot_relaunch_same_durable_running_job(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);fds=[];channel=None;first=None
            try:
                for name in ('state','control','results'):
                    path=root/name;path.mkdir(mode=0o700)
                    fds.append(os.open(path,os.O_RDONLY|os.O_DIRECTORY))
                journal=Journal(fds[0],owner=os.getuid())
                channel=ObservationChannel(fds[1],fds[2],journal=journal,owner=os.getuid())
                nonce='0000000000000001'+'a'*16;boot='11111111-1111-4111-8111-111111111111'
                job=ObservationJob(1,'c'*32,nonce,1,boot,'d'*32,'b'*64,'2026-10-28T07:00:00Z',100,101,1000)
                with journal.exclusive():
                    journal.initialize('a'*32)
                    journal.receive('observation',nonce,boot,100,'b'*64)
                    journal.start('observation',nonce,boot,101,policy='b'*64)
                    channel.write_job(job)
                    first=service.ObservationService(journal,channel,job)
                    with self.assertRaises(ValueError):service.ObservationService(journal,channel,job)
                    self.assertEqual(journal.snapshot()['capabilities']['observation']['active']['phase'],'running')
                with journal.exclusive(),self.root_launch_context(first),patch.object(service,'SourceBundle') as bundle,patch.object(service,'show_unit',return_value={'LoadState':'not-found'}),patch.object(service.subprocess,'Popen',side_effect=RuntimeError('must not spawn')) as spawn:
                    with self.assertRaises(ValueError):first.launch()
                    bundle.assert_not_called();spawn.assert_not_called()
            finally:
                if first is not None:first.close()
                if channel is not None:channel.close()
                for fd in fds:os.close(fd)

    def launchable(self):
        value=self.owned();value._invocation=None;value._wrapper=None;value._attempted=False
        value._job=SimpleNamespace(boot_id='11111111-1111-4111-8111-111111111111',started_boottime_ms=100,deadline_boottime_ms=1000)
        value._channel=Mock();value._channel.read_job.return_value=value._job
        value._journal=Mock();value._generation=value._journal._launch_epoch
        return value

    def root_launch_context(self,value):
        stack=ExitStack()
        stack.enter_context(patch.object(service.sys,'platform','linux'))
        stack.enter_context(patch.object(service.os,'getresuid',return_value=(0,0,0),create=True))
        stack.enter_context(patch.object(service.os,'getresgid',return_value=(0,0,0),create=True))
        stack.enter_context(patch.object(service,'kernel_clock',return_value=(value._job.boot_id,105)))
        return stack

    def test_source_cleanup_failure_after_capture_still_reaps_owned_service(self):
        value=self.launchable();wrapper=Mock();wrapper.poll.return_value=None
        properties=self.properties(value,InvocationID='a'*32)
        with tempfile.TemporaryDirectory() as directory:
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with self.root_launch_context(value),patch.object(service,'SourceBundle') as bundle,patch.object(service,'show_unit',side_effect=[{'LoadState':'not-found'},properties,properties,properties]),patch.object(service,'open_cgroup',return_value=fd),patch.object(value,'_same_invocation'),patch.object(service.subprocess,'Popen',return_value=wrapper),patch.object(service,'stop_unit') as stop:
                    bundle.return_value.close.side_effect=OSError('source fd close uncertain')
                    with self.assertRaises(OSError):value.launch()
                    stop.assert_called_once();wrapper.kill.assert_called_once();wrapper.wait.assert_called_once()
                    with self.assertRaises(OSError):os.fstat(fd)
            finally:
                if value._cgroup_fd is not None:os.close(value._cgroup_fd);value._cgroup_fd=None

    def test_preexisting_unit_rejected_before_spawn_and_not_stopped(self):
        value=self.launchable()
        with self.root_launch_context(value),patch.object(service,'SourceBundle') as bundle,patch.object(service,'show_unit',return_value={'LoadState':'loaded'}),patch.object(service.subprocess,'Popen') as spawn,patch.object(service,'stop_unit') as stop:
            with self.assertRaises(ValueError):value.launch()
            spawn.assert_not_called();stop.assert_not_called();bundle.return_value.close.assert_called_once()

    def test_failed_spawn_without_ownership_never_stops_unit(self):
        value=self.launchable()
        with self.root_launch_context(value),patch.object(service,'SourceBundle'),patch.object(service,'show_unit',return_value={'LoadState':'not-found'}),patch.object(service.subprocess,'Popen',side_effect=OSError('spawn failed')),patch.object(service,'stop_unit') as stop:
            with self.assertRaises(OSError):value.launch()
            stop.assert_not_called()

    def test_foreign_unit_during_capture_reaps_wrapper_without_stopping_unit(self):
        value=self.launchable();wrapper=Mock();wrapper.poll.return_value=None
        foreign=self.properties(value,Description='foreign invocation')
        with self.root_launch_context(value),patch.object(service,'SourceBundle'),patch.object(service,'show_unit',side_effect=[{'LoadState':'not-found'},foreign]),patch.object(service.subprocess,'Popen',return_value=wrapper),patch.object(service,'stop_unit') as stop:
            with self.assertRaises(ValueError):value.launch()
            stop.assert_not_called();wrapper.kill.assert_called_once();wrapper.wait.assert_called_once()

    def test_fixed_profile_has_no_shell_path_or_command_interface(self):
        argv=service.observation_argv()
        self.assertEqual(argv[0],'/usr/bin/systemd-run')
        self.assertIn('--unit='+service.UNIT,argv)
        self.assertEqual(argv[-4:],('/usr/bin/python3','-I','-B',service.LIB_ROOT+'/observation-guardian.py'))
        for prop in ('User=0','Group=0','CapabilityBoundingSet=CAP_KILL CAP_SETPCAP',
                     'KillMode=control-group','KillSignal=SIGKILL','NoNewPrivileges=yes',
                     'TemporaryFileSystem=/etc:ro /var/lib:ro /run:ro','TasksMax=2'):
            self.assertIn(prop,argv)
        with self.assertRaises(TypeError):service.observation_argv('caller option')

    def test_same_name_replacement_is_never_stopped_but_owned_wrapper_reaped(self):
        value=self.owned()
        with patch.object(service,'show_unit',return_value=self.properties(value,InvocationID='c'*32)),patch.object(service,'stop_unit') as stop:
            with self.assertRaises(ValueError):value.close()
            stop.assert_not_called();value._wrapper.kill.assert_called_once();value._wrapper.wait.assert_called_once()

    def test_missing_ownership_never_stops_encountered_unit(self):
        value=self.owned();value._invocation=None
        with patch.object(service,'show_unit') as show,patch.object(service,'stop_unit') as stop:
            value.close();show.assert_not_called();stop.assert_not_called()
            value._wrapper.kill.assert_called_once()

    def test_owned_invocation_requires_same_cgroup_identity_before_stop(self):
        value=self.owned()
        with patch.object(service,'show_unit',return_value=self.properties(value)),patch.object(service,'cgroup_identity',return_value=(1,3)),patch.object(service,'stop_unit') as stop:
            with self.assertRaises(ValueError):value.close()
            stop.assert_not_called();value._wrapper.wait.assert_called_once()

    def test_stop_failure_still_reaps_only_owned_wrapper(self):
        value=self.owned()
        with patch.object(service,'show_unit',return_value=self.properties(value)),patch.object(service,'cgroup_identity',return_value=(1,2)),patch.object(service,'stop_unit',side_effect=OSError('stop failed')):
            with self.assertRaises(OSError):value.close()
            value._wrapper.kill.assert_called_once();value._wrapper.wait.assert_called_once()

    def test_collected_unit_does_not_authorize_stop_of_any_replacement(self):
        value=self.owned();value._wrapper.poll.return_value=0
        with patch.object(service,'show_unit',return_value={'LoadState':'not-found'}),patch.object(service,'stop_unit') as stop:
            value.close();stop.assert_not_called();value._wrapper.kill.assert_not_called()
            value._wrapper.wait.assert_called_once()

if __name__=='__main__':unittest.main()
