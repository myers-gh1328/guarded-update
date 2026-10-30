"""Standalone disposable ReporterParent supervisor checks."""
import os
import fcntl
from pathlib import Path
import sys
import time
import tempfile
import types
import unittest
from contextlib import ExitStack
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import native_inventory_exec_parent as native
from inventory_refresh_exec_lock_fixture import ExecLock,DIRECTORY,FILE


class NativeExecParentTests(unittest.TestCase):
    def test_only_exact_named_test_output_passes(self):
        good=b'running 1 test\ntest inventory::process::tests::hosted_fd_reporter_parent_admission ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s\n'
        native.validate_output(good)
        for value in (b'',good+b'extra\n',good.replace(b'running 1 test',b'running 0 tests')):
            with self.assertRaises(ValueError):native.validate_output(value)

    def test_frame_rejects_extra_and_timeout(self):
        for invalid in (b'EXEC-WRAPPER-READY\nextra',b'WRONG\n'):
            read,write=os.pipe();os.set_blocking(read,False)
            try:
                os.write(write,invalid)
                with self.assertRaises(ValueError):native.read_frame(read,b'EXEC-WRAPPER-READY\n',time.monotonic()+1,lambda:None)
            finally:os.close(read);os.close(write)
        read,write=os.pipe();os.set_blocking(read,False)
        try:
            with self.assertRaises(ValueError):native.read_frame(read,b'EXEC-WRAPPER-READY\n',time.monotonic()+.03,lambda:None)
        finally:os.close(read);os.close(write)

    def test_requires_shared_lock_continuously(self):
        with tempfile.TemporaryDirectory() as path:
            parent=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            try:
                lock=ExecLock.create(parent,os.getuid(),os.getgid(),lambda:None)
                fd=os.open(Path(path)/DIRECTORY/FILE,os.O_RDONLY|os.O_NOFOLLOW)
                fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
                native.require_shared_lock(lock);os.close(fd)
                with self.assertRaises(ValueError):native.require_shared_lock(lock)
                lock.close()
            finally:os.close(parent)

    def test_exec_identity_rejects_pid_start_and_inode_drift(self):
        info=types.SimpleNamespace(st_dev=7,st_ino=9)
        for pid,start,expected,samples in ((0,5,(7,9),[5,5]),(4,5,(7,9),[6,5]),(4,5,(7,9),[5,6]),(4,5,(7,10),[5,5])):
            with self.subTest(pid=pid,samples=samples,expected=expected):
                probe=Mock();probe.sample.side_effect=samples
                with patch.object(native.os,'stat',return_value=info):
                    with self.assertRaises(ValueError):native.verify_exec_identity(pid,start,expected,probe)
        probe=Mock();probe.sample.side_effect=[5,5]
        with patch.object(native.os,'stat',return_value=info):native.verify_exec_identity(4,5,(7,9),probe)

    def test_ack_is_exact_and_bounded(self):
        read,write=os.pipe();os.set_blocking(write,False)
        try:
            with self.assertRaises(ValueError):native.write_frame(write,b'wrong',time.monotonic()+1,lambda:None)
            native.write_frame(write,b'EXEC-ACK\n',time.monotonic()+1,lambda:None)
            self.assertEqual(os.read(read,32),b'EXEC-ACK\n')
        finally:os.close(read);os.close(write)

    def test_supervisor_frame_failure_retains_files_and_closes_all_owners(self):
        for fault in ('first_frame','second_frame','profile','invocation','close'):
            with self.subTest(fault=fault),ExitStack() as stack:
                owners=[]
                def owner():
                    value=Mock();value.fds=[100,101];owners.append(value);return value
                chain_factory=Mock(side_effect=lambda parts:owner())
                slice_file=owner();cache=owner();lock=owner();sources=owner();binary=owner();artifact=owner()
                lock.file_metadata=(7,8,0,0,0,1,0,0,0);binary._target_metadata=(7,9,0,0,0,1,10,0,0);binary._digest='a'*64
                launcher=Mock();launcher.poll.return_value=None
                for index,stream in enumerate((launcher.stdin,launcher.stdout,launcher.stderr)):stream.fileno.return_value=10+index
                probe=Mock();probe.sample.return_value=5;reference=Mock();bus=Mock()
                fake_modules={
                    'inventory_refresh_artifact_fixture':types.SimpleNamespace(LIB='lib/',verify_archive=Mock(return_value={'source_commit':'a'*40,'files':{'lib/'+name:b'x' for name in native.PARENT_SOURCE_NAMES}})),
                    'inventory_refresh_rust_native_admission':types.SimpleNamespace(RunnerArtifact=types.SimpleNamespace(fixed=Mock(return_value=artifact))),
                    'inventory_refresh_rust_parent_fixture':types.SimpleNamespace(FixtureBinary=types.SimpleNamespace(fixed=Mock(return_value=binary))),
                    'inventory_refresh_resources':types.SimpleNamespace(_Chain=chain_factory,_read=Mock(return_value=b'0'),limit=Mock(side_effect=lambda value:next(limits))),
                    'inventory_refresh_cache_fixture':types.SimpleNamespace(CacheFixture=types.SimpleNamespace(fixed=Mock(return_value=cache))),
                }
                limits=iter((268435456,0,64,268435456,0,64))
                stack.enter_context(patch.dict(sys.modules,fake_modules))
                stack.enter_context(patch.object(native.sys,'platform','linux'))
                stack.enter_context(patch.object(native.os,'getresuid',return_value=(0,0,0),create=True));stack.enter_context(patch.object(native.os,'getresgid',return_value=(0,0,0),create=True))
                stack.enter_context(patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}))
                for name in ('check_loaded_slices','require_cgroup_absent','manager_command','validate_slice_config','observe_empty','create_account','worker_account','ensure_libexec','verify_endpoints','observe_single_process','require_shared_lock'):
                    stack.enter_context(patch.object(native,name))
                stack.enter_context(patch.object(native,'unit_status',side_effect=[{'LoadState':'not-found'},{'LoadState':'loaded','InvocationID':'a'*32,'ControlGroup':'/command.slice/command-center.slice/command-center-inventory.slice/'+native.UNIT}]*3))
                stack.enter_context(patch.object(native,'slice_status',return_value={}))
                stack.enter_context(patch.object(native,'validate_slice_identity',return_value='b'*32))
                stack.enter_context(patch.object(native,'unit_pin_decision',return_value='ready'))
                identity=stack.enter_context(patch.object(native,'validate_live_identity',return_value=('a'*32,42)))
                if fault=='invocation':identity.side_effect=[('a'*32,42),ValueError('changed')]
                stack.enter_context(patch.object(native.SliceFile,'create',return_value=slice_file))
                stack.enter_context(patch.object(native.UnitReference,'acquire',return_value=reference))
                stack.enter_context(patch.object(native.NativeBus,'fixed',return_value=bus))
                stack.enter_context(patch.object(native.ProcessProbe,'fixed',return_value=probe))
                if fault=='profile':probe.sample.side_effect=ValueError('changed')
                stack.enter_context(patch.object(native.ExecLock,'create',return_value=lock))
                stack.enter_context(patch.object(native,'MarkerSources',return_value=sources))
                stack.enter_context(patch.object(native.os,'mkdir'));stack.enter_context(patch.object(native.os,'fsync'))
                stack.enter_context(patch.object(native.os,'fstat',side_effect=lambda fd:types.SimpleNamespace(st_dev=7,st_ino=fd if fd in (10,11,12) else 8,st_mode=0o010600)));stack.enter_context(patch.object(native.os,'set_blocking'))
                stack.enter_context(patch.object(native.fcntl,'fcntl',side_effect=lambda fd,op:os.O_WRONLY if fd==10 else os.O_RDONLY))
                popen=stack.enter_context(patch.object(native.subprocess,'Popen',return_value=launcher))
                frame_fault={'first_frame':[ValueError('bad')],'second_frame':[None,ValueError('bad')]}.get(fault,[None,None])
                frame=stack.enter_context(patch.object(native,'read_frame',side_effect=frame_fault))
                write=stack.enter_context(patch.object(native,'write_frame'))
                stack.enter_context(patch.object(native,'verify_exec_identity'))
                stack.enter_context(patch.object(native,'read_completion',return_value=b'fixed'))
                stack.enter_context(patch.object(native,'validate_output'))
                stack.enter_context(patch.object(native,'validate_final_identity'))
                launcher.wait.return_value=0
                if fault=='close':reference.close.side_effect=ValueError('uncertain close')
                remove=stack.enter_context(patch.object(native.os,'unlink'));rmdir=stack.enter_context(patch.object(native.os,'rmdir'))
                with self.assertRaises(ValueError):native.run('synthetic')
                expected={'first_frame':(1,0),'second_frame':(2,1),'profile':(1,0),'invocation':(0,0),'close':(2,2)}[fault]
                self.assertEqual((frame.call_count,write.call_count),expected)
                popen.assert_called_once();launcher.kill.assert_not_called();launcher.terminate.assert_not_called()
                remove.assert_not_called();rmdir.assert_not_called()
                for value in owners:value.close.assert_called_once()
                if fault!='invocation':reference.close.assert_called_once();probe.close.assert_called_once()
                if launcher.stdin is not None:launcher.stdin.close.assert_called_once()
                launcher.stdout.close.assert_called_once();launcher.stderr.close.assert_called_once()
