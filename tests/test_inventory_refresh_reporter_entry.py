"""Generated entry mechanics with explicit owned descriptor fixtures."""
from pathlib import Path
import io
import os
import sys
import types
import unittest
import fcntl
import tempfile
import subprocess
from contextlib import contextmanager
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from inventory_refresh_reporter_build import generate


def generated_entry():
    raw,_=generate((ROOT/'scripts/inventory_refresh_root_entry.py').read_bytes(),
        (ROOT/'scripts/inventory_refresh_reporter_template.py').read_bytes())
    entry=types.ModuleType('generated_reporter_entry_fixture')
    exec(compile(raw,'synthetic-reporter.py','exec'),entry.__dict__)
    return entry


class EntryStdioTests(unittest.TestCase):
    def setUp(self):
        self.entry=generated_entry();self.fds=set();self.streams=[]
    def tearDown(self):
        for stream in self.streams:
            if not stream.closed:stream.close()
        for fd in self.fds:
            try:os.close(fd)
            except OSError:pass
    def streams_for(self,closefd):
        incoming,peer_write=os.pipe();peer_read,outgoing=os.pipe();error=os.dup(outgoing)
        self.fds.update((incoming,peer_write,peer_read,outgoing,error))
        for fd,reading in ((incoming,True),(outgoing,False),(error,False)):
            raw=io.FileIO(fd,'rb' if reading else 'wb',closefd=closefd)
            buffered=io.BufferedReader(raw) if reading else io.BufferedWriter(raw)
            self.streams.append(io.TextIOWrapper(buffered,encoding='utf-8'))
        return tuple(self.streams),(incoming,outgoing,error)

    def test_borrowing_python_wrappers_and_inherited_raw_fds_are_both_closed(self):
        streams,descriptors=self.streams_for(False)
        owner=self.entry._Stdio._from_streams(streams,descriptors)
        owner.nonblocking();owner.close();owner.close()
        self.assertTrue(all(stream.closed for stream in streams))
        for fd in descriptors:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_owning_python_wrappers_close_each_fd_without_raw_close_retry(self):
        streams,descriptors=self.streams_for(True)
        owner=self.entry._Stdio._from_streams(streams,descriptors)
        with patch.object(self.entry.os,'close',side_effect=AssertionError('raw retry after owning wrapper')):
            owner.close();owner.close()
        for fd in descriptors:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_borrowing_wrapper_failure_still_closes_all_raw_fds_once(self):
        streams,descriptors=self.streams_for(False);owner=self.entry._Stdio._from_streams(streams,descriptors)
        actual=streams[0].close
        def uncertain():actual();raise OSError('synthetic wrapper close uncertainty')
        with patch.object(streams[0],'close',side_effect=uncertain),\
                patch.object(self.entry.os,'close',wraps=os.close) as close:
            with self.assertRaises(ValueError):owner.close()
            owner.close();self.assertEqual([call.args[0] for call in close.call_args_list],list(descriptors))
        self.assertTrue(all(stream.closed for stream in streams))

    def test_owning_wrapper_failure_never_retries_raw_fd_but_closes_other_streams(self):
        streams,descriptors=self.streams_for(True);owner=self.entry._Stdio._from_streams(streams,descriptors)
        actual=streams[0].close
        def uncertain():actual();raise OSError('synthetic owning wrapper close uncertainty')
        with patch.object(streams[0],'close',side_effect=uncertain),\
                patch.object(self.entry.os,'close',side_effect=AssertionError('raw owning retry')) as close:
            with self.assertRaises(ValueError):owner.close()
            owner.close();close.assert_not_called()
        self.assertTrue(all(stream.closed for stream in streams))

    def test_raw_close_error_attempts_every_record_once_without_retry(self):
        streams,descriptors=self.streams_for(False);owner=self.entry._Stdio._from_streams(streams,descriptors)
        actual=os.close;calls=[]
        def uncertain(fd):
            calls.append(fd);actual(fd)
            if len(calls)==1:raise OSError('synthetic raw close uncertainty')
        with patch.object(self.entry.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):owner.close()
            owner.close()
        self.assertEqual(calls,list(descriptors));self.assertTrue(all(stream.closed for stream in streams))

    def test_replaced_stdout_is_not_flushed_or_closed_while_other_records_close(self):
        streams,descriptors=self.streams_for(False);owner=self.entry._Stdio._from_streams(streams,descriptors)
        streams[1].write('buffered fixture bytes')
        replacement,peer=os.pipe();self.fds.update((replacement,peer))
        os.dup2(peer,descriptors[1]);os.set_blocking(replacement,False)
        identity=os.fstat(descriptors[1])
        with self.assertRaises(ValueError):owner.close()
        self.assertFalse(streams[1].closed)
        self.assertEqual(os.fstat(descriptors[1]).st_ino,identity.st_ino)
        with self.assertRaises(BlockingIOError):os.read(replacement,100)
        self.assertTrue(streams[0].closed);self.assertTrue(streams[2].closed)
        # Fixture still owns the foreign pipe; discard buffered text without
        # flushing it during test teardown (production uses outer os._exit).
        streams[1].buffer.raw.close();streams[1].close()

    def test_both_originals_are_checked_before_any_nonblocking_flag_change(self):
        streams,descriptors=self.streams_for(False);owner=self.entry._Stdio._from_streams(streams,descriptors)
        actual=fcntl.fcntl;checked=[]
        def flags(fd,operation,*args):
            if operation==fcntl.F_GETFL:checked.append(fd)
            return actual(fd,operation,*args)
        setter=os.set_blocking
        def set_flags(fd,value):
            self.assertEqual(checked[:2],list(descriptors[:2]));setter(fd,value)
        with patch.object(self.entry.fcntl,'fcntl',side_effect=flags),patch.object(self.entry.os,'set_blocking',side_effect=set_flags):
            owner.nonblocking()
        owner.close()

    def test_regular_stdout_is_rejected_before_any_original_flag_change(self):
        streams,descriptors=self.streams_for(False)
        with tempfile.TemporaryFile() as file:
            replacement=os.dup(file.fileno());self.fds.add(replacement)
            stream=io.TextIOWrapper(io.BufferedWriter(io.FileIO(replacement,'wb',closefd=False)),encoding='utf-8')
            self.streams.append(stream)
            owner=self.entry._Stdio._from_streams((streams[0],stream,streams[2]),(descriptors[0],replacement,descriptors[2]))
            with patch.object(self.entry.os,'set_blocking') as flags:
                with self.assertRaises(ValueError):owner.nonblocking()
                flags.assert_not_called()


class EntryMainTests(unittest.TestCase):
    def setUp(self):self.entry=generated_entry()

    def test_profile_failure_prevents_sources_runtime_and_nonblocking_changes(self):
        stdio=Mock()
        with patch.object(self.entry._Stdio,'capture',return_value=stdio),\
                patch.object(self.entry,'admit_profile',side_effect=ValueError('synthetic profile rejection')),\
                patch.object(self.entry.RootSources,'fixed') as sources:
            self.assertEqual(self.entry.main(),74)
            sources.assert_not_called();stdio.nonblocking.assert_not_called();stdio.close.assert_called_once()

    @contextmanager
    def managed(self):
        events=[];stdio=Mock();sources=Mock();runtime=Mock();channel=Mock()
        def event(name,result=None):
            def invoke(*_):events.append(name);return result
            return invoke
        stdio.nonblocking.side_effect=event('nonblocking');stdio.close.side_effect=event('stdio close')
        sources.close.side_effect=event('source close');runtime.close.side_effect=event('runtime close');channel.close.side_effect=event('channel close')
        factory=Mock(side_effect=event('runtime',runtime));admit=Mock(side_effect=event('channel',channel))
        def run(first,second):
            self.assertIs(first,runtime);self.assertIs(second,channel)
            events.append('dialogue');first.close();second.close()
        dialogue=Mock(side_effect=run)
        sources.execute.side_effect=event('execute',{
            'inventory_refresh_reporter_runtime':types.SimpleNamespace(ReporterRuntime=types.SimpleNamespace(fixed=factory)),
            'inventory_refresh_reporter_pipe':types.SimpleNamespace(PipeChannel=types.SimpleNamespace(admit=admit)),
            'inventory_refresh_reporter_dialogue':types.SimpleNamespace(run=dialogue)})
        with patch.object(self.entry._Stdio,'capture',side_effect=event('stdio',stdio)),\
                patch.object(self.entry,'admit_profile',side_effect=event('profile')),\
                patch.object(self.entry,'_environment',side_effect=event('environment')),\
                patch.object(self.entry.RootSources,'fixed',side_effect=event('sources',sources)):
            yield types.SimpleNamespace(events=events,stdio=stdio,sources=sources,runtime=runtime,channel=channel,factory=factory,admit=admit,dialogue=dialogue)

    def test_main_closes_source_before_flags_runtime_and_transfers_dialogue_owners_once(self):
        with self.managed() as state:
            self.assertEqual(self.entry.main(),0)
        self.assertEqual(state.events,['stdio','profile','environment','sources','execute','source close','nonblocking','runtime','channel','dialogue','runtime close','channel close','stdio close'])
        state.admit.assert_called_once_with(0,1,state.runtime.clock)
        state.runtime.close.assert_called_once();state.channel.close.assert_called_once()

    def test_source_close_failure_blocks_nonblocking_and_runtime_without_retry(self):
        with self.managed() as state:
            state.sources.close.side_effect=OSError('synthetic source cleanup uncertainty')
            self.assertEqual(self.entry.main(),74)
        state.sources.close.assert_called_once();state.stdio.nonblocking.assert_not_called()
        state.factory.assert_not_called();state.stdio.close.assert_called_once()

    def test_channel_admission_failure_closes_runtime_and_original_stdio(self):
        with self.managed() as state:
            state.admit.side_effect=ValueError('synthetic channel admission failure')
            self.assertEqual(self.entry.main(),74)
        state.runtime.close.assert_called_once();state.stdio.close.assert_called_once();state.dialogue.assert_not_called()

    def test_original_stdio_close_error_after_successful_dialogue_returns_failure(self):
        with self.managed() as state:
            state.stdio.close.side_effect=OSError('synthetic original descriptor close uncertainty')
            self.assertEqual(self.entry.main(),74)
        state.runtime.close.assert_called_once();state.channel.close.assert_called_once();state.stdio.close.assert_called_once()

    def test_entry_profile_rejection_in_real_isolated_child_exits_silently(self):
        raw,_=generate((ROOT/'scripts/inventory_refresh_root_entry.py').read_bytes(),
            (ROOT/'scripts/inventory_refresh_reporter_template.py').read_bytes())
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'wrong-entry-path.py';path.write_bytes(raw)
            result=subprocess.run([sys.executable,'-I','-B','-S',str(path)],input=b'',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(74,b'',b''))


class EntryProfileTests(unittest.TestCase):
    def setUp(self):
        self.entry=generated_entry();self.flags=types.SimpleNamespace(isolated=1,dont_write_bytecode=1,no_site=1)
        self.status=(b'Uid:\t60002 60002 60002 60002\nGid:\t60002 60002 60002 60002\nGroups:\t60002\nNoNewPrivs:\t1\n'+
            b''.join(name+b':\t0000000000000000\n' for name in (b'CapInh',b'CapPrm',b'CapEff',b'CapBnd',b'CapAmb')))
    @contextmanager
    def profile(self):
        def read(name,limit):return self.status if name=='status' else ('0::'+self.entry.SELF_CGROUP+'\n').encode()
        with patch.object(self.entry.sys,'platform','linux'),patch.object(self.entry.sys,'flags',self.flags),\
                patch.object(self.entry.sys,'argv',[self.entry.ENTRY]),\
                patch.object(self.entry.os,'getresuid',return_value=(60002,60002,60002),create=True),\
                patch.object(self.entry.os,'getresgid',return_value=(60002,60002,60002),create=True),\
                patch.object(self.entry.os,'getgroups',return_value=[60002]),patch.object(self.entry,'_proc',side_effect=read):
            yield

    def test_preliminary_profile_requires_isolation_exact_argv_and_current_unit(self):
        with self.profile():
            self.entry.admit_profile();self.flags.no_site=0
            with self.assertRaises(ValueError):self.entry.admit_profile()
            self.flags.no_site=1
            with patch.object(self.entry.sys,'argv',[self.entry.ENTRY,'extra']):
                with self.assertRaises(ValueError):self.entry.admit_profile()
            with patch.object(self.entry,'_proc',return_value=b'0::/other.service\n'):
                with self.assertRaises(ValueError):self.entry.admit_profile()

    def test_saved_root_supplementary_groups_capabilities_and_no_new_privileges_fail(self):
        with self.profile():
            with patch.object(self.entry.os,'getresuid',return_value=(60002,60002,0)):
                with self.assertRaises(ValueError):self.entry.admit_profile()
            with patch.object(self.entry.os,'getgroups',return_value=[60002,0]):
                with self.assertRaises(ValueError):self.entry.admit_profile()
            original=self.status
            for key in (b'CapInh',b'CapPrm',b'CapEff',b'CapBnd',b'CapAmb'):
                self.status=original.replace(key+b':\t0000000000000000',key+b':\t0000000000000001')
                with self.subTest(key=key),self.assertRaises(ValueError):self.entry.admit_profile()
            self.status=original.replace(b'NoNewPrivs:\t1',b'NoNewPrivs:\t0')
            with self.assertRaises(ValueError):self.entry.admit_profile()


if __name__=='__main__':unittest.main()
