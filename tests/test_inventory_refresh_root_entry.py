"""Fixed root bootstrap admission, using synthetic source bytes only."""
import ast
import builtins
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_root_entry as entry


class RootEntryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name);self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY)
        self.names=(('root_fixture_one','one.py'),('root_fixture_two','two.py'))
        self.patch=patch.object(entry,'SOURCES',self.names);self.patch.start();self.events=[]
        builtins._root_entry_test_events=self.events
        for name,filename in self.names:(self.path/filename).write_text('import builtins\nbuiltins._root_entry_test_events.append('+repr(name)+')\n')
        self.bundle=None
    def tearDown(self):
        if self.bundle is not None:self.bundle.close()
        for name,_ in self.names:sys.modules.pop(name,None)
        del builtins._root_entry_test_events;self.patch.stop();os.close(self.fd);self.temp.cleanup()
    def open(self):
        self.bundle=entry.RootSources(self.fd,owner=os.getuid());return self.bundle

    def test_entire_bundle_is_admitted_and_compiled_before_execution(self):
        bundle=self.open();self.assertEqual(self.events,[])
        modules=bundle.execute();self.assertEqual(self.events,[name for name,_ in self.names])
        self.assertEqual(set(modules),{name for name,_ in self.names})
        self.assertNotIn(str(self.path),sys.path)

    def test_invalid_later_source_prevents_all_execution(self):
        (self.path/'two.py').chmod(0o666)
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(self.events,[])

    def test_compile_error_prevents_all_execution(self):
        (self.path/'two.py').write_text('invalid python syntax !')
        bundle=self.open()
        with self.assertRaises((ValueError,SyntaxError)):bundle.execute()
        self.assertEqual(self.events,[])

    def test_replacement_during_last_compile_prevents_all_execution(self):
        bundle=self.open();original=compile;count=0
        def compiling(*args,**kwargs):
            nonlocal count
            result=original(*args,**kwargs);count+=1
            if count==2:
                replacement=self.path/'replacement';replacement.write_text('raise Exception("unadmitted")')
                replacement.replace(self.path/'one.py')
            return result
        with patch('builtins.compile',side_effect=compiling):
            with self.assertRaises(ValueError):bundle.execute()
        self.assertEqual(self.events,[])

    def test_later_module_collision_prevents_first_execution_and_preserves_foreign(self):
        bundle=self.open();foreign=object();sys.modules[self.names[-1][0]]=foreign
        with self.assertRaises(ValueError):bundle.execute()
        self.assertEqual(self.events,[]);self.assertIs(sys.modules[self.names[-1][0]],foreign)

    def test_execution_failure_removes_only_modules_installed_by_loader(self):
        (self.path/'two.py').write_text('raise ValueError("synthetic")')
        bundle=self.open()
        with self.assertRaises(ValueError):bundle.execute()
        self.assertEqual(self.events,['root_fixture_one'])
        self.assertTrue(all(name not in sys.modules for name,_ in self.names))

    def test_single_link_and_source_size_are_required(self):
        os.link(self.path/'two.py',self.path/'link')
        with self.assertRaises(ValueError):self.open()
        (self.path/'link').unlink();(self.path/'two.py').write_bytes(b' '*65537)
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(self.events,[])

    def test_main_never_retries_step_and_closes_after_sleep_error(self):
        runtime=Mock();runtime.step.return_value=None
        sources=Mock();sources.execute.return_value={'inventory_refresh_runtime':SimpleNamespace(FixedRuntime=SimpleNamespace(fixed=Mock(return_value=runtime)))}
        with (patch.object(entry,'admit_profile'),patch.object(entry,'_environment'),patch.object(entry.RootSources,'fixed',return_value=sources),
              patch.object(entry.time,'sleep',side_effect=OSError('synthetic')) as sleep):
            self.assertEqual(entry.main(),74)
        sleep.assert_called_once_with(.25);runtime.step.assert_called_once();runtime.close.assert_called_once();sources.close.assert_called_once()

    def test_close_error_cannot_return_success(self):
        runtime=Mock();runtime.step.side_effect=ValueError('private');runtime.close.side_effect=ValueError('private')
        factory=Mock(return_value=runtime);sources=Mock();sources.execute.return_value={'inventory_refresh_runtime':SimpleNamespace(FixedRuntime=SimpleNamespace(fixed=factory))}
        with patch.object(entry,'admit_profile'),patch.object(entry,'_environment'),patch.object(entry.RootSources,'fixed',return_value=sources):
            self.assertEqual(entry.main(),74)
        factory.assert_called_once();runtime.step.assert_called_once();runtime.close.assert_called_once()

    def test_profile_rejects_extra_args_missing_site_isolation_or_wrong_cgroup(self):
        flags=SimpleNamespace(isolated=1,dont_write_bytecode=1,no_site=1)
        status=b'CapPrm:\t0000000000000003\nCapEff:\t0000000000000003\nCapBnd:\t0000000000000003\nCapInh:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n'
        def read(name,limit):return status if name=='status' else ('0::'+entry.SELF_CGROUP+'\n').encode()
        with (patch.object(entry.sys,'platform','linux'),patch.object(entry.sys,'flags',flags),
              patch.object(entry.sys,'argv',[entry.ENTRY]),patch.object(entry.os,'getresuid',return_value=(0,0,0),create=True),
              patch.object(entry.os,'getresgid',return_value=(0,0,0),create=True),patch.object(entry,'_proc',side_effect=read)):
            entry.admit_profile()
            flags.no_site=0
            with self.assertRaises(ValueError):entry.admit_profile()
            flags.no_site=1
            with patch.object(entry.sys,'argv',[entry.ENTRY,'extra']):
                with self.assertRaises(ValueError):entry.admit_profile()
            with patch.object(entry,'_proc',return_value=b'0::/other\n'):
                with self.assertRaises(ValueError):entry.admit_profile()


if __name__=='__main__':unittest.main()
