"""Read-only checks for the disposable cross-UID marker runner."""
import sys
import subprocess
import os
import time
import types
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import native_inventory_maintenance_public as native


class PublicMarkerNativeTests(unittest.TestCase):
    def test_two_sources_publish_exclusively_and_revalidate(self):
        with tempfile.TemporaryDirectory() as path:
            directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            contents={name:name.encode() for name in native.SOURCE_NAMES}
            try:
                stage=native.MarkerSources(directory,contents,os.getuid(),os.getgid())
                stage.publish();stage.verify()
                with self.assertRaises(ValueError):
                    native.MarkerSources(directory,contents,os.getuid(),os.getgid()).publish()
                os.chmod(Path(path)/native.SOURCE_NAMES[0],0o600)
                with self.assertRaises(ValueError):stage.verify()
                stage.close()
            finally:os.close(directory)

    def test_two_source_publication_preserves_partial_and_rejects_extra(self):
        with tempfile.TemporaryDirectory() as path:
            directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            contents={name:b'fixed bytes' for name in native.SOURCE_NAMES}
            try:
                stage=native.MarkerSources(directory,contents,os.getuid(),os.getgid())
                with patch.object(native.os,'fsync',side_effect=OSError('uncertain')):
                    with self.assertRaises(ValueError):stage.publish()
                self.assertTrue((Path(path)/native.SOURCE_NAMES[0]).exists());stage.close()
            finally:os.close(directory)
        with tempfile.TemporaryDirectory() as path:
            directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            try:
                (Path(path)/'shadow.py').write_bytes(b'foreign')
                stage=native.MarkerSources(directory,contents,os.getuid(),os.getgid())
                with self.assertRaises(ValueError):stage.publish()
                self.assertEqual((Path(path)/'shadow.py').read_bytes(),b'foreign');stage.close()
            finally:os.close(directory)

    def test_two_source_short_writes_and_close_failure(self):
        with tempfile.TemporaryDirectory() as path:
            directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            contents={name:b'fixed bytes' for name in native.SOURCE_NAMES}
            try:
                stage=native.MarkerSources(directory,contents,os.getuid(),os.getgid())
                original=native.os.write
                with patch.object(native.os,'write',side_effect=lambda fd,data:original(fd,data[:1])):stage.publish()
                stage.verify()
                original_close=native.os.close
                def fail(fd):original_close(fd);raise OSError('uncertain')
                with patch.object(native.os,'close',side_effect=fail):
                    with self.assertRaises(ValueError):stage.close()
                    with self.assertRaises(ValueError):stage.close()
            finally:os.close(directory)

    def test_replaced_staged_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            contents={name:b'fixed bytes' for name in native.SOURCE_NAMES}
            try:
                stage=native.MarkerSources(directory,contents,os.getuid(),os.getgid());stage.publish()
                target=Path(path)/native.SOURCE_NAMES[0];target.rename(Path(path)/'old')
                target.write_bytes(contents[native.SOURCE_NAMES[0]]);target.chmod(0o444)
                with self.assertRaises(ValueError):stage.verify()
                stage.close()
            finally:os.close(directory)
    def test_command_has_fixed_profile_and_only_known_modes(self):
        command=native.command('absent',False)
        self.assertEqual(command[:6],['/usr/bin/setpriv','--reuid=60002','--regid=60002','--clear-groups','--inh-caps=-all','--bounding-set=-all'])
        self.assertIn('--no-new-privs',command)
        self.assertNotIn('/bin/sh',command)
        with self.assertRaises(ValueError):native.command('other',False)
        with self.assertRaises(ValueError):native.command('create',False)

    def test_output_is_single_fixed_record(self):
        native.validate_output('absent',b'ABSENT\n')
        for data in (b'',b'ABSENT',b'ABSENT\nextra',b'PRESENT\n'):
            with self.assertRaises(ValueError):native.validate_output('absent',data)

    def test_bounded_invocation_never_signals_on_timeout(self):
        spawned=[];original=subprocess.Popen
        def spawn(*args,**kwargs):
            child=original(*args,**kwargs);spawned.append(child);return child
        with (patch.object(native,'command',return_value=[sys.executable,'-I','-c','import time;time.sleep(.2)']),
              patch.object(native.subprocess,'Popen',side_effect=spawn),
              patch.object(original,'kill',side_effect=AssertionError('signal')),
              patch.object(original,'terminate',side_effect=AssertionError('signal'))):
            with self.assertRaises(ValueError):native.invoke('absent',time.monotonic()+.03)
            self.assertEqual(spawned[0].wait(timeout=3),0)

    def test_bounded_invocation_rejects_oversized_output(self):
        spawned=[];original=subprocess.Popen
        def spawn(*args,**kwargs):
            child=original(*args,**kwargs);spawned.append(child);return child
        with (patch.object(native,'command',return_value=[sys.executable,'-I','-c',"import os;os.write(1,b'x'*129)"]),
              patch.object(native.subprocess,'Popen',side_effect=spawn)):
            with self.assertRaises(ValueError):native.invoke('absent',time.monotonic()+3)
            spawned[0].wait(timeout=3)

    def test_pipe_close_failure_rejects_success(self):
        original=subprocess.Popen;spawned=[]
        def spawn(*args,**kwargs):
            child=original(*args,**kwargs);stream=child.stdout;wrapper=Mock(wraps=stream)
            def fail():stream.close();raise OSError('uncertain close')
            wrapper.close.side_effect=fail;child.stdout=wrapper;spawned.append(child);return child
        with (patch.object(native,'command',return_value=[sys.executable,'-I','-c',"print('ABSENT')"]),
              patch.object(native.subprocess,'Popen',side_effect=spawn)):
            with self.assertRaises(ValueError):native.invoke('absent',time.monotonic()+3)
        self.assertEqual(spawned[0].returncode,0)

    def test_existing_fixture_directory_stops_before_invocation(self):
        chain=Mock();chain.fds=[123]
        fake_modules={
            'inventory_refresh_artifact_fixture':types.SimpleNamespace(LIB='lib/',verify_archive=Mock(return_value={'files':{}})),
            'inventory_refresh_resources':types.SimpleNamespace(_Chain=Mock(return_value=chain)),
            'inventory_refresh_reporter_fixture_files':types.SimpleNamespace(FixtureSources=Mock()),
            'native_inventory_cross_uid':types.SimpleNamespace(create_account=Mock(),ensure_libexec=Mock()),
        }
        with (patch.dict(sys.modules,fake_modules),patch.object(native.sys,'platform','linux'),
              patch.object(native.os,'getresuid',return_value=(0,0,0),create=True),
              patch.object(native.os,'getresgid',return_value=(0,0,0),create=True),
              patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}),
              patch.object(native.os,'mkdir',side_effect=FileExistsError),patch.object(native,'invoke') as invoke,
              patch('builtins.print') as diagnostic):
            with self.assertRaises(ValueError):native.run('synthetic')
        invoke.assert_not_called();self.assertEqual(chain.close.call_count,2)
        self.assertEqual(diagnostic.call_args.args,('Synthetic public marker stage=libexec',))

    def test_changed_parent_stops_before_invocation(self):
        local=Mock();local.fds=[123];local.verify.side_effect=[None,ValueError('replaced')]
        fake_modules={
            'inventory_refresh_artifact_fixture':types.SimpleNamespace(LIB='lib/',verify_archive=Mock(return_value={'files':{}})),
            'inventory_refresh_resources':types.SimpleNamespace(_Chain=Mock(return_value=local)),
            'inventory_refresh_reporter_fixture_files':types.SimpleNamespace(FixtureSources=Mock()),
            'native_inventory_cross_uid':types.SimpleNamespace(create_account=Mock(),ensure_libexec=Mock()),
        }
        with (patch.dict(sys.modules,fake_modules),patch.object(native.sys,'platform','linux'),
              patch.object(native.os,'getresuid',return_value=(0,0,0),create=True),
              patch.object(native.os,'getresgid',return_value=(0,0,0),create=True),
              patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}),patch.object(native,'invoke') as invoke):
            with self.assertRaises(ValueError):native.run('synthetic')
        invoke.assert_not_called();local.close.assert_called_once()

    def test_changed_staged_source_stops_before_invocation(self):
        chain=Mock();chain.fds=[123];sources=Mock();sources.verify.side_effect=[None,ValueError('replaced')]
        contents={'lib/'+name:b'x' for name in native.SOURCE_NAMES}
        fake_modules={
            'inventory_refresh_artifact_fixture':types.SimpleNamespace(LIB='lib/',verify_archive=Mock(return_value={'files':contents})),
            'inventory_refresh_resources':types.SimpleNamespace(_Chain=Mock(return_value=chain)),
            'inventory_refresh_reporter_fixture_files':types.SimpleNamespace(FixtureSources=Mock()),
            'native_inventory_cross_uid':types.SimpleNamespace(create_account=Mock(),ensure_libexec=Mock()),
        }
        info=types.SimpleNamespace(st_uid=0,st_gid=0,st_mode=0o40755)
        with (patch.dict(sys.modules,fake_modules),patch.object(native.sys,'platform','linux'),
              patch.object(native.os,'getresuid',return_value=(0,0,0),create=True),
              patch.object(native.os,'getresgid',return_value=(0,0,0),create=True),
              patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}),patch.object(native.os,'mkdir'),
              patch.object(native.os,'fsync'),patch.object(native.os,'fstat',return_value=info),patch.object(native,'MarkerSources',return_value=sources),
              patch.object(native,'invoke') as invoke):
            with self.assertRaises(ValueError):native.run('synthetic')
        invoke.assert_not_called();sources.close.assert_called_once()
