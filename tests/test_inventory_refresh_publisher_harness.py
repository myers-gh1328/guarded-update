"""Run the native proof's actual synthetic actor without root or real writes."""
import ast
import json
import os
import time
import contextlib
import io
import stat
import re
import sys
from types import SimpleNamespace
from pathlib import Path
import unittest
import tempfile
import subprocess
from unittest.mock import Mock,patch


class PublisherHarnessTests(unittest.TestCase):
    def test_rust_reporter_staging_retires_only_after_preflight_and_confirmed_empty(self):
        names=('stage_rust_reporter_artifact_fixture','retire_rust_reporter_artifact_fixture')
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]
        self.assertEqual({node.name for node in nodes},set(names))
        events=[]
        class Owner:
            def __init__(self,name):self.name=name
            def publish(self):events.append((self.name,'publish'))
            def verify(self):events.append((self.name,'verify'))
            def verify_published(self):events.append((self.name,'verify'))
            def retire(self,empty):events.append((self.name,'retire',empty))
            def close(self):events.append((self.name,'close'))
        artifact,sources,binary=(Owner(name) for name in ('artifact','sources','binary'))
        scope={'ROOT':'checkout','verify_archive':lambda root,path:{'source_commit':'commit'},
            'RunnerArtifact':SimpleNamespace(fixed=lambda commit,deadline:artifact),
            'FixtureSources':SimpleNamespace(fixed=lambda verified,include_entry:sources),
            'FixtureBinary':SimpleNamespace(fixed=lambda supplied:binary)}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<rust-stage>','exec'),scope)
        fixture=scope[names[0]]('archive',100)
        events.clear();scope[names[1]](fixture,True)
        self.assertEqual(events,[('artifact','verify'),('sources','verify'),('binary','verify'),
            ('binary','retire',True),('sources','retire',True),('artifact','close')])
        with self.assertRaises(AssertionError):scope[names[1]](fixture,True)
        fixture=scope[names[0]]('archive',100);events.clear()
        with self.assertRaises(AssertionError):scope[names[1]](fixture,False)
        self.assertEqual(events,[('binary','retire',False),('sources','retire',False),('artifact','close')])
        fixture=scope[names[0]]('archive',100);events.clear()
        def fail():events.append(('binary','verify'));raise ValueError('changed')
        binary.verify_published=fail
        with self.assertRaises(AssertionError):scope[names[1]](fixture,True)
        self.assertEqual(events,[('artifact','verify'),('sources','verify'),('binary','verify'),
            ('binary','retire',False),('sources','retire',False),('artifact','close')])
    def test_rust_staging_failure_closes_owners_without_retiring(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in
            ('stage_rust_reporter_artifact_fixture','retire_rust_reporter_artifact_fixture')]
        for failure in ('sources.publish','binary.publish','binary.verify_published'):
            events=[]
            class Owner:
                def __init__(self,name):self.name=name
                def effect(self,op):
                    events.append((self.name,op))
                    if self.name+'.'+op==failure:raise OSError('uncertain')
                def publish(self):self.effect('publish')
                def verify(self):self.effect('verify')
                def verify_published(self):self.effect('verify_published')
                def close(self):self.effect('close')
                def retire(self,empty):events.append((self.name,'retire',empty))
            artifact,sources,binary=(Owner(name) for name in ('artifact','sources','binary'))
            scope={'ROOT':'checkout','verify_archive':lambda root,path:{'source_commit':'commit'},
                'RunnerArtifact':SimpleNamespace(fixed=lambda commit,deadline:artifact),
                'FixtureSources':SimpleNamespace(fixed=lambda verified,include_entry:sources),
                'FixtureBinary':SimpleNamespace(fixed=lambda supplied:binary)}
            exec(compile(ast.Module(body=nodes,type_ignores=[]),'<rust-stage>','exec'),scope)
            with self.assertRaises(ValueError):scope['stage_rust_reporter_artifact_fixture']('archive',100)
            self.assertFalse(any('retire' in event for event in events))
            expected=['artifact','sources'] if failure=='sources.publish' else ['artifact','sources','binary']
            self.assertCountEqual([event[0] for event in events if event[1]=='close'],expected)

    def test_rust_retirement_failure_propagates_unknown_and_closes_artifact(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        node=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='retire_rust_reporter_artifact_fixture')
        scope={};exec(compile(ast.Module(body=[node],type_ignores=[]),'<rust-retire>','exec'),scope)
        events=[]
        def fail(empty):events.append(('binary',empty));raise OSError('uncertain')
        fixture={'artifact':SimpleNamespace(verify=lambda:None,close=lambda:events.append(('artifact','close'))),
            'sources':SimpleNamespace(verify=lambda:None,retire=lambda empty:events.append(('sources',empty))),
            'binary':SimpleNamespace(verify_published=lambda:None,retire=fail)}
        with self.assertRaises(AssertionError):scope['retire_rust_reporter_artifact_fixture'](fixture,True)
        self.assertEqual(events,[('binary',True),('sources',False),('artifact','close')])

    def test_rust_test_output_requires_exact_single_executed_test(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        node=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='validate_rust_proof_output')
        scope={'re':re};exec(compile(ast.Module(body=[node],type_ignores=[]),'<rust-output>','exec'),scope)
        check=scope['validate_rust_proof_output']
        valid=(b'\nrunning 1 test\ntest inventory::reporter_obs::tests::hosted_real_reporter_rust_journal_roundtrip ... ok\n'
            b'\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 169 filtered out; finished in 1.23s\n')
        check(valid)
        for bad in (valid.replace(b'running 1 test',b'running 0 tests'),valid.replace(b'0 ignored',b'1 ignored'),
            valid.replace(b' ... ok',b' ... ignored'),valid+b'extra\n',valid.replace(b'1 passed',b'0 passed')):
            with self.assertRaises((AssertionError,ValueError)):check(bad)

    def test_rust_properties_timeout_never_signals_owned_process(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        node=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='rust_unit_properties')
        read_fd,write_fd=os.pipe();stream=os.fdopen(read_fd,'rb',buffering=0)
        child=SimpleNamespace(stdout=stream,wait=Mock(),kill=Mock(),terminate=Mock())
        process=SimpleNamespace(Popen=Mock(return_value=child),DEVNULL=subprocess.DEVNULL,PIPE=subprocess.PIPE)
        scope={'subprocess':process,'os':os,'time':time,'select':__import__('select'),'ENV':{},'PROPERTIES':('LoadState',)}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<properties>','exec'),scope)
        try:
            with self.assertRaises(ValueError):scope['rust_unit_properties'](time.monotonic()+.03,('LoadState',))
            child.kill.assert_not_called();child.terminate.assert_not_called()
            self.assertTrue(stream.closed)
            self.assertEqual(process.Popen.call_args.args[0][0],'/bin/systemctl')
        finally:os.close(write_fd)

    def test_real_coordinator_runs_rust_reporter_after_packaged_reporter(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        node=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prove_actual_coordinator_entry_loop')
        code=ast.unparse(node)
        self.assertLess(code.index('prove_packaged_reporter_roundtrip'),code.index('prove_rust_reporter_roundtrip'))
        self.assertIn('restricted_rust_parent_real_reporter_journal_mechanics_verified',code)

    def test_rust_reporter_unit_has_fixed_identity_scope_and_cleanup_gate(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        node=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prove_rust_reporter_roundtrip')
        code=ast.unparse(node)
        for item in ('User=60002','Group=60002','NoNewPrivileges=yes','PrivateNetwork=yes','RuntimeMaxSec=20',
            '--exact','--ignored','--test-threads=1','hosted_real_reporter_rust_journal_roundtrip',
            'InvocationID','cgroup.events','populated 0','validate_rust_proof_output','retire_rust_reporter_artifact_fixture'):
            self.assertIn(item,code)
        self.assertNotIn('.kill(',code);self.assertNotIn('os.kill(',code)

    def test_packaged_reporter_launch_has_fixed_unprivileged_scope_and_no_root_signal(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        launch=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prove_packaged_reporter_roundtrip')
        code=ast.unparse(launch)
        for value in ('User=60002','Group=60002','NoNewPrivileges=yes','PrivateNetwork=yes','RuntimeMaxSec=20'):
            self.assertIn(value,code)
        self.assertIn('run_reporter_controller',code)
        self.assertIn('retire_reporter_artifact_fixture',code)
        self.assertNotIn('.kill(',code);self.assertNotIn('os.kill(',code)

    def test_artifact_staging_verifies_then_publishes_before_literal_parent_install(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        names=('stage_reporter_artifact_fixture','retire_reporter_artifact_fixture')
        nodes=[next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==name) for name in names]
        events=[]
        def retire_sources(empty):
            events.append(('sources',empty))
            if not empty:raise ValueError('Unknown fixture cleanup')
        sources=SimpleNamespace(publish=lambda:events.append('publish'),retire=retire_sources)
        verified={'files':{'libexec/command-center-inventory-refresh/reporter.py':b'fixed entry'}}
        parent={'owned':True}
        def verify(repo,path):events.append(('verify',repo,path));return verified
        def fixed(value):self.assertIs(value,verified);events.append('fixed');return sources
        def install(program,**options):
            self.assertEqual((program,options),('fixed entry',{'reporter':True}));events.append('parent');return parent
        scope={'ROOT':'checkout','verify_archive':verify,'FixtureSources':SimpleNamespace(fixed=fixed),
            'install_parent_fixture':install,'retire_parent_fixture':lambda value,empty:events.append(('parent-retire',empty))}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<artifact-staging>','exec'),scope)
        fixture=scope[names[0]]('archive')
        self.assertEqual(events,[('verify','checkout','archive'),'fixed','publish','parent'])
        with self.assertRaises(AssertionError):scope[names[1]](fixture,False)
        self.assertEqual(events[-2:],[('parent-retire',False),('sources',False)])
        self.assertIsNone(fixture['sources']);self.assertIsNone(fixture['parent'])
        retired_events=list(events)
        with self.assertRaises(AssertionError):scope[names[1]](fixture,True)
        self.assertEqual(events,retired_events)
        events.clear();sources.retire=lambda empty:events.append(('sources',empty))
        def failed_parent(value,empty):events.append(('parent-retire',empty));raise OSError('private')
        scope['retire_parent_fixture']=failed_parent
        with self.assertRaises(AssertionError):scope[names[1]]({'parent':parent,'sources':sources},True)
        self.assertEqual(events,[('parent-retire',True),('sources',True)])
        events.clear()
        scope['retire_parent_fixture']=lambda value,empty:events.append(('parent-retire',empty))
        with self.assertRaises(AssertionError):scope[names[1]]({'parent':parent,'sources':sources},1)
        self.assertEqual(events,[('parent-retire',False),('sources',False)])
        events.clear()
        def failed_install(*args,**kwargs):raise OSError('private')
        scope['install_parent_fixture']=failed_install
        with self.assertRaises(OSError):scope[names[0]]('archive')
        self.assertEqual(events[-1],('sources',True))
        events.clear()
        def failed_verify(*args):raise ValueError('private')
        scope['verify_archive']=failed_verify
        with self.assertRaises(ValueError):scope[names[0]]('archive')
        self.assertEqual(events,[])
        scope['verify_archive']=verify
        def failed_publish():events.append('partial-publish');raise OSError('private')
        sources.publish=failed_publish
        with self.assertRaises(OSError):scope[names[0]]('archive')
        self.assertEqual(events[-2:],['partial-publish',('sources',True)])

    def test_fixed_c_parent_has_two_literal_entry_cases_and_no_forwarded_program(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        factory=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='parent_fixture_c_source')
        scope={};exec(compile(ast.Module(body=[factory],type_ignores=[]),'<fixed-parent-source>','exec'),scope)
        for reporter,name in ((False,'reporter-parent-proof.py'),(True,'reporter.py')):
            code=scope['parent_fixture_c_source'](reporter)
            self.assertIn('/usr/local/libexec/command-center-inventory-refresh/'+name,code)
            self.assertIn('int main(void)',code);self.assertNotIn('argv[',code);self.assertNotIn('kill(',code)
            result=subprocess.run(['/usr/bin/cc','-Wall','-Wextra','-Werror','-x','c','-fsyntax-only','-'],
                input=code.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        with self.assertRaises(AssertionError):scope['parent_fixture_c_source'](1)

    def test_parent_mechanics_program_has_only_fixed_readonly_sources(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        factory=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='parent_mechanics_program')
        scope={'ROOT':Path(__file__).resolve().parents[1]}
        exec(compile(ast.Module(body=[factory],type_ignores=[]),'<parent-factory>','exec'),scope)
        code=scope['parent_mechanics_program']();compile(code,'<parent-mechanics>','exec')
        body=ast.parse(code)
        assignments=[node.value for node in body.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='SOURCES' for target in node.targets)]
        self.assertEqual(ast.literal_eval(assignments[-1]),tuple((name,name+'.py') for name in (
            'inventory_refresh_resources','inventory_refresh_reporter_resources','inventory_refresh_reporter_parent')))
        self.assertIn("owner=loaded['inventory_refresh_reporter_parent'].ReporterParent.fixed()",code)
        self.assertNotIn('ReporterRequestWriter',code)
        coordinator=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prove_actual_coordinator_entry_loop')
        self.assertIn('prove_reporter_parent_mechanics()',ast.unparse(coordinator))

    def test_environment_mechanics_program_pins_without_writer_or_os_queries(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        factory=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='environment_mechanics_program')
        scope={'ROOT':Path(__file__).resolve().parents[1]}
        exec(compile(ast.Module(body=[factory],type_ignores=[]),'<environment-factory>','exec'),scope)
        code=scope['environment_mechanics_program']();compile(code,'<environment-mechanics>','exec')
        self.assertIn("owner=loaded['inventory_refresh_reporter_environment'].ReporterEnvironment.fixed()",code)
        self.assertIn('pinned=owner.pin_current()',code)
        body=ast.parse(code)
        assignments=[node.value for node in body.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='SOURCES' for target in node.targets)]
        modules={name for name,_ in ast.literal_eval(assignments[-1])}
        self.assertEqual(len(modules),13)
        for forbidden in ('inventory_refresh_io','inventory_refresh_policy','inventory_refresh_guardian'):
            self.assertNotIn(forbidden,modules)
        self.assertNotIn('session.policy(',code)
        coordinator=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prove_actual_coordinator_entry_loop')
        self.assertIn('prove_reporter_environment_mechanics(public)',ast.unparse(coordinator))

    def parent_file_helpers(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        helpers=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('publish_parent_fixture_file','retire_parent_fixture')]
        scope={'os':os,'stat':stat};exec(compile(ast.Module(body=helpers,type_ignores=[]),'<parent-files>','exec'),scope)
        return scope['publish_parent_fixture_file'],scope['retire_parent_fixture']

    def test_parent_fixture_preserves_preexisting_and_foreign_files(self):
        publish,retire=self.parent_file_helpers()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                target=root/'command-center-inventory';target.write_bytes(b'foreign')
                fixture={'files':[],'directories':[]}
                with self.assertRaises(FileExistsError):publish(fixture,directory,target.name,b'synthetic',0o555)
                self.assertEqual(target.read_bytes(),b'foreign');self.assertEqual(fixture['files'],[])
                target.unlink();publish(fixture,directory,target.name,b'synthetic',0o555)
                held=os.open(target,os.O_RDONLY)
                try:
                    target.unlink();target.write_bytes(b'foreign replacement')
                    with self.assertRaises(AssertionError):retire(fixture,True)
                    self.assertEqual(target.read_bytes(),b'foreign replacement')
                finally:os.close(held)
            finally:os.close(directory)

    def test_parent_fixture_retirement_requires_unit_empty_and_closes_caps(self):
        publish,retire=self.parent_file_helpers()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                cap=Mock();fixture={'files':[],'directories':[cap]}
                publish(fixture,directory,'command-center-inventory',b'synthetic',0o555)
                with self.assertRaises(AssertionError):retire(fixture,False)
                self.assertTrue((root/'command-center-inventory').exists());cap.close.assert_called_once()
                (root/'command-center-inventory').unlink()
                fixture={'files':[],'directories':[]};publish(fixture,directory,'command-center-inventory',b'synthetic',0o555)
                retire(fixture,True);self.assertFalse((root/'command-center-inventory').exists())
            finally:os.close(directory)

    def test_restricted_reporter_phase_is_bounded_exact_and_duplicate_strict(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        decoder=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='decode_reporter_phase')
        scope={'json':json};exec(compile(ast.Module(body=[decoder],type_ignores=[]),'<reporter-phase>','exec'),scope)
        decode=scope['decode_reporter_phase']
        pinned={'phase':'pinned','cache_generation':'a'*32,'policy_generation':'b'*64,'boot_id':'11111111-1111-4111-8111-111111111111'}
        self.assertEqual(decode((json.dumps(pinned)+'\n').encode(),'pinned'),pinned)
        for raw in [b'{"phase":"pinned"}\nextra',b'{"phase":"pinned","phase":"pinned"}\n',
                    b'{"phase":"complete"}\n',b'{"phase":"pinned","extra":null}\n',b'x'*4097,b'[]\n']:
            with self.subTest(raw=raw[:80]),self.assertRaises(ValueError):decode(raw,'pinned')

    def test_restricted_reporter_library_program_compiles_and_uses_fixed_sources(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        factory=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='reporter_library_program')
        scope={'ROOT':Path(__file__).resolve().parents[1]}
        exec(compile(ast.Module(body=[factory],type_ignores=[]),'<reporter-factory>','exec'),scope)
        code=scope['reporter_library_program']();compile(code,'<native-reporter>','exec')
        body=ast.parse(code)
        assignments=[node.value for node in body.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCES' for t in node.targets)]
        sources=ast.literal_eval(assignments[-1])
        self.assertEqual(len(sources),11)
        self.assertIn(('inventory_refresh_reader_tools','inventory_refresh_reader_tools.py'),sources)
        self.assertIn(('inventory_refresh_reporter_resources','inventory_refresh_reporter_resources.py'),sources)
        self.assertIn("resources=loaded['inventory_refresh_reporter_resources'].ReporterResources.fixed()",code)
        self.assertIn('command-center-inventory.service',code)
        self.assertEqual(sources[-2:],(('inventory_refresh_reader_session','inventory_refresh_reader_session.py'),('inventory_refresh_reporter_io','inventory_refresh_reporter_io.py')))
        self.assertIn('Synthetic seam only',code)
        self.assertIn("session.policy(['inventory-proof'])",code)
        self.assertIn('frozen=session.frozen_scan_bounds()',code)
        self.assertIn('evidence[key]==value for key,value in frozen.items()',code)
        for method in ('installed','native_architecture','holds'):
            self.assertIn('session.'+method+'()',code)
        self.assertNotIn('subprocess.run(',code)
        setup=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prove_reporter_library_roundtrip')
        copy_loop=next(node for node in setup.body if isinstance(node,ast.For))
        self.assertIn('inventory_refresh_reader_tools',ast.literal_eval(copy_loop.iter))
        prints=[node for node in ast.walk(body) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='print']
        self.assertEqual(len(prints),3)
        self.assertTrue(all(any(keyword.arg=='flush' and isinstance(keyword.value,ast.Constant) and keyword.value.value is True for keyword in node.keywords) for node in prints))

    def test_restricted_reporter_rejects_nonzero_exit_surplus_and_missing_eof(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        finish=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='finish_reporter_output')
        scope={'os':os,'time':time};exec(compile(ast.Module(body=[finish],type_ignores=[]),'<reporter-eof>','exec'),scope)
        for surplus,exit_status,keep_open in [(b'',0,False),(b'extra',0,False),(b'',74,False),(b'',0,True)]:
            read,write=os.pipe()
            try:
                if surplus:os.write(write,surplus)
                if not keep_open:os.close(write);write=None
                with os.fdopen(read,'rb') as stream:
                    process=SimpleNamespace(stdout=stream,wait=Mock(return_value=exit_status))
                    if not surplus and exit_status==0 and not keep_open:scope['finish_reporter_output'](process,time.monotonic()+.1)
                    else:
                        with self.assertRaises(AssertionError):scope['finish_reporter_output'](process,time.monotonic()+.05)
            finally:
                if write is not None:os.close(write)

    def test_parent_pipe_close_failure_still_closes_owned_cgroup_descriptor(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        closer=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='close_reporter_parent')
        close=Mock();scope={'os':SimpleNamespace(close=close)}
        exec(compile(ast.Module(body=[closer],type_ignores=[]),'<reporter-parent-close>','exec'),scope)
        stream=SimpleNamespace(close=Mock(side_effect=OSError('synthetic pipe close')))
        with self.assertRaises(OSError):scope['close_reporter_parent'](stream,42)
        close.assert_called_once_with(42)

    def test_actual_child_poll_retries_only_publication_change_using_new_read(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        factory=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='reporter_library_program')
        scope={'ROOT':Path(__file__).resolve().parents[1]};exec(compile(ast.Module(body=[factory],type_ignores=[]),'<factory>','exec'),scope)
        body=ast.parse(scope['reporter_library_program']())
        public=next(node for node in ast.walk(body) if isinstance(node,ast.FunctionDef) and node.name=='public')
        class Error(ValueError):
            def __init__(self,reason):self.reason=reason
        chain=Mock();fresh=object();reader=Mock();reader.read.side_effect=[Error('publication_changed'),fresh]
        scope={'chains':[chain],'reader':reader,'loaded':{'inventory_refresh_reporter_io':SimpleNamespace(ReporterIOError=Error)}}
        exec(compile(ast.Module(body=[public],type_ignores=[]),'<actual-child-public>','exec'),scope)
        self.assertIsNone(scope['public']());self.assertIs(scope['public'](),fresh)
        self.assertEqual(reader.read.call_count,2);self.assertEqual(chain.verify.call_count,4)
        for reason in ('state_inconsistent','cleanup_unconfirmed'):
            reader.read.side_effect=Error(reason)
            with self.assertRaises(Error):scope['public']()
    def test_actual_child_close_failure_withholds_final_evidence(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        factory=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='reporter_library_program')
        scope={'ROOT':Path(__file__).resolve().parents[1]};exec(compile(ast.Module(body=[factory],type_ignores=[]),'<factory>','exec'),scope)
        body=ast.parse(scope['reporter_library_program']())
        cleanup=next(node for node in body.body if isinstance(node,ast.Try) and node.finalbody)
        output=body.body[-1]
        owned=SimpleNamespace(close=Mock(side_effect=OSError('synthetic close failure')))
        reader=Mock();chain=Mock();resources=Mock();scope={'session':owned,'reader':reader,'sources':None,'chains':[chain],'root':None,'resources':resources,
            'evidence':{'synthetic':True},'json':json}
        attempt=ast.Try(body=[ast.Pass()],handlers=[],orelse=[],finalbody=cleanup.finalbody)
        code=ast.fix_missing_locations(ast.Module(body=[attempt,output],type_ignores=[]))
        stdout=io.StringIO()
        with contextlib.redirect_stdout(stdout),self.assertRaises(ValueError):exec(compile(code,'<actual-child-cleanup>','exec'),scope)
        self.assertEqual(stdout.getvalue(),'');reader.close.assert_called_once();chain.close.assert_called_once()
        resources.close.assert_called_once()

    def test_actual_writer_actor_uses_only_admitted_fixed_dependencies_and_capabilities(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        factory=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='reporter_request_program')
        scope={'ROOT':Path(__file__).resolve().parents[1]}
        exec(compile(ast.Module(body=[factory],type_ignores=[]),'<writer-actor-factory>','exec'),scope)
        code=scope['reporter_request_program']();compile(code,'<writer-actor>','exec');body=ast.parse(code)
        assignments=[node.value for node in body.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCES' for t in node.targets)]
        modules=ast.literal_eval(assignments[-1]);self.assertEqual(len(modules),9)
        self.assertIn(('inventory_refresh_io','inventory_refresh_io.py'),modules)
        self.assertIn("sys.argv[1] in ('observation','release')",code)
        self.assertIn('writer.publish(sys.argv[2])',code)
        self.assertIn('not production admission',code)

    def test_synthetic_actor_has_own_imports_and_transfers_ownership_after_chmod(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        outer=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prove_root_refresh_transaction')
        assignment=next(node for node in outer.body if isinstance(node,ast.Assign) and
            any(isinstance(target,ast.Name) and target.id=='body' for target in node.targets))
        text=assignment.value.func.value.value.replace('@GENERATION@',repr('a'*64))
        body=ast.parse(text)
        actor=next(node for node in ast.walk(body) if isinstance(node,ast.FunctionDef) and node.name=='synthetic_request')
        imports=[node for node in body.body if isinstance(node,ast.Import)]
        fake=Mock();fake.O_RDONLY=0;fake.O_DIRECTORY=1;fake.O_NOFOLLOW=2
        fake.O_WRONLY=4;fake.O_CREAT=8;fake.O_EXCL=16
        fake.open.side_effect=[10,11];fake.write.return_value=32
        # os is a standard bootstrap import; actor-specific imports must be in
        # the actual body, not inherited accidentally from the host harness.
        scope={'os':fake}
        exec(compile(ast.Module(body=imports+[actor],type_ignores=[]),'<synthetic-actor>','exec'),scope)
        scope['synthetic_request']('observation','0000000000000005'+'d'*16)
        calls=[call[0] for call in fake.mock_calls]
        self.assertLess(calls.index('fchmod'),calls.index('fchown'))
        self.assertLess(calls.index('fchown'),calls.index('fsync'))
        self.assertLess(calls.index('fsync'),calls.index('rename'))
        self.assertEqual(fake.close.call_count,2)

    def test_restricted_actor_completes_partial_writes_before_durable_replacement(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        code=next(node.value.value for node in tree.body if isinstance(node,ast.Assign) and
            any(isinstance(target,ast.Name) and target.id=='REPORTER_INBOX_CODE' for target in node.targets))
        fake=Mock();fake.O_RDONLY=0;fake.O_DIRECTORY=1;fake.O_NOFOLLOW=2
        fake.O_WRONLY=4;fake.O_CREAT=8;fake.O_EXCL=16
        fake.open.side_effect=[10,11];fake.write.side_effect=[7,25]
        fake.urandom.return_value=b'x'*8
        fake.fstat.return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=60002,st_gid=60002,st_nlink=1)
        identity='Uid: 60002 60002 60002 60002\nGid: 60002 60002 60002 60002\nGroups:\nNoNewPrivs: 1\n'
        identity+=''.join(name+': 0000000000000000\n' for name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
        nonce='0000000000000006'+'f'*16
        with patch.dict(sys.modules,{'os':fake,'sys':SimpleNamespace(argv=['-c','observation',nonce])}):
            exec(compile(code,'<restricted-actor>','exec'),{'open':lambda path:io.StringIO(identity)})
        self.assertEqual(fake.write.call_args_list[0].args,(11,nonce.encode()))
        self.assertEqual(fake.write.call_args_list[1].args,(11,nonce.encode()[7:]))
        calls=[call[0] for call in fake.mock_calls]
        self.assertLess(calls.index('fsync'),calls.index('rename'));self.assertEqual(fake.close.call_count,2)
        fake.fchown.assert_not_called();fake.unlink.assert_not_called()

    def test_policy_restore_latch_precedes_any_truncating_write(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        proof=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prove_actual_coordinator_entry_loop')
        invalidate=next(node for node in proof.body if isinstance(node,ast.FunctionDef) and node.name=='invalidate_policy')
        wrapper=ast.parse('def exercise(write_policy):\n changed=False\n try:\n  invalidate_policy()\n except OSError:pass\n return changed\n')
        wrapper.body[0].body.insert(1,invalidate);scope={}
        exec(compile(ast.fix_missing_locations(wrapper),'<policy-latch>','exec'),scope)
        write=Mock(side_effect=OSError('synthetic post-truncate fsync failure'))
        self.assertTrue(scope['exercise'](write));write.assert_called_once_with(b'{}')

    def test_entry_start_waits_for_invocation_instead_of_claiming_loaded_object(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        proof=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prove_actual_coordinator_entry_loop')
        attempt=next(node for node in proof.body if isinstance(node,ast.Try) and any(isinstance(child,ast.While) for child in node.body))
        loop=next(node for node in attempt.body if isinstance(node,ast.While))
        pending={'LoadState':'loaded','InvocationID':'','Transient':'yes','Description':'synthetic-owned'}
        ready={**pending,'InvocationID':'a'*32}
        properties=Mock(side_effect=[pending,ready]);clock=Mock();clock.monotonic.return_value=0
        scope={'properties':properties,'description':'synthetic-owned','group':None,'limit':1,
               'launcher':SimpleNamespace(poll=lambda:None),'time':clock}
        def pin(value):
            self.assertEqual(value['InvocationID'],'a'*32);scope['group']=object()
        claiming=Mock(side_effect=pin);scope['pin']=claiming
        exec(compile(ast.Module(body=[loop],type_ignores=[]),'<entry-start>','exec'),scope)
        claiming.assert_called_once_with(ready);clock.sleep.assert_called_once_with(.02)

    def test_projected_reader_native_candidate_and_pin_assertions_accept_real_format(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        code=next(node.value.value for node in tree.body if isinstance(node,ast.Assign) and
            any(isinstance(target,ast.Name) and target.id=='PROJECTED_READER_CODE' for target in node.targets))
        body=ast.parse(code)
        checks=[node for node in ast.walk(body) if isinstance(node,ast.Assert) and isinstance(node.test,ast.Call) and
            isinstance(node.test.func,ast.Attribute) and node.test.func.attr=='search']
        self.assertEqual(len(checks),2)
        sample=b'inventory-proof:\n  Installed: (none)\n  Candidate: 1.0\n  Version table:\n     1.0 123\n        500 https://127.0.0.1/repo proof/main arm64 Packages\n'
        exec(compile(ast.Module(body=checks,type_ignores=[]),'<native-candidate>','exec'),{'re':re,'result':SimpleNamespace(stdout=sample)})
        cgroups=[node.test.comparators[0] for node in ast.walk(body) if isinstance(node,ast.Assert) and
            isinstance(node.test,ast.Compare) and isinstance(node.test.comparators[0],ast.Constant) and
            isinstance(node.test.comparators[0].value,str) and node.test.comparators[0].value.startswith('0::/')]
        self.assertEqual(len(cgroups),1);self.assertTrue(cgroups[0].value.endswith('\n'))

    def test_native_reader_diagnostic_keeps_only_static_stage_and_kind(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        factory=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='projected_reader_program')
        scope={'PROJECTED_READER_CODE':"private='synthetic-private-value';raise ValueError(private)"}
        exec(compile(ast.Module(body=[factory],type_ignores=[]),'<reader-diagnostics>','exec'),scope)
        output=io.StringIO()
        with contextlib.redirect_stderr(output):
            with self.assertRaises(SystemExit) as result:exec(compile(scope['projected_reader_program'](),'<native-reader>','exec'),{})
        self.assertEqual(result.exception.code,74);self.assertNotIn('synthetic-private-value',output.getvalue())
        self.assertIn('"stage": "identity"',output.getvalue());self.assertIn('"kind": "ValueError"',output.getvalue())

    def test_reporter_fingerprints_require_exact_root_receipt_and_complete_lock_interval(self):
        tree=ast.parse((Path(__file__).parent/'native_inventory_refresh_apt.py').read_bytes())
        matcher=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='match_projected_reader_receipt')
        scope={'re':re};exec(compile(ast.Module(body=[matcher],type_ignores=[]),'<reader-match>','exec'),scope)
        offer={'nonce':'0000000000000006'+'f'*16,'boot_id':'11111111-1111-4111-8111-111111111111',
            'cache_generation':'a'*32,'policy_generation':'b'*64,'lock_open_boottime_ms':100,'expires_boottime_ms':120100}
        reader={'schema_version':1,'observation_nonce':offer['nonce'],'boot_id':offer['boot_id'],'cache_generation':offer['cache_generation'],
            'policy_generation':offer['policy_generation'],'scan_started_boottime_ms':101,'scan_finished_boottime_ms':110,
            'installed_before_sha256':'c'*64,'installed_after_sha256':'c'*64}
        receipt={**offer,'lock_held_until_boottime_ms':111,'released_boottime_ms':112,'outcome':'released',
            'installed_before_sha256':'c'*64,'installed_after_sha256':'c'*64}
        self.assertTrue(scope['match_projected_reader_receipt'](offer,reader,receipt))
        for field,value in (('installed_after_sha256','d'*64),('scan_started_boottime_ms',99),
                            ('scan_finished_boottime_ms',112),('cache_generation','d'*32),('schema_version',True)):
            changed={**reader,field:value}
            with self.assertRaises((ValueError,AssertionError)):scope['match_projected_reader_receipt'](offer,changed,receipt)
        with self.assertRaises((ValueError,AssertionError)):scope['match_projected_reader_receipt'](offer,reader,{**receipt,'outcome':'expired'})


if __name__=='__main__':unittest.main()
