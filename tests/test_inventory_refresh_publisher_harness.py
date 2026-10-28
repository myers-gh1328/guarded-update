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
from unittest.mock import Mock,patch


class PublisherHarnessTests(unittest.TestCase):
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
        self.assertEqual(len(sources),8)
        self.assertEqual(sources[-2:],(('inventory_refresh_reader_session','inventory_refresh_reader_session.py'),('inventory_refresh_reporter_io','inventory_refresh_reporter_io.py')))
        self.assertIn('Synthetic seam only',code)
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
        reader=Mock();chain=Mock();scope={'session':owned,'reader':reader,'sources':None,'chains':[chain],'root':None,
            'evidence':{'synthetic':True},'json':json}
        attempt=ast.Try(body=[ast.Pass()],handlers=[],orelse=[],finalbody=cleanup.finalbody)
        code=ast.fix_missing_locations(ast.Module(body=[attempt,output],type_ignores=[]))
        stdout=io.StringIO()
        with contextlib.redirect_stdout(stdout),self.assertRaises(ValueError):exec(compile(code,'<actual-child-cleanup>','exec'),scope)
        self.assertEqual(stdout.getvalue(),'');reader.close.assert_called_once();chain.close.assert_called_once()

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
