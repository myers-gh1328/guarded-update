"""Run the native proof's actual synthetic actor without root or real writes."""
import ast
import io
import stat
import sys
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest.mock import Mock,patch


class PublisherHarnessTests(unittest.TestCase):
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


if __name__=='__main__':unittest.main()
