"""Run the native proof's actual synthetic actor without root or real writes."""
import ast
from pathlib import Path
import unittest
from unittest.mock import Mock


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


if __name__=='__main__':unittest.main()
