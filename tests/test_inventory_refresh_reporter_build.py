"""Build-only source generation; generated self-checks are not provenance."""
from pathlib import Path
import ast
import hashlib
import sys
import unittest
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import inventory_refresh_reporter_build as builder

TEMPLATE=b'''import os,stat,sys,types
LIB_ROOT='/usr/local/libexec/command-center-inventory-refresh'
# @FIXED_SOURCE_MODULES@
# @FIXED_SOURCE_LOADER@
'''


class ReporterBuildTests(unittest.TestCase):
    def test_generated_loader_is_exact_source_segments_and_fixed_reporter_closure(self):
        original=(ROOT/'scripts/inventory_refresh_root_entry.py').read_bytes()
        generated,metadata=builder.generate(original,TEMPLATE)
        original_text=original.decode();generated_text=generated.decode()
        old={node.name:ast.get_source_segment(original_text,node) for node in ast.parse(original_text).body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
        new={node.name:ast.get_source_segment(generated_text,node) for node in ast.parse(generated_text).body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
        self.assertEqual(set(new),{'_require','_stable','_directory','RootSources'})
        for name in new:self.assertEqual(new[name],old[name])
        self.assertEqual(metadata['loader_source_sha256'],hashlib.sha256(original).hexdigest())
        self.assertEqual(metadata['template_sha256'],hashlib.sha256(TEMPLATE).hexdigest())
        self.assertEqual(metadata['generated_entry_sha256'],hashlib.sha256(generated).hexdigest())
        namespace={'__name__':'reporter_build_fixture'};exec(compile(generated,'synthetic-reporter.py','exec'),namespace)
        self.assertEqual(tuple(name for name,_ in namespace['SOURCES']),builder.MODULES)
        self.assertEqual(len(namespace['SOURCES']),18)
        self.assertNotIn('inventory_refresh_runtime',builder.MODULES)
        self.assertNotIn('inventory_refresh_root_entry',builder.MODULES)

    def test_unexpected_loader_shapes_and_template_markers_are_rejected_without_execution(self):
        original=(ROOT/'scripts/inventory_refresh_root_entry.py').read_bytes()
        bad=[original+b'\ndef _stable(info): return ()\n',
            original.replace(b'def _stable(info):',b'@staticmethod\ndef _stable(info):'),
            original.replace(b'class RootSources:',b'class RootSources(object):'),
            original.replace(b'owner=0):',b'owner=os.getuid()):'),
            original.replace(b'def _require(condition):',b'async def _require(condition):'),
            original+b'\nRootSources=None\n',original.replace(b'def close(self):',b'def close(self,extra):'),
            original.replace(b'def _directory(info,owner):',b'def _directory(info,owner=0):')]
        for raw in bad:
            with self.subTest(length=len(raw)),self.assertRaises(ValueError):builder.generate(raw,TEMPLATE)
        for template in (TEMPLATE.replace(b'# @FIXED_SOURCE_LOADER@',b''),TEMPLATE+b'# @FIXED_SOURCE_MODULES@\n',
                TEMPLATE.replace(b'# @FIXED_SOURCE_LOADER@',b' # @FIXED_SOURCE_LOADER@'),b'\xff',b'x'*65537):
            with self.subTest(length=len(template)),self.assertRaises(ValueError):builder.generate(original,template)

    def test_full_reporter_closure_loads_in_clean_isolated_process_without_project_path(self):
        original=(ROOT/'scripts/inventory_refresh_root_entry.py').read_bytes()
        generated,_=builder.generate(original,TEMPLATE)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'entry.py').write_bytes(generated)
            for name in builder.MODULES:
                target=root/(name+'.py');target.write_bytes((ROOT/'scripts'/(name+'.py')).read_bytes());target.chmod(0o444)
            program=r'''
import os,sys,json
namespace={'__name__':'isolated_reporter_fixture'}
with open(sys.argv[1],'rb') as source:raw=source.read(65537)
exec(compile(raw,'synthetic-reporter.py','exec'),namespace)
assert not any(name.startswith('inventory_refresh_') for name in sys.modules)
directory=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)
bundle=None
try:
 bundle=namespace['RootSources'](directory,owner=os.getuid())
 loaded=bundle.execute()
 assert set(loaded)==set(name for name,_ in namespace['SOURCES'])
 assert all('guarded-update' not in path for path in sys.path)
 assert set(name for name in sys.modules if name.startswith('inventory_refresh_'))==set(loaded)
 decoder=loaded['inventory_refresh_reporter_protocol'].CommandDecoder()
 command=decoder.decode(b'{"schema_version":1,"id":1,"operation":"policy","packages":["synthetic:arm64"]}\n')
 assert command.packages==('synthetic:arm64',)
 try:loaded['inventory_refresh_reporter_io'].ReporterRequestWriter(-1,'invalid',os.getuid(),os.getgid(),owner=os.getuid())
 except ValueError:pass
 else:raise AssertionError('Invalid fixture capability accepted')
finally:
 if bundle is not None:bundle.close()
 os.close(directory)
print(json.dumps({'admitted_modules':len(loaded),'ambient_project_imports':False}))
'''
            result=subprocess.run([sys.executable,'-I','-B','-S','-c',program,str(root/'entry.py'),str(root)],
                cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            self.assertEqual(result.stdout,b'{"admitted_modules": 18, "ambient_project_imports": false}\n')

    def test_template_cannot_shadow_generated_closure_or_security_helpers(self):
        original=(ROOT/'scripts/inventory_refresh_root_entry.py').read_bytes()
        for extra in (b'SOURCES=()\n',b'RootSources=None\n',b'def _require(condition): pass\n',b'import os as RootSources\n'):
            with self.subTest(extra=extra),self.assertRaises(ValueError):builder.generate(original,TEMPLATE+extra)


if __name__=='__main__':unittest.main()
