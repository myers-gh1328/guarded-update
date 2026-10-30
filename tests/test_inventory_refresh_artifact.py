"""Inactive helper source archive: actual Git blobs, no root or remote writes."""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from inventory_refresh_root_entry import SOURCES
from inventory_refresh_reporter_build import MODULES as REPORTER_MODULES,generate
spec=importlib.util.spec_from_file_location('inventory_helper_packager',ROOT/'scripts/package-inventory-helper.py')
packager=importlib.util.module_from_spec(spec);spec.loader.exec_module(packager)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.repo=self.root/'repo';self.repo.mkdir()
        (self.repo/'scripts').mkdir();(self.repo/'docs').mkdir()
        names={name+'.py' for name,_ in SOURCES}|{name+'.py' for name in REPORTER_MODULES}|{
            'inventory_refresh_root_entry.py','inventory_refresh_worker.py','package-inventory-helper.py',
            'inventory_refresh_reporter_build.py','inventory_refresh_reporter_template.py'}
        for name in names:shutil.copyfile(ROOT/'scripts'/name,self.repo/'scripts'/name)
        shutil.copyfile(ROOT/'docs/inventory-refresh-contract.md',self.repo/'docs/inventory-refresh-contract.md')
        self.git('init','-q');self.commit()
    def tearDown(self):self.temp.cleanup()
    def git(self,*args):
        return subprocess.check_output(['git','-c','commit.gpgsign=false','-c','user.name=Fixture','-c','user.email=fixture@example.invalid',*args],cwd=self.repo,stderr=subprocess.DEVNULL)
    def commit(self):self.git('add','.');self.git('commit','-qm','Synthetic fixture')
    def archive(self,directory):return directory/'command-center-inventory-metadata-helper.tar.gz'
    def test_deterministic_across_output_directories_with_exact_readonly_closure(self):
        one=packager.build(self.repo,self.root/'one');two=packager.build(self.repo,self.root/'different-name')
        raw=self.archive(one).read_bytes();self.assertEqual(raw,self.archive(two).read_bytes())
        self.assertEqual(raw[3]&8,0);self.assertEqual(raw[4:8],b'\0'*4)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            members=archive.getmembers();self.assertEqual([m.name for m in members],sorted(m.name for m in members))
            for member in members:
                self.assertTrue(member.isfile());self.assertEqual((member.uid,member.gid,member.mode,member.mtime),(0,0,0o444,0))
                self.assertFalse(member.name.startswith('/'));self.assertNotIn('..',Path(member.name).parts);self.assertFalse(member.pax_headers)
            data={member.name:archive.extractfile(member).read() for member in members}
        manifest=json.loads(data.pop('manifest.json'))
        self.assertEqual(manifest['source_commit'],self.git('rev-parse','HEAD').decode().strip())
        self.assertFalse(manifest['installs_or_enables_services'])
        self.assertEqual({row['path'] for row in manifest['files']},set(data))
        for row in manifest['files']:
            self.assertEqual(hashlib.sha256(data[row['path']]).hexdigest(),row['sha256']);self.assertEqual(len(data[row['path']]),row['size'])
        prefix='libexec/command-center-inventory-refresh/'
        expected={prefix+filename for _,filename in SOURCES}|{prefix+name+'.py' for name in REPORTER_MODULES}|{
            prefix+name for name in ('coordinator.py','worker.py','observation-native.py','observation-guardian.py','reporter.py')}
        self.assertEqual({name for name in data if name.startswith(prefix)},expected)
        generated,recipe=generate(self.git('show','HEAD:scripts/inventory_refresh_root_entry.py'),
            self.git('show','HEAD:scripts/inventory_refresh_reporter_template.py'))
        self.assertEqual(data[prefix+'reporter.py'],generated)
        self.assertEqual(manifest['reporter_bootstrap'],dict(recipe,generator_sha256=hashlib.sha256(
            self.git('show','HEAD:scripts/inventory_refresh_reporter_build.py')).hexdigest(),entry_path=prefix+'reporter.py',module_names=list(REPORTER_MODULES)))
        self.assertEqual(data[prefix+'inventory_refresh_entry.py'],data[prefix+'observation-native.py'])
        self.assertEqual(data[prefix+'observation-native.py'],data[prefix+'observation-guardian.py'])
        checksum=(one/(self.archive(one).name+'.sha256')).read_text()
        self.assertEqual(checksum,hashlib.sha256(raw).hexdigest()+'  '+self.archive(one).name+'\n')
    def test_relevant_dirty_source_is_rejected_before_output(self):
        (self.repo/'scripts/inventory_refresh_worker.py').write_text('dirty')
        with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
        self.assertFalse((self.root/'out').exists())

    def test_assume_unchanged_cannot_hide_dirty_tested_source(self):
        path='scripts/inventory_refresh_worker.py';self.git('update-index','--assume-unchanged',path)
        (self.repo/path).write_text('dirty but hidden from git diff')
        self.assertEqual(self.git('diff','--quiet','HEAD','--',path),b'')
        with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
        self.assertFalse((self.root/'out').exists())

    def test_unisolated_cli_rejects_before_any_shadowed_standard_library_import(self):
        marker=self.root/'shadow-ran'
        (self.repo/'scripts/json.py').write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("unexpected shadow")\nraise RuntimeError("shadow sentinel")\n')
        result=subprocess.run([sys.executable,'-B',str(self.repo/'scripts/package-inventory-helper.py'),str(self.root/'out')],
            cwd=self.repo,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists())
        self.assertNotIn(b'shadow sentinel',result.stderr);self.assertFalse((self.root/'out').exists())

    def test_isolated_cli_ignores_unrelated_standard_library_shadow_files(self):
        marker=self.root/'shadow-ran'
        source='from pathlib import Path\nPath('+repr(str(marker))+').write_text("unexpected shadow")\nraise RuntimeError("shadow sentinel")\n'
        for name in ('ast.py','json.py'):(self.repo/'scripts'/name).write_text(source)
        result=subprocess.run([sys.executable,'-I','-B','-S',str(self.repo/'scripts/package-inventory-helper.py'),str(self.root/'out')],
            cwd=self.repo,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'));self.assertFalse(marker.exists())
        self.assertEqual(len(list((self.root/'out').rglob('*.tar.gz'))),1)

    def test_hidden_dirty_new_generator_template_and_dependency_never_execute(self):
        for flag,path in (('--assume-unchanged','scripts/inventory_refresh_reporter_build.py'),
                ('--skip-worktree','scripts/inventory_refresh_reporter_template.py'),
                ('--assume-unchanged','scripts/inventory_refresh_reporter_dialogue.py')):
            with self.subTest(path=path):
                original=(self.repo/path).read_bytes();self.git('update-index',flag,path)
                try:
                    (self.repo/path).write_bytes(original+b'\n# hidden changed source\n')
                    self.assertEqual(self.git('diff','--quiet','HEAD','--',path),b'')
                    with patch.object(packager,'execute_reporter_generator',side_effect=AssertionError('generator before byte admission')) as execute:
                        with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
                        execute.assert_not_called()
                    self.assertFalse((self.root/'out').exists())
                finally:
                    (self.repo/path).write_bytes(original)
                    self.git('update-index','--no-assume-unchanged' if flag=='--assume-unchanged' else '--no-skip-worktree',path)

    def test_wrong_generator_closure_is_rejected_before_execution_or_output(self):
        generator=self.repo/'scripts/inventory_refresh_reporter_build.py'
        generator.write_bytes(generator.read_bytes()+b'\nMODULES=()\n');self.commit()
        with patch.object(packager,'execute_reporter_generator') as execute:
            with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
            execute.assert_not_called()
        self.assertFalse((self.root/'out').exists())

    def test_selected_generator_cannot_supply_a_false_input_recipe(self):
        generator=self.repo/'scripts/inventory_refresh_reporter_build.py'
        generator.write_bytes(generator.read_bytes()+b'''\n_original_generate=generate
def generate(entry,template):
 raw,recipe=_original_generate(entry,template)
 recipe['template_sha256']='0'*64
 return raw,recipe
''');self.commit()
        with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
        self.assertFalse((self.root/'out').exists())

    def test_generated_entry_closure_is_checked_independently_of_recipe_hashes(self):
        generator=self.repo/'scripts/inventory_refresh_reporter_build.py'
        generator.write_bytes(generator.read_bytes()+b'''\n_original_generate=generate
def generate(entry,template):
 raw,recipe=_original_generate(entry,template)
 raw=raw.replace(('SOURCES='+repr(tuple((name,name+'.py') for name in MODULES))).encode(),b'SOURCES=()')
 recipe['generated_entry_sha256']=hashlib.sha256(raw).hexdigest()
 return raw,recipe
''');self.commit()
        with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
        self.assertFalse((self.root/'out').exists())

    def test_hidden_worktree_symlink_is_not_followed_even_when_bytes_match(self):
        path='scripts/inventory_refresh_reporter_dialogue.py';source=self.repo/path
        duplicate=self.root/'same-bytes.py';duplicate.write_bytes(source.read_bytes())
        self.git('update-index','--assume-unchanged',path);source.unlink();source.symlink_to(duplicate)
        with patch.object(packager,'execute_reporter_generator') as execute:
            with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
            execute.assert_not_called()
        self.assertFalse((self.root/'out').exists())

    def test_local_replace_objects_cannot_substitute_code_under_original_commit_id(self):
        original=self.git('rev-parse','HEAD').decode().strip()
        template=self.repo/'scripts/inventory_refresh_reporter_template.py'
        template.write_bytes(template.read_bytes()+b'\n# substituted commit fixture\n');self.commit()
        substitute=self.git('rev-parse','HEAD').decode().strip()
        self.git('replace',original,substitute)
        self.git('update-ref','HEAD',original,substitute)
        self.assertEqual(self.git('rev-parse','HEAD').decode().strip(),original)
        self.assertEqual(self.git('diff','--quiet','HEAD','--','scripts/inventory_refresh_reporter_template.py'),b'')
        with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
        self.assertFalse((self.root/'out').exists())
    def test_unrelated_dirty_files_do_not_enter_artifact(self):
        (self.repo/'unrelated').write_text('excluded')
        output=packager.build(self.repo,self.root/'out')
        with tarfile.open(self.archive(output),'r:gz') as archive:self.assertFalse(any('unrelated' in name for name in archive.getnames()))
    def test_missing_blob_or_symlink_is_rejected_without_output(self):
        worker=self.repo/'scripts/inventory_refresh_worker.py';worker.unlink();worker.symlink_to('/etc/passwd');self.commit()
        with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
        self.assertFalse((self.root/'out').exists())
    def test_existing_generation_is_never_overwritten(self):
        output=packager.build(self.repo,self.root/'out');before=self.archive(output).read_bytes()
        with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
        self.assertEqual(self.archive(output).read_bytes(),before)
    def test_new_file_descriptor_is_closed_when_identity_read_fails(self):
        stage=self.root/'stage';stage.mkdir();directory=os.open(stage,os.O_RDONLY|os.O_DIRECTORY)
        fd=os.open(stage/'payload',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);original_close=os.close
        try:
            with (patch.object(packager.os,'open',return_value=fd),
                  patch.object(packager.os,'fstat',side_effect=OSError('synthetic identity error')),
                  patch.object(packager.os,'close',wraps=original_close) as closing):
                with self.assertRaises(OSError):packager.write(directory,'payload',b'synthetic',[])
                closing.assert_called_once_with(fd)
            self.assertFalse(any(path.name.endswith('.tar.gz') for path in self.root.rglob('*')))
        finally:
            try:original_close(fd)
            except OSError:pass
            original_close(directory)

    def test_failed_publication_removes_only_own_archive_preserving_foreign_file(self):
        original=os.link;calls=0
        def linking(src,dst,**kwargs):
            nonlocal calls
            calls+=1
            if calls==2:
                fd=os.open(dst,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=kwargs['dst_dir_fd'])
                try:os.write(fd,b'foreign')
                finally:os.close(fd)
                raise FileExistsError('synthetic publication race')
            return original(src,dst,**kwargs)
        with patch.object(packager.os,'link',side_effect=linking):
            with self.assertRaises(ValueError):packager.build(self.repo,self.root/'out')
        files=list((self.root/'out').rglob('*'))
        self.assertFalse(any(path.name=='command-center-inventory-metadata-helper.tar.gz' for path in files))
        self.assertEqual([path.read_bytes() for path in files if path.is_file()],[b'foreign'])


if __name__=='__main__':unittest.main()
