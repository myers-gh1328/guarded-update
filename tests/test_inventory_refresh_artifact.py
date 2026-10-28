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
spec=importlib.util.spec_from_file_location('inventory_helper_packager',ROOT/'scripts/package-inventory-helper.py')
packager=importlib.util.module_from_spec(spec);spec.loader.exec_module(packager)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.repo=self.root/'repo';self.repo.mkdir()
        (self.repo/'scripts').mkdir();(self.repo/'docs').mkdir()
        names={name+'.py' for name,_ in SOURCES}|{'inventory_refresh_root_entry.py','inventory_refresh_worker.py','package-inventory-helper.py'}
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
        expected={prefix+filename for _,filename in SOURCES}|{prefix+name for name in ('coordinator.py','worker.py','observation-native.py','observation-guardian.py')}
        self.assertEqual({name for name in data if name.startswith(prefix)},expected)
        self.assertEqual(data[prefix+'inventory_refresh_entry.py'],data[prefix+'observation-native.py'])
        self.assertEqual(data[prefix+'observation-native.py'],data[prefix+'observation-guardian.py'])
        checksum=(one/(self.archive(one).name+'.sha256')).read_text()
        self.assertEqual(checksum,hashlib.sha256(raw).hexdigest()+'  '+self.archive(one).name+'\n')
    def test_relevant_dirty_source_is_rejected_before_output(self):
        (self.repo/'scripts/inventory_refresh_worker.py').write_text('dirty')
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
