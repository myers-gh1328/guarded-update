"""Disposable native-fixture archive admission, never a production installer."""
from pathlib import Path
import sys
import unittest
import gzip
import hashlib
import json
import tempfile
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_inventory_refresh_artifact as fixtures
import inventory_refresh_artifact_fixture as verifier


class FixtureArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=fixtures.ArtifactTests(methodName='runTest');cls.fixture.setUp()
        output=fixtures.packager.build(cls.fixture.repo,cls.fixture.root/'artifact')
        cls.original=cls.fixture.archive(output).read_bytes()
        cls.commit,cls.data=verifier.expected_files(cls.fixture.repo)
    @classmethod
    def tearDownClass(cls):cls.fixture.tearDown()
    def setUp(self):
        self.case=tempfile.TemporaryDirectory(dir=self.fixture.root)
        self.archive=Path(self.case.name)/verifier.ARCHIVE;self.store(self.original)
    def tearDown(self):self.case.cleanup()
    def store(self,raw):
        self.archive.write_bytes(raw)
        self.archive.with_name(verifier.ARCHIVE+'.sha256').write_text(hashlib.sha256(raw).hexdigest()+'  '+verifier.ARCHIVE+'\n')
    def rejected(self,raw):
        self.store(raw)
        with self.assertRaises(ValueError):verifier.verify_archive(self.fixture.repo,self.archive)
    def changed_manifest(self,mutate):
        data=dict(self.data);value=json.loads(data['manifest.json']);mutate(value)
        data['manifest.json']=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        self.rejected(gzip.compress(verifier.ustar(data),mtime=0))

    def test_exact_pipeline_shape_reconstructs_without_runtime_or_generator_execution(self):
        result=verifier.verify_archive(self.fixture.repo,self.archive)
        self.assertEqual(result['source_commit'],self.fixture.git('rev-parse','HEAD').decode().strip())
        self.assertEqual(len(result['files']),45)
        self.assertEqual(len(result['reporter_modules']),18)
        self.assertIn('libexec/command-center-inventory-refresh/reporter.py',result['files'])

    def test_verification_never_executes_generator_or_runtime_code(self):
        with patch('builtins.exec',side_effect=AssertionError('project execution in Root verifier')):
            self.assertEqual(verifier.verify_archive(self.fixture.repo,self.archive)['source_commit'],self.commit)

    def test_truncated_crc_bad_concatenated_and_trailing_gzip_streams_are_rejected(self):
        for raw in (self.original[:-8],self.original[:-8]+b'\0'*8,self.original+gzip.compress(b'extra',mtime=0),self.original+b'trailing'):
            with self.subTest(length=len(raw)):self.rejected(raw)

    def test_decompression_limit_is_enforced_before_any_git_source_read(self):
        self.store(gzip.compress(b'0'*(4*1024*1024+1),mtime=0))
        with patch.object(verifier,'expected_files',side_effect=AssertionError('source read after expansion overflow')) as source:
            with self.assertRaises(ValueError):verifier.verify_archive(self.fixture.repo,self.archive)
            source.assert_not_called()

    def test_extra_members_and_hidden_nonzero_tar_suffix_are_rejected(self):
        tar=verifier.ustar(self.data)
        self.rejected(gzip.compress(tar+b'x'*512,mtime=0))
        self.rejected(gzip.compress(tar+verifier.ustar({'../hidden.py':b'unexpected'}),mtime=0))

    def test_duplicate_json_keys_manifest_rows_and_bool_aliases_are_rejected(self):
        data=dict(self.data);data['manifest.json']=b'{"schema_version":1,'+data['manifest.json'][1:]
        self.rejected(gzip.compress(verifier.ustar(data),mtime=0))
        self.changed_manifest(lambda value:value['files'].append(dict(value['files'][0])))
        self.changed_manifest(lambda value:value['files'][0].update(uid=False))

    def test_forged_self_consistent_entry_hashes_cannot_replace_selected_git_code(self):
        data=dict(self.data);name=verifier.LIB+'reporter.py';data[name]=b'# altered entry\n'+data[name]
        value=json.loads(data['manifest.json']);digest=hashlib.sha256(data[name]).hexdigest()
        value['reporter_bootstrap']['generated_entry_sha256']=digest
        for row in value['files']:
            if row['path']==name:row.update(sha256=digest,size=len(data[name]))
        data['manifest.json']=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        self.rejected(gzip.compress(verifier.ustar(data),mtime=0))

    def test_wrong_commit_or_recipe_is_not_accepted_as_authority(self):
        self.changed_manifest(lambda value:value.update(source_commit='0'*40))
        self.changed_manifest(lambda value:value['reporter_bootstrap'].update(template_sha256='0'*64))

    def test_archive_and_sidecar_symlinks_are_not_followed(self):
        original=self.archive.with_name('original');original.write_bytes(self.original)
        self.archive.unlink();self.archive.symlink_to(original)
        with self.assertRaises(ValueError):verifier.verify_archive(self.fixture.repo,self.archive)
        self.archive.unlink();self.store(self.original)
        sidecar=self.archive.with_name(verifier.ARCHIVE+'.sha256');copy=sidecar.with_name('sidecar-copy');copy.write_bytes(sidecar.read_bytes())
        sidecar.unlink();sidecar.symlink_to(copy)
        with self.assertRaises(ValueError):verifier.verify_archive(self.fixture.repo,self.archive)

    def test_wrong_sidecar_and_oversized_compressed_file_are_rejected_before_source_reads(self):
        self.archive.with_name(verifier.ARCHIVE+'.sha256').write_bytes(b'0'*64+b'  '+verifier.ARCHIVE.encode()+b'\n')
        with patch.object(verifier,'expected_files') as source:
            with self.assertRaises(ValueError):verifier.verify_archive(self.fixture.repo,self.archive)
            source.assert_not_called()
        self.store(b'x'*(2*1024*1024+1))
        with patch.object(verifier,'expected_files') as source:
            with self.assertRaises(ValueError):verifier.verify_archive(self.fixture.repo,self.archive)
            source.assert_not_called()


if __name__=='__main__':unittest.main()
