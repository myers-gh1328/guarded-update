"""Real temporary filesystem broker-spool tests; no APT or network access."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('executor_cleanup', Path(__file__).resolve().parents[1]/'scripts/apt_executor.py')
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class ResponseCleanupTests(unittest.TestCase):
    def test_successful_response_consumes_both_spool_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            requests,responses=root/'requests',root/'responses'
            requests.mkdir(mode=0o700);responses.mkdir(mode=0o700)
            identity='a'*32
            request=requests/(identity+'.json')
            response=responses/(identity+'.json')
            request.write_text('{}')
            response.write_text(json.dumps({'schema_version':1,'request_id':identity,'http_status':200,'body':{'job':None}}))
            result=helper.response({'broker_dir':str(requests),'responses_dir':str(responses)},identity)
            self.assertEqual(result,{'job':None})
            self.assertFalse(request.exists())
            self.assertFalse(response.exists())


class StaleResponseTests(unittest.TestCase):
    def test_expiry_only_removes_regular_response_and_temporary_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            spool=root/'responses';spool.mkdir(mode=0o700)
            old=spool/('a'*32+'.json');old.write_text('{}')
            temporary=spool/('.'+'b'*32+'.tmp');temporary.write_text('partial')
            fresh=spool/('c'*32+'.json');fresh.write_text('{}')
            journal=spool/'execution-result.json';journal.write_text('preserved')
            target=root/'target';target.write_text('never delete')
            link=spool/('d'*32+'.json');link.symlink_to(target)
            nested=spool/('e'*32+'.json');nested.mkdir()
            for path in [old,temporary,journal,nested]: os.utime(path,(1000,1000))
            os.utime(fresh,(1600,1600))
            fd=os.open(spool,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try: self.assertEqual(helper.prune_responses(fd,1601),2)
            finally: os.close(fd)
            self.assertFalse(old.exists());self.assertFalse(temporary.exists())
            self.assertTrue(fresh.exists());self.assertTrue(link.is_symlink());self.assertTrue(nested.is_dir())
            self.assertEqual(journal.read_text(),'preserved');self.assertEqual(target.read_text(),'never delete')

    def test_cleanup_has_a_fixed_removal_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for i in range(140):
                path=root/(format(i,'032x')+'.json');path.write_text('{}');os.utime(path,(1000,1000))
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try: self.assertEqual(helper.prune_responses(fd,1601),128)
            finally: os.close(fd)
            self.assertEqual(len(list(root.iterdir())),12)


class CleanupBoundaryTests(unittest.TestCase):
    def test_timeout_removes_only_matching_request_and_response(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);requests=root/'requests';responses=root/'responses'
            requests.mkdir(mode=0o700);responses.mkdir(mode=0o700)
            identity='a'*32
            for spool in [requests,responses]: (spool/(identity+'.json')).write_text('{}')
            unrelated=responses/('b'*32+'.json');unrelated.write_text('preserved')
            with self.assertRaisesRegex(ValueError,'unavailable'):
                helper.response({'broker_dir':str(requests),'responses_dir':str(responses)},identity,timeout=0)
            self.assertFalse((requests/(identity+'.json')).exists())
            self.assertFalse((responses/(identity+'.json')).exists())
            self.assertEqual(unrelated.read_text(),'preserved')

    def test_response_symlinks_never_delete_their_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);requests=root/'requests';responses=root/'responses'
            requests.mkdir(mode=0o700);responses.mkdir(mode=0o700)
            identity='a'*32;name=identity+'.json'
            target=root/'transaction-journal';target.write_text('preserved')
            (requests/name).write_text('{}');(responses/name).symlink_to(target)
            with self.assertRaises(OSError):
                helper.response({'broker_dir':str(requests),'responses_dir':str(responses)},identity)
            self.assertFalse((responses/name).is_symlink())
            self.assertEqual(target.read_text(),'preserved')
            alias=root/'response-alias';alias.symlink_to(responses,target_is_directory=True)
            (responses/name).write_text('do not follow directory link')
            (requests/name).write_text('{}')
            with self.assertRaises(OSError):
                helper.response({'broker_dir':str(requests),'responses_dir':str(alias)},identity)
            self.assertEqual((responses/name).read_text(),'do not follow directory link')
            self.assertFalse((requests/name).exists())

    def test_prune_never_deletes_files_owned_by_another_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);target=root/('a'*32+'.json');target.write_text('preserved')
            os.utime(target,(1000,1000));info=target.stat()
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                with patch.object(helper.os,'stat',return_value=SimpleNamespace(st_mode=info.st_mode,st_uid=info.st_uid+1,st_mtime=info.st_mtime)):
                    self.assertEqual(helper.prune_responses(fd,1601),0)
            finally: os.close(fd)
            self.assertEqual(target.read_text(),'preserved')

    def test_prune_scans_at_most_1024_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for i in range(1030): (root/(format(i,'032x')+'.json')).write_text('{}')
            original=helper.os.scandir
            class Counted:
                count=0
                def __init__(self,fd): self.entries=original(fd)
                def __enter__(self): return self
                def __exit__(self,*args): self.entries.close()
                def __iter__(self): return self
                def __next__(self):
                    Counted.count+=1
                    return next(self.entries)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                with patch.object(helper.os,'scandir',Counted): self.assertEqual(helper.prune_responses(fd),0)
            finally: os.close(fd)
            self.assertEqual(Counted.count,1024)


class LateResponseTests(unittest.TestCase):
    def test_next_wait_expires_a_late_response_without_touching_a_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);requests=root/'requests';responses=root/'responses'
            requests.mkdir(mode=0o700);responses.mkdir(mode=0o700)
            config={'broker_dir':str(requests),'responses_dir':str(responses)}
            expired='a'*32;active='b'*32
            (requests/(expired+'.json')).write_text('{}')
            with self.assertRaises(ValueError): helper.response(config,expired,timeout=0)
            late=responses/(expired+'.json');late.write_text('late transport')
            os.utime(late,(1000,1000))
            journal=root/'execution-result.json';journal.write_text('preserved')
            os.utime(journal,(1000,1000))
            (requests/(active+'.json')).write_text('{}')
            (responses/(active+'.json')).write_text(json.dumps({'schema_version':1,'request_id':active,'http_status':200,'body':{'ok':True}}))
            self.assertEqual(helper.response(config,active),{'ok':True})
            self.assertFalse(late.exists())
            self.assertEqual(journal.read_text(),'preserved')


if __name__ == '__main__': unittest.main()
