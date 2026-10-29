"""No Root Git execution is admitted by the hosted archive verifier."""
from pathlib import Path
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import inventory_refresh_artifact_fixture as verifier


class GitBoundaryTests(unittest.TestCase):
    def test_root_git_command_drops_every_privilege_before_git_exec(self):
        account=SimpleNamespace(pw_uid=1001,pw_gid=1001,pw_dir='/home/runner')
        command=verifier._git_command(Path('/work/repo'),('rev-parse','--verify','HEAD^{commit}'),0,account,'linux','true')
        self.assertEqual(command[:8],['/usr/bin/setpriv','--reuid=1001','--regid=1001','--clear-groups',
            '--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs'])
        self.assertEqual(command[8:11],['--','/usr/bin/git','--no-replace-objects'])
        probe=verifier._privilege_probe_command(Path('/work/repo'),account)
        self.assertEqual(probe[:9],command[:9]);self.assertEqual(probe[9:14],['/usr/bin/python3','-I','-B','-S','-c'])
        for field in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','getresuid','getresgid','getgroups'):
            self.assertIn(field,probe[14])
        self.assertEqual(verifier.ENV['GIT_NO_LAZY_FETCH'],'1')
        self.assertNotIn('GITHUB_TOKEN',verifier.ENV)
        with self.assertRaises(ValueError):verifier._git_command(Path('/work/repo'),('status',),0,account,'linux','true')
        with self.assertRaises(ValueError):verifier._git_command(Path('/work/repo'),('rev-parse','--verify','HEAD^{commit}'),0,account,'linux',None)
        for invalid in [None,SimpleNamespace(pw_uid=0,pw_gid=1001,pw_dir='/home/runner'),SimpleNamespace(pw_uid=1001,pw_gid=0,pw_dir='/home/runner'),SimpleNamespace(pw_uid=1001,pw_gid=1001,pw_dir='/other')]:
            with self.assertRaises(ValueError):verifier._git_command(Path('/work/repo'),('rev-parse','--verify','HEAD^{commit}'),0,invalid,'linux','true')

    def test_blob_bytes_must_match_the_git_object_id(self):
        fake_oid=b'1'*40
        result=[b'100644 blob '+fake_oid+b'\tfile\0',b'3\n',b'bad']
        with patch.object(verifier,'_git',side_effect=result):
            with self.assertRaises(ValueError):verifier._blob(Path('/work/repo'),'a'*40,'file')

    def test_bounded_child_timeout_and_oversize_never_signal_process(self):
        real=subprocess.Popen
        for code,timeout in [('import time;time.sleep(0.3)',.04),('import sys;sys.stdout.buffer.write(b"x"*(3*1024*1024));sys.stdout.buffer.flush()',3)]:
            children=[]
            def child(_command,**kwargs):
                result=real(['/usr/bin/python3','-I','-c',code],**kwargs);children.append(result);return result
            with patch.object(verifier.subprocess,'Popen',side_effect=child):
                with self.assertRaises(ValueError):verifier._bounded_git(['/fixed-command'],Path('/tmp'),timeout)
            self.assertEqual(len(children),1)
            # The fixture owns an unprivileged child; the verifier never signals it.
            children[0].wait(timeout=3)

    def test_uncertain_selector_close_prevents_success(self):
        real=subprocess.Popen;selector=verifier.selectors.DefaultSelector();close=selector.close
        def uncertain():close();raise OSError('synthetic close uncertainty')
        def child(_command,**kwargs):return real(['/usr/bin/python3','-I','-c','print("fixture")'],**kwargs)
        with patch.object(selector,'close',side_effect=uncertain),patch.object(verifier.selectors,'DefaultSelector',return_value=selector),patch.object(verifier.subprocess,'Popen',side_effect=child):
            with self.assertRaises(ValueError):verifier._bounded_git(['/fixed-command'],Path('/tmp'))
