"""Fixed policy-command boundary; child fixtures never invoke package tools."""
from contextlib import contextmanager
from pathlib import Path
import os
import subprocess
import sys
import time
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_reader_tools as tools


class PolicyToolsTests(unittest.TestCase):
    def setUp(self):
        self.calls=[];self.verified=[];self.now=100;self.children=[]
        self.launch=subprocess.Popen
    @contextmanager
    def fixture(self,code):
        @contextmanager
        def generation(cache,generation):
            self.assertIs(cache,self);self.assertEqual(generation,'a'*32)
            yield '/synthetic-reader/apt.conf',lambda:self.verified.append(True)
        def launch(argv,**kwargs):
            self.calls.append((argv,kwargs))
            child=self.launch([sys.executable,'-I','-B','-S','-c',code],**kwargs)
            self.children.append(child)
            return child
        with patch.object(tools,'_fixed_generation',generation),patch.object(tools.subprocess,'Popen',side_effect=launch):
            yield
    def query(self,packages=('synthetic:arm64',),limit=65536):
        return tools._policy(self,'a'*32,packages,lambda:self.now,100000,limit)

    def test_query_uses_only_fixed_argv_environment_and_waits_for_clean_eof(self):
        with self.fixture("print('synthetic: Candidate: 2')"):
            self.assertEqual(self.query(),'synthetic: Candidate: 2\n')
        argv,kwargs=self.calls[0]
        self.assertEqual(argv,['/usr/bin/apt-cache','policy','synthetic:arm64'])
        self.assertEqual(kwargs,dict(env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C',
            'APT_CONFIG':'/synthetic-reader/apt.conf'},cwd='/',stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True))
        self.assertGreaterEqual(len(self.verified),2)

    def test_untrusted_inputs_never_launch_a_child(self):
        for packages in ([],['a']*301,['a','a'],['--help'],['pkg/other'],['a b'],['a\n'],['Ä'],['a:amd64:extra'],
                         ['a'*257],[True],'synthetic',('a',None)):
            with self.subTest(packages=packages),self.fixture("raise Exception('never')"):
                with self.assertRaises(ValueError):self.query(packages)
        self.assertEqual(self.calls,[])

    def test_bound_is_streamed_and_exact_bound_is_accepted(self):
        with self.fixture("import os;os.write(1,b'a'*8)"):
            self.assertEqual(self.query(limit=8),'a'*8)
        with self.fixture("import os;os.write(1,b'a'*9)"):
            with self.assertRaises(ValueError):self.query(limit=8)

    def test_nonzero_and_non_utf8_output_cannot_be_returned(self):
        for code in ("print('partial');raise SystemExit(7)","import os;os.write(1,b'\\xff')"):
            with self.subTest(code=code),self.fixture(code):
                with self.assertRaises(ValueError):self.query()

    def test_eof_is_insufficient_until_child_success(self):
        start=time.monotonic()
        with self.fixture("import os,time;os.close(1);time.sleep(.1);raise SystemExit(3)"):
            with self.assertRaises(ValueError):self.query()
        self.assertGreaterEqual(time.monotonic()-start,.09)

    def test_final_verification_expiry_cannot_return_already_read_output(self):
        def late_verification():
            self.verified.append(True)
            if len(self.verified)>1:self.now=100000
        @contextmanager
        def generation(*_):yield '/synthetic-reader/apt.conf',late_verification
        with self.fixture("print('never publish')"),patch.object(tools,'_fixed_generation',generation):
            with self.assertRaises(ValueError):self.query()

    def test_expired_reserve_never_launches_child(self):
        self.now=99000
        with self.fixture("raise Exception('never')"):
            with self.assertRaises(ValueError):self.query()
        self.assertEqual(self.calls,[])

    def test_expiry_during_running_child_reaps_it_and_closes_output(self):
        for close_stdout in (False,True):
            started=time.monotonic()
            def clock():return 99001 if time.monotonic()-started>.1 else 100
            code=('import os;os.close(1);' if close_stdout else '')+'import time;time.sleep(30)'
            with self.subTest(close_stdout=close_stdout),self.fixture(code):
                with self.assertRaises(ValueError):tools._policy(self,'a'*32,['synthetic'],clock,100000,100)
            self.assertLess(time.monotonic()-started,2)
            self.assertIsNotNone(self.children[-1].returncode)
            self.assertNotEqual(self.children[-1].returncode,0)
            self.assertTrue(self.children[-1].stdout.closed)

    def test_child_success_with_external_held_pipe_is_not_eof(self):
        read,write=os.pipe();child=None
        @contextmanager
        def generation(*_):yield '/synthetic-reader/apt.conf',lambda:None
        def launch(argv,**kwargs):
            nonlocal child
            kwargs['stdout']=write
            child=self.launch([sys.executable,'-I','-B','-S','-c',"print('incomplete')"],**kwargs)
            child.stdout=os.fdopen(read,'rb')
            return child
        start=time.monotonic()
        def clock():return 99001 if time.monotonic()-start>.1 else 100
        try:
            with patch.object(tools,'_fixed_generation',generation),patch.object(tools.subprocess,'Popen',side_effect=launch):
                with self.assertRaises(ValueError):tools._policy(self,'a'*32,['synthetic'],clock,100000,100)
            self.assertEqual(child.returncode,0);self.assertTrue(child.stdout.closed)
            self.assertLess(time.monotonic()-start,2)
        finally:
            os.close(write)
            if child is None:os.close(read)

    def test_selector_close_error_still_reaps_child_and_closes_pipe(self):
        original=tools.selectors.DefaultSelector
        def selector():
            value=original();close=value.close
            def failure():close();raise OSError('synthetic selector close')
            value.close=failure
            return value
        with self.fixture("print('never publish')"),patch.object(tools.selectors,'DefaultSelector',side_effect=selector):
            with self.assertRaises(ValueError):self.query()
        self.assertEqual(self.children[-1].returncode,0)
        self.assertTrue(self.children[-1].stdout.closed)

    @contextmanager
    def fixed_tree(self):
        # Only trust-origin admission is substituted. The real ancestry and FD
        # identity checks run against an owned disposable directory tree.
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);generation=root/'var/cache/command-center-inventory-refresh'/('generation-'+'a'*32)
            generation.mkdir(parents=True)
            root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            held=os.open(generation,os.O_RDONLY|os.O_DIRECTORY)
            admit=tools._Ancestry.open
            def ancestry(actual_root,components):
                self.assertEqual(components,('var','cache','command-center-inventory-refresh','generation-'+'a'*32))
                return admit(root_fd,components,owner=os.getuid())
            try:
                with patch.object(tools._Ancestry,'open',side_effect=ancestry):
                    yield SimpleNamespace(fd=held,owner=0),generation
            finally:os.close(held);os.close(root_fd)

    def test_fixed_generation_requires_the_exact_held_directory_before_query(self):
        with self.fixed_tree() as (cache,generation):
            foreign=os.open(generation.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with self.assertRaises(ValueError),tools._fixed_generation(SimpleNamespace(fd=foreign,owner=0),'a'*32):
                    self.fail('Foreign generation admitted')
                with self.assertRaises(ValueError),tools._fixed_generation(SimpleNamespace(fd=cache.fd,owner=123),'a'*32):
                    self.fail('Non-root ownership admitted')
                with tools._fixed_generation(cache,'a'*32) as (config,verify):
                    self.assertEqual(config,'/var/cache/command-center-inventory-refresh/generation-'+'a'*32+'/_inventory-reader/apt.conf')
                    verify()
                os.fstat(cache.fd)
            finally:os.close(foreign)

    def test_fixed_generation_replacement_cannot_survive_post_query_verification(self):
        with self.fixed_tree() as (cache,generation):
            with self.assertRaises(ValueError),tools._fixed_generation(cache,'a'*32):
                generation.rename(generation.with_name('retained'))
                generation.mkdir()
            os.fstat(cache.fd)


if __name__=='__main__':unittest.main()
