"""Private rooted-path samples; never production mount-admission evidence."""
import os
import errno
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_mount_resolver as resolver


class MountResolverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        (self.root/'a'/'b').mkdir(parents=True)
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
    def tearDown(self):os.close(self.fd);self.tmp.cleanup()
    def sample(self,path='/a/b',reader=lambda fd:7):
        return resolver.resolve(self.fd,path,time.monotonic()+1,reader)
    def test_exact_held_path_returns_sampled_mount_id(self):self.assertEqual(self.sample(),7)
    def test_unsafe_paths_and_symlinks_fail(self):
        (self.root/'link').symlink_to('a',target_is_directory=True)
        for path in ('a/b','/a/../b','/a//b','/link/b','/a/b/',('/x'*33),'/'+'x'*256):
            with self.assertRaises(ValueError):self.sample(path)
    def test_final_regular_file_is_sampled_but_special_and_intermediate_files_fail(self):
        (self.root/'a'/'file').write_bytes(b'unchanged')
        self.assertEqual(self.sample('/a/file'),7)
        self.assertEqual((self.root/'a'/'file').read_bytes(),b'unchanged')
        (self.root/'a'/'filelink').symlink_to('file')
        os.mkfifo(self.root/'a'/'fifo')
        for path in ('/a/file/child','/a/filelink','/a/fifo'):
            with self.assertRaises(ValueError):self.sample(path)
        calls=[]
        def replace_file(fd):
            if not calls:
                calls.append(True);(self.root/'a'/'file').rename(self.root/'a'/'oldfile')
                (self.root/'a'/'file').write_bytes(b'replacement')
            return 7
        with self.assertRaises(ValueError):self.sample('/a/file',replace_file)

    def test_safe_linux_component_characters_and_encoded_byte_limits(self):
        for name in ('unit@123',r'unit\x2dname','with space','item:1'):
            (self.root/name).mkdir()
            self.assertEqual(self.sample('/'+name),7)
        name=os.fsdecode(b'bad-\xff')
        self.assertEqual(os.fsencode(name),b'bad-\xff')
        if sys.platform=='linux':
            os.mkdir(os.fsencode(self.root)+b'/bad-\xff')
            self.assertEqual(self.sample('/'+name),7)
        with self.assertRaises(ValueError):self.sample('/'+('é'*128))
        with self.assertRaises(ValueError):self.sample('/bad\x00name')

    def test_replacement_and_mount_id_change_fail(self):
        calls=[]
        def replaced(fd):
            calls.append(1)
            if len(calls)==1:
                (self.root/'a'/'b').rename(self.root/'a'/'old');(self.root/'a'/'b').mkdir()
            return 7
        with self.assertRaises(ValueError):self.sample(reader=replaced)
        calls.clear()
        def changing(fd):calls.append(1);return len(calls)
        with self.assertRaises(ValueError):self.sample(reader=changing)
    def test_deadline_and_close_failure_are_unknown(self):
        with self.assertRaises(ValueError):resolver.resolve(self.fd,'/a/b',time.monotonic()-1,lambda fd:7)
        actual=os.close;calls=[]
        def uncertain(fd):calls.append(fd);actual(fd);raise OSError('uncertain')
        with patch.object(resolver.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):self.sample()
        self.assertEqual(len(calls),3)
    @unittest.skipUnless(sys.platform=='linux','Linux procfs mount IDs required')
    def test_actual_linux_rooted_mount_id(self):
        from inventory_refresh_resources import _mount_id
        # This fixture intentionally follows its own kernel /proc/self/root magiclink.
        root=os.open('/proc/self/root',os.O_RDONLY|os.O_DIRECTORY)
        target=os.open('/sys',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        cgroup_file=os.open('/sys/fs/cgroup/cgroup.procs',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            self.assertEqual(resolver.resolve(root,'/sys',time.monotonic()+3,_mount_id),_mount_id(target))
            self.assertEqual(resolver.resolve(root,'/sys/fs/cgroup/cgroup.procs',time.monotonic()+3,_mount_id),_mount_id(cgroup_file))
        finally:os.close(cgroup_file);os.close(target);os.close(root)

    def test_passive_metadata_is_fixed_and_acl_uncertainty_is_explicit(self):
        target=self.root/'a'/'cgroup.procs';target.write_bytes(b'unchanged');target.chmod(0o640)
        row={'id':7,'path':'/a/cgroup.procs','fs':b'cgroup2','options':{b'rw'}}
        with patch.object(resolver.sys,'platform','linux'),patch.object(resolver.os,'getxattr',side_effect=OSError(errno.ENODATA,'absent'),create=True):
            self.assertEqual(resolver.classify_metadata(self.fd,[row],time.monotonic()+1,lambda fd:7,os.getuid(),os.getgid()),
                ('sample','self','self','yes','no','no','absent'))
        with patch.object(resolver.os,'getxattr',side_effect=OSError(errno.ENOTSUP,'unsupported'),create=True):
            self.assertEqual(resolver.classify_metadata(self.fd,[row],time.monotonic()+1,lambda fd:7,os.getuid(),os.getgid())[-1],'unknown')
        for values in ([b'one',b'two'],[b'x'*65537]):
            with patch.object(resolver.os,'getxattr',side_effect=values,create=True):
                self.assertEqual(resolver.classify_metadata(self.fd,[row],time.monotonic()+1,lambda fd:7,os.getuid(),os.getgid()),('unavailable',))
        self.assertEqual(target.read_bytes(),b'unchanged')

    def test_matching_mount_reports_only_fixed_object_category(self):
        (self.root/'a'/'cgroup.procs').write_bytes(b'')
        (self.root/'a'/'confidential-name').mkdir()
        def row(path):return {'id':7,'path':path,'fs':b'cgroup2','options':{b'rw'}}
        self.assertEqual(resolver.classify_detail(self.fd,[row('/a/cgroup.procs')],time.monotonic()+1,lambda fd:7),('matching','file_procs'))
        self.assertEqual(resolver.classify_detail(self.fd,[row('/a/confidential-name')],time.monotonic()+1,lambda fd:7),('matching','directory_other'))

    def test_unavailable_comparison_exposes_only_fixed_failure_category(self):
        row={'id':7,'path':'/secret-name','fs':b'cgroup2','options':{b'rw'}}
        result,detail=resolver.classify_detail(self.fd,[row],time.monotonic()+1,lambda fd:7)
        self.assertEqual((result,detail),('unavailable','open_missing'))
        row['path']='/../unsafe'
        self.assertEqual(resolver.classify_detail(self.fd,[row],time.monotonic()+1,lambda fd:7),('unavailable','validation'))

    def test_writable_row_classification_is_diagnostic_and_ambiguity_absorbs(self):
        def row(identifier,path='/a/b',options=None):
            return {'id':identifier,'path':path,'fs':b'cgroup2','options':{b'rw'} if options is None else options}
        deadline=time.monotonic()+1
        self.assertEqual(resolver.classify(self.fd,[row(7)],deadline,lambda fd:7),'matching')
        self.assertEqual(resolver.classify(self.fd,[row(8)],deadline,lambda fd:7),'different')
        self.assertEqual(resolver.classify(self.fd,[row(7),row(8)],deadline,lambda fd:7),'matching')
        self.assertEqual(resolver.classify(self.fd,[row(7),row(8,'/missing')],deadline,lambda fd:7),'unavailable')
        self.assertEqual(resolver.classify(self.fd,[row(7),row(7)],deadline,lambda fd:7),'unavailable')
        self.assertEqual(resolver.classify(self.fd,[row(True)],deadline,lambda fd:7),'unavailable')
        self.assertEqual(resolver.classify(self.fd,[row(7,options={b'ro'})],deadline,lambda fd:7),'unavailable')
