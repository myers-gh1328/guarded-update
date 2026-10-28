"""Temporary-fixture tests for fixed helper inbox and public status I/O."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
spec = importlib.util.spec_from_file_location('inventory_refresh_io', ROOT/'scripts/inventory_refresh_io.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
from inventory_refresh_state import Journal
from inventory_refresh_status import PublicStatus


class HelperIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inbox = self.root/'refresh'
        self.inbox.mkdir(mode=0o770)
        self.inbox.chmod(0o770)
        self.parent = os.open(self.root, os.O_RDONLY|os.O_DIRECTORY)
        self.reader = p.Inbox(self.parent, 'refresh', os.getuid(), os.getgid(), owner=os.getuid())
        self.nonce = '0000000000000001'+'a'*16
        self.private=self.root/'private'
        self.private.mkdir(mode=0o700)
        self.private_fd=os.open(self.private,os.O_RDONLY|os.O_DIRECTORY)
        self.journal=Journal(self.private_fd,owner=os.getuid())
        with self.journal.exclusive():
            self.journal.initialize('a'*32)
        self.public=self.root/'public'
        self.public.mkdir(mode=0o750)
        self.public.chmod(0o750)
        self.public_fd=os.open(self.public,os.O_RDONLY|os.O_DIRECTORY)
        self.publisher=p.StatusPublisher(self.public_fd,self.journal,os.getgid(),owner=os.getuid())

    def tearDown(self):
        self.reader.close()
        self.publisher.close()
        os.close(self.public_fd)
        os.close(self.private_fd)
        os.close(self.parent)
        self.temp.cleanup()

    def request(self, value):
        path = self.inbox/'request'
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    def test_nonce_parser_rejects_whitespace_aliases_unknown_fields_and_counter_overflow(self):
        invalid=[b'',b'a'*65,self.nonce.upper().encode(),(self.nonce+'\r\n').encode(),
                 (self.nonce+'\n\n').encode(),(' '+self.nonce).encode(),
                 b'0000000000000000'+b'a'*16,b'0020000000000000'+b'a'*16,b'{"nonce":"synthetic"}']
        for raw in invalid:
            self.request(raw)
            with self.subTest(raw_length=len(raw)),self.assertRaises(p.IOErrorState):
                self.reader.read()

    def test_untrusted_file_kinds_links_owner_and_mode_cannot_be_admitted(self):
        path=self.request(self.nonce.encode())
        path.chmod(0o644)
        with self.assertRaises(p.IOErrorState):
            self.reader.read()
        path.chmod(0o600)
        alias=self.root/'alias'
        os.link(path,alias)
        with self.assertRaises(p.IOErrorState):
            self.reader.read()
        alias.unlink()
        self.root.chmod(0o755)
        other=p.Inbox(self.parent,'refresh',os.getuid()+1,os.getgid(),owner=os.getuid())
        try:
            with self.assertRaises(p.IOErrorState):
                other.read()
        finally:
            other.close()
            self.root.chmod(0o700)
        for kind in ['symlink','fifo','directory']:
            path.unlink()
            if kind=='symlink':
                alias.write_bytes(self.nonce.encode())
                alias.chmod(0o600)
                path.symlink_to(alias)
            elif kind=='fifo':
                os.mkfifo(path,0o600)
            else:
                path.mkdir(mode=0o600)
            with self.subTest(kind=kind),self.assertRaises(p.IOErrorState):
                self.reader.read()
            if kind=='directory':
                path.rmdir()
            else:
                path.unlink()
            self.request(self.nonce.encode())

    def test_inbox_replacement_or_unsafe_parent_permissions_are_rejected(self):
        self.request(self.nonce.encode())
        self.root.chmod(0o777)
        with self.assertRaises(p.IOErrorState):
            self.reader.read()
        self.root.chmod(0o700)
        self.inbox.rename(self.root/'old-refresh')
        self.inbox.mkdir(mode=0o770)
        self.inbox.chmod(0o770)
        with self.assertRaises(p.IOErrorState):
            self.reader.read()

    def test_mutation_during_read_is_rejected_and_total_read_is_capped(self):
        path=self.request(self.nonce.encode())
        original_read=p.os.read
        sizes=[]
        def grow(fd,count):
            chunk=original_read(fd,count)
            sizes.append(len(chunk))
            if len(sizes)==1:
                with path.open('ab') as target:
                    target.write(b'x'*100)
            return chunk
        with patch.object(p.os,'read',side_effect=grow):
            with self.assertRaises(p.IOErrorState):
                self.reader.read()
        self.assertEqual(sum(sizes),65)

    def test_publication_requires_root_journal_lock_and_atomically_publishes_read_only_bytes(self):
        raw=b'{"schema_version":1,"synthetic_status":"received"}'
        with self.assertRaises(ValueError):
            self.publisher._publish(raw)
        self.assertFalse((self.public/'status.json').exists())
        with self.journal.exclusive():
            self.publisher._publish(raw)
        public=self.public/'status.json'
        self.assertEqual(public.read_bytes(),raw)
        info=public.stat()
        self.assertEqual(info.st_uid,os.getuid())
        self.assertEqual(info.st_gid,os.getgid())
        self.assertEqual(info.st_mode&0o7777,0o640)
        self.assertEqual(info.st_nlink,1)
        self.assertFalse(any(path.name.startswith('.status-') for path in self.public.iterdir()))

    def test_failed_exclusive_temp_creation_never_deletes_an_existing_private_file(self):
        temporary=self.public/('.status-'+'d'*32)
        temporary.write_bytes(b'existing synthetic private bytes')
        temporary.chmod(0o600)
        with self.journal.exclusive(),patch.object(p.secrets,'token_hex',return_value='d'*32):
            with self.assertRaises(p.PublicationError) as failed:
                self.publisher._publish(b'{"schema_version":1}')
        self.assertFalse(failed.exception.may_be_visible)
        self.assertEqual(temporary.read_bytes(),b'existing synthetic private bytes')

    def test_publication_failure_before_and_after_rename_reports_different_visibility(self):
        old=b'{"schema_version":1,"synthetic_status":"old"}'
        new=b'{"schema_version":1,"synthetic_status":"new"}'
        for failure_at in [1,2]:
            with self.journal.exclusive():
                self.publisher._publish(old)
                original_fsync=p.os.fsync
                calls=[0]
                def fail(fd):
                    calls[0]+=1
                    if calls[0]==failure_at:
                        raise OSError('synthetic persistence failure')
                    return original_fsync(fd)
                with patch.object(p.os,'fsync',side_effect=fail):
                    with self.assertRaises(p.PublicationError) as failed:
                        self.publisher._publish(new)
            self.assertEqual(failed.exception.may_be_visible,failure_at==2)
            self.assertEqual((self.public/'status.json').read_bytes(),new if failure_at==2 else old)
            self.assertFalse(any(path.name.startswith('.status-') for path in self.public.iterdir()))

    def test_status_directory_must_have_expected_reporter_group_and_traversal_mode(self):
        for bad_mode,bad_group in [(0o700,os.getgid()),(0o750,os.getgid()+1)]:
            self.public.chmod(bad_mode)
            extra=None
            try:
                with self.subTest(mode=bad_mode,group=bad_group),self.assertRaises(p.IOErrorState):
                    extra=p.StatusPublisher(self.public_fd,self.journal,bad_group,owner=os.getuid())
            finally:
                if extra is not None:
                    extra.close()
                self.public.chmod(0o750)
        self.public.chmod(0o700)
        try:
            with self.journal.exclusive(),self.assertRaises(p.IOErrorState):
                self.publisher._publish(b'{"schema_version":1}')
            self.assertFalse((self.public/'status.json').exists())
        finally:
            self.public.chmod(0o750)

    def test_reporter_must_be_able_to_traverse_every_fixed_ancestor(self):
        # Distinct synthetic reporter UID; mode checks do not impersonate it.
        reporter=os.getuid()+1
        with self.assertRaises(p.IOErrorState):
            p._traversable([self.parent,self.public_fd],reporter,os.getgid())
        self.root.chmod(0o755)
        try:
            p._traversable([self.parent,self.public_fd],reporter,os.getgid())
            self.public.chmod(0o700)
            with self.assertRaises(p.IOErrorState):
                p._traversable([self.parent,self.public_fd],reporter,os.getgid())
        finally:
            self.public.chmod(0o750)
            self.root.chmod(0o700)

    def test_request_name_substitution_during_read_is_rejected_without_deleting_new_request(self):
        path=self.request(self.nonce.encode())
        replacement=('0000000000000002'+'b'*16).encode()
        original_read=p.os.read
        changed=[False]
        def replace(fd,count):
            raw=original_read(fd,count)
            if not changed[0]:
                changed[0]=True
                path.rename(self.inbox/'retained-old')
                self.request(replacement)
            return raw
        with patch.object(p.os,'read',side_effect=replace),self.assertRaises(p.IOErrorState):
            self.reader.read()
        self.assertEqual(path.read_bytes(),replacement)

    def test_unsafe_existing_public_status_is_never_repaired_or_followed(self):
        old=b'{"schema_version":1,"synthetic_status":"old"}'
        public=self.public/'status.json'
        with self.journal.exclusive():
            self.publisher._publish(old)
            public.chmod(0o644)
            with self.assertRaises(p.IOErrorState):
                self.publisher._publish(b'{"schema_version":1}')
            self.assertEqual(public.read_bytes(),old)
            self.assertEqual(public.stat().st_mode&0o777,0o644)
            public.chmod(0o640)
            alias=self.public/'alias'
            os.link(public,alias)
            with self.assertRaises(p.IOErrorState):
                self.publisher._publish(b'{"schema_version":1}')
            alias.unlink()
            public.rename(alias)
            public.symlink_to(alias)
            with self.assertRaises(p.IOErrorState):
                self.publisher._publish(b'{"schema_version":1}')
            self.assertEqual(alias.read_bytes(),old)
            self.assertTrue(public.is_symlink())
        self.assertFalse(any(path.name.startswith('.status-') for path in self.public.iterdir()))

    def test_oversized_or_zero_progress_status_write_cannot_replace_old_public_bytes(self):
        old=b'{"schema_version":1}'
        with self.journal.exclusive():
            self.publisher._publish(old)
            with self.assertRaises(p.IOErrorState):
                self.publisher._publish(b'x'*65537)
            with patch.object(p.os,'write',return_value=0):
                with self.assertRaises(p.PublicationError) as failed:
                    self.publisher._publish(b'{"synthetic_status":"new"}')
            self.assertFalse(failed.exception.may_be_visible)
        self.assertEqual((self.public/'status.json').read_bytes(),old)
        self.assertFalse(any(path.name.startswith('.status-') for path in self.public.iterdir()))

    def test_public_publisher_requires_validated_status_instead_of_raw_private_bytes(self):
        value={'schema_version':1,'operation_nonce':None,'phase':'deferred','reason':'cache_unavailable',
               'policy_generation':None,'cache_generation':None,'successful_checked_at':None,
               'started_at':None,'finished_at':None,'attempt':None,
               'observation_lease':None,'observation_receipt':None}
        status=PublicStatus.create(value)
        with self.journal.exclusive():
            with self.assertRaises(p.IOErrorState):
                self.publisher.publish(b'{"private":"synthetic-sensitive-material"}')
            self.assertFalse((self.public/'status.json').exists())
            self.publisher.publish(status)
        self.assertEqual((self.public/'status.json').read_bytes(),status.encoded())

    def test_fixed_nonce_read_is_exact_bounded_and_preserves_original_request(self):
        self.assertIsNone(self.reader.read())
        path = self.request((self.nonce+'\n').encode('ascii'))
        original = path.read_bytes()
        self.assertEqual(self.reader.read(), (self.nonce, 1))
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.reader.read(), (self.nonce, 1))


if __name__ == '__main__':
    unittest.main()
