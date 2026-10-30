"""Reporter request publication in a temporary capability directory only."""
import os
from unittest.mock import patch
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_io import Inbox
from inventory_refresh_reporter_io import ReporterRequestWriter, RequestPublicationError


class ReporterWriterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.leaf=self.root/'observation';self.leaf.mkdir();self.leaf.chmod(0o770)
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        self.reader=Inbox(self.fd,'observation',os.getuid(),os.getgid(),owner=os.getuid())
        self.writer=ReporterRequestWriter(self.fd,'observation',os.getuid(),os.getgid(),owner=os.getuid())
    def tearDown(self):
        self.writer.close();self.reader.close();os.close(self.fd);self.temp.cleanup()
    def test_root_inbox_reads_exact_new_nonce_after_atomic_publication(self):
        nonce='0000000000000001'+'a'*16
        self.assertIsNone(self.reader.read())
        self.writer.publish(nonce)
        self.assertEqual(self.reader.read(),(nonce,1))
        self.assertEqual((self.leaf/'request').stat().st_mode&0o777,0o600)
        self.assertEqual(sorted(p.name for p in self.leaf.iterdir()),['request'])
        self.writer.close();self.writer.close();os.fstat(self.fd)
    def test_lost_published_reference_cannot_return_success(self):
        nonce='0000000000000001'+'a'*16;other='0000000000000002'+'b'*16
        sync=os.fsync;calls=[0]
        def replace_after_rename(fd):
            calls[0]+=1
            if calls[0]==2:
                path=self.leaf/'other';path.write_bytes(other.encode());path.chmod(0o600)
                os.replace(path,self.leaf/'request')
            sync(fd)
        with patch('inventory_refresh_reporter_io.os.fsync',side_effect=replace_after_rename):
            with self.assertRaises(RequestPublicationError) as caught:self.writer.publish(nonce)
        self.assertTrue(caught.exception.may_be_visible)
        self.assertEqual(self.reader.read(),(other,2))
    def test_invalid_nonce_and_capability_create_no_request(self):
        for nonce in ['', 'a'*65, '0000000000000000'+'a'*16, '0000000000000001'+'A'*16,
                      '0000000000000001'+'a'*16+'\n', None]:
            with self.subTest(nonce=nonce),self.assertRaises(ValueError):self.writer.publish(nonce)
        self.assertEqual(list(self.leaf.iterdir()),[])
        with self.assertRaises(ValueError):ReporterRequestWriter(self.fd,'arbitrary',os.getuid(),os.getgid(),owner=os.getuid())
    def test_equal_lower_and_conflicting_sequence_never_overwrite(self):
        nonce='0000000000000002'+'b'*16;self.writer.publish(nonce)
        for incoming in [nonce,'0000000000000001'+'a'*16,'0000000000000002'+'c'*16]:
            with self.assertRaises(RequestPublicationError):self.writer.publish(incoming)
            self.assertEqual(self.reader.read(),(nonce,2))
            self.assertEqual(sorted(p.name for p in self.leaf.iterdir()),['request'])
    def test_higher_sequence_replaces_previous_once(self):
        self.writer.publish('0000000000000001'+'a'*16)
        self.writer.publish('0000000000000002'+'b'*16)
        self.assertEqual(self.reader.read(),('0000000000000002'+'b'*16,2))
    def test_unsafe_existing_request_is_not_repaired(self):
        path=self.leaf/'request';path.write_bytes(('0000000000000001'+'a'*16).encode());path.chmod(0o644)
        with self.assertRaises(RequestPublicationError):self.writer.publish('0000000000000002'+'b'*16)
        self.assertEqual(path.stat().st_mode&0o777,0o644)
        path.unlink();path.symlink_to(self.root/'missing')
        with self.assertRaises(RequestPublicationError):self.writer.publish('0000000000000002'+'b'*16)
        self.assertTrue(path.is_symlink())
    def test_partial_writes_complete_but_zero_write_removes_only_own_temp(self):
        write=os.write
        with patch('inventory_refresh_reporter_io.os.write',side_effect=lambda fd,raw:write(fd,raw[:7])):
            self.writer.publish('0000000000000001'+'a'*16)
        with patch('inventory_refresh_reporter_io.os.write',return_value=0):
            with self.assertRaises(RequestPublicationError) as caught:self.writer.publish('0000000000000002'+'b'*16)
        self.assertFalse(caught.exception.may_be_visible);self.assertFalse(caught.exception.cleanup_uncertain)
        self.assertEqual(self.reader.read(),('0000000000000001'+'a'*16,1))
        self.assertEqual(sorted(p.name for p in self.leaf.iterdir()),['request'])
    def test_fsync_failure_before_and_after_rename_has_conservative_visibility(self):
        for fail_at in [1,2]:
            sync=os.fsync;calls=[0]
            def fail(fd):
                calls[0]+=1
                if calls[0]==fail_at:raise OSError('synthetic fsync failure')
                sync(fd)
            with patch('inventory_refresh_reporter_io.os.fsync',side_effect=fail):
                with self.assertRaises(RequestPublicationError) as caught:self.writer.publish('0000000000000001'+'a'*16)
            self.assertEqual(caught.exception.may_be_visible,fail_at==2)
            if fail_at==1:self.assertIsNone(self.reader.read())
            else:self.assertEqual(self.reader.read(),('0000000000000001'+'a'*16,1))
    def test_failed_rename_never_claims_rollback_even_if_visible(self):
        replace=os.replace
        for visible in [False,True]:
            nonce=('0000000000000002' if visible else '0000000000000001')+'a'*16
            def fail(*args,**kwargs):
                if visible:replace(*args,**kwargs)
                raise OSError('synthetic rename failure')
            with patch('inventory_refresh_reporter_io.os.replace',side_effect=fail):
                with self.assertRaises(RequestPublicationError) as caught:self.writer.publish(nonce)
            self.assertTrue(caught.exception.may_be_visible)
            self.assertEqual(self.reader.read(),(nonce,2) if visible else None)
    def test_changed_previous_inode_rejects_before_promotion(self):
        nonce='0000000000000001'+'a'*16;self.writer.publish(nonce)
        read=self.writer._inbox.read_snapshot;calls=[0]
        def replace_before_check():
            calls[0]+=1
            if calls[0]==2:
                other=self.leaf/'other';other.write_bytes(nonce.encode());other.chmod(0o600);os.replace(other,self.leaf/'request')
            return read()
        with patch.object(self.writer._inbox,'read_snapshot',side_effect=replace_before_check):
            with self.assertRaises(RequestPublicationError):self.writer.publish('0000000000000003'+'c'*16)
        self.assertEqual(self.reader.read(),(nonce,1))
        self.assertEqual(sorted(p.name for p in self.leaf.iterdir()),['request'])
    def test_foreign_temp_replacement_is_preserved(self):
        sync=os.fsync;changed=[False];foreign=b'foreign-request-data'
        def replace_temp(fd):
            if not changed[0]:
                changed[0]=True
                path=next(self.leaf.glob('.request-*'));path.unlink();path.write_bytes(foreign);path.chmod(0o600)
            sync(fd)
        with patch('inventory_refresh_reporter_io.os.fsync',side_effect=replace_temp):
            with self.assertRaises(RequestPublicationError) as caught:self.writer.publish('0000000000000001'+'a'*16)
        self.assertTrue(caught.exception.cleanup_uncertain)
        self.assertIsNone(self.reader.read());self.assertEqual(next(self.leaf.iterdir()).read_bytes(),foreign)
    def test_temp_collision_is_not_deleted(self):
        path=self.leaf/('.request-'+'f'*32);path.write_bytes(b'foreign')
        with patch('secrets.token_hex',return_value='f'*32):
            with self.assertRaises(RequestPublicationError):self.writer.publish('0000000000000001'+'a'*16)
        self.assertEqual(path.read_bytes(),b'foreign')
    def test_file_close_failure_prevents_success_after_visibility(self):
        import inventory_refresh_reporter_io as module
        close=module._close;calls=[]
        def fail(fd):
            calls.append(fd);close(fd);raise module.ReporterIOError('cleanup_unconfirmed')
        with patch.object(module,'_close',side_effect=fail):
            with self.assertRaises(RequestPublicationError) as caught:self.writer.publish('0000000000000001'+'a'*16)
        self.assertTrue(caught.exception.may_be_visible);self.assertTrue(caught.exception.cleanup_uncertain)
        self.assertEqual(len(calls),1);self.assertEqual(self.reader.read(),('0000000000000001'+'a'*16,1))
    def test_writer_close_attempts_both_owned_fds_after_first_close_error(self):
        close=os.close;calls=[]
        def fail(fd):
            calls.append(fd);close(fd)
            if len(calls)==1:raise OSError('synthetic first close')
        with patch('inventory_refresh_io.os.close',side_effect=fail):
            with self.assertRaises(ValueError):self.writer.close()
            self.writer.close()
        self.assertEqual(len(calls),2);os.fstat(self.fd)


if __name__=='__main__':unittest.main()
