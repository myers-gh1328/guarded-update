"""Actual descriptor tests for the reporter's protected status input."""
import os
import json
from unittest.mock import patch
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_status import PublicStatus
from inventory_refresh_reporter_io import StatusReader, ReporterIOError


class ReporterStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.root.chmod(0o750);self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        self.reader=StatusReader(self.fd,os.getgid(),owner=os.getuid())
        self.status=PublicStatus.create(dict(schema_version=1,operation_nonce=None,phase='unconfirmed',reason='cache_unavailable',
            policy_generation=None,cache_generation=None,successful_checked_at=None,started_at=None,finished_at=None,
            attempt=None,observation_lease=None,observation_receipt=None))
    def tearDown(self):
        self.reader.close();os.close(self.fd);self.temp.cleanup()
    def write(self,raw):
        path=self.root/'status.json';path.write_bytes(raw);path.chmod(0o640)
        return path
    def test_reads_exact_typed_root_status_and_never_reuses_missing_previous(self):
        self.assertIsNone(self.reader.read())
        self.write(self.status.encoded())
        self.assertEqual(self.reader.read().encoded(),self.status.encoded())
        (self.root/'status.json').unlink()
        self.assertIsNone(self.reader.read())
        self.reader.close();self.reader.close();os.fstat(self.fd)
        with self.assertRaises(ValueError):self.reader.read()
    def test_exact_byte_bound_accepts_valid_whitespace_but_rejects_one_extra_byte(self):
        raw=self.status.encoded();self.write(raw+b' '*(65536-len(raw)))
        self.assertEqual(self.reader.read().encoded(),raw)
        self.write(raw+b' '*(65537-len(raw)))
        with self.assertRaises(ValueError):self.reader.read()
    def test_duplicate_nested_receipt_key_is_rejected(self):
        value=json.loads(self.status.encoded())
        value['cache_generation']='a'*32;value['policy_generation']='b'*64
        value['successful_checked_at']='2026-10-28T00:00:00Z'
        value['observation_lease']=dict(nonce='0000000000000001'+'c'*16,
            boot_id='11111111-1111-4111-8111-111111111111',cache_generation='a'*32,policy_generation='b'*64,
            lock_open_boottime_ms=100,expires_boottime_ms=200)
        raw=PublicStatus.create(value).encoded().replace(b'"lock_open_boottime_ms":100',b'"lock_open_boottime_ms":100,"lock_open_boottime_ms":100')
        self.write(raw)
        with self.assertRaises(ValueError):self.reader.read()
    def test_missing_status_revalidates_directory_before_returning_none(self):
        def missing(*args,**kwargs):
            self.root.chmod(0o770)
            raise FileNotFoundError('synthetic missing input')
        with patch('inventory_refresh_reporter_io.os.open',side_effect=missing):
            with self.assertRaises(ValueError):self.reader.read()
        self.root.chmod(0o750)
    def test_unsafe_owner_group_mode_type_link_and_oversize_rejected(self):
        path=self.write(self.status.encoded())
        path.chmod(0o644)
        with self.assertRaises(ValueError):self.reader.read()
        path.chmod(0o640)
        alias=self.root/'alias';os.link(path,alias)
        with self.assertRaises(ValueError):self.reader.read()
        alias.unlink();path.unlink();path.symlink_to(self.root/'absent')
        with self.assertRaises(ValueError):self.reader.read()
        path.unlink();path.mkdir()
        with self.assertRaises(ValueError):self.reader.read()
        path.rmdir();self.write(b'x'*65537)
        with self.assertRaises(ValueError):self.reader.read()
        self.write(self.status.encoded());self.root.chmod(0o770)
        with self.assertRaises(ValueError):self.reader.read()
        self.root.chmod(0o750)
        for kwargs in [dict(owner=os.getuid()+1),dict(reader_gid=os.getgid()+1)]:
            owner=kwargs.pop('owner',os.getuid());group=kwargs.pop('reader_gid',os.getgid())
            with self.assertRaises(ValueError):StatusReader(self.fd,group,owner=owner)
    def test_malformed_unknown_duplicate_and_numeric_aliases_are_static_errors(self):
        raw=self.status.encoded()
        for invalid in [b'\xff',raw[:-1]+b',"phase":"unconfirmed"}',raw[:-1]+b',"extra":null}',
                        raw.replace(b'"schema_version":1',b'"schema_version":true'),
                        raw.replace(b'"schema_version":1',b'"schema_version":1.0'),
                        raw.replace(b'"schema_version":1',b'"schema_version":NaN'),
                        b'['*1200+b']'*1200]:
            self.write(invalid)
            with self.subTest(length=len(invalid)),self.assertRaises(ReporterIOError) as caught:self.reader.read()
            self.assertEqual(str(caught.exception),'Protected inventory status unavailable: state_inconsistent')
    def test_replacement_during_schema_parse_rejected_then_fresh_poll_succeeds(self):
        self.write(self.status.encoded());create=PublicStatus.create
        def replace(value):
            replacement=self.root/'replacement';replacement.write_bytes(self.status.encoded());replacement.chmod(0o640)
            os.replace(replacement,self.root/'status.json')
            return create(value)
        with patch.object(PublicStatus,'create',side_effect=replace):
            with self.assertRaises(ReporterIOError) as caught:self.reader.read()
        self.assertEqual(caught.exception.reason,'publication_changed')
        self.assertEqual(self.reader.read().encoded(),self.status.encoded())
    def test_in_place_mutation_during_schema_parse_rejected(self):
        self.write(self.status.encoded());create=PublicStatus.create
        def mutate(value):
            self.write(self.status.encoded()+b' ')
            return create(value)
        with patch.object(PublicStatus,'create',side_effect=mutate):
            with self.assertRaises(ValueError):self.reader.read()
    def test_bounded_growth_cannot_read_unlimited_bytes(self):
        self.write(self.status.encoded());read=os.read;read_count=[0]
        def grow(fd,count):
            read_count[0]+=1
            if read_count[0]==1:
                with (self.root/'status.json').open('ab') as output:output.write(b'x'*100000)
            return read(fd,count)
        with patch('inventory_refresh_reporter_io.os.read',side_effect=grow):
            with self.assertRaises(ValueError):self.reader.read()
        self.assertLessEqual(read_count[0],2)
    def test_file_close_failure_prevents_status_return(self):
        self.write(self.status.encoded());close=os.close
        def fail(fd):
            close(fd)
            raise OSError('synthetic close failure')
        with patch('inventory_refresh_reporter_io.os.close',side_effect=fail):
            with self.assertRaises(ReporterIOError) as caught:self.reader.read()
        self.assertEqual(caught.exception.reason,'cleanup_unconfirmed');os.fstat(self.fd)
    def test_reader_close_failure_is_not_retried_and_borrowed_fd_stays_open(self):
        close=os.close;closed=[]
        def fail(fd):
            closed.append(fd);close(fd)
            raise OSError('synthetic close failure')
        with patch('inventory_refresh_reporter_io.os.close',side_effect=fail):
            with self.assertRaises(ReporterIOError):self.reader.close()
            self.reader.close()
        self.assertEqual(len(closed),1);os.fstat(self.fd)


if __name__=='__main__':unittest.main()
