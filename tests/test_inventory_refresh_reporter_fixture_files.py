"""Owned temporary file staging mechanics; capability seams are not origin proof."""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import inventory_refresh_artifact_fixture as artifact
import inventory_refresh_reporter_fixture_files as staging


class FixtureFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.owner=None
        self.missing={'inventory_refresh_reporter_runtime.py','inventory_refresh_reporter_protocol.py',
            'inventory_refresh_reporter_pipe.py','inventory_refresh_reporter_dialogue.py'}
        self.files={artifact.LIB+name:b'synthetic '+name.encode() for name in staging.LIBRARY_NAMES}
        self.files.update({'manifest.json':b'synthetic manifest','share/doc/command-center-inventory-refresh/contract.md':b'synthetic contract'})
        for name in staging.LIBRARY_NAMES-{'reporter.py'}-self.missing:
            path=self.root/name;path.write_bytes(self.files[artifact.LIB+name]);path.chmod(0o444)
    def tearDown(self):
        if self.owner is not None:self.owner.close()
        os.close(self.fd);self.temp.cleanup()
    def admit(self):
        self.owner=staging.FixtureSources._from_directory(self.fd,self.files,owner=(os.getuid(),os.getgid()))
        return self.owner

    def test_missing_reporter_sources_publish_and_retire_only_after_confirmed_empty(self):
        owner=self.admit();owner.publish();owner.verify()
        for name in self.missing:self.assertEqual((self.root/name).read_bytes(),self.files[artifact.LIB+name])
        owner.retire(True)
        for name in self.missing:self.assertFalse((self.root/name).exists())

    def test_reporter_entry_can_be_owned_and_retired_with_the_verified_closure(self):
        self.owner=staging.FixtureSources._from_directory(self.fd,self.files,owner=(os.getuid(),os.getgid()),include_entry=True)
        self.owner.publish();entry=self.root/'reporter.py'
        self.assertEqual(entry.read_bytes(),self.files[artifact.LIB+'reporter.py'])
        self.owner.retire(True);self.assertFalse(entry.exists())

    def test_requested_entry_must_be_absent_even_when_existing_bytes_match(self):
        target=self.root/'reporter.py';raw=self.files[artifact.LIB+'reporter.py'];target.write_bytes(raw);target.chmod(0o444)
        with self.assertRaises(ValueError):staging.FixtureSources._from_directory(self.fd,self.files,owner=(os.getuid(),os.getgid()),include_entry=True)
        self.assertEqual(target.read_bytes(),raw)
        with self.assertRaises(ValueError):staging.FixtureSources._from_directory(self.fd,self.files,owner=(os.getuid(),os.getgid()),include_entry=1)
        self.assertTrue((self.root/'coordinator.py').is_file());os.fstat(self.fd)

    def test_unknown_retirement_is_absorbing_and_cannot_be_relabelled_success(self):
        owner=self.admit();owner.publish()
        with self.assertRaises(ValueError):owner.retire(False)
        with self.assertRaises(ValueError):owner.retire(True)
        for name in self.missing:self.assertTrue((self.root/name).is_file())

    def test_uncertain_publication_fd_close_cannot_later_claim_clean_retirement(self):
        owner=self.admit();actual=os.close;closed=[]
        def uncertain(fd):
            closed.append(fd);actual(fd)
            if len(closed)==1:raise OSError('synthetic publication descriptor close uncertainty')
        with patch.object(staging.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):owner.publish()
        with self.assertRaises(ValueError):owner.retire(True)

    def test_failed_descriptor_close_remains_uncertain_on_repeat(self):
        owner=self.admit();actual=os.close;attempts=[]
        def uncertain(fd):
            attempts.append(fd);actual(fd);raise OSError('synthetic close uncertainty')
        with patch.object(staging.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):owner.close()
        with self.assertRaises(ValueError):owner.close()
        self.assertEqual(len(attempts),1)
        self.owner=None

    def test_existing_root_source_mismatch_is_never_overwritten(self):
        target=self.root/'coordinator.py';target.chmod(0o600);target.write_bytes(b'foreign existing coordinator');target.chmod(0o444)
        with self.assertRaises(ValueError):self.admit()
        self.assertEqual(target.read_bytes(),b'foreign existing coordinator')
        for name in self.missing:self.assertFalse((self.root/name).exists())
        os.fstat(self.fd)

    def test_missing_core_source_is_not_treated_as_new_reporter_file(self):
        (self.root/'coordinator.py').unlink()
        with self.assertRaises(ValueError):self.admit()
        self.assertFalse((self.root/'coordinator.py').exists())

    def test_group_writable_existing_source_and_symlink_are_rejected(self):
        target=self.root/'coordinator.py';target.chmod(0o464)
        with self.assertRaises(ValueError):self.admit()
        target.chmod(0o444);actual=self.root/'outside';actual.write_bytes(target.read_bytes())
        target.unlink();target.symlink_to(actual)
        with self.assertRaises(ValueError):self.admit()
        self.assertTrue(target.is_symlink())

    def test_foreign_name_appearing_before_publication_prevents_all_creates(self):
        owner=self.admit();name=next(iter(sorted(self.missing)));target=self.root/name
        target.write_bytes(self.files[artifact.LIB+name]);target.chmod(0o444)
        with self.assertRaises(ValueError):owner.publish()
        for other in self.missing-{name}:self.assertFalse((self.root/other).exists())
        self.assertTrue(target.is_file())

    def test_unknown_retirement_preserves_all_created_files_and_borrowed_directory(self):
        owner=self.admit();owner.publish()
        with self.assertRaises(ValueError):owner.retire(False)
        for name in self.missing:self.assertTrue((self.root/name).is_file())
        os.fstat(self.fd)

    def test_replaced_created_inode_is_preserved_and_other_owned_files_retire(self):
        owner=self.admit();owner.publish();name=next(iter(sorted(self.missing)));target=self.root/name
        held=os.open(target,os.O_RDONLY)
        try:
            target.unlink();target.write_bytes(b'foreign replacement');target.chmod(0o444)
            with self.assertRaises(ValueError):owner.retire(True)
            self.assertEqual(target.read_bytes(),b'foreign replacement')
            for other in self.missing-{name}:self.assertFalse((self.root/other).exists())
        finally:os.close(held)

    def test_changed_same_inode_metadata_is_preserved(self):
        owner=self.admit();owner.publish();name=next(iter(sorted(self.missing)));target=self.root/name
        info=target.stat();os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns+1000000000))
        with self.assertRaises(ValueError):owner.retire(True)
        self.assertTrue(target.is_file())

    def test_partial_failed_create_is_owned_and_can_retire_before_any_unit_start(self):
        owner=self.admit()
        with patch.object(staging.os,'write',side_effect=OSError('synthetic write failure')):
            with self.assertRaises(ValueError):owner.publish()
        owner.retire(True)
        for name in self.missing:self.assertFalse((self.root/name).exists())

    def test_second_publication_is_rejected_without_replacing_first_files(self):
        owner=self.admit();owner.publish();before={name:(self.root/name).stat().st_ino for name in self.missing}
        with self.assertRaises(ValueError):owner.publish()
        self.assertEqual({name:(self.root/name).stat().st_ino for name in self.missing},before)
        owner.retire(True)

    def test_changed_partial_file_is_preserved_instead_of_deleted(self):
        owner=self.admit()
        with patch.object(staging.os,'write',side_effect=OSError('synthetic partial write failure')):
            with self.assertRaises(ValueError):owner.publish()
        created=[self.root/name for name in self.missing if (self.root/name).exists()]
        self.assertEqual(len(created),1);created[0].write_bytes(b'changed partial fixture')
        with self.assertRaises(ValueError):owner.retire(True)
        self.assertEqual(created[0].read_bytes(),b'changed partial fixture')

    def test_unconfirmed_partial_metadata_capture_preserves_file(self):
        owner=self.admit();failed=[];actual=os.fstat
        def write(*_):failed.append(True);raise OSError('synthetic partial write failure')
        def metadata(fd):
            if failed:raise OSError('synthetic failed partial metadata capture')
            return actual(fd)
        with patch.object(staging.os,'write',side_effect=write),patch.object(staging.os,'fstat',side_effect=metadata):
            with self.assertRaises(ValueError):owner.publish()
        created=[self.root/name for name in self.missing if (self.root/name).exists()]
        self.assertEqual(len(created),1)
        with self.assertRaises(ValueError):owner.retire(True)
        self.assertTrue(created[0].is_file())


if __name__=='__main__':unittest.main()
