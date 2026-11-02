"""Synthetic protected request-seal observations; never enrollment authority."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_state import Journal
from inventory_refresh_request_seal import SealError, observe, publish

EPOCH='a'*32
ENROLLMENT='00000000-0000-4000-8000-000000000001'


class RequestSealTests(unittest.TestCase):
    def test_failed_publication_never_removes_or_recreates_an_uncertain_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);marker=root/'var/lib/command-center-inventory-refresh/initialized-requests'
            marker.parent.mkdir(parents=True);state=root/'state';state.mkdir(mode=0o700)
            rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);statefd=os.open(state,os.O_RDONLY|os.O_DIRECTORY)
            try:
                journal=Journal(statefd,owner=os.getuid())
                with journal.exclusive():
                    journal.initialize(EPOCH)
                    with self.assertRaises(SealError):publish(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,'b'*32,time.monotonic()+5,lambda:None)
                    self.assertFalse(marker.exists())
                    with patch('inventory_refresh_request_seal.os.fsync',side_effect=OSError('synthetic')):
                        with self.assertRaises(SealError):publish(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,lambda:None)
                    original=marker.read_bytes()
                    self.assertEqual(observe(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,lambda:None)['state'],'present_unconfirmed')
                    with self.assertRaises(SealError):publish(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,lambda:None)
                    self.assertEqual(marker.read_bytes(),original)
            finally:os.close(statefd);os.close(rootfd)
    def test_one_way_durable_publication_is_bound_to_the_locked_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);marker=root/'var/lib/command-center-inventory-refresh/initialized-requests'
            marker.parent.mkdir(parents=True)
            state=root/'state';state.mkdir(mode=0o700)
            rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);statefd=os.open(state,os.O_RDONLY|os.O_DIRECTORY)
            try:
                journal=Journal(statefd,owner=os.getuid())
                with journal.exclusive():
                    journal.initialize(EPOCH)
                    publish(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,lambda:None)
                    self.assertEqual(observe(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,lambda:None)['state'],'present_unconfirmed')
                    original=marker.read_bytes()
                    with self.assertRaises(SealError):publish(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,lambda:None)
                    self.assertEqual(marker.read_bytes(),original)
            finally:os.close(statefd);os.close(rootfd)
    def test_observation_requires_private_fixed_marker_and_held_matching_root_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);marker=root/'var/lib/command-center-inventory-refresh/initialized-requests'
            marker.parent.mkdir(parents=True)
            marker.write_text(json.dumps({'schema_version':1,'enrollment_id':ENROLLMENT,'root_epoch':EPOCH}));marker.chmod(0o644)
            state=root/'state';state.mkdir(mode=0o700)
            rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);statefd=os.open(state,os.O_RDONLY|os.O_DIRECTORY)
            try:
                journal=Journal(statefd,owner=os.getuid())
                with journal.exclusive():
                    journal.initialize(EPOCH)
                    before=marker.read_bytes()
                    self.assertEqual(observe(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,lambda:None),{'state':'present_unconfirmed','enrollment_id':ENROLLMENT,'root_epoch':EPOCH})
                    self.assertEqual(marker.read_bytes(),before)
                    for fault in ('missing','malformed','duplicate','symlink','hardlink','mode','ancestor','epoch','enrollment','lock-loss'):
                        with self.subTest(fault=fault):
                            marker.unlink(missing_ok=True);marker.write_bytes(before);marker.chmod(0o644)
                            if fault=='missing':marker.unlink()
                            elif fault=='malformed':marker.write_bytes(b'{}')
                            elif fault=='duplicate':marker.write_bytes(b'{"schema_version":1,"schema_version":1}')
                            elif fault=='symlink':marker.unlink();marker.symlink_to('missing')
                            elif fault=='hardlink':os.link(marker,marker.with_name('other'))
                            elif fault=='mode':marker.chmod(0o666)
                            elif fault=='ancestor':marker.parent.chmod(0o777)
                            elif fault=='epoch':marker.write_text(json.dumps({'schema_version':1,'enrollment_id':ENROLLMENT,'root_epoch':'b'*32}))
                            elif fault=='enrollment':marker.write_text(json.dumps({'schema_version':1,'enrollment_id':'00000000-0000-4000-8000-000000000002','root_epoch':EPOCH}))
                            verify=(lambda:(_ for _ in ()).throw(ValueError())) if fault=='lock-loss' else (lambda:None)
                            with self.assertRaises(SealError):observe(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,verify)
                            if fault=='hardlink':marker.with_name('other').unlink()
                            if fault=='ancestor':marker.parent.chmod(0o755)
                    marker.unlink(missing_ok=True);marker.write_bytes(before);marker.chmod(0o644)
                    for owner,group in ((os.getuid()+1,os.getgid()),(os.getuid(),os.getgid()+1)):
                        with self.assertRaises(SealError):observe(journal,rootfd,owner,group,ENROLLMENT,EPOCH,time.monotonic()+5,lambda:None)
                    with self.assertRaises(SealError):observe(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()-1,lambda:None)
                    calls=[]
                    def lost_during_read():
                        calls.append(1)
                        if len(calls)>4:raise ValueError('synthetic lock loss')
                    with self.assertRaises(SealError):observe(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,lost_during_read)
                    real_read=os.read; changed=[]
                    def replacement(fd,size):
                        value=real_read(fd,size)
                        if value and not changed and os.fstat(fd).st_ino==marker.stat().st_ino:
                            new=marker.with_name('next');new.write_bytes(before);new.chmod(0o644);os.replace(new,marker);changed.append(True)
                        return value
                    with patch('inventory_refresh_request_seal.os.read',side_effect=replacement):
                        with self.assertRaises(SealError):observe(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,lambda:None)
                with self.assertRaises(SealError):observe(journal,rootfd,os.getuid(),os.getgid(),ENROLLMENT,EPOCH,time.monotonic()+5,lambda:None)
            finally:os.close(statefd);os.close(rootfd)


if __name__=='__main__':unittest.main()
