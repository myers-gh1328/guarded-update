"""Internal consistency fixture; no authenticated enrollment authority."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_binding_candidate import CandidateError, _candidate_from
from inventory_refresh_state import Journal


class BindingCandidateTests(unittest.TestCase):
    def test_candidate_requires_matching_locked_journal_marker_and_key_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);marker=root/'var'/'lib'/'command-center-inventory'/'initialized-enrollment'
            marker.parent.mkdir(parents=True);marker.write_text('00000000-0000-4000-8000-000000000001\n');marker.chmod(0o644)
            state=root/'state';state.mkdir(mode=0o700)
            root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);state_fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY)
            try:
                journal=Journal(state_fd,owner=os.getuid())
                key=b'synthetic-public-spki'
                server={'device_id':'pi-1','fleet':'personal','boundary':'Home','enrollment_id':'00000000-0000-4000-8000-000000000001',
                        'key_id':'key-1','fingerprint':hashlib.sha256(key).hexdigest()}
                with journal.exclusive():
                    journal.initialize('a'*32)
                    before=(state/'control.json').read_bytes()
                    result=_candidate_from(journal,root_fd,os.getuid(),os.getgid(),time.monotonic()+5,server,key,'a'*32)
                    self.assertEqual(result['root_epoch'],'a'*32)
                    self.assertEqual(result['enrollment_id'],server['enrollment_id'])
                    self.assertEqual(result['fingerprint'],server['fingerprint'])
                    variants=[dict(server,enrollment_id='00000000-0000-4000-8000-000000000002'),
                              dict(server,fingerprint='0'*64),dict(server,key_id='bad key'),dict(server,extra='x'),
                              dict(server,fleet='other'),dict(server,boundary='\x00')]
                    for item in variants:
                        with self.assertRaises(CandidateError):_candidate_from(journal,root_fd,os.getuid(),os.getgid(),time.monotonic()+5,item,key,'a'*32)
                    with self.assertRaises(CandidateError):_candidate_from(journal,root_fd,os.getuid(),os.getgid(),time.monotonic()+5,server,key,'b'*32)
                    with self.assertRaises(CandidateError):_candidate_from(journal,root_fd,os.getuid(),os.getgid(),time.monotonic()-1,server,key,'a'*32)
                    self.assertEqual((state/'control.json').read_bytes(),before)
                    self.assertEqual(marker.read_text(),'00000000-0000-4000-8000-000000000001\n')
                    journal.receive('refresh','0000000000000001'+'a'*16,'11111111-1111-4111-8111-111111111111',100,'b'*64)
                    with self.assertRaises(CandidateError):_candidate_from(journal,root_fd,os.getuid(),os.getgid(),time.monotonic()+5,server,key,'a'*32)
                with self.assertRaises(CandidateError):_candidate_from(journal,root_fd,os.getuid(),os.getgid(),time.monotonic()+5,server,key,'a'*32)
            finally:os.close(state_fd);os.close(root_fd)

if __name__=='__main__':unittest.main()
