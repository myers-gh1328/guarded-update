"""Owned observation offer gates; all process fixtures are synthetic."""
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_service as service
from inventory_refresh_cached_observation import ObservationJob,ObservationResult

BOOT='11111111-1111-4111-8111-111111111111'
JOB=ObservationJob(1,'c'*32,'0000000000000001'+'a'*16,1,BOOT,'d'*32,'b'*64,'2026-10-28T07:00:00Z',100,101,1000)
LEASE={'nonce':JOB.operation_nonce,'boot_id':BOOT,'cache_generation':'d'*32,'policy_generation':'b'*64,
       'lock_open_boottime_ms':110,'expires_boottime_ms':1000}
OPENED=ObservationResult.create(JOB,'opened',lease=LEASE)

class LivenessTests(unittest.TestCase):
    def setUp(self):
        self.value=object.__new__(service.ObservationService)
        v=self.value
        v._closed=False;v._job=JOB;v._journal=Mock();v._channel=Mock()
        v._channel._parent_snapshot.return_value={'capabilities':{'release':{'active':None,'terminal':None}}}
        v._channel.read_result.return_value=OPENED;v._channel.read_release.return_value=None
        v._same_invocation=Mock();v._pidfds={};v._pair=None;v._opened=None;v._live_failed=False;v._last_live_time=None
        self.properties={'LoadState':'loaded','ActiveState':'active','MainPID':'100'}
        self.patchers=[patch.object(service,'show_unit',return_value=self.properties),
            patch.object(service,'kernel_clock',return_value=(BOOT,120)),
            patch.object(service.ObservationService,'_members',return_value=(100,200)),
            patch.object(service,'inspect_process'),patch.object(service,'pidfds_live'),
            patch.object(service.os,'pidfd_open',side_effect=[101,102],create=True),
            patch.object(service.os,'close')]
        self.mocks=[]
        for patcher in self.patchers:
            self.mocks.append(patcher.start());self.addCleanup(patcher.stop)

    def test_matching_offer_requires_live_pinned_pair_and_rechecks_before_return(self):
        self.assertEqual(self.value.live_opened().encoded(),OPENED.encoded())
        self.assertEqual(self.value._pair,(100,200));self.assertEqual(len(self.value._pidfds),2)
        self.assertGreaterEqual(self.mocks[4].call_count,2)
        self.assertGreaterEqual(self.mocks[2].call_count,2)
        self.assertGreaterEqual(self.value._same_invocation.call_count,2)
        self.assertEqual(self.value.live_opened().encoded(),OPENED.encoded())
        self.assertEqual(self.mocks[5].call_count,2)

    def test_received_release_or_root_grant_fences_unchanged_live_opened(self):
        for kind in ('received','grant'):
            with self.subTest(kind=kind):
                self.value._live_failed=False
                self.value._channel._parent_snapshot.return_value={'capabilities':{'release':{'active':None,'terminal':None}}}
                self.value._channel.read_release.return_value=None
                if kind=='received':self.value._channel._parent_snapshot.return_value['capabilities']['release']['active']={'correlator':JOB.operation_nonce}
                else:self.value._channel.read_release.return_value=object()
                with self.assertRaises(ValueError):self.value.live_opened()
        self.mocks[5].assert_not_called()

    def test_expired_wrong_boot_or_rewound_clock_rejects(self):
        for clock in ((BOOT,1000),('22222222-2222-4222-8222-222222222222',120),(BOOT,100)):
            with self.subTest(clock=clock):
                self.value._live_failed=False;self.mocks[1].return_value=clock
                with self.assertRaises(ValueError):self.value.live_opened()
        self.mocks[5].assert_not_called()

    def test_extra_or_changed_cgroup_member_cannot_be_accepted(self):
        self.mocks[2].return_value=(100,200,300)
        with self.assertRaises(ValueError):self.value.live_opened()
        self.mocks[5].assert_not_called()

    def test_changed_pair_does_not_reattach_after_first_offer(self):
        self.value.live_opened();self.mocks[2].return_value=(100,201)
        with self.assertRaises(ValueError):self.value.live_opened()
        self.assertEqual(self.mocks[5].call_count,2)

    def test_pidfd_exit_readiness_rejects_even_if_numeric_profiles_still_match(self):
        self.value.live_opened();self.mocks[4].side_effect=ValueError('dead pinned task')
        with self.assertRaises(ValueError):self.value.live_opened()
        self.mocks[4].side_effect=None
        with self.assertRaises(ValueError):self.value.live_opened()

    def test_second_pidfd_failure_closes_first_without_half_adoption(self):
        self.mocks[5].side_effect=[101,OSError('exited')]
        with self.assertRaises((ValueError,OSError)):self.value.live_opened()
        self.mocks[6].assert_called_once_with(101)
        self.assertIsNone(self.value._pair);self.assertFalse(self.value._pidfds)

    def test_terminal_result_written_during_process_probes_rejects_old_opened(self):
        failed=ObservationResult.create(JOB,'failed',reason='internal_error')
        self.value._channel.read_result.side_effect=[OPENED,failed]
        with self.assertRaises(ValueError):self.value.live_opened()
        self.assertTrue(self.value._live_failed)

    def test_changed_result_during_process_probes_rejects_old_opened(self):
        changed=ObservationResult.create(JOB,'opened',lease=dict(LEASE,lock_open_boottime_ms=111))
        self.value._channel.read_result.side_effect=[OPENED,changed]
        with self.assertRaises(ValueError):self.value.live_opened()
        self.assertTrue(self.value._live_failed)

    def test_changed_opened_bytes_cannot_extend_original_offer(self):
        self.value.live_opened()
        changed=ObservationResult.create(JOB,'opened',lease=dict(LEASE,lock_open_boottime_ms=111))
        self.value._channel.read_result.return_value=changed
        with self.assertRaises(ValueError):self.value.live_opened()

def profile(guardian=False,state='S',parent=100):
    cap='0000000000000120' if guardian else '0000000000000000'
    inherited='0000000000000100' if guardian else '0000000000000000'
    return ('Uid: 0 0 0 0\nGid: 0 0 0 0\nGroups: 0\nState: '+state+' (fixture)\nPPid: '+str(parent)+'\n'+
        ''.join(key+': '+value+'\n' for key,value in [('CapPrm',cap),('CapEff',cap),('CapBnd',cap),
            ('CapInh',inherited),('CapAmb','0000000000000000'),('NoNewPrivs','1')])).encode()

class ProcessProofTests(unittest.TestCase):
    def test_actual_profile_parser_rejects_stopped_dead_foreign_or_wrong_argv(self):
        argv=b'/usr/bin/python3\0-I\0-B\0'+(service.LIB_ROOT+'/observation-native.py').encode()+b'\0'
        with patch.object(service,'_process_file',side_effect=[profile(),argv]):service.inspect_process(200,parent=100)
        cases=[(profile(state='T'),argv),(profile(state='Z'),argv),(profile(parent=101),argv),
               (profile().replace(b'CapEff: 0000000000000000',b'CapEff: 0000000000000001'),argv),
               (profile(),argv.replace(b'observation-native.py',b'other.py'))]
        for raw,command in cases:
            with self.subTest(raw=raw,command=command),patch.object(service,'_process_file',side_effect=[raw,command]):
                with self.assertRaises(ValueError):service.inspect_process(200,parent=100)

    def test_poll_detects_real_readiness_instead_of_descriptor_existence(self):
        read,write=os.pipe()
        try:
            service.pidfds_live((read,write))
            os.write(write,b'x')
            with self.assertRaises(ValueError):service.pidfds_live((read,write))
        finally:os.close(read);os.close(write)

if __name__=='__main__':unittest.main()
