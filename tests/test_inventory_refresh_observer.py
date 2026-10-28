"""Observation process failure and profile contracts; no live service changes."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_cached_observation import ObservationJob
import inventory_refresh_observer as observer

BOOT='11111111-1111-4111-8111-111111111111'
JOB=ObservationJob(1,'c'*32,'0000000000000001'+'a'*16,1,BOOT,'d'*32,'b'*64,'2026-10-28T07:00:00Z',100,101,1000)

def profile(cap='0000000000000000',inherit='0000000000000000'):
    return ('Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0\n'+
            ''.join(key+':\t'+value+'\n' for key,value in (
                ('CapPrm',cap),('CapEff',cap),('CapBnd',cap),('CapInh',inherit),
                ('CapAmb','0000000000000000'),('NoNewPrivs','1')))).encode()

class ObserverTests(unittest.TestCase):
    def test_native_requires_all_five_capability_sets_empty_and_all_ids_root(self):
        observer.admit_profile(profile())
        for key,value in ((b'CapEff:\t0000000000000000',b'CapEff:\t0000000000000001'),
                          (b'Uid:\t0\t0\t0\t0',b'Uid:\t0\t0\t0\t1'),
                          (b'Groups:\t0',b'Groups:\t0 7'),(b'NoNewPrivs:\t1',b'NoNewPrivs:\t0')):
            with self.subTest(key=key),self.assertRaises(ValueError):observer.admit_profile(profile().replace(key,value))
        with self.assertRaises(ValueError):observer.admit_profile(profile()+b'CapAmb:\t0000000000000000\n')

    def test_guardian_requires_only_kill_setpcap(self):
        observer.admit_profile(profile('0000000000000120','0000000000000100'),guardian=True)
        with self.assertRaises(ValueError):observer.admit_profile(profile('00000000000001e0'),guardian=True)

    def test_expired_wrong_boot_and_rewound_jobs_do_not_open_native_cache(self):
        for clock in ((BOOT,1000),('22222222-2222-4222-8222-222222222222',105),(BOOT,100)):
            with self.subTest(clock=clock),patch.object(observer,'identity'),patch.object(observer,'kernel_clock',return_value=clock),patch.object(observer.ObservationChannel,'fixed') as channel,patch.object(observer,'FixedCache') as cache:
                channel.return_value.read_job.return_value=JOB
                self.assertEqual(observer.run_native(),74)
                cache.assert_not_called()
                channel.return_value.close.assert_called_once()

    def test_cache_enter_verification_failure_closes_all_owned_ancestry(self):
        cache=object.__new__(observer.FixedCache)
        ancestry=Mock();ancestry.verify.side_effect=ValueError('changed')
        cache._ancestry=ancestry;cache.reader=object()
        with self.assertRaises(ValueError):cache.__enter__()
        ancestry.close.assert_called_once()
        self.assertIsNone(cache._ancestry)

    def test_fixed_child_command_has_no_uid_switch_or_caller_arguments(self):
        argv=observer.native_argv()
        self.assertEqual(argv,('/usr/bin/setpriv','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs','/usr/bin/python3','-I','-B',observer.LIB_ROOT+'/observation-native.py'))

    def test_guardian_entry_retains_completion_without_changing_native_success(self):
        with patch.object(observer,'identity'),patch.object(observer,'kernel_clock',return_value=(BOOT,105)),patch.object(observer.ObservationChannel,'fixed') as channel,patch.object(observer,'supervise',return_value=0):
            channel.return_value.read_job.return_value=JOB
            self.assertEqual(observer.run_guardian(),90)

    def test_guardian_rejects_stale_boot_before_spawn(self):
        with patch.object(observer,'identity'),patch.object(observer,'kernel_clock',return_value=('22222222-2222-4222-8222-222222222222',105)),patch.object(observer.ObservationChannel,'fixed') as channel,patch.object(observer.subprocess,'Popen') as spawn:
            channel.return_value.read_job.return_value=JOB
            self.assertEqual(observer.run_guardian(),74);spawn.assert_not_called()

if __name__=='__main__':unittest.main()
