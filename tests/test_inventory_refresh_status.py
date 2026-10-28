"""Pure public status shape/identity tests with synthetic metadata only."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_status import PublicStatus, StatusError


def initial():
    return {'schema_version':1,'operation_nonce':None,'phase':'deferred','reason':'cache_unavailable',
            'policy_generation':None,'cache_generation':None,'successful_checked_at':None,
            'started_at':None,'finished_at':None,'attempt':None,
            'observation_lease':None,'observation_receipt':None}


def succeeded():
    value=initial()
    value.update({'phase':'succeeded','reason':None,'operation_nonce':'0000000000000001'+'a'*16,
                  'policy_generation':'b'*64,'cache_generation':'c'*32,
                  'successful_checked_at':'2026-10-28T00:00:01Z',
                  'attempt':{'correlator':'0000000000000001'+'a'*16,'helper_sequence':1,
                             'boot_id':'11111111-1111-4111-8111-111111111111',
                             'accepted_boottime_ms':1000,'started_boottime_ms':1001,'finished_boottime_ms':1002}})
    return value


def receipt_status():
    value=succeeded()
    value['observation_receipt']={'nonce':'0000000000000002'+'d'*16,
        'boot_id':'11111111-1111-4111-8111-111111111111','cache_generation':'c'*32,
        'policy_generation':'b'*64,'lock_open_boottime_ms':2000,'expires_boottime_ms':122000,
        'lock_held_until_boottime_ms':3000,'released_boottime_ms':3001,
        'outcome':'released','installed_before_sha256':'e'*64,'installed_after_sha256':'e'*64}
    return value


class PublicStatusTests(unittest.TestCase):
    def test_helper_phases_require_correlated_evidence_and_preserve_last_success_metadata(self):
        for phase in ['received','deferred','running','succeeded','failed','unconfirmed']:
            value=initial()
            value.update({'phase':phase,'reason':None if phase in ['received','running','succeeded'] else 'repository_failed',
                          'operation_nonce':'0000000000000001'+'a'*16,'policy_generation':'b'*64,
                          'cache_generation':'c'*32,'successful_checked_at':'2026-10-28T00:00:01.123456Z'})
            attempt={'correlator':value['operation_nonce'],'helper_sequence':1,
                     'boot_id':'11111111-1111-4111-8111-111111111111','accepted_boottime_ms':1000,
                     'started_boottime_ms':None if phase in ['received','deferred'] else 1001,
                     'finished_boottime_ms':1002 if phase in ['succeeded','failed'] else None}
            value['attempt']=attempt
            status=PublicStatus.create(value)
            decoded=json.loads(status.encoded())
            self.assertEqual(decoded,value)
            attempt['boot_id']='mutated synthetic input'
            self.assertEqual(json.loads(status.encoded())['attempt']['boot_id'],decoded['attempt']['boot_id'])
            self.assertEqual(decoded['cache_generation'],'c'*32)
            self.assertEqual(decoded['successful_checked_at'],'2026-10-28T00:00:01.123456Z')
        for phase in ['received','running','succeeded']:
            value=initial();value.update({'phase':phase,'reason':None})
            with self.subTest(missing_attempt=phase),self.assertRaises(StatusError):
                PublicStatus.create(value)

    def test_observation_lease_exposes_actual_open_and_receipt_remains_independent_of_refresh(self):
        value=initial()
        value.update({'policy_generation':'b'*64,'cache_generation':'c'*32,
                      'successful_checked_at':'2026-10-28T00:00:01Z'})
        lease={'nonce':'0000000000000002'+'d'*16,'boot_id':'11111111-1111-4111-8111-111111111111',
               'cache_generation':'c'*32,'policy_generation':'b'*64,
               'lock_open_boottime_ms':2000,'expires_boottime_ms':122000}
        value['observation_lease']=lease
        active=json.loads(PublicStatus.create(value).encoded())
        self.assertEqual(active['observation_lease']['lock_open_boottime_ms'],2000)
        self.assertEqual(active['phase'],'deferred')
        self.assertIsNone(active['operation_nonce'])
        receipt={**lease,'lock_held_until_boottime_ms':3000,'released_boottime_ms':3001,
                 'outcome':'released','installed_before_sha256':'e'*64,'installed_after_sha256':'e'*64}
        value['observation_lease']=None
        value['observation_receipt']=receipt
        terminal=json.loads(PublicStatus.create(value).encoded())
        self.assertEqual(terminal['observation_receipt'],receipt)
        self.assertIsNone(terminal['attempt'])
        lease['nonce']='0000000000000003'+'f'*16
        value['observation_lease']=lease
        self.assertEqual(json.loads(PublicStatus.create(value).encoded())['observation_receipt'],receipt)
        value['observation_lease']['nonce']=receipt['nonce']
        with self.assertRaises(StatusError):
            PublicStatus.create(value)

    def test_private_unknown_and_hostile_scalar_values_are_static_rejections(self):
        cases=[('private_policy',{'password':'synthetic-sensitive-value'}),('schema_version',True),
               ('schema_version',float('nan')),('phase',[]),('reason',{}),('operation_nonce','../synthetic'),
               ('policy_generation','B'*64),('cache_generation',[]),
               ('successful_checked_at','2026-02-30T00:00:00Z'),('started_at','synthetic-sensitive-value'),
               ('finished_at','2026-10-28T25:00:00Z'),('attempt',[]),('observation_receipt',{}),
               ('observation_lease',{'command':'synthetic-sensitive-value'})]
        for field,bad in cases:
            value=initial();value[field]=bad
            with self.subTest(field=field),self.assertRaises(StatusError) as caught:
                PublicStatus.create(value)
            self.assertNotIn('synthetic-sensitive-value',str(caught.exception))
        for field in initial():
            value=initial();del value[field]
            with self.subTest(missing=field),self.assertRaises(StatusError):
                PublicStatus.create(value)

    def test_inconsistent_helper_identity_times_and_success_never_publish(self):
        cases=[('helper_sequence',True),('helper_sequence',2),('boot_id','not-a-boot'),
               ('accepted_boottime_ms',-1),('accepted_boottime_ms',9007199254740992),
               ('started_boottime_ms',999),('finished_boottime_ms',1000),
               ('finished_boottime_ms',601002),('finished_boottime_ms',None),('started_boottime_ms',None),
               ('correlator','0000000000000000'+'a'*16)]
        for field,bad in cases:
            value=succeeded();value['attempt'][field]=bad
            with self.subTest(field=field,bad=bad),self.assertRaises(StatusError):
                PublicStatus.create(value)
        for field in ['policy_generation','cache_generation','successful_checked_at']:
            value=succeeded();value[field]=None
            with self.subTest(missing=field),self.assertRaises(StatusError):
                PublicStatus.create(value)
        value=succeeded();value['phase']='deferred';value['reason']='minimum_interval'
        with self.assertRaises(StatusError):
            PublicStatus.create(value)

    def test_successful_observation_cannot_hide_expiry_changed_state_or_invalid_identity(self):
        cases=[('nonce','0000000000000000'+'a'*16),('boot_id',[]),('expires_boottime_ms',122001),
               ('lock_open_boottime_ms',True),('lock_held_until_boottime_ms',1999),
               ('released_boottime_ms',2999),('released_boottime_ms',122001),
               ('outcome',[]),('installed_after_sha256','f'*64)]
        for field,bad in cases:
            value=receipt_status();value['observation_receipt'][field]=bad
            with self.subTest(field=field),self.assertRaises(StatusError):
                PublicStatus.create(value)
        value=receipt_status();value['observation_receipt'].update({'outcome':'expired','released_boottime_ms':122001})
        self.assertEqual(json.loads(PublicStatus.create(value).encoded())['observation_receipt']['outcome'],'expired')
        value['observation_receipt']['outcome']='released'
        with self.assertRaises(StatusError):
            PublicStatus.create(value)

    def test_initial_public_status_requires_explicit_fields_and_freezes_encoded_bytes(self):
        value=initial()
        status=PublicStatus.create(value)
        raw=status.encoded()
        self.assertEqual(json.loads(raw),value)
        value['reason']='policy_unsupported'
        self.assertEqual(json.loads(status.encoded())['reason'],'cache_unavailable')
        self.assertLessEqual(len(raw),65536)
        with self.assertRaises(TypeError):
            PublicStatus(raw)
        with self.assertRaises(AttributeError):
            status._raw=b'private synthetic material'
        with self.assertRaises(StatusError):
            PublicStatus.create({'schema_version':1})


if __name__=='__main__':
    unittest.main()
