"""Strict public helper status construction; no OS or lifecycle authority."""


from datetime import datetime
import json
import re

from inventory_refresh_protocol import correlator, MAX_SAFE_INTEGER
from inventory_refresh_state import REASONS

FIELDS=('schema_version','operation_nonce','phase','reason','policy_generation','cache_generation',
        'successful_checked_at','started_at','finished_at','attempt','observation_lease','observation_receipt')
PHASES={'received','running','succeeded','deferred','failed','unconfirmed'}


def _require(condition):
    if not condition:
        raise StatusError()


def _object(value, fields):
    _require(type(value) is dict and set(value)==set(fields))
    return {field:value[field] for field in fields}


def _hex(value,size):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None)


def _nonce(value):
    _require(type(value) is str)
    try:
        parsed,sequence=correlator(value.encode('ascii'))
    except (ValueError,UnicodeError):
        raise StatusError() from None
    _require(parsed==value)
    return sequence


def _utc(value):
    _require(type(value) is str and len(value)<=27 and re.fullmatch(
        r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z',value) is not None)
    try:
        return datetime.fromisoformat(value[:-1]+'+00:00')
    except ValueError:
        raise StatusError() from None


def _safe(value):
    _require(type(value) is int and 0<=value<=MAX_SAFE_INTEGER)


def _boot(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value) is not None)


def _attempt(value, phase, nonce):
    value=_object(value,('correlator','helper_sequence','boot_id','accepted_boottime_ms','started_boottime_ms','finished_boottime_ms'))
    sequence=_nonce(value['correlator'])
    _safe(value['helper_sequence'])
    _require(sequence==value['helper_sequence'] and value['correlator']==nonce)
    _boot(value['boot_id'])
    accepted=value['accepted_boottime_ms']
    _safe(accepted)
    started=value['started_boottime_ms']
    finished=value['finished_boottime_ms']
    if started is not None:
        _safe(started)
        _require(started>=accepted)
    if finished is not None:
        _safe(finished)
        _require(finished>=(accepted if started is None else started))
    if phase=='received':
        _require(started is None and finished is None)
    if phase=='deferred':
        _require(started is None)
    if phase=='running':
        _require(started is not None and finished is None)
    if phase=='succeeded':
        _require(started is not None and finished is not None and finished-started<=600000)
    return value


LEASE_FIELDS=('nonce','boot_id','cache_generation','policy_generation','lock_open_boottime_ms','expires_boottime_ms')
RECEIPT_FIELDS=LEASE_FIELDS+('lock_held_until_boottime_ms','released_boottime_ms','outcome','installed_before_sha256','installed_after_sha256')


def _observation(value, receipt=False):
    value=_object(value,RECEIPT_FIELDS if receipt else LEASE_FIELDS)
    _nonce(value['nonce'])
    _boot(value['boot_id'])
    _hex(value['cache_generation'],32)
    _hex(value['policy_generation'],64)
    opened=value['lock_open_boottime_ms']
    expires=value['expires_boottime_ms']
    _safe(opened)
    _safe(expires)
    _require(opened<=expires and expires-opened<=120000)
    if receipt:
        held=value['lock_held_until_boottime_ms']
        released=value['released_boottime_ms']
        _safe(held)
        _safe(released)
        _require(opened<=held<=released)
        _require(type(value['outcome']) is str and value['outcome'] in {'released','expired','unconfirmed'})
        _hex(value['installed_before_sha256'],64)
        _hex(value['installed_after_sha256'],64)
        if value['outcome']=='released':
            _require(released<=expires and value['installed_before_sha256']==value['installed_after_sha256'])
    return value


class StatusError(ValueError):
    def __init__(self):
        super().__init__('Invalid public inventory helper status')


class PublicStatus:
    __slots__=('_raw',)
    def __new__(cls, *args, **kwargs):
        raise TypeError('Use validated public status construction')

    @classmethod
    def create(cls, value):
        try:
            _require(cls is PublicStatus)
            value=_object(value,FIELDS)
            _require(type(value['schema_version']) is int and value['schema_version']==1)
            phase=value['phase']
            _require(type(phase) is str and phase in PHASES)
            reason=value['reason']
            if phase in {'received','running','succeeded'}:
                _require(reason is None)
            else:
                _require(type(reason) is str and reason in REASONS)
            if value['operation_nonce'] is not None:
                _nonce(value['operation_nonce'])
            for field,size in [('policy_generation',64),('cache_generation',32)]:
                if value[field] is not None:
                    _hex(value[field],size)
            for field in ['successful_checked_at','started_at','finished_at']:
                if value[field] is not None:
                    _utc(value[field])
            if value['cache_generation'] is not None or value['successful_checked_at'] is not None:
                _require(value['cache_generation'] is not None and value['successful_checked_at'] is not None and value['policy_generation'] is not None)
            if value['attempt'] is None:
                _require(phase in {'deferred','failed','unconfirmed'} and value['operation_nonce'] is None and value['started_at'] is None and value['finished_at'] is None)
            else:
                value['attempt']=_attempt(value['attempt'],phase,value['operation_nonce'])
                if value['started_at'] is not None:
                    _require(value['attempt']['started_boottime_ms'] is not None)
                if value['finished_at'] is not None:
                    _require(value['attempt']['finished_boottime_ms'] is not None)
            if phase=='succeeded':
                _require(value['cache_generation'] is not None and value['policy_generation'] is not None and value['successful_checked_at'] is not None)
            if value['observation_lease'] is not None:
                value['observation_lease']=_observation(value['observation_lease'])
                _require(value['observation_lease']['cache_generation']==value['cache_generation'] and
                         value['observation_lease']['policy_generation']==value['policy_generation'])
            if value['observation_receipt'] is not None:
                value['observation_receipt']=_observation(value['observation_receipt'],True)
            if value['observation_lease'] is not None and value['observation_receipt'] is not None:
                _require(value['observation_lease']['nonce']!=value['observation_receipt']['nonce'])
            raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
            _require(len(raw)<=65536)
            status=object.__new__(PublicStatus)
            object.__setattr__(status,'_raw',raw)
            return status
        except (KeyError,TypeError,OverflowError,RecursionError):
            raise StatusError() from None

    def encoded(self):
        return self._raw

    def __setattr__(self, name, value):
        raise AttributeError('Public status is immutable')
