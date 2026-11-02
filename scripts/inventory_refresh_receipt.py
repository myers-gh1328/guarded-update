"""Pure observation metadata shape; no acceptance or lifecycle authority."""
import re
from inventory_refresh_protocol import correlator, MAX_SAFE_INTEGER


def _require(condition):
    if not condition:
        raise ValueError('Invalid inventory observation proof')


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
        raise ValueError('Invalid inventory observation proof') from None
    _require(parsed==value)
    return sequence


def _safe(value):
    _require(type(value) is int and 0<=value<=MAX_SAFE_INTEGER)


def _boot(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value) is not None)


LEASE_FIELDS=('nonce','boot_id','cache_generation','policy_generation','lock_open_boottime_ms','expires_boottime_ms')
RECEIPT_FIELDS=LEASE_FIELDS+('lock_held_until_boottime_ms','released_boottime_ms','outcome','installed_before_sha256','installed_after_sha256')


def observation(value, receipt=False):
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

