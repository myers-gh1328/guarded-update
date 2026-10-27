"""Pure fixed-capability protocol rules. No file, command or privileged operations."""
from dataclasses import dataclass
import hashlib
import hmac
import re

MAX_SAFE_INTEGER = 9_007_199_254_740_991
POLICY_SECTIONS = ('schema', 'sources', 'trust', 'pins', 'architectures', 'proxy', 'auth')
POLICY_DOMAIN = b'command-center-inventory-policy-v1\x00'


def safe_integer(value):
    return type(value) is int and 0 <= value <= MAX_SAFE_INTEGER


def correlator(raw):
    if type(raw) is not bytes or len(raw) > 64:
        raise ValueError('Invalid fixed capability correlator')
    if raw.endswith(b'\n'):
        raw = raw[:-1]
    if not re.fullmatch(b'[0-9a-f]{32}', raw):
        raise ValueError('Invalid fixed capability correlator')
    counter = int(raw[:16], 16)
    if not 1 <= counter <= MAX_SAFE_INTEGER:
        raise ValueError('Invalid fixed capability counter')
    return raw.decode('ascii'), counter


@dataclass(frozen=True)
class OperationState:
    high_water: int
    active: str | None
    terminal: str | None

    def admit(self, incoming):
        if not safe_integer(self.high_water):
            raise ValueError('Invalid durable helper counter')
        _, counter = correlator(incoming.encode('ascii'))
        for retained in [self.active, self.terminal]:
            if retained is not None:
                _, retained_counter = correlator(retained.encode('ascii'))
                if retained_counter > self.high_water:
                    raise ValueError('Inconsistent durable helper counter')
        if incoming in [self.active, self.terminal]:
            return 'existing'
        if counter <= self.high_water:
            return 'stale'
        if self.active is not None:
            return 'busy'
        return 'new'


def policy_commitment(key, fields):
    if type(key) is not bytes or len(key) != 32:
        raise ValueError('Invalid private policy commitment key')
    if type(fields) is not dict or set(fields) != set(POLICY_SECTIONS):
        raise ValueError('Invalid admitted policy sections')
    if any(type(value) is not bytes or len(value) > 4 * 1024 * 1024
           for value in fields.values()) or sum(map(len, fields.values())) > 8 * 1024 * 1024:
        raise ValueError('Admitted policy exceeds bounds')
    digest = hmac.new(key, POLICY_DOMAIN, hashlib.sha256)
    for name in POLICY_SECTIONS:
        encoded = name.encode('ascii')
        digest.update(len(encoded).to_bytes(8, 'big'))
        digest.update(encoded)
        digest.update(len(fields[name]).to_bytes(8, 'big'))
        digest.update(fields[name])
    return digest.hexdigest()


def post_acceptance_attempt(attempt, expected_correlator, boot_id, accepted_ms):
    keys = {'correlator', 'helper_sequence', 'boot_id', 'accepted_boottime_ms',
            'started_boottime_ms', 'finished_boottime_ms'}
    if type(attempt) is not dict or set(attempt) != keys or not safe_integer(accepted_ms):
        return False
    try:
        _, counter = correlator(expected_correlator.encode('ascii'))
    except (ValueError, AttributeError, UnicodeError):
        return False
    if (attempt['correlator'] != expected_correlator or attempt['boot_id'] != boot_id or
            type(boot_id) is not str or not re.fullmatch(
                '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', boot_id) or
            not safe_integer(attempt['helper_sequence']) or attempt['helper_sequence'] != counter):
        return False
    started = attempt['started_boottime_ms']
    helper_accepted = attempt['accepted_boottime_ms']
    finished = attempt['finished_boottime_ms']
    return (safe_integer(started) and safe_integer(helper_accepted) and
            helper_accepted <= started and accepted_ms <= started and
            (finished is None or safe_integer(finished) and started <= finished))
