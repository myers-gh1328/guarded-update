"""Bounded durable helper metadata; no process/service/refresh execution interface.

Runtime never initializes missing state. The fixed coordinator must hold this
same root lock across admission, process lifecycle, publication and retirement.
Returning True from start is the only permission to launch work, after fsync.
"""
from contextlib import contextmanager
import fcntl
import json
import os
import re
import secrets
import stat

from inventory_refresh_protocol import OperationState, correlator, safe_integer

CAPABILITIES = ('refresh', 'observation', 'release')
LIMIT = 65536
MIN_REFRESH_MS = 900000
REASONS = {'busy', 'package_manager_busy', 'executor_busy', 'minimum_interval',
           'policy_unsupported', 'policy_changed', 'repository_failed', 'timeout',
           'resource_limit', 'cleanup_unconfirmed', 'cache_unavailable',
           'state_inconsistent', 'invalid_request', 'lease_expired', 'internal_error'}
OP_FIELDS = {'correlator', 'helper_sequence', 'boot_id', 'accepted_boottime_ms',
             'started_boottime_ms', 'finished_boottime_ms', 'policy_generation',
             'cache_generation', 'phase', 'reason'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def hexadecimal(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None


def boot(value):
    return type(value) is str and re.fullmatch(
        '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value) is not None


def identity(value):
    try:
        return correlator(value.encode('ascii'))
    except (AttributeError, UnicodeError):
        raise ValueError('Invalid helper correlator') from None


def operation(value):
    if type(value) is not dict or set(value) != OP_FIELDS:
        raise ValueError('Invalid helper operation metadata')
    _, sequence = identity(value['correlator'])
    accepted = value['accepted_boottime_ms']
    started = value['started_boottime_ms']
    finished = value['finished_boottime_ms']
    if (not safe_integer(value['helper_sequence']) or value['helper_sequence'] != sequence or
            not boot(value['boot_id']) or not safe_integer(accepted) or
            not hexadecimal(value['policy_generation'], 64) or
            value['reason'] is not None and (type(value['reason']) is not str or value['reason'] not in REASONS) or
            value['cache_generation'] is not None and not hexadecimal(value['cache_generation'], 32) or
            started is not None and (not safe_integer(started) or started < accepted) or
            finished is not None and (not safe_integer(finished) or finished < (started or accepted))):
        raise ValueError('Invalid helper operation values')
    if type(value['phase']) is not str or value['phase'] not in {'received', 'running', 'succeeded', 'deferred', 'failed', 'unconfirmed'}:
        raise ValueError('Invalid helper operation phase')
    if value['phase'] == 'succeeded' and (started is None or finished is None or
                                        value['cache_generation'] is None or value['reason'] is not None):
        raise ValueError('Successful helper metadata requires a completed started generation')
    if value['phase'] == 'running' and (started is None or finished is not None):
        raise ValueError('Invalid running helper operation')
    if value['phase'] in ['received', 'deferred'] and (started is not None or finished is not None):
        raise ValueError('Unstarted helper phase contains execution evidence')
    return value


class Journal:
    def __init__(self, directory_fd, owner=0):
        metadata = os.fstat(directory_fd)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != owner or
                metadata.st_mode & 0o077):
            raise ValueError('Helper journal requires a private admitted root directory')
        self.fd = directory_fd
        self.owner = owner
        self._held = False

    def _check(self, fd):
        value = os.fstat(fd)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != self.owner or
                value.st_mode & 0o077 or value.st_nlink != 1 or value.st_size > LIMIT):
            raise ValueError('Helper metadata requires a bounded private single-link file')

    @contextmanager
    def exclusive(self):
        if self._held:
            raise ValueError('Helper journal lock is not reentrant')
        try:
            fd = os.open('control.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=self.fd)
        except OSError:
            raise ValueError('Helper root lock could not be admitted') from None
        try:
            self._check(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._held = True
            yield self
        finally:
            self._held = False
            os.close(fd)

    def _locked(self):
        if not self._held:
            raise ValueError('Helper metadata changes require its fixed root lock')

    def _read(self, entry):
        try:
            fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except OSError:
            raise ValueError('Helper durable state missing or unsafe; explicit recovery required') from None
        try:
            self._check(fd)
            result = bytearray()
            while len(result) <= LIMIT:
                data = os.read(fd, min(65536, LIMIT+1-len(result)))
                if not data:
                    break
                result.extend(data)
            if len(result) > LIMIT:
                raise ValueError('Helper metadata exceeds bounds')
            return bytes(result)
        finally:
            os.close(fd)

    def _new(self, entry, data):
        fd = os.open(entry, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fchown(fd, self.owner, -1)
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _save(self, value):
        self._locked()
        self._validate(value)
        data = encoded(value)
        if len(data) > LIMIT:
            raise ValueError('Helper journal exceeds bounds')
        entry = '.control-'+secrets.token_hex(16)
        try:
            self._new(entry, data)
            os.replace(entry, 'control.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(entry, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def initialize(self, epoch):
        """Explicit inactive provisioning only. Runtime never calls this method."""
        self._locked()
        if not hexadecimal(epoch, 32):
            raise ValueError('Invalid helper journal epoch')
        for entry in ['initialized-epoch', 'control.json']:
            try:
                os.stat(entry, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError('Existing helper metadata requires recovery, never reset')
        self._new('initialized-epoch', epoch.encode('ascii'))
        os.fsync(self.fd)
        self._save({'schema_version': 1, 'epoch': epoch, 'unconfirmed': False,
                    'capabilities': {key: {'high_water': 0, 'active': None, 'terminal': None, 'last_started': None}
                                     for key in CAPABILITIES}})

    def _validate(self, value):
        if (type(value) is not dict or
                set(value) != {'schema_version', 'epoch', 'unconfirmed', 'capabilities'} or
                type(value['schema_version']) is not int or value['schema_version'] != 1 or
                not hexadecimal(value['epoch'], 32) or type(value['unconfirmed']) is not bool or
                type(value['capabilities']) is not dict or set(value['capabilities']) != set(CAPABILITIES)):
            raise ValueError('Unsupported or malformed helper journal')
        for state in value['capabilities'].values():
            if (type(state) is not dict or set(state) != {'high_water', 'active', 'terminal', 'last_started'} or
                    not safe_integer(state['high_water'])):
                raise ValueError('Invalid helper capability journal')
            last = state['last_started']
            if last is not None:
                if (type(last) is not dict or
                        set(last) != {'correlator', 'helper_sequence', 'boot_id', 'started_boottime_ms'} or
                        not boot(last['boot_id']) or not safe_integer(last['started_boottime_ms']) or
                        not safe_integer(last['helper_sequence']) or
                        identity(last['correlator'])[1] != last['helper_sequence'] or
                        last['helper_sequence'] > state['high_water']):
                    raise ValueError('Invalid durable helper start high-water evidence')
            for key in ['active', 'terminal']:
                if state[key] is not None:
                    record = operation(state[key])
                    if record['helper_sequence'] > state['high_water']:
                        raise ValueError('Helper journal high-water mark is inconsistent')
                    phases = ['succeeded', 'failed'] if key == 'terminal' else ['received', 'deferred', 'running', 'unconfirmed']
                    if record['phase'] not in phases:
                        raise ValueError('Helper journal phase is inconsistent')
        return value

    def snapshot(self):
        marker = self._read('initialized-epoch')
        if len(marker) != 32:
            raise ValueError('Helper initialized marker is invalid')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('Duplicate helper journal field')
                result[key] = value
            return result
        try:
            value = json.loads(self._read('control.json'), object_pairs_hook=unique)
            self._validate(value)
            if value['epoch'].encode('ascii') != marker:
                raise ValueError('Helper initialization identity mismatch')
            return value
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            raise ValueError('Malformed helper journal requires explicit recovery') from None

    def startup_ready(self):
        self._locked()
        value = self.snapshot()
        unresolved = any(state['active'] is not None and state['active']['started_boottime_ms'] is not None
                         for state in value['capabilities'].values())
        if unresolved and not value['unconfirmed']:
            value['unconfirmed'] = True
            for state in value['capabilities'].values():
                if state['active'] is not None and state['active']['started_boottime_ms'] is not None:
                    state['active']['phase'] = 'unconfirmed'
            self._save(value)
        return not value['unconfirmed']

    def receive(self, capability, incoming, boot_id, now, policy):
        self._locked()
        if capability not in CAPABILITIES or not boot(boot_id) or not safe_integer(now) or not hexadecimal(policy, 64):
            raise ValueError('Invalid fixed helper request metadata')
        _, sequence = identity(incoming)
        value = self.snapshot()
        if value['unconfirmed']:
            return 'unconfirmed'
        state = value['capabilities'][capability]
        active = state['active']
        terminal = state['terminal']
        decision = OperationState(state['high_water'], active['correlator'] if active else None,
                                  terminal['correlator'] if terminal else None).admit(incoming)
        if decision in ['existing', 'stale']:
            return decision
        observation = value['capabilities']['observation']['active']
        releasing = (capability == 'release' and observation is not None and
                     observation['correlator'] == incoming and observation['boot_id'] == boot_id and
                     observation['policy_generation'] == policy and
                     observation['started_boottime_ms'] is not None)
        if capability == 'release' and not releasing:
            raise ValueError('Release requires its exact running observation')
        if any(item['active'] is not None and item['active']['started_boottime_ms'] is not None
               for item in value['capabilities'].values()) and not releasing:
            return 'busy'
        if decision == 'busy':
            if active is None or active['started_boottime_ms'] is not None or sequence <= state['high_water']:
                return 'busy'
            # A higher correlator explicitly abandons only proven never-started work.
            active['phase'] = 'failed'
            active['reason'] = 'state_inconsistent'
            active['finished_boottime_ms'] = now if boot_id == active['boot_id'] and now >= active['accepted_boottime_ms'] else None
            state['terminal'] = active
        state['high_water'] = sequence
        state['active'] = {'correlator': incoming, 'helper_sequence': sequence,
            'boot_id': boot_id, 'accepted_boottime_ms': now, 'started_boottime_ms': None,
            'finished_boottime_ms': None, 'policy_generation': policy, 'cache_generation': None,
            'phase': 'received', 'reason': None}
        self._save(value)
        return 'new'

    def start(self, capability, incoming, boot_id, now, *, policy):
        self._locked()
        value = self.snapshot()
        if capability not in CAPABILITIES or value['unconfirmed'] or not hexadecimal(policy, 64):
            raise ValueError('Helper start is not authorized by durable state')
        record = value['capabilities'][capability]['active']
        if (record is None or record['correlator'] != incoming or record['boot_id'] != boot_id or
                record['policy_generation'] != policy or not safe_integer(now) or now < record['accepted_boottime_ms']):
            raise ValueError('Helper start does not match its accepted operation')
        if record['started_boottime_ms'] is not None:
            return False
        for other, state in value['capabilities'].items():
            current = state['active']
            if other == capability or current is None or current['started_boottime_ms'] is None:
                continue
            if not (capability == 'release' and other == 'observation' and current['correlator'] == incoming):
                return False
        last = value['capabilities']['refresh']['last_started']
        if capability == 'refresh' and last is not None:
            due = last['started_boottime_ms'] + MIN_REFRESH_MS if last['boot_id'] == boot_id else MIN_REFRESH_MS
            if now < due:
                record['phase'] = 'deferred'
                record['reason'] = 'minimum_interval'
                self._save(value)
                return False
        record['started_boottime_ms'] = now
        record['phase'] = 'running'
        record['reason'] = None
        value['capabilities'][capability]['last_started'] = {
            'correlator': incoming, 'helper_sequence': record['helper_sequence'],
            'boot_id': boot_id, 'started_boottime_ms': now}
        self._save(value)
        return True

    def defer(self, capability, incoming, boot_id, reason):
        self._locked()
        value = self.snapshot()
        if capability not in CAPABILITIES or type(reason) is not str or reason not in REASONS or value['unconfirmed']:
            raise ValueError('Invalid helper deferral')
        record = value['capabilities'][capability]['active']
        if (record is None or record['correlator'] != incoming or record['boot_id'] != boot_id or
                record['started_boottime_ms'] is not None):
            raise ValueError('Started work cannot be deferred and re-executed')
        record['phase'] = 'deferred'
        record['reason'] = reason
        self._save(value)

    def finish(self, capability, incoming, boot_id, now, phase, reason=None, cache=None, policy=None):
        """Caller must prove owned cgroup empty before publication or terminal success."""
        self._locked()
        value = self.snapshot()
        if (capability not in CAPABILITIES or phase not in ['succeeded', 'failed'] or
                reason is not None and reason not in REASONS):
            raise ValueError('Invalid helper terminal outcome')
        state = value['capabilities'][capability]
        record = state['active']
        if phase == 'succeeded' and not hexadecimal(policy, 64):
            raise ValueError('Successful helper outcome requires its admitted publication policy')
        if record is None:
            terminal = state['terminal']
            if (terminal is not None and terminal['correlator'] == incoming and terminal['boot_id'] == boot_id and
                    terminal['phase'] == phase and terminal['reason'] == reason and terminal['cache_generation'] == cache and
                    (phase != 'succeeded' or terminal['policy_generation'] == policy)):
                return
            raise ValueError('Helper terminal outcome conflicts with durable metadata')
        if (record['correlator'] != incoming or record['boot_id'] != boot_id or
                not safe_integer(now) or now < (record['started_boottime_ms'] or record['accepted_boottime_ms'])):
            raise ValueError('Helper outcome does not match its accepted operation')
        if phase == 'succeeded' and record['policy_generation'] != policy:
            raise ValueError('Published generation policy does not match the accepted operation')
        record['finished_boottime_ms'] = now
        record['phase'] = phase
        record['reason'] = reason
        record['cache_generation'] = cache
        operation(record)
        state['terminal'] = record
        state['active'] = None
        self._save(value)
