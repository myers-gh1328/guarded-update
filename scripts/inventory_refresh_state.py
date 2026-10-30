"""Bounded durable helper metadata; no process/service/refresh execution interface.

Runtime never initializes missing state. The fixed coordinator must hold this
same root lock across admission, process lifecycle, publication and retirement.
Returning True from start is the only permission to launch work, after fsync.
"""
from contextlib import contextmanager
from datetime import datetime
import fcntl
import json
import os
import re
import secrets
import stat

from inventory_refresh_protocol import OperationState, correlator, safe_integer
from inventory_refresh_receipt import observation as validate_observation

CAPABILITIES = ('refresh', 'observation', 'release')
LIMIT = 65536
MIN_REFRESH_MS = 900000
REASONS = {'busy', 'package_manager_busy', 'executor_busy', 'minimum_interval',
           'policy_unsupported', 'policy_changed', 'repository_failed', 'timeout',
           'resource_limit', 'cleanup_unconfirmed', 'cache_unavailable',
           'state_inconsistent', 'invalid_request', 'lease_expired', 'internal_error'}
OP_FIELDS = {'correlator', 'helper_sequence', 'boot_id', 'accepted_boottime_ms',
             'started_boottime_ms', 'finished_boottime_ms', 'policy_generation',
             'cache_generation', 'phase', 'reason', 'decision_boottime_ms'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def metadata_identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


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


def checked_timestamp(value):
    if (type(value) is not str or len(value)>27 or re.fullmatch(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z',value) is None):
        raise ValueError('Invalid retained cache success timestamp')
    try:
        datetime.fromisoformat(value[:-1]+'+00:00')
    except ValueError:
        raise ValueError('Invalid retained cache success timestamp') from None
    return value


def operation(value):
    if type(value) is not dict or set(value) != OP_FIELDS:
        raise ValueError('Invalid helper operation metadata')
    _, sequence = identity(value['correlator'])
    accepted = value['accepted_boottime_ms']
    started = value['started_boottime_ms']
    finished = value['finished_boottime_ms']
    decision = value['decision_boottime_ms']
    if (not safe_integer(value['helper_sequence']) or value['helper_sequence'] != sequence or
            not boot(value['boot_id']) or not safe_integer(accepted) or
            not hexadecimal(value['policy_generation'], 64) or
            value['reason'] is not None and (type(value['reason']) is not str or value['reason'] not in REASONS) or
            value['cache_generation'] is not None and not hexadecimal(value['cache_generation'], 32) or
            started is not None and (not safe_integer(started) or started < accepted) or
            finished is not None and (not safe_integer(finished) or finished < (started or accepted)) or
            decision is not None and (not safe_integer(decision) or decision < accepted)):
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
    if (value['phase'] == 'deferred') != (decision is not None):
        raise ValueError('No-work decision requires its immutable deferred phase')
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
        self._launch_permits=set()
        self._launch_epoch=object()
        self._needs_reconciliation = True

    def _check(self, fd):
        value = os.fstat(fd)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != self.owner or
                value.st_mode & 0o077 or value.st_nlink != 1 or value.st_size > LIMIT):
            raise ValueError('Helper metadata requires a bounded private single-link file')
        return value

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
            self._launch_permits.clear()
            self._launch_epoch=object()
            self._held = False
            os.close(fd)

    def _held_lock(self):
        if not self._held:
            raise ValueError('Helper metadata changes require its fixed root lock')

    def _ready(self):
        if self._needs_reconciliation:
            raise ValueError('Helper durable state requires explicit reconciliation')

    def _locked(self):
        self._held_lock()
        self._ready()

    def _read_descriptor(self, fd):
        before=self._check(fd)
        result=bytearray()
        while len(result)<=LIMIT:
            chunk=os.read(fd,min(65536,LIMIT+1-len(result)))
            if not chunk:
                break
            result.extend(chunk)
        after=self._check(fd)
        if (len(result)>LIMIT or len(result)!=before.st_size or
                metadata_identity(before)!=metadata_identity(after)):
            raise ValueError('Helper metadata changed or exceeded bounds during read')
        return bytes(result),after

    def _read(self, entry):
        try:
            fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except OSError:
            raise ValueError('Helper durable state missing or unsafe; explicit recovery required') from None
        try:
            return self._read_descriptor(fd)[0]
        finally:
            os.close(fd)

    def _write_descriptor(self, fd, data):
        offset=0
        while offset<len(data):
            written=os.write(fd,data[offset:])
            if written<=0:
                raise OSError('Helper metadata write made no progress')
            offset+=written
        os.fchown(fd,self.owner,-1)
        os.fchmod(fd,0o600)
        os.fsync(fd)

    def _new(self, entry, data):
        fd = os.open(entry, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            self._write_descriptor(fd,data)
        finally:
            os.close(fd)

    def _save(self, value):
        self._held_lock()
        self._launch_permits.clear()
        self._launch_epoch=object()
        self._validate(value)
        data=encoded(value)
        if len(data)>LIMIT:
            raise ValueError('Helper journal exceeds bounds')
        self._needs_reconciliation=True
        entry='.control-'+secrets.token_hex(16)
        fd=None
        created=False
        try:
            fd=os.open(entry,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
            created=True
            self._write_descriptor(fd,data)
            closing,fd=fd,None
            os.close(closing)
            os.replace(entry,'control.json',src_dir_fd=self.fd,dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                if fd is not None:
                    closing,fd=fd,None
                    os.close(closing)
            finally:
                if created:
                    try:
                        os.unlink(entry,dir_fd=self.fd)
                    except FileNotFoundError:
                        pass
        self._needs_reconciliation=False

    def initialize(self, epoch):
        """Explicit inactive provisioning only. Runtime never calls this method."""
        self._held_lock()
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
        self._save({'schema_version': 3, 'epoch': epoch, 'unconfirmed': False, 'last_success': None, 'last_observation': None,
                    'capabilities': {key: {'high_water': 0, 'active': None, 'terminal': None, 'last_started': None}
                                     for key in CAPABILITIES}})

    def _validate(self, value):
        if (type(value) is not dict or
                set(value) != {'schema_version', 'epoch', 'unconfirmed', 'capabilities', 'last_success', 'last_observation'} or
                type(value['schema_version']) is not int or value['schema_version'] != 3 or
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
                    phases = ['succeeded', 'failed', 'deferred'] if key == 'terminal' else ['received', 'deferred', 'running', 'unconfirmed']
                    if record['phase'] not in phases:
                        raise ValueError('Helper journal phase is inconsistent')
        success=value['last_success']
        refresh=value['capabilities']['refresh']
        if success is not None:
            if type(success) is not dict or set(success)!={'attempt','successful_checked_at'}:
                raise ValueError('Invalid retained cache success evidence')
            prior=operation(success['attempt'])
            checked_timestamp(success['successful_checked_at'])
            if (prior['phase']!='succeeded' or prior['helper_sequence']>refresh['high_water'] or
                    prior['finished_boottime_ms']-prior['started_boottime_ms']>600000):
                raise ValueError('Invalid retained successful refresh')
        terminal=refresh['terminal']
        if terminal is not None and terminal['phase']=='succeeded' and (success is None or terminal!=success['attempt']):
            raise ValueError('Successful refresh terminal lacks matching retained evidence')
        accepted=value['last_observation']
        if accepted is not None:
            if type(accepted) is not dict or set(accepted)!={'observation','release','receipt'}:
                raise ValueError('Invalid retained observation acceptance')
            receipt=validate_observation(accepted['receipt'],True)
            records={capability:operation(accepted[capability]) for capability in ('observation','release')}
            self._observation_binding(records,receipt,terminal=True)
            for capability,record in records.items():
                if record['helper_sequence']>value['capabilities'][capability]['high_water']:
                    raise ValueError('Observation acceptance exceeds durable counter')
        for capability in ('observation','release'):
            terminal=value['capabilities'][capability]['terminal']
            if terminal is not None and terminal['phase']=='succeeded' and (accepted is None or terminal!=accepted[capability]):
                raise ValueError('Successful observation terminal lacks accepted receipt')
        return value

    @staticmethod
    def _observation_binding(records,receipt,*,terminal):
        if receipt['outcome']!='released':
            raise ValueError('Only released observation evidence may complete')
        for record in records.values():
            if (record is None or record['phase']!=('succeeded' if terminal else 'running') or
                    record['started_boottime_ms'] is None or record['decision_boottime_ms'] is not None or
                    record['correlator']!=receipt['nonce'] or record['boot_id']!=receipt['boot_id'] or
                    record['policy_generation']!=receipt['policy_generation'] or
                    terminal and (record['cache_generation']!=receipt['cache_generation'] or
                                  record['finished_boottime_ms']!=receipt['released_boottime_ms'])):
                raise ValueError('Observation acceptance does not bind its running operations')
        observed=records['observation'];released=records['release']
        if not (observed['accepted_boottime_ms']<=released['accepted_boottime_ms'] and
                observed['started_boottime_ms']<=receipt['lock_open_boottime_ms']<=
                released['started_boottime_ms']<=receipt['lock_held_until_boottime_ms'] and
                receipt['expires_boottime_ms']<=observed['accepted_boottime_ms']+120000):
            raise ValueError('Observation acceptance times do not bind held interval')

    def finish_observation(self,receipt):
        """Commit metadata only AFTER caller proves exact grant/current scope and cleanup."""
        self._locked()
        receipt=validate_observation(receipt,True)
        value=self.snapshot()
        if value['unconfirmed']:
            raise ValueError('Unconfirmed observation cannot complete')
        records={capability:value['capabilities'][capability]['active'] for capability in ('observation','release')}
        if all(record is None for record in records.values()):
            accepted=value['last_observation']
            if (accepted is not None and accepted['receipt']==receipt and
                    all(value['capabilities'][capability]['terminal']==accepted[capability] for capability in records)):
                return
            raise ValueError('Observation completion conflicts with durable metadata')
        self._observation_binding(records,receipt,terminal=False)
        accepted={'receipt':dict(receipt)}
        for capability,record in records.items():
            record.update(phase='succeeded',reason=None,cache_generation=receipt['cache_generation'],
                          finished_boottime_ms=receipt['released_boottime_ms'])
            operation(record)
            state=value['capabilities'][capability]
            state['terminal']=record;state['active']=None
            accepted[capability]=dict(record)
        value['last_observation']=accepted
        self._validate(value)
        self._save(value)

    def snapshot(self):
        self._ready()
        return self._decode_snapshot(self._read('initialized-epoch'),self._read('control.json'))

    def counter_snapshot(self):
        """Read one locked historical projection; never a reservation or seed."""
        self._locked()
        state=self.snapshot()
        capabilities=state['capabilities']
        if state['unconfirmed'] or any(capabilities[name]['active'] is not None for name in CAPABILITIES):
            raise ValueError('Helper counter snapshot unavailable')
        return {'schema_version':1,'root_epoch':state['epoch'],
                'refresh_high_water':capabilities['refresh']['high_water'],
                'observation_high_water':capabilities['observation']['high_water'],
                'release_high_water':capabilities['release']['high_water']}

    def _decode_snapshot(self, marker, raw):
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
            value = json.loads(raw, object_pairs_hook=unique)
            self._validate(value)
            if value['epoch'].encode('ascii') != marker:
                raise ValueError('Helper initialization identity mismatch')
            return value
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            raise ValueError('Malformed helper journal requires explicit recovery') from None

    def fence_external(self):
        """Fence after caller-observed external I/O/cleanup uncertainty.

        Preserve frozen terminals and receipts. A failed/unknown journal cannot
        be repaired here; no runtime method clears the durable global fence.
        Caller terminates rather than retrying possibly started work.
        """
        self._held_lock()
        self._launch_permits.clear()
        self._launch_epoch=object()
        if self._needs_reconciliation:
            return False
        try:
            value=self.snapshot()
            self._needs_reconciliation=True
            value['unconfirmed']=True
            for state in value['capabilities'].values():
                record=state['active']
                if record is not None and record['started_boottime_ms'] is not None:
                    record['phase']='unconfirmed'
            self._save(value)
            return True
        except BaseException:
            self._needs_reconciliation=True
            raise

    def startup_ready(self):
        self._held_lock()
        self._launch_permits.clear()
        self._launch_epoch=object()
        self._needs_reconciliation=True
        fd=None
        try:
            marker=self._read('initialized-epoch')
            fd=os.open('control.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
            raw,before=self._read_descriptor(fd)
            value=self._decode_snapshot(marker,raw)
            named=os.stat('control.json',dir_fd=self.fd,follow_symlinks=False)
            if metadata_identity(before)!=metadata_identity(named):
                raise ValueError('Helper control reference changed before durability barrier')
            os.fsync(fd)
            os.fsync(self.fd)
            after=self._check(fd)
            named=os.stat('control.json',dir_fd=self.fd,follow_symlinks=False)
            if (metadata_identity(before)!=metadata_identity(after) or
                    metadata_identity(after)!=metadata_identity(named) or self._read('initialized-epoch')!=marker):
                raise ValueError('Helper control reference changed during durability barrier')
        finally:
            if fd is not None:
                closing,fd=fd,None
                os.close(closing)
        self._needs_reconciliation=False
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
            if (active is None or active['started_boottime_ms'] is not None or
                    active['phase'] not in ['received','deferred'] or sequence <= state['high_water']):
                return 'busy'
            # A completed no-work decision remains byte-for-byte immutable.
            # Only an unacknowledged received record needs an abandonment outcome.
            if active['phase'] != 'deferred':
                active['phase'] = 'failed'
                active['reason'] = 'state_inconsistent'
                active['finished_boottime_ms'] = now if boot_id == active['boot_id'] and now >= active['accepted_boottime_ms'] else None
            state['terminal'] = active
        state['high_water'] = sequence
        state['active'] = {'correlator': incoming, 'helper_sequence': sequence,
            'boot_id': boot_id, 'accepted_boottime_ms': now, 'started_boottime_ms': None,
            'finished_boottime_ms': None, 'policy_generation': policy, 'cache_generation': None,
            'phase': 'received', 'reason': None, 'decision_boottime_ms': None}
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
        if record['started_boottime_ms'] is not None or record['decision_boottime_ms'] is not None:
            return False
        if record['phase'] != 'received':
            raise ValueError('Only a newly received helper attempt may start')
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
                record['decision_boottime_ms'] = now
                self._save(value)
                return False
        record['started_boottime_ms'] = now
        record['phase'] = 'running'
        record['reason'] = None
        value['capabilities'][capability]['last_started'] = {
            'correlator': incoming, 'helper_sequence': record['helper_sequence'],
            'boot_id': boot_id, 'started_boottime_ms': now}
        self._save(value)
        self._launch_permits.add((capability,incoming,boot_id,policy))
        return True

    def _consume_launch(self,capability,incoming,boot_id,policy):
        """Consume only a new-start permission in this held root lifecycle.

        Existing durable running metadata or a new Journal instance cannot mint
        this process-local permission. Startup reconciliation invalidates it.
        """
        self._locked()
        value=self.snapshot()
        permit=(capability,incoming,boot_id,policy)
        if value['unconfirmed'] or permit not in self._launch_permits:
            raise ValueError('Physical helper launch lacks a new one-use start')
        record=value['capabilities'][capability]['active']
        if (record is None or record['phase']!='running' or record['correlator']!=incoming or
                record['boot_id']!=boot_id or record['policy_generation']!=policy):
            raise ValueError('Physical helper launch does not match its new start')
        self._launch_permits.remove(permit)

    def defer(self, capability, incoming, boot_id, reason, *, now):
        self._locked()
        value = self.snapshot()
        if capability not in CAPABILITIES or type(reason) is not str or reason not in REASONS or value['unconfirmed']:
            raise ValueError('Invalid helper deferral')
        record = value['capabilities'][capability]['active']
        if (record is None or record['correlator'] != incoming or record['boot_id'] != boot_id or
                record['started_boottime_ms'] is not None or not safe_integer(now) or
                now < record['accepted_boottime_ms'] or record['phase'] not in ['received','deferred']):
            raise ValueError('Started or unknown work cannot be deferred and re-executed')
        if record['decision_boottime_ms'] is not None:
            return
        record['phase'] = 'deferred'
        record['reason'] = reason
        record['decision_boottime_ms'] = now
        self._save(value)

    def finish(self, capability, incoming, boot_id, now, phase, reason=None, cache=None, policy=None,
               *, successful_checked_at=None):
        """Caller must prove owned cgroup empty before publication or terminal success."""
        self._locked()
        value = self.snapshot()
        if (capability not in CAPABILITIES or phase not in ['succeeded', 'failed'] or
                reason is not None and reason not in REASONS):
            raise ValueError('Invalid helper terminal outcome')
        if capability in ('observation','release') and phase=='succeeded':
            raise ValueError('Observation success requires atomic receipt acceptance')
        refresh_success=capability=='refresh' and phase=='succeeded'
        if refresh_success:
            checked_timestamp(successful_checked_at)
        elif successful_checked_at is not None:
            raise ValueError('Only successful refresh records a cache success timestamp')
        state = value['capabilities'][capability]
        record = state['active']
        if phase == 'succeeded' and not hexadecimal(policy, 64):
            raise ValueError('Successful helper outcome requires its admitted publication policy')
        if record is None:
            terminal = state['terminal']
            if (terminal is not None and terminal['correlator'] == incoming and terminal['boot_id'] == boot_id and
                    terminal['phase'] == phase and terminal['reason'] == reason and terminal['cache_generation'] == cache and
                    (phase != 'succeeded' or terminal['policy_generation'] == policy) and
                    (not refresh_success or value['last_success']['successful_checked_at']==successful_checked_at)):
                return
            raise ValueError('Helper terminal outcome conflicts with durable metadata')
        if refresh_success and (value['unconfirmed'] or record['phase']!='running'):
            raise ValueError('Unconfirmed or unstarted refresh cannot complete successfully')
        if (record['correlator'] != incoming or record['boot_id'] != boot_id or
                record['decision_boottime_ms'] is not None or not safe_integer(now) or now < (record['started_boottime_ms'] or record['accepted_boottime_ms'])):
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
        if refresh_success:
            value['last_success']={'attempt':dict(record),'successful_checked_at':successful_checked_at}
        self._save(value)
