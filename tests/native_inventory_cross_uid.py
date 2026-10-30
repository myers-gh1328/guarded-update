#!/usr/bin/env python3
"""Disposable cross-UID fixture; no production authentication or start authority."""
import json
import os
import re
import stat
import math
import select
import subprocess
import fcntl
import grp
import pwd
import secrets
import sys
import time
from pathlib import Path
from inventory_refresh_cgroup_witness import observe_empty

ERROR = 'Synthetic cross-UID fixture unavailable'
BINDING = {
    'schema_version': 1,
    'epoch': 'a' * 32,
    'enrollment': '00000000-0000-4000-8000-000000000001',
    'nonce': '0000000000000008' + 'd' * 16,
    'policy': 'b' * 64,
}
UNIT_PROPERTIES = ('LoadState', 'ActiveState', 'Description', 'InvocationID', 'ControlGroup',
                   'MainPID', 'Result', 'ExecMainCode', 'ExecMainStatus', 'Delegate',
                   'ProtectControlGroups', 'MemoryPressureWatch')
UNIT = 'command-center-inventory.service'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}


class PinError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(ERROR)


def unit_pin_decision(status, exit_code, expected_group, deadline):
    if time.monotonic() >= deadline: raise PinError('unit_pin_deadline')
    if status['LoadState'] not in ('not-found', 'loaded'): raise PinError('unit_pin_load')
    group = status['ControlGroup']
    if group and group != expected_group: raise PinError('unit_pin_cgroup')
    if status['LoadState'] == 'loaded' and status['InvocationID'] and group == expected_group:
        return 'ready'
    if exit_code is not None: raise PinError('unit_pin_exited')
    return 'wait'


def account_command(kind, deadline):
    commands = {
        'group': ['/usr/sbin/groupadd', '--system', '--gid', '60002', 'ccinventory'],
        'user': ['/usr/sbin/useradd', '--system', '--uid', '60002', '--gid', 'ccinventory',
                 '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', 'ccinventory'],
    }
    if kind not in commands or time.monotonic() >= deadline: raise ValueError(ERROR)
    child = subprocess.Popen(commands[kind], env=ENV, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or child.wait(timeout=remaining) != 0 or time.monotonic() >= deadline:
            raise ValueError(ERROR)
    except BaseException:
        # The direct Root child may still exist; never signal it or infer cleanup.
        raise ValueError(ERROR) from None


def create_account(deadline):
    for query, value in ((pwd.getpwnam, 'ccinventory'), (pwd.getpwuid, 60002),
                         (grp.getgrnam, 'ccinventory'), (grp.getgrgid, 60002)):
        try: query(value)
        except KeyError: pass
        else: raise ValueError(ERROR)
    account_command('group', deadline)
    account_command('user', deadline)
    account = pwd.getpwnam('ccinventory')
    group = grp.getgrnam('ccinventory')
    if (account.pw_uid, account.pw_gid, group.gr_gid) != (60002, 60002, 60002): raise ValueError(ERROR)


def parse_unit_status(raw):
    if type(raw) is not bytes or len(raw) > 4096: raise ValueError(ERROR)
    try:
        result = {}
        for line in raw.decode('ascii').splitlines():
            name, separator, value = line.partition('=')
            if not separator or name not in UNIT_PROPERTIES or name in result: raise ValueError(ERROR)
            result[name] = value
        if set(result) != set(UNIT_PROPERTIES): raise ValueError(ERROR)
        return result
    except (UnicodeDecodeError, ValueError):
        raise ValueError(ERROR) from None


def validate_live_identity(status, description, group, invocation=None, pid=None):
    try:
        current = status['InvocationID']
        process = status['MainPID']
        if status['LoadState'] != 'loaded': raise PinError('unit_identity_load')
        active = status['ActiveState']
        if active != 'active':
            category = active if active in ('activating', 'inactive', 'failed', 'deactivating') else 'other'
            raise PinError('unit_identity_active_' + category)
        if status['Description'] != description: raise PinError('unit_identity_description')
        if status['ControlGroup'] != group: raise PinError('unit_identity_cgroup')
        if not re.fullmatch('[0-9a-f]{32}', current) or (invocation is not None and current != invocation):
            raise PinError('unit_identity_invocation')
        if not re.fullmatch('[1-9][0-9]{0,9}', process) or (pid is not None and process != str(pid)):
            raise PinError('unit_identity_pid')
        if status['Delegate'] != 'no': raise PinError('unit_identity_delegate')
        if status['ProtectControlGroups'] != 'yes': raise PinError('unit_identity_protect')
        if status['MemoryPressureWatch'] != 'off': raise PinError('unit_identity_pressure')
        return current, int(process)
    except PinError:
        raise
    except (KeyError, TypeError, ValueError):
        raise PinError('unit_identity_fields') from None


def validate_test_output(raw):
    if type(raw) is not bytes or len(raw) > 8192: raise ValueError(ERROR)
    try:
        lines = [line for line in raw.decode('ascii').splitlines() if line]
        if (len(lines) != 3 or lines[0] != 'running 1 test' or
            lines[1] != 'test inventory::reporter_obs::tests::hosted_cross_uid_counter_admission ... ok' or
            not re.fullmatch(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s', lines[2])):
            raise ValueError(ERROR)
    except (UnicodeDecodeError, ValueError):
        raise ValueError(ERROR) from None


def verify_endpoints(endpoints):
    for stream, direction, identity in endpoints:
        info = os.fstat(stream.fileno())
        flags = fcntl.fcntl(stream.fileno(), fcntl.F_GETFL)
        if (not stat.S_ISFIFO(info.st_mode) or (info.st_dev, info.st_ino) != identity or
            flags & (os.O_ACCMODE | os.O_NONBLOCK) != direction | os.O_NONBLOCK):
            raise ValueError(ERROR)


def read_marker(fd, deadline, verify=lambda: None):
    marker = b'INVENTORY-BARRIER-1\n'
    data = bytearray()
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while len(data) < len(marker):
        verify()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not poller.poll(max(1, int(remaining * 1000))): raise ValueError(ERROR)
        try: chunk = os.read(fd, len(marker) + 1 - len(data))
        except BlockingIOError: continue
        if not chunk or time.monotonic() >= deadline: raise ValueError(ERROR)
        data.extend(chunk)
        if not marker.startswith(data): raise ValueError(ERROR)
        verify()
    return bytes(data)


def write_ack(fd, deadline, verify=lambda: None):
    data = b'ACK-1\n'
    offset = 0
    poller = select.poll()
    poller.register(fd, select.POLLOUT | select.POLLHUP | select.POLLERR)
    while offset < len(data):
        verify()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not poller.poll(max(1, int(remaining * 1000))): raise ValueError(ERROR)
        try: count = os.write(fd, data[offset:])
        except BlockingIOError: continue
        if count <= 0 or count > len(data) - offset or time.monotonic() >= deadline: raise ValueError(ERROR)
        offset += count
        verify()


def empty_group(parent, name, group, deadline):
    observe_empty(parent, name, group, deadline)
    try:
        entries = os.listdir(group)
        if len(entries) > 512: raise ValueError(ERROR)
        for entry in entries:
            if time.monotonic() >= deadline: raise ValueError(ERROR)
            info = os.stat(entry, dir_fd=group, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode): raise ValueError(ERROR)
        observe_empty(parent, name, group, deadline)
    except (OSError, ValueError):
        raise ValueError(ERROR) from None


def read_completion(stdout, stderr, deadline, verify=lambda: None):
    """Read both pipes concurrently; stderr must have no bytes after the marker."""
    poller = select.poll()
    fds = {stdout: bytearray(), stderr: bytearray()}
    for fd in fds: poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    remaining_fds = set(fds)
    while remaining_fds:
        verify()
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise ValueError(ERROR)
        events = poller.poll(max(1, int(remaining * 1000)))
        if not events: raise ValueError(ERROR)
        for fd, _ in events:
            if fd not in remaining_fds: raise ValueError(ERROR)
            try: chunk = os.read(fd, (8193 if fd == stdout else 1) - len(fds[fd]))
            except BlockingIOError: continue
            if time.monotonic() >= deadline: raise ValueError(ERROR)
            if not chunk:
                remaining_fds.remove(fd)
                poller.unregister(fd)
            else:
                fds[fd].extend(chunk)
                if len(fds[fd]) > (8192 if fd == stdout else 0): raise ValueError(ERROR)
            verify()
    return bytes(fds[stdout])


def unit_status(deadline):
    """Bounded fixed systemctl query; timeout never signals its Root child."""
    child = None
    failed = False
    raw = bytearray()
    try:
        if time.monotonic() >= deadline: raise ValueError(ERROR)
        child = subprocess.Popen(['/bin/systemctl', 'show', '--property=' + ','.join(UNIT_PROPERTIES), UNIT],
            env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        fd = child.stdout.fileno()
        os.set_blocking(fd, False)
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not poller.poll(max(1, int(remaining * 1000))): raise ValueError(ERROR)
            try: chunk = os.read(fd, 4097 - len(raw))
            except BlockingIOError: continue
            if time.monotonic() >= deadline: raise ValueError(ERROR)
            if not chunk: break
            raw.extend(chunk)
            if len(raw) > 4096: raise ValueError(ERROR)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or child.wait(timeout=remaining) not in (0, 4): raise ValueError(ERROR)
    except BaseException:
        failed = True
    finally:
        if child is not None:
            try: child.stdout.close()
            except BaseException: failed = True
    if failed or time.monotonic() >= deadline: raise ValueError(ERROR)
    return parse_unit_status(bytes(raw))


def accept_after_marker(marker, fixture, journal, inbox):
    """Synthetic-only coordinator admission; no start or caller authentication."""
    if marker != b'INVENTORY-BARRIER-1\n': raise ValueError(ERROR)
    fixture.verify()
    if inbox.read() != (BINDING['nonce'], 8): raise ValueError(ERROR)
    if journal.admit_counter_proposal(BINDING['epoch'], 'observation', BINDING['nonce'],
        BINDING['enrollment'], 1001, BINDING['policy']) != 'new': raise ValueError(ERROR)
    active = journal.snapshot()['capabilities']['observation']['active']
    if (type(active) is not dict or active.get('correlator') != BINDING['nonce'] or
        active.get('phase') != 'received' or active.get('started_boottime_ms') is not None):
        raise ValueError(ERROR)
    fixture.verify()


def parse_binding(raw):
    """Validate fixed fixture bytes only; this is not an authenticated binding."""
    if type(raw) is not bytes or len(raw) > 1024:
        raise ValueError(ERROR)
    expected = json.dumps(BINDING, separators=(',', ':')).encode('ascii')
    if raw != expected:
        raise ValueError(ERROR)
    return dict(BINDING)


def ensure_libexec(parent, owner, deadline):
    """Admit or exclusively create libexec under a caller-pinned parent."""
    child = None
    failed = False
    try:
        if type(owner) is not int or type(deadline) not in (float, int) or not math.isfinite(deadline) or time.monotonic() >= deadline:
            raise ValueError(ERROR)
        before = os.fstat(parent)
        identity = (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid)
        if not stat.S_ISDIR(before.st_mode) or before.st_uid != owner or before.st_mode & 0o022: raise ValueError(ERROR)
        try:
            os.stat('libexec', dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            os.mkdir('libexec', 0o755, dir_fd=parent)
            if time.monotonic() >= deadline: raise ValueError(ERROR)
            os.fsync(parent)
        child = os.open('libexec', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        held = os.fstat(child)
        named = os.stat('libexec', dir_fd=parent, follow_symlinks=False)
        after = os.fstat(parent)
        if (not stat.S_ISDIR(held.st_mode) or held.st_uid != owner or held.st_mode & 0o022 or
            (held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid) !=
            (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid) or
            (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid) != identity):
            raise ValueError(ERROR)
    except BaseException:
        failed = True
    finally:
        if child is not None:
            try: os.close(child)
            except OSError: failed = True
    if failed or time.monotonic() >= deadline: raise ValueError(ERROR)


class Fixture:
    """Exclusive borrowed-parent fixture; all filesystem contents are retained.

    The caller must independently pin the parent ancestry and exclude mutation.
    These sampled checks do not authenticate a binding or prove process cleanup.
    """
    NAME = 'command-center-inventory-cas-fixture'

    @classmethod
    def create(cls, parent, owner, group, deadline):
        value = cls()
        value._fds = []
        value._refs = []
        value._closed = False
        value._close_failed = False
        try:
            if (type(owner) is not int or type(group) is not int or os.geteuid() != owner or
                type(deadline) not in (float, int) or not math.isfinite(deadline) or time.monotonic() >= deadline):
                raise ValueError(ERROR)
            value._deadline = deadline
            value._owner, value._group = owner, group
            base = os.dup(parent)
            value._fds.append(base)
            info = os.fstat(base)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
                raise ValueError(ERROR)
            value._base_identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            os.mkdir(cls.NAME, 0o755, dir_fd=base)
            value._time()
            root = os.open(cls.NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base)
            value._fds.append(root)
            os.fchmod(root, 0o755)
            value._refs.append((base, cls.NAME, root, 0o755, owner, os.getegid()))
            for name, mode, gid in [('observation', 0o770, group), ('state', 0o700, os.getegid())]:
                os.mkdir(name, mode, dir_fd=root)
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
                value._fds.append(fd)
                os.fchown(fd, owner, gid)
                os.fchmod(fd, mode)
                value._refs.append((root, name, fd, mode, owner, gid))
                setattr(value, name, fd)
                os.fsync(fd)
                value._time()
            raw = json.dumps(BINDING, separators=(',', ':')).encode('ascii')
            fd = os.open('binding.json', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
            value._fds.append(fd)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0: raise ValueError(ERROR)
                offset += written
            os.fsync(fd)
            value._time()
            value._binding = fd
            value._root = root
            value.root = root
            value._binding_metadata = value._metadata(os.fstat(fd))
            os.fsync(root)
            os.fsync(base)
            value._time()
            value.verify()
            return value
        except BaseException:
            try: value.close()
            except BaseException: pass
            raise ValueError(ERROR) from None

    def verify(self):
        if self._closed: raise ValueError(ERROR)
        self._time()
        self._dirs()
        before = os.fstat(self._binding)
        named = os.stat('binding.json', dir_fd=self._root, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != self._owner or before.st_gid != os.getegid() or
            stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > 1024 or
            before.st_dev != os.fstat(self._root).st_dev or
            self._metadata(before) != self._binding_metadata or self._metadata(named) != self._binding_metadata):
            raise ValueError(ERROR)
        os.lseek(self._binding, 0, os.SEEK_SET)
        data = bytearray()
        while len(data) <= 1024:
            chunk = os.read(self._binding, 1025 - len(data))
            if not chunk: break
            data.extend(chunk)
        parse_binding(bytes(data))
        if (self._metadata(os.fstat(self._binding)) != self._binding_metadata or
            self._metadata(os.stat('binding.json', dir_fd=self._root, follow_symlinks=False)) != self._binding_metadata):
            raise ValueError(ERROR)
        self._dirs()
        self._time()

    def _dirs(self):
        info = os.fstat(self._fds[0])
        if (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) != self._base_identity:
            raise ValueError(ERROR)
        for parent, name, fd, mode, uid, gid in self._refs:
            held, named = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISDIR(held.st_mode) or stat.S_IMODE(held.st_mode) != mode or
                (held.st_uid, held.st_gid) != (uid, gid) or
                (held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid) !=
                (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid)):
                raise ValueError(ERROR)
    def _time(self):
        if time.monotonic() >= self._deadline: raise ValueError(ERROR)

    @staticmethod
    def _metadata(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def close(self):
        if self._closed:
            if self._close_failed: raise ValueError(ERROR)
            return
        self._closed = True
        for fd in reversed(self._fds):
            try: os.close(fd)
            except OSError: self._close_failed = True
        self._fds = []
        deadline = getattr(self, '_deadline', None)
        if deadline is not None and time.monotonic() >= deadline: self._close_failed = True
        if self._close_failed: raise ValueError(ERROR)


def run(archive):
    """Dedicated hosted test only. No production IPC, start or cleanup authority."""
    if sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError(ERROR)
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / 'scripts'))
    from inventory_refresh_artifact_fixture import verify_archive
    from inventory_refresh_rust_native_admission import RunnerArtifact
    from inventory_refresh_rust_parent_fixture import FixtureBinary
    from inventory_refresh_resources import _Chain
    from inventory_refresh_process_snapshot import ProcessProbe
    from inventory_refresh_cgroup_witness import observe_single_process
    from inventory_refresh_state import Journal
    from inventory_refresh_io import Inbox

    deadline = time.monotonic() + 60
    parent_chain = group_chain = fixture = artifact = binary = journal = inbox = probe = launcher = None
    failed = False
    completed = False
    stage = 'unit_status'
    try:
        if unit_status(min(deadline, time.monotonic() + 3))['LoadState'] != 'not-found': raise ValueError(ERROR)
        stage = 'account'
        create_account(deadline)
        stage = 'archive'
        verified = verify_archive(root, archive)
        stage = 'artifact'
        artifact = RunnerArtifact.fixed(verified['source_commit'], deadline)
        stage = 'libexec'
        libexec_parent = _Chain(('usr', 'local'))
        try:
            libexec_parent.verify()
            ensure_libexec(libexec_parent.fds[-1], 0, deadline)
            libexec_parent.verify()
        finally:
            libexec_parent.close()
        stage = 'binary_constructor'
        binary = FixtureBinary.fixed(artifact)
        stage = 'binary_publish'
        binary.publish()
        stage = 'binary_verify'
        binary.verify_published()
        stage = 'fixture'
        parent_chain = _Chain(('run',))
        parent_chain.verify()
        fixture = Fixture.create(parent_chain.fds[-1], 0, 60002, deadline)
        parent_chain.verify()
        stage = 'journal'
        journal = Journal(fixture.state)
        inbox = Inbox(fixture.root, 'observation', 60002, 60002)
        description = 'Synthetic cross-UID inventory CAS ' + secrets.token_hex(16)
        expected_group = '/command.slice/command-center.slice/command-center-inventory.slice/' + UNIT
        with journal.exclusive():
            journal.initialize(BINDING['epoch'])
            state = journal.snapshot()
            state['capabilities']['observation']['high_water'] = 7
            state['capabilities']['release']['high_water'] = 7
            journal._save(state)
            args = ['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--unit=' + UNIT,
                '--slice=command-center-inventory.slice', '--description=' + description,
                '--setenv=GUARDED_UPDATE_CROSS_UID_PROOF=1']
            for item in ('User=60002', 'Group=60002', 'Type=exec', 'Restart=no', 'RemainAfterExit=no',
                'RuntimeMaxSec=20', 'TasksMax=8', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=',
                'AmbientCapabilities=', 'ProtectSystem=strict', 'ProtectHome=yes', 'ProtectControlGroups=yes',
                'ProtectKernelTunables=yes', 'PrivateDevices=yes', 'PrivateTmp=yes', 'PrivateNetwork=yes',
                'Delegate=no', 'ReadOnlyPaths=/sys/fs/cgroup', 'MountFlags=private', 'MemoryPressureWatch=off',
                'ReadWritePaths=/run/command-center-inventory-cas-fixture/observation'):
                args += ['-p', item]
            args += ['/usr/local/libexec/command-center-inventory', '--exact',
                'inventory::reporter_obs::tests::hosted_cross_uid_counter_admission', '--ignored',
                '--test-threads=1', '--nocapture']
            artifact.verify(); binary.verify_published(); fixture.verify(); parent_chain.verify()
            if time.monotonic() >= deadline: raise ValueError(ERROR)
            stage = 'launch'
            launcher = subprocess.Popen(args, env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            endpoints = ((launcher.stdin, os.O_WRONLY), (launcher.stdout, os.O_RDONLY), (launcher.stderr, os.O_RDONLY))
            identities = []
            for stream, direction in endpoints:
                info = os.fstat(stream.fileno())
                flags = fcntl.fcntl(stream.fileno(), fcntl.F_GETFL)
                if not stat.S_ISFIFO(info.st_mode) or flags & os.O_ACCMODE != direction: raise ValueError(ERROR)
                identities.append((info.st_dev, info.st_ino))
            if len(set(identities)) != 3: raise ValueError(ERROR)
            for stream, _ in endpoints: os.set_blocking(stream.fileno(), False)
            verified_endpoints = tuple((stream, direction, identity) for (stream, direction), identity in zip(endpoints, identities))
            verify_endpoints(verified_endpoints)
            stage = 'unit_pin_query'
            while True:
                status = unit_status(min(deadline, time.monotonic() + 3))
                try: decision = unit_pin_decision(status, launcher.poll(), expected_group, deadline)
                except PinError as error:
                    stage = error.reason
                    raise
                if decision == 'ready': break
                time.sleep(.02)
            stage = 'unit_pin_identity'
            try: invocation, pid = validate_live_identity(status, description, expected_group)
            except PinError as error:
                stage = error.reason
                raise
            stage = 'group_pin'
            group_chain = _Chain(('sys', 'fs', 'cgroup', 'command.slice', 'command-center.slice',
                'command-center-inventory.slice', UNIT))
            group_chain.verify()
            held = os.fstat(group_chain.fds[-1])
            probe = ProcessProbe.fixed(pid, (os.major(held.st_dev), os.minor(held.st_dev)), deadline)
            stage = 'marker'
            marker = read_marker(launcher.stderr.fileno(), deadline, lambda: verify_endpoints(verified_endpoints))
            stage = 'process_sample'
            start = probe.sample()
            observe_single_process(group_chain.fds[-2], UNIT, group_chain.fds[-1], pid, deadline)
            fixture.verify(); parent_chain.verify(); group_chain.verify()
            stage = 'cas'
            accept_after_marker(marker, fixture, journal, inbox)
            stage = 'process_recheck'
            if probe.sample() != start: raise ValueError(ERROR)
            observe_single_process(group_chain.fds[-2], UNIT, group_chain.fds[-1], pid, deadline)
            again = unit_status(min(deadline, time.monotonic() + 3))
            validate_live_identity(again, description, expected_group, invocation, pid)
            fixture.verify(); parent_chain.verify(); group_chain.verify()
            probe.close(); probe = None
            stage = 'ack'
            write_ack(launcher.stdin.fileno(), deadline, lambda: verify_endpoints(verified_endpoints))
            launcher.stdin.close(); launcher.stdin = None
            stage = 'completion'
            output = read_completion(launcher.stdout.fileno(), launcher.stderr.fileno(), deadline,
                lambda: verify_endpoints(verified_endpoints[1:]))
            remaining = deadline - time.monotonic()
            if remaining <= 0 or launcher.wait(timeout=remaining) != 0: raise ValueError(ERROR)
            validate_test_output(output)
            stage = 'unit_final'
            final = unit_status(min(deadline, time.monotonic() + 3))
            if (final['Description'] != description or final['InvocationID'] != invocation or
                final['ActiveState'] not in ('inactive', 'failed') or final['Result'] != 'success' or
                final['ExecMainCode'] != '1' or final['ExecMainStatus'] != '0'): raise ValueError(ERROR)
            stage = 'group_empty'
            group_chain.verify()
            empty_group(group_chain.fds[-2], UNIT, group_chain.fds[-1], deadline)
            fixture.verify(); parent_chain.verify(); artifact.verify(); binary.verify_published()
            completed = True
    except BaseException:
        failed = True
    finally:
        if completed: stage = 'cleanup'
        if launcher is not None:
            for stream in (launcher.stdin, launcher.stdout, launcher.stderr):
                if stream is not None:
                    try: stream.close()
                    except BaseException: failed = True
        for owned in (probe, inbox, group_chain, fixture, parent_chain, binary, artifact):
            if owned is not None:
                try: owned.close()
                except BaseException: failed = True
    if failed or not completed or time.monotonic() >= deadline:
        print('Synthetic cross-UID stage=' + stage, file=sys.stderr)
        raise ValueError(ERROR)
    return {'synthetic_cross_uid_journal_cas_received_unstarted': True,
            'production_authority': False, 'all_producer_cleanup_proven': False}


if __name__ == '__main__':
    if len(sys.argv) != 2: raise SystemExit(ERROR)
    print(json.dumps(run(sys.argv[1]), sort_keys=True))
