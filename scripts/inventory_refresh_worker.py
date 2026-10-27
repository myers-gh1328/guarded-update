#!/usr/bin/python3
"""Fixed low-privilege APT metadata worker. No command/path/options interface.

Installed source is root-owned; systemd starts it as ccrefresh in its dedicated
contained worker slice. The root coordinator owns admission and publication.
"""
import hashlib
import json
import os
from pathlib import PurePosixPath
import pwd
import re
import stat
import subprocess
import sys

POLICY_ROOT = '/etc/command-center-inventory-refresh'
CACHE_ROOT = '/var/cache/command-center-inventory-refresh'
RUNTIME_ROOT = '/run/command-center-inventory-refresh'
REFRESH_ACCOUNT = 'ccrefresh'
REPORTER_ACCOUNT = 'ccinventory'
APT_COMMAND = ('/usr/bin/apt-get', 'update')
EXIT_UNSUPPORTED = 74
EXIT_REPOSITORY = 75
EXIT_TIMEOUT = 76
MAX_SAFE = 9_007_199_254_740_991
LIMIT = 65536


def invalid():
    return ValueError('Unsupported fixed inventory refresh worker state')


def _hex(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None


def _integer(value):
    return type(value) is int and 0 <= value <= MAX_SAFE


def parse_job(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= LIMIT:
        raise invalid()
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise invalid()
            result[name] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise invalid() from None
    fields = {'schema_version', 'staging_token', 'config_sha256', 'policy_generation',
              'operation_nonce', 'helper_sequence', 'boot_id',
              'accepted_boottime_ms', 'started_boottime_ms'}
    if (type(value) is not dict or set(value) != fields or
            type(value['schema_version']) is not int or value['schema_version'] != 1 or
            not _hex(value['staging_token'], 32) or not _hex(value['config_sha256'], 64) or
            not _hex(value['policy_generation'], 64) or not _hex(value['operation_nonce'], 32) or
            not _integer(value['helper_sequence']) or value['helper_sequence'] == 0 or
            int(value['operation_nonce'][:16], 16) != value['helper_sequence'] or
            type(value['boot_id']) is not str or not re.fullmatch(
                '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value['boot_id']) or
            not _integer(value['accepted_boottime_ms']) or not _integer(value['started_boottime_ms']) or
            value['started_boottime_ms'] < value['accepted_boottime_ms']):
        raise invalid()
    return value


def worker_environment(staging_token):
    if not _hex(staging_token, 32):
        raise invalid()
    temporary = CACHE_ROOT+'/staging-'+staging_token+'/tmp'
    return {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
            'APT_CONFIG': RUNTIME_ROOT+'/worker-apt.conf', 'TMPDIR': temporary,
            'HOME': temporary, 'DO_NOT_TRACK': '1'}


def root_directory(path):
    """Admit fixed root ancestry by FD, including root-controlled mount boundaries."""
    parsed = PurePosixPath(path)
    if not parsed.is_absolute() or str(parsed) != path or '..' in parsed.parts:
        raise invalid()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parsed.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            os.close(fd)
            fd = child
            metadata = os.fstat(fd)
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise invalid()
        return fd
    except BaseException:
        os.close(fd)
        raise


def root_file(path, group):
    parsed = PurePosixPath(path)
    directory = root_directory(str(parsed.parent))
    fd = None
    try:
        fd = os.open(parsed.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != group or
                metadata.st_mode & 0o137 or metadata.st_nlink != 1 or metadata.st_size > LIMIT):
            raise invalid()
        data = bytearray()
        while len(data) <= LIMIT:
            chunk = os.read(fd, min(65536, LIMIT+1-len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if (len(data) != metadata.st_size or
                (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_nlink) !=
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink)):
            raise invalid()
        return bytes(data)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def stage_ready(token, user):
    parent = root_directory(CACHE_ROOT)
    stage = None
    try:
        stage = os.open('staging-'+token, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        metadata = os.fstat(stage)
        if (metadata.st_uid != user.pw_uid or metadata.st_mode & 0o077 or
                metadata.st_dev != os.fstat(parent).st_dev):
            raise invalid()
        for entry in ['lists', 'tmp', 'cache', 'archives', 'log']:
            fd = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=stage)
            try:
                value = os.fstat(fd)
                if (value.st_uid != user.pw_uid or value.st_mode & 0o022 or
                        value.st_dev != metadata.st_dev):
                    raise invalid()
            finally:
                os.close(fd)
    finally:
        if stage is not None:
            os.close(stage)
        os.close(parent)


def worker_main():
    try:
        user = pwd.getpwnam(REFRESH_ACCOUNT)
        reporter = pwd.getpwnam(REPORTER_ACCOUNT)
        if (user.pw_uid <= 0 or user.pw_gid <= 0 or reporter.pw_uid <= 0 or reporter.pw_gid <= 0 or
                user.pw_uid == reporter.pw_uid or user.pw_gid == reporter.pw_gid or
                user.pw_gid in os.getgrouplist(REPORTER_ACCOUNT, reporter.pw_gid) or os.geteuid() != user.pw_uid or os.getegid() != user.pw_gid or
                set(os.getgroups()) - {user.pw_gid}):
            return EXIT_UNSUPPORTED
        if (not hasattr(os, 'getresuid') or not hasattr(os, 'getresgid') or
                os.getresuid() != (user.pw_uid,)*3 or os.getresgid() != (user.pw_gid,)*3):
            return EXIT_UNSUPPORTED
        job = parse_job(root_file(RUNTIME_ROOT+'/job.json', user.pw_gid))
        config = root_file(RUNTIME_ROOT+'/worker-apt.conf', user.pw_gid)
        if hashlib.sha256(config).hexdigest() != job['config_sha256']:
            return EXIT_UNSUPPORTED
        with open('/proc/sys/kernel/random/boot_id', 'r', encoding='ascii') as source:
            if source.read(64).strip() != job['boot_id']:
                return EXIT_UNSUPPORTED
        stage_ready(job['staging_token'], user)
        result = subprocess.run(APT_COMMAND, env=worker_environment(job['staging_token']),
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=570, check=False)
        return 0 if result.returncode == 0 else EXIT_REPOSITORY
    except subprocess.TimeoutExpired:
        # Root coordinator must still stop/prove the entire owned cgroup empty.
        return EXIT_TIMEOUT
    except (OSError, ValueError, KeyError):
        return EXIT_UNSUPPORTED


if __name__ == '__main__':
    raise SystemExit(worker_main() if len(sys.argv) == 1 else EXIT_UNSUPPORTED)
