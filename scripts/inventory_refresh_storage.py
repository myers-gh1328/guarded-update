"""Descriptor-only generation storage; caller must prove containment before publish.

No executable entrypoint or caller-supplied policy/path interface exists here.
The fixed coordinator will admit the root cache FD and prove its worker cgroup
empty before calling publish. Native tests must prove UID separation and limits.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat

MAX_GENERATION = 128 * 1024 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
MAX_FILES = 8192
MANIFEST = '_inventory-manifest.json'
LEASE = '_inventory-lease'


def name(value):
    if type(value) is not str or not re.fullmatch('[A-Za-z0-9_%+~.:-]{1,255}', value) or value in ['.', '..']:
        raise ValueError('Invalid inventory cache entry')
    return value


def token(value):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{32}', value):
        raise ValueError('Invalid inventory generation identifier')
    return value


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def opened(parent, entry, owner, directory=False, limit=MAX_GENERATION):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(name(entry), flags, dir_fd=parent)
    except OSError:
        raise ValueError('Inventory cache entry could not be admitted') from None
    metadata = os.fstat(fd)
    parent_metadata = os.fstat(parent)
    if (metadata.st_uid != owner or metadata.st_dev != parent_metadata.st_dev or
            metadata.st_mode & 0o022 or
            (directory and not stat.S_ISDIR(metadata.st_mode)) or
            (not directory and (not stat.S_ISREG(metadata.st_mode) or
                                metadata.st_nlink != 1 or metadata.st_size > limit))):
        os.close(fd)
        raise ValueError('Inventory cache entry failed descriptor admission')
    return fd


def digest_fd(fd, limit):
    before = os.fstat(fd)
    digest = hashlib.sha256()
    count = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        count += len(chunk)
        if count > limit:
            raise ValueError('Inventory cache file exceeds bounds')
        digest.update(chunk)
    after = os.fstat(fd)
    if (count != before.st_size or before.st_nlink != 1 or after.st_nlink != 1 or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError('Inventory cache file changed during admission')
    return count, digest.hexdigest()


def read_json(parent, entry, owner, limit):
    fd = opened(parent, entry, owner, limit=limit)
    try:
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError('Inventory metadata exceeds bounds')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('Duplicate inventory metadata field')
                result[key] = value
            return result
        return json.loads(data, object_pairs_hook=unique), data
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError('Invalid inventory metadata') from None
    finally:
        os.close(fd)


class CacheReader:
    """Lease-only cache view; no worker identity or publication authority.

    The fixed OS adapter must admit the cache's full ancestry before passing its
    borrowed descriptor. This view never performs account/NSS lookups.
    """
    def __init__(self, cache_fd, *, owner=0):
        metadata = os.fstat(cache_fd)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != owner or
                metadata.st_mode & 0o022):
            raise ValueError('Inventory cache root is not admitted')
        self.fd = cache_fd
        self.uid = owner

    def _current(self):
        pointer, data = read_json(self.fd, 'current.json', self.uid, 65536)
        if (type(pointer) is not dict or
                set(pointer) != {'schema_version', 'cache_generation', 'manifest_sha256'} or
                pointer['schema_version'] != 1 or type(pointer['schema_version']) is not int or
                not re.fullmatch('[0-9a-f]{64}', str(pointer['manifest_sha256']))):
            raise ValueError('Invalid current inventory reference')
        token(pointer['cache_generation'])
        return pointer, data

    @contextmanager
    def lease_current(self):
        pointer, before = self._current()
        directory = opened(self.fd, 'generation-'+pointer['cache_generation'], self.uid, directory=True)
        lock = None
        try:
            lock = opened(directory, LEASE, self.uid, limit=0)
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Inventory generation lease unavailable') from None
            manifest, encoded = read_json(directory, MANIFEST, self.uid, MAX_MANIFEST)
            _, after = self._current()
            if (before != after or hashlib.sha256(encoded).hexdigest() != pointer['manifest_sha256'] or
                    manifest.get('cache_generation') != pointer['cache_generation']):
                raise ValueError('Inventory generation changed before lease admission')
            yield Lease(directory, manifest, self.uid)
        finally:
            if lock is not None:
                os.close(lock)
            os.close(directory)


class Store(CacheReader):
    def __init__(self, cache_fd, publisher_uid=0, reader_gid=0, worker_uid=None):
        super().__init__(cache_fd, owner=publisher_uid)
        if worker_uid is None:
            raise ValueError('Inventory cache worker identity is not admitted')
        self.gid = reader_gid
        self.worker = worker_uid

    def _new_file(self, parent, entry, data, limit, mode=0o440):
        if len(data) > limit:
            raise ValueError('Inventory publication exceeds bounds')
        fd = os.open(name(entry), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fchown(fd, self.uid, self.gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)

    def publish(self, staging_token, generation_token, policy, checked_at):
        token(staging_token)
        token(generation_token)
        if (type(policy) is not str or not re.fullmatch('[0-9a-f]{64}', policy) or
                type(checked_at) is not str or not re.fullmatch(
                    r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z', checked_at)):
            raise ValueError('Invalid inventory publication evidence')
        stage = opened(self.fd, 'staging-'+staging_token, self.worker, directory=True)
        directory = None
        try:
            directory = opened(stage, 'lists', self.worker, directory=True)
            manifest = {'schema_version': 1, 'cache_generation': generation_token,
                        'policy_generation': policy, 'successful_checked_at': checked_at, 'files': []}
            count = [0, 0]
            self._seal(directory, '', manifest['files'], count, 0)
            data = encode(manifest)
            self._new_file(directory, MANIFEST, data, MAX_MANIFEST)
            self._new_file(directory, LEASE, b'', 0)
            os.fchown(directory, self.uid, self.gid)
            os.fchmod(directory, 0o700)
            os.fsync(directory)
            destination = 'generation-'+generation_token
            try:
                os.stat(destination, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('Inventory generation already exists')
            os.rename('lists', destination, src_dir_fd=stage, dst_dir_fd=self.fd)
            os.fchmod(directory, 0o550)
            os.fsync(directory)
            os.fsync(stage)
            os.fsync(self.fd)
            pointer = encode({'schema_version': 1, 'cache_generation': generation_token,
                              'manifest_sha256': hashlib.sha256(data).hexdigest()})
            temporary = '.current-'+secrets.token_hex(16)
            self._new_file(self.fd, temporary, pointer, 65536)
            os.replace(temporary, 'current.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
            return manifest
        finally:
            if directory is not None:
                os.close(directory)
            os.close(stage)

    def _seal(self, directory, prefix, files, counts, depth):
        entries = sorted(os.listdir(directory))
        if depth > 4 or len(entries) > MAX_FILES:
            raise ValueError('Inventory generation exceeds traversal bounds')
        for entry in entries:
            name(entry)
            if entry in [MANIFEST, LEASE]:
                raise ValueError('Worker supplied reserved publication metadata')
            metadata = os.stat(entry, dir_fd=directory, follow_symlinks=False)
            is_directory = stat.S_ISDIR(metadata.st_mode)
            fd = opened(directory, entry, self.worker, directory=is_directory)
            try:
                counts[0] += 1
                if counts[0] > MAX_FILES:
                    raise ValueError('Inventory generation exceeds inode admission bounds')
                if is_directory:
                    self._seal(fd, prefix+entry+'/', files, counts, depth+1)
                    mode = 0o550
                else:
                    size, digest = digest_fd(fd, MAX_GENERATION-counts[1])
                    counts[1] += size
                    files.append({'path': prefix+entry, 'size': size, 'sha256': digest})
                    mode = 0o440
                os.fchown(fd, self.uid, self.gid)
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)

    def retire(self, generation_token):
        token(generation_token)
        pointer, _ = self._current()
        if pointer['cache_generation'] == generation_token:
            return False
        entry = 'generation-'+generation_token
        directory = opened(self.fd, entry, self.uid, directory=True)
        lock = None
        try:
            lock = opened(directory, LEASE, self.uid, limit=0)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            if self._current()[0]['cache_generation'] == generation_token:
                return False
            self._remove(directory, 0, [0])
            os.rmdir(entry, dir_fd=self.fd)
            os.fsync(self.fd)
            return True
        finally:
            if lock is not None:
                os.close(lock)
            os.close(directory)

    def _remove(self, directory, depth, count):
        if depth > 4:
            raise ValueError('Inventory retirement exceeds depth bound')
        os.fchmod(directory, 0o700)
        for entry in os.listdir(directory):
            count[0] += 1
            if count[0] > MAX_FILES+2:
                raise ValueError('Inventory retirement exceeds inode bound')
            metadata = os.stat(name(entry), dir_fd=directory, follow_symlinks=False)
            is_directory = stat.S_ISDIR(metadata.st_mode)
            fd = opened(directory, entry, self.uid, directory=is_directory)
            try:
                if is_directory:
                    self._remove(fd, depth+1, count)
                    os.rmdir(entry, dir_fd=directory)
                else:
                    os.unlink(entry, dir_fd=directory)
            finally:
                os.close(fd)


class Lease:
    def __init__(self, directory, manifest, owner):
        self.fd = directory
        self.manifest = manifest
        self.owner = owner

    def verify_index(self, relative):
        with self._index(relative, MAX_GENERATION) as (fd, record):
            count, digest = digest_fd(fd, MAX_GENERATION)
            if count != record['size'] or digest != record['sha256']:
                raise ValueError('Inventory index failed manifest verification')
            return count, digest

    @contextmanager
    def _index(self, relative, limit):
        parts = relative.split('/')
        for part in parts:
            name(part)
        records = [row for row in self.manifest['files'] if row['path'] == relative]
        if len(records) != 1 or records[0]['size'] > limit:
            raise ValueError('Inventory index is missing or exceeds read bound')
        directory = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                child = opened(directory, part, self.owner, directory=True)
                os.close(directory)
                directory = child
            fd = opened(directory, parts[-1], self.owner, limit=limit)
            try:
                yield fd, records[0]
            finally:
                os.close(fd)
        finally:
            os.close(directory)

    def read_index(self, relative, limit=1024*1024):
        with self._index(relative, limit) as (fd, record):
            chunks = bytearray()
            while True:
                chunk = os.read(fd, min(65536, limit+1-len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > limit:
                    raise ValueError('Inventory index exceeds read bound')
            data = bytes(chunks)
            if (len(data) != record['size'] or
                    hashlib.sha256(data).hexdigest() != record['sha256']):
                raise ValueError('Inventory index failed manifest verification')
            return data
