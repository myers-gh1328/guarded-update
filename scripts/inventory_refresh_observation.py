"""Fixed Linux native observation primitives; no executable request interface.

The root coordinator must independently enforce its deadline and own immutable
cache leases, durable journal/status and containment before activation.
"""
from dataclasses import dataclass
import fcntl
import hashlib
import re
import os
import stat
import sys
import threading

_NATIVE_OWNER = threading.Lock()
MAX_STATE_BYTES = 64*1024*1024
MAX_STATE_FILES = 4096
MAX_SAFE = 9_007_199_254_740_991


def _deadline(deadline, now):
    current = now()
    if type(deadline) is not int or type(current) is not int or not 0 <= current <= deadline <= MAX_SAFE:
        raise ObservationError('lease_expired')
    return current


def _before_deadline(deadline, now):
    if deadline is None:
        return
    if not callable(now):
        raise ObservationError('state_inconsistent')
    try:
        current=_deadline(deadline,now)
    except ObservationError:
        raise
    except Exception:
        raise ObservationError('state_inconsistent') from None
    if current>=deadline:
        raise ObservationError('lease_expired')


def _stable(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _frame(digest, value):
    digest.update(len(value).to_bytes(8, 'big'))
    digest.update(value)


class ObservationError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__('Native inventory observation unavailable: '+reason)


def _directory(fd, owner):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise ObservationError('state_inconsistent')
    return info


def _file(fd, owner):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
            info.st_mode & 0o022 or info.st_nlink != 1):
        raise ObservationError('state_inconsistent')
    return info


def _identity(info):
    return info.st_dev, info.st_ino


def installed_fingerprint(directory,owner,deadline_ms,now):
    """Bounded data hash only; no lock ownership, freshness or attestation.

    Borrowed directory remains caller-owned. Eligibility additionally requires
    the actual root observation/lease/clock and matching final root receipt.
    """
    _deadline(deadline_ms, now)
    before = _directory(directory, owner)
    digest = hashlib.sha256(b'command-center-native-dpkg-state-v1\x00')
    remaining = [MAX_STATE_BYTES]
    try:
        _fingerprint_file(directory, 'status', 'status', digest, remaining, deadline_ms, now, owner)
        try:
            os.stat('arch', dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            _frame(digest, b'arch')
            _frame(digest, b'absent')
        else:
            _fingerprint_file(directory, 'arch', 'arch', digest, remaining, deadline_ms, now, owner)
        updates = os.open('updates', os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=directory)
        try:
            updates_before = _directory(updates, owner)
            entries = []
            with os.scandir(updates) as iterator:
                for entry in iterator:
                    _deadline(deadline_ms, now)
                    if len(entries) >= MAX_STATE_FILES:
                        raise ObservationError('resource_limit')
                    if re.fullmatch('[0-9]{4}', entry.name) is None:
                        raise ObservationError('state_inconsistent')
                    entries.append(entry.name)
            entries.sort()
            _frame(digest, b'updates')
            _frame(digest, b'directory')
            _frame(digest, len(entries).to_bytes(8, 'big'))
            for name in entries:
                _deadline(deadline_ms, now)
                _fingerprint_file(updates, name, 'updates/'+name, digest, remaining, deadline_ms, now, owner)
            if (_stable(updates_before)!=_stable(os.fstat(updates)) or
                    _identity(os.stat('updates',dir_fd=directory,follow_symlinks=False))!=_identity(updates_before)):
                raise ObservationError('state_inconsistent')
        finally:
            os.close(updates)
        if _stable(before)!=_stable(os.fstat(directory)):
            raise ObservationError('state_inconsistent')
        _deadline(deadline_ms, now)
        return digest.hexdigest()
    except OSError:
        raise ObservationError('state_inconsistent') from None

def _fingerprint_file(directory,name,relative,digest,remaining,deadline,now,owner):
    _deadline(deadline, now)
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        before=_file(fd,owner)
        if before.st_size>remaining[0]:
            raise ObservationError('resource_limit')
        _frame(digest,relative.encode('ascii'))
        _frame(digest,b'regular')
        digest.update(before.st_size.to_bytes(8,'big'))
        count=0
        while True:
            _deadline(deadline, now)
            chunk=os.read(fd,min(65536,remaining[0]+1))
            if not chunk:
                break
            remaining[0]-=len(chunk)
            if remaining[0]<0:
                raise ObservationError('resource_limit')
            count+=len(chunk)
            digest.update(chunk)
        if (count!=before.st_size or _stable(before)!=_stable(os.fstat(fd)) or
                _identity(before)!=_identity(os.stat(name,dir_fd=directory,follow_symlinks=False))):
            raise ObservationError('state_inconsistent')
    finally:
        os.close(fd)



class NativeReadLocks:
    """Own actual POSIX dpkg locks and the real executor's flock guard.

    Directory FDs come from the fixed root coordinator, not caller requests.
    Never open/close any other FD for either native lock inode while held: POSIX
    record locks are process-owned and such a close would drop that lock.
    """
    def __init__(self):
        self._directories = []
        self._files = []
        self._ancestries = []
        self._closed = True
        self.owner = None
        self._process_owned = False
        self._cleanup_uncertain = False

    @classmethod
    def fixed(cls, *, deadline_ms=None, now=None):
        """Root coordinator only: exact Linux native paths, no caller options."""
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise ObservationError('policy_unsupported')
        _before_deadline(deadline_ms,now)
        root = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        ancestries=[]
        guard=None
        try:
            ancestries.append(_Ancestry.open(root,('var','lib','dpkg')))
            ancestries.append(_Ancestry.open(root,('run',)))
            guard=cls.acquire(ancestries[0].fds[-1],ancestries[1].fds[-1],deadline_ms=deadline_ms,now=now)
            guard._ancestries=ancestries
            ancestries=[]
            guard.verify()
            return guard
        except BaseException:
            if guard is not None:
                guard.close()
            raise
        finally:
            os.close(root)
            for ancestry in ancestries:
                ancestry.close()

    @classmethod
    def acquire(cls, dpkg_directory, runtime_directory, *, owner=0, deadline_ms=None, now=None):
        _before_deadline(deadline_ms,now)
        guard = cls()
        guard.owner = owner
        if not _NATIVE_OWNER.acquire(blocking=False):
            raise ObservationError('busy')
        guard._process_owned = True
        try:
            for directory in [dpkg_directory, runtime_directory]:
                _directory(directory, owner)
                guard._directories.append(os.dup(directory))
            dpkg, runtime = guard._directories
            for directory, entry, native in [
                    (runtime, 'guarded-update-executor.lock', False),
                    (dpkg, 'lock-frontend', True), (dpkg, 'lock', True)]:
                _before_deadline(deadline_ms,now)
                flags = os.O_RDONLY
                fd = os.open(entry, flags | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o600, dir_fd=directory)
                guard._files.append((directory, entry, fd, native, _identity(os.fstat(fd))))
                _file(fd, owner)
                _before_deadline(deadline_ms,now)
                try:
                    if native:
                        fcntl.lockf(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    else:
                        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ObservationError('package_manager_busy' if native else 'executor_busy') from None
            guard._closed = False
            guard.verify()
            _before_deadline(deadline_ms,now)
            return guard
        except BaseException as error:
            guard.close()
            if isinstance(error, OSError):
                raise ObservationError('state_inconsistent') from None
            raise

    def fingerprint(self, deadline_ms, now):
        """Actual owned guard verification surrounds the shared data-only hash."""
        _deadline(deadline_ms,now);self.verify()
        digest=installed_fingerprint(self._directories[0],self.owner,deadline_ms,now)
        self.verify();_deadline(deadline_ms,now);return digest

    def verify(self):
        try:
            if self._closed:
                raise ObservationError('state_inconsistent')
            for ancestry in self._ancestries:
                ancestry.verify()
            for directory in self._directories:
                _directory(directory, self.owner)
            for directory, entry, fd, _, identity in self._files:
                before = _file(fd, self.owner)
                path = os.stat(entry, dir_fd=directory, follow_symlinks=False)
                if (_identity(before) != identity or _identity(path) != identity or
                        not stat.S_ISREG(path.st_mode) or path.st_nlink != 1):
                    raise ObservationError('state_inconsistent')
        except OSError:
            raise ObservationError('state_inconsistent') from None

    def close(self):
        if self._cleanup_uncertain:
            raise ObservationError('cleanup_unconfirmed')
        self._closed = True
        files, directories = self._files, self._directories
        self._files, self._directories = [], []
        failed = False
        for fd in [item[2] for item in files] + directories:
            try:
                os.close(fd)
            except OSError:
                failed = True
        ancestries,self._ancestries=self._ancestries,[]
        for ancestry in ancestries:
            try:
                ancestry.close()
            except ObservationError:
                failed=True
        if failed:
            self._cleanup_uncertain = True
            # Do not release process ownership after uncertain descriptor cleanup.
            raise ObservationError('cleanup_unconfirmed')
        if self._process_owned:
            self._process_owned = False
            _NATIVE_OWNER.release()


class _Ancestry:
    @classmethod
    def open(cls, root, components, owner=0):
        result=cls()
        result.owner=owner
        result.fds=[]
        result.links=[]
        try:
            if type(components) is not tuple or len(components)>8:
                raise ObservationError('state_inconsistent')
            _directory(root,owner)
            result.fds.append(os.dup(root))
            for component in components:
                if type(component) is not str or re.fullmatch('[A-Za-z0-9_-]{1,255}',component) is None:
                    raise ObservationError('state_inconsistent')
                parent=result.fds[-1]
                child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                result.fds.append(child)
                info=_directory(child,owner)
                result.links.append((parent,component,child,_identity(info)))
            result.verify()
            return result
        except BaseException as error:
            result.close()
            if isinstance(error,OSError):
                raise ObservationError('state_inconsistent') from None
            raise

    def verify(self):
        if not self.fds:
            raise ObservationError('state_inconsistent')
        try:
            for fd in self.fds:
                _directory(fd,self.owner)
            for parent,name,child,identity in self.links:
                named=os.stat(name,dir_fd=parent,follow_symlinks=False)
                if (_identity(os.fstat(child))!=identity or _identity(named)!=identity or
                        not stat.S_ISDIR(named.st_mode) or named.st_uid!=self.owner or named.st_mode&0o022):
                    raise ObservationError('state_inconsistent')
        except OSError:
            raise ObservationError('state_inconsistent') from None

    def close(self):
        fds,self.fds=self.fds,[]
        failed=False
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                failed=True
        if failed:
            raise ObservationError('cleanup_unconfirmed')


@dataclass(frozen=True)
class _ObservationIdentity:
    nonce: str
    boot_id: str
    cache_generation: str
    policy_generation: str
    accepted_boottime_ms: int
    lock_open_boottime_ms: int
    expires_boottime_ms: int
    installed_before_sha256: str


class Observation:
    """Consumes its guard; only one exact release can produce a receipt.

    The caller must keep the immutable cache lease and policy guard pinned, and
    independently enforce the 120s deadline even if this process stops responding.
    """
    @classmethod
    def begin(cls, guard, nonce, boot_id, cache, policy, accepted_ms, clock, *, deadline_ms=None):
        value=cls()
        value._guard=guard
        value._clock=clock
        value._boot_id=boot_id
        value._last_time=None
        value._used=False
        try:
            valid_hex=lambda text,size: type(text) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',text) is not None
            if (not valid_hex(nonce,32) or not 1<=int(nonce[:16],16)<=MAX_SAFE or
                    type(boot_id) is not str or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',boot_id) is None or
                    not valid_hex(cache,32) or not valid_hex(policy,64) or
                    type(accepted_ms) is not int or not 0<=accepted_ms<=MAX_SAFE):
                raise ObservationError('invalid_request')
            guard.verify()
            opened=value._time()
            expiry=opened+120000
            if deadline_ms is not None:
                if type(deadline_ms) is not int or not 0<=deadline_ms<=MAX_SAFE:
                    raise ObservationError('invalid_request')
                expiry=min(expiry,deadline_ms)
            if expiry<=opened:
                raise ObservationError('lease_expired')
            if accepted_ms>opened or expiry>MAX_SAFE:
                raise ObservationError('state_inconsistent')
            before=guard.fingerprint(expiry,value._time)
            value._identity=_ObservationIdentity(nonce,boot_id,cache,policy,accepted_ms,opened,expiry,before)
            return value
        except BaseException:
            value._used=True
            guard.close()
            raise

    def _time(self):
        try:
            boot,current=self._clock()
        except Exception:
            raise ObservationError('state_inconsistent') from None
        if (boot!=self._boot_id or type(current) is not int or not 0<=current<=MAX_SAFE or
                self._last_time is not None and current<self._last_time):
            raise ObservationError('state_inconsistent')
        self._last_time=current
        return current

    def lease(self):
        if self._used:
            raise ObservationError('state_inconsistent')
        identity=self._identity
        try:
            self._guard.verify()
            _deadline(identity.expires_boottime_ms,self._time)
            return {'nonce':identity.nonce,'boot_id':identity.boot_id,
                    'cache_generation':identity.cache_generation,'policy_generation':identity.policy_generation,
                    'lock_open_boottime_ms':identity.lock_open_boottime_ms,
                    'expires_boottime_ms':identity.expires_boottime_ms}
        except BaseException:
            self.abort()
            raise

    def finish(self, nonce):
        if self._used:
            raise ObservationError('state_inconsistent')
        identity=self._identity
        if type(nonce) is not str or nonce!=identity.nonce:
            # An unrelated release request cannot unlock this observation.
            raise ObservationError('invalid_request')
        self._used=True
        try:
            after=self._guard.fingerprint(identity.expires_boottime_ms,self._time)
            if after!=identity.installed_before_sha256:
                raise ObservationError('state_inconsistent')
            self._guard.verify()
            held_until=_deadline(identity.expires_boottime_ms,self._time)
        finally:
            self._guard.close()
        released=_deadline(identity.expires_boottime_ms,self._time)
        return {'nonce':identity.nonce,'boot_id':identity.boot_id,
                'cache_generation':identity.cache_generation,'policy_generation':identity.policy_generation,
                'expires_boottime_ms':identity.expires_boottime_ms,
                'lock_open_boottime_ms':identity.lock_open_boottime_ms,
                'lock_held_until_boottime_ms':held_until,'released_boottime_ms':released,
                'outcome':'released','installed_before_sha256':identity.installed_before_sha256,
                'installed_after_sha256':after}

    def abort(self):
        self._used=True
        self._guard.close()


def prepare_executor_guard(runtime_directory, *, owner=0):
    """Trusted parent only; never truncate, repair or remove an existing guard."""
    fd=None
    created=False
    try:
        _directory(runtime_directory,owner)
        try:
            fd=os.open('guarded-update-executor.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=runtime_directory)
        except FileNotFoundError:
            fd=os.open('guarded-update-executor.lock',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=runtime_directory)
            created=True
        info=_file(fd,owner)
        if stat.S_IMODE(info.st_mode)!=0o600:
            raise ObservationError('state_inconsistent')
        named=os.stat('guarded-update-executor.lock',dir_fd=runtime_directory,follow_symlinks=False)
        if _stable(info)!=_stable(named):
            raise ObservationError('state_inconsistent')
        if created:
            os.fsync(fd)
            os.fsync(runtime_directory)
        after=_file(fd,owner)
        named=os.stat('guarded-update-executor.lock',dir_fd=runtime_directory,follow_symlinks=False)
        if _stable(info)!=_stable(after) or _stable(after)!=_stable(named):
            raise ObservationError('state_inconsistent')
        return created
    except OSError:
        raise ObservationError('state_inconsistent') from None
    finally:
        if fd is not None:
            os.close(fd)


def prepare_fixed_executor_guard():
    if sys.platform!='linux' or os.geteuid()!=0:
        raise ObservationError('policy_unsupported')
    root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    ancestry=None
    try:
        ancestry=_Ancestry.open(root,('run',))
        created=prepare_executor_guard(ancestry.fds[-1])
        ancestry.verify()
        return created
    finally:
        if ancestry is not None:
            ancestry.close()
        os.close(root)
