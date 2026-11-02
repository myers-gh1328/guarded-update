"""Dedicated fixture-only systemd reference; no process cleanup authority.

The runner's dynamic loader, its cache and library dependencies are trusted.
The library path is sampled under exclusive mutation, not immutable provenance.
Local connection/FD checks do not prove remote liveness or process cleanup.
"""
import errno
import ctypes
import fcntl
import os
import re
import stat
import time

ERROR = 'Fixture systemd reference unavailable'
DESTINATION = b'org.freedesktop.systemd1'
OBJECT = b'/org/freedesktop/systemd1/unit/command_2dcenter_2dinventory_2eservice'
INTERFACE = b'org.freedesktop.systemd1.Unit'


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def load_from_directory(parent, owner, deadline, loader):
    """Sample held/named fixed library under caller-owned protected ancestry."""
    fd = None
    failed = False
    loaded = None
    try:
        if time.monotonic() >= deadline: raise ValueError(ERROR)
        directory = os.fstat(parent)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != owner or directory.st_mode & 0o022:
            raise ValueError(ERROR)
        link = os.stat('libsystemd.so.0', dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISLNK(link.st_mode) or link.st_uid != owner: raise ValueError(ERROR)
        target = os.readlink('libsystemd.so.0', dir_fd=parent)
        if not re.fullmatch(r'libsystemd\.so\.0\.[0-9]+(?:\.[0-9]+)*', target): raise ValueError(ERROR)
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        named = os.stat(target, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022 or
            info.st_nlink != 1 or not 0 < info.st_size <= 16 * 1024 * 1024 or info.st_dev != directory.st_dev or
            _metadata(info) != _metadata(named)):
            raise ValueError(ERROR)
        loaded = loader('/proc/self/fd/' + str(fd))
        after_directory = os.fstat(parent)
        if (time.monotonic() >= deadline or _metadata(os.fstat(fd)) != _metadata(info) or
            _metadata(os.stat(target, dir_fd=parent, follow_symlinks=False)) != _metadata(info) or
            _metadata(os.stat('libsystemd.so.0', dir_fd=parent, follow_symlinks=False)) != _metadata(link) or
            os.readlink('libsystemd.so.0', dir_fd=parent) != target or
            (after_directory.st_dev, after_directory.st_ino, after_directory.st_mode, after_directory.st_uid, after_directory.st_gid) !=
            (directory.st_dev, directory.st_ino, directory.st_mode, directory.st_uid, directory.st_gid)):
            raise ValueError(ERROR)
    except BaseException:
        failed = True
    finally:
        if fd is not None:
            try: os.close(fd)
            except OSError: failed = True
    if failed or time.monotonic() >= deadline: raise ValueError(ERROR)
    return loaded


class NativeBus:
    """One fixed sd-bus connection; methods do not stop or signal any unit."""
    @classmethod
    def fixed(cls, deadline):
        import sys
        if sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
            raise ValueError(ERROR)
        from inventory_refresh_resources import _Chain
        chain = _Chain(('usr', 'lib', 'aarch64-linux-gnu'))
        try:
            chain.verify()
            library = load_from_directory(chain.fds[-1], 0, deadline, ctypes.CDLL)
            chain.verify()
        finally:
            chain.close()
        return cls.from_library(library, deadline)

    @classmethod
    def from_library(cls, library, deadline):
        p = ctypes.c_void_p
        signatures = {
            'sd_bus_open_system': ([ctypes.POINTER(p)], ctypes.c_int),
            'sd_bus_set_method_call_timeout': ([p, ctypes.c_uint64], ctypes.c_int),
            'sd_bus_get_fd': ([p], ctypes.c_int), 'sd_bus_is_open': ([p], ctypes.c_int),
            'sd_bus_call_method': ([p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                    p, ctypes.POINTER(p), ctypes.c_char_p], ctypes.c_int),
            'sd_bus_message_unref': ([p], p), 'sd_bus_close': ([p], None), 'sd_bus_unref': ([p], p),
        }
        for name, (arguments, result) in signatures.items():
            method = getattr(library, name)
            method.argtypes, method.restype = arguments, result
        value = cls()
        value._library, value._bus, value._fd, value._closed = library, p(), -1, False
        try:
            if time.monotonic() >= deadline or library.sd_bus_open_system(ctypes.byref(value._bus)) < 0 or not value._bus.value:
                raise ValueError(ERROR)
            value._fd = library.sd_bus_get_fd(value._bus)
            info = os.fstat(value._fd)
            if not stat.S_ISSOCK(info.st_mode): raise ValueError(ERROR)
            value._identity = (info.st_dev, info.st_ino, info.st_mode)
            if not value.alive() or time.monotonic() >= deadline: raise ValueError(ERROR)
            return value
        except BaseException:
            value.close()
            raise ValueError(ERROR) from None

    def alive(self):
        try:
            if self._closed or not self._bus.value or self._library.sd_bus_is_open(self._bus) != 1 or self._library.sd_bus_get_fd(self._bus) != self._fd:
                return False
            info = os.fstat(self._fd)
            fcntl.fcntl(self._fd, fcntl.F_GETFD)
            return (info.st_dev, info.st_ino, info.st_mode) == self._identity
        except (OSError, ValueError):
            return False

    def _call(self, method, deadline):
        reply = ctypes.c_void_p()
        accepted = False
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.alive(): raise ValueError(ERROR)
            timeout = max(1, int(remaining * 1_000_000))
            if self._library.sd_bus_set_method_call_timeout(self._bus, timeout) < 0: raise ValueError(ERROR)
            result = self._library.sd_bus_call_method(self._bus, DESTINATION, OBJECT, INTERFACE, method,
                                                       None, ctypes.byref(reply), None)
            accepted = result >= 0 and bool(reply.value) and time.monotonic() < deadline and self.alive()
        except BaseException:
            accepted = False
        finally:
            if reply.value:
                try:
                    if self._library.sd_bus_message_unref(reply): accepted = False
                except BaseException: accepted = False
        return accepted and time.monotonic() < deadline

    def ref(self, deadline): return self._call(b'Ref', deadline)
    def unref(self, deadline): return self._call(b'Unref', deadline)

    def close(self):
        if self._closed: return False
        self._closed = True
        if not self._bus.value: return False
        failed = self._fd < 0
        if self._fd >= 0:
            try:
                info = os.fstat(self._fd)
                if (info.st_dev, info.st_ino, info.st_mode) != self._identity: failed = True
            except (OSError, AttributeError): failed = True
        try: self._library.sd_bus_close(self._bus)
        except BaseException: failed = True
        if self._fd >= 0:
            try:
                fcntl.fcntl(self._fd, fcntl.F_GETFD)
                failed = True
            except OSError as error:
                if error.errno != errno.EBADF: failed = True
        try:
            if self._library.sd_bus_unref(self._bus): failed = True
        except BaseException: failed = True
        self._bus = ctypes.c_void_p()
        return not failed
