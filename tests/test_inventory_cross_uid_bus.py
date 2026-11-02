"""Unit-reference fixture ownership and protected library admission."""
import os
import ctypes
import socket
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import inventory_cross_uid_bus as bus


class LibraryTest(unittest.TestCase):
    def test_bus_uses_only_fixed_ref_and_unref_and_closes_once(self):
        class Function:
            def __init__(self, callback): self.callback=callback
            def __call__(self, *args): return self.callback(*args)
        left, right = socket.socketpair()
        fd = left.detach()
        calls = []
        class Library: pass
        library = Library()
        def open_bus(out): ctypes.cast(out, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(1); return 0
        def call(*args):
            calls.append((args[1], args[2], args[3], args[4]))
            ctypes.cast(args[6], ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(2)
            return 1
        functions = {'sd_bus_open_system': open_bus, 'sd_bus_set_method_call_timeout': lambda *_: 0,
            'sd_bus_get_fd': lambda *_: fd, 'sd_bus_is_open': lambda *_: 1, 'sd_bus_call_method': call,
            'sd_bus_message_unref': lambda *_: None, 'sd_bus_close': lambda *_: os.close(fd),
            'sd_bus_unref': lambda *_: None}
        for name, function in functions.items(): setattr(library, name, Function(function))
        try:
            connection = bus.NativeBus.from_library(library, time.monotonic() + 5)
            self.assertTrue(connection.ref(time.monotonic() + 5))
            self.assertTrue(connection.alive())
            self.assertTrue(connection.unref(time.monotonic() + 5))
            self.assertTrue(connection.close())
            self.assertFalse(connection.close())
            self.assertEqual([item[3] for item in calls], [b'Ref', b'Unref'])
            self.assertTrue(all(item[:3] == (bus.DESTINATION, bus.OBJECT, bus.INTERFACE) for item in calls))
        finally: right.close()

    def test_library_is_held_and_revalidated_without_following_foreign_links(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            target = path / 'libsystemd.so.0.38.0'
            target.write_bytes(b'synthetic')
            target.chmod(0o755)
            (path / 'libsystemd.so.0').symlink_to(target.name)
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(bus.load_from_directory(parent, os.geteuid(), time.monotonic() + 5, lambda _: 'loaded'), 'loaded')
                (path / 'libsystemd.so.0').unlink()
                (path / 'libsystemd.so.0').symlink_to('../foreign')
                with self.assertRaises(ValueError):
                    bus.load_from_directory(parent, os.geteuid(), time.monotonic() + 5, lambda _: 'loaded')
            finally: os.close(parent)

    def test_changed_target_and_close_error_fail_without_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            target = path / 'libsystemd.so.0.38.0'
            target.write_bytes(b'synthetic'); target.chmod(0o755)
            (path / 'libsystemd.so.0').symlink_to(target.name)
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                def replace(_):
                    target.rename(path / 'old')
                    target.write_bytes(b'foreign'); target.chmod(0o755)
                    return 'loaded'
                with self.assertRaises(ValueError):
                    bus.load_from_directory(parent, os.geteuid(), time.monotonic() + 5, replace)
                self.assertEqual(target.read_bytes(), b'foreign')
                self.assertTrue((path / 'old').exists())
                real_close = os.close
                def fail_after_close(fd): real_close(fd); raise OSError('injected')
                with patch.object(bus.os, 'close', side_effect=fail_after_close):
                    with self.assertRaises(ValueError):
                        bus.load_from_directory(parent, os.geteuid(), time.monotonic() + 5, lambda _: 'loaded')
            finally: real_close(parent)


if __name__ == '__main__': unittest.main()
