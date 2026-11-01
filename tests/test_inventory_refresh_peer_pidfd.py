"""Socket-derived pidfd fixture, not peer authorization."""
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_peer_pidfd as peer


class PeerPidfdTests(unittest.TestCase):
    def test_fdinfo_requires_one_canonical_live_pid(self):
        self.assertEqual(peer.parse_fdinfo(b'pos:\t0\nPid:\t17\nNSpid:\t17\n'),17)
        for raw in (b'',b'Pid:\t-1\n',b'Pid:\t017\n',b'Pid:\t17\nPid:\t17\n',b'Pid:\t1\n'):
            with self.assertRaises(ValueError):peer.parse_fdinfo(raw)

    def test_failed_acquisition_closes_returned_fd_once(self):
        left,right=socket.socketpair();fd=os.open('/dev/null',os.O_RDONLY)
        connection=Mock();connection.fileno.return_value=left.fileno();connection.family=socket.AF_UNIX
        def getsockopt(level,name,*args):
            if name==socket.SO_TYPE:return socket.SOCK_STREAM
            if name==17:return struct.pack('iII',os.getpid(),os.getuid(),os.getgid())
            if name==peer.SO_PEERPIDFD:return struct.pack('i',fd)
            raise ValueError('unexpected')
        connection.getsockopt.side_effect=getsockopt
        try:
            with (patch.object(peer.sys,'platform','linux'),patch.object(peer.platform,'machine',return_value='x86_64'),
                  patch.object(peer.socket,'SO_PEERCRED',17,create=True),patch.object(peer.os,'readlink',return_value='wrong')):
                with self.assertRaises(ValueError):peer.PeerPin(connection,(os.getpid(),os.getuid(),os.getgid()),time.monotonic()+3)
            with self.assertRaises(OSError):os.fstat(fd)
        finally:left.close();right.close()

    def test_unsupported_socket_option_fails_without_fallback(self):
        left,right=socket.socketpair()
        connection=Mock();connection.fileno.return_value=left.fileno();connection.family=socket.AF_UNIX
        def getsockopt(level,name,*args):
            if name==socket.SO_TYPE:return socket.SOCK_STREAM
            if name==17:return struct.pack('iII',os.getpid(),os.getuid(),os.getgid())
            if name==peer.SO_PEERPIDFD:raise OSError('unsupported')
            raise AssertionError('unexpected fallback')
        connection.getsockopt.side_effect=getsockopt
        try:
            with (patch.object(peer.sys,'platform','linux'),patch.object(peer.platform,'machine',return_value='x86_64'),
                  patch.object(peer.socket,'SO_PEERCRED',17,create=True)):
                with self.assertRaises(ValueError):peer.PeerPin(connection,(os.getpid(),os.getuid(),os.getgid()),time.monotonic()+3)
            self.assertEqual(connection.getsockopt.call_count,3)
        finally:left.close();right.close()

    @unittest.skipUnless(sys.platform=='linux','Linux SO_PEERPIDFD fixture')
    def test_accepted_peer_pidfd_tracks_natural_exit(self):
        path=tempfile.mkdtemp(prefix='inventory-peer-pidfd-');address=str(Path(path)/'socket')
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(address);listener.listen(1)
        program="import socket,sys\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5);s.connect(sys.argv[1]);assert s.recv(1)==b'x';s.close()"
        child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,address],
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        listener.settimeout(5);connection,_=listener.accept()
        owner=peer.PeerPin(connection,(child.pid,os.getuid(),os.getgid()),time.monotonic()+5)
        owner.verify();connection.sendall(b'x');self.assertEqual(child.wait(timeout=5),0)
        with self.assertRaises(ValueError):owner.verify()
        with self.assertRaises(ValueError):owner.close()
        connection.close();listener.close();os.unlink(address);os.rmdir(path)
