"""Synthetic Unix-stream transport, not peer authentication."""
import os
import fcntl
from pathlib import Path
import socket
import select
import array
import subprocess
import struct
import sys
import time
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_unix_stream as packet


class SeqpacketTests(unittest.TestCase):
    def test_only_exact_fixed_packet_is_accepted(self):
        packet.validate(b'DRAIN-1',b'DRAIN-1')
        for raw in (b'',b'DRAIN',b'DRAIN-1extra'):
            with self.assertRaises(ValueError):packet.validate(raw,b'DRAIN-1')
        with self.assertRaises(ValueError):packet.validate(b'DRAIN-1',bytearray(b'DRAIN-1'))

    def test_received_descriptor_cleanup_attempts_all_once(self):
        raw=array.array('i',[41,42,41]).tobytes();calls=[]
        def close(fd):
            calls.append(fd)
            if fd==41:raise OSError('uncertain')
        with patch.object(packet.os,'close',side_effect=close):
            with self.assertRaises(ValueError):packet.OneMessage._discard([(socket.SOL_SOCKET,socket.SCM_RIGHTS,raw)])
        self.assertEqual(calls,[41,42])

    def test_message_credentials_are_exact_and_caller_supplied(self):
        credential=struct.pack('3i',17,0,0)
        record=(socket.SOL_SOCKET,getattr(socket,'SCM_CREDENTIALS',2),credential)
        self.assertEqual(packet.decode_credentials(b'DRAIN-1',[record],0,(17,0,0)),(17,0,0))
        for raw,records,flags,expected in ((b'', [record],0,(17,0,0)),
            (b'DRAIN-1',[record,record],0,(17,0,0)),
            (b'DRAIN-1',[record],socket.MSG_CTRUNC,(17,0,0)),
            (b'DRAIN-1',[record],0,(18,0,0)),
            (b'DRAIN-1',[(socket.SOL_SOCKET,getattr(socket,'SCM_CREDENTIALS',2),b'bad')],0,(17,0,0))):
            with self.assertRaises(ValueError):packet.decode_credentials(raw,records,flags,expected)
        rights=(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[41,42]).tobytes())
        with patch.object(packet.os,'close') as close:
            with self.assertRaises(ValueError):packet.decode_credentials(b'DRAIN-1',[record,rights],0,(17,0,0))
        self.assertEqual([call.args[0] for call in close.call_args_list],[41,42])
        with patch.object(packet.os,'close') as close:
            with self.assertRaises(ValueError):packet.decode_credentials(b'DRAIN-1',[('malformed',),rights],0,(17,0,0))
        self.assertEqual([call.args[0] for call in close.call_args_list],[41,42])

    @unittest.skipUnless(sys.platform=='linux','Linux Unix-stream fixture')
    def test_actual_child_packet_and_eof(self):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        program="import os,socket,sys\ns=socket.socket(fileno=int(sys.argv[1]));s.send(b'DRAIN-1');s.shutdown(socket.SHUT_WR);s.close()"
        child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,str(right.fileno())],pass_fds=(right.fileno(),),
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        right.close();owner=packet.OneMessage(left.detach(),time.monotonic()+3)
        try:
            self.assertEqual(owner.creation_credentials(),(os.getpid(),os.getuid(),os.getgid()))
            owner.receive(b'DRAIN-1');self.assertEqual(child.wait(timeout=3),0)
        finally:owner.close()

    @unittest.skipUnless(sys.platform=='linux','Linux Unix-stream fixture')
    def test_extra_bytes_and_passed_descriptors_are_rejected(self):
        for mode in ('extra','rights'):
            with self.subTest(mode=mode):
                left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
                program="import array,os,socket,sys\ns=socket.socket(fileno=int(sys.argv[1]));m=sys.argv[2]\nif m=='rights':\n f=os.open('/dev/null',os.O_RDONLY);s.sendmsg([b'DRAIN-1'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[f]))]);os.close(f)\nelse:s.sendall(b'DRAIN-1extra')\ns.shutdown(socket.SHUT_WR);s.close()"
                child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,str(right.fileno()),mode],pass_fds=(right.fileno(),),
                    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                right.close();owner=packet.OneMessage(left.detach(),time.monotonic()+3)
                before=len(os.listdir('/proc/self/fd'))
                with self.assertRaises(ValueError):owner.receive(b'DRAIN-1')
                self.assertEqual(len(os.listdir('/proc/self/fd')),before)
                with self.assertRaises(ValueError):owner.close()
                self.assertEqual(child.wait(timeout=3),0)

    @unittest.skipUnless(sys.platform=='linux','Linux Unix-stream fixture')
    def test_held_open_partial_and_close_uncertainty_fail(self):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        owner=packet.OneMessage(left.detach(),time.monotonic()+.05)
        right.sendall(b'DRAIN')
        with self.assertRaises(ValueError):owner.receive(b'DRAIN-1')
        with self.assertRaises(ValueError):owner.close()
        right.close()
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        owner=packet.OneMessage(left.detach(),time.monotonic()+3);original=os.close;calls=[]
        def close(fd):calls.append(fd);original(fd);raise OSError('uncertain')
        with patch.object(packet.os,'close',side_effect=close):
            with self.assertRaises(ValueError):owner.close()
            with self.assertRaises(ValueError):owner.close()
        self.assertEqual(len(calls),1);right.close()

    @unittest.skipUnless(sys.platform=='linux','Linux Unix-stream fixture')
    def test_underlying_nonblocking_flag_mutation_is_rejected(self):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        owner=packet.OneMessage(left.detach(),time.monotonic()+3)
        flags=fcntl.fcntl(owner.sock.fileno(),fcntl.F_GETFL)
        fcntl.fcntl(owner.sock.fileno(),fcntl.F_SETFL,flags & ~os.O_NONBLOCK)
        with self.assertRaises(ValueError):owner.receive(b'DRAIN-1')
        with self.assertRaises(ValueError):owner.close()
        right.close()

    @unittest.skipUnless(sys.platform=='linux','Linux SCM_CREDENTIALS fixture')
    def test_accepted_connection_attributes_each_sender(self):
        program="import os,socket,sys\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5);s.connect(sys.argv[1]);assert s.recv(1)==b'x'\nif sys.argv[2]=='fork':\n p=os.fork()\n if p==0:s.sendall(b'DRAIN-1');s.shutdown(socket.SHUT_WR);os._exit(0)\n _,status=os.waitpid(p,0);assert os.WIFEXITED(status) and os.WEXITSTATUS(status)==0\nelse:s.sendall(b'DRAIN-1');s.shutdown(socket.SHUT_WR)\ns.close()"
        for mode in ('direct','fork'):
            with self.subTest(mode=mode):
                path=tempfile.mkdtemp(prefix='inventory-credential-')
                address=str(Path(path)/'control.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);listener.bind(address);listener.listen(1)
                child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,address,mode],
                    env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                listener.settimeout(5);connection,_=listener.accept();connection.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
                self.assertEqual(connection.getsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED),1)
                credentials=struct.unpack('iII',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                self.assertEqual(credentials,(child.pid,os.getuid(),os.getgid()));connection.sendall(b'x')
                received=b'';deadline=time.monotonic()+5
                while len(received)<len(b'DRAIN-1'):
                    remaining=deadline-time.monotonic();self.assertGreater(remaining,0)
                    self.assertTrue(select.select([connection],[],[],remaining)[0])
                    raw,ancillary,flags,_=connection.recvmsg(8-len(received),socket.CMSG_SPACE(12),socket.MSG_CMSG_CLOEXEC)
                    self.assertTrue(raw);received+=raw;self.assertTrue(b'DRAIN-1'.startswith(received))
                    if mode=='direct':self.assertEqual(packet.decode_credentials(raw,ancillary,flags,credentials),credentials)
                    else:
                        with self.assertRaises(ValueError):packet.decode_credentials(raw,ancillary,flags,credentials)
                self.assertEqual(received,b'DRAIN-1')
                remaining=deadline-time.monotonic();self.assertGreater(remaining,0)
                self.assertTrue(select.select([connection],[],[],remaining)[0])
                extra,ancillary,flags,_=connection.recvmsg(1,socket.CMSG_SPACE(16),socket.MSG_CMSG_CLOEXEC)
                packet.OneMessage._discard(ancillary)
                self.assertEqual(extra,b'');self.assertEqual(ancillary,[]);self.assertFalse(flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC))
                connection.close();listener.close();self.assertEqual(child.wait(timeout=5),0)
                os.unlink(address);os.rmdir(path)
