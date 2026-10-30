"""Unregistered Linux Unix-stream mechanics; no peer-authentication authority.

Socketpair SO_PEERCRED reflects connection-creation credentials, not the later
child's identity. Callers own the open-file description exclusively; deadline
checks are sampled and do not prove process or remote socket cleanup.
"""
import array
import fcntl
import math
import os
import select
import socket
import stat
import struct
import sys
import time

ERROR='Synthetic Unix stream unavailable'
ALLOWED=(b'DRAIN-1',b'DRAINED-1')


def validate(raw,expected):
    if type(raw) is not bytes or type(expected) is not bytes or expected not in ALLOWED or raw!=expected:raise ValueError(ERROR)


class OneMessage:
    def __init__(self,fd,deadline):
        self.sock=None;self.closed=False;self.failed=False;self.deadline=deadline;self.identity=None
        try:
            if sys.platform!='linux' or type(fd) is not int or type(deadline) not in (int,float) or not math.isfinite(deadline):raise ValueError(ERROR)
            info=os.fstat(fd);self.identity=(info.st_dev,info.st_ino,info.st_mode)
            if not stat.S_ISSOCK(info.st_mode) or os.get_inheritable(fd):raise ValueError(ERROR)
            self.sock=socket.socket(fileno=fd)
            if self.sock.family!=socket.AF_UNIX or self.sock.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_STREAM:raise ValueError(ERROR)
            self.sock.setblocking(False);self._check()
        except BaseException:
            self.failed=True
            try:self.close()
            except BaseException:pass
            raise ValueError(ERROR) from None

    def _check(self):
        if self.closed or self.failed or self.sock is None or time.monotonic()>=self.deadline:raise ValueError(ERROR)
        info=os.fstat(self.sock.fileno())
        flags=fcntl.fcntl(self.sock.fileno(),fcntl.F_GETFL)
        if (info.st_dev,info.st_ino,info.st_mode)!=self.identity or os.get_inheritable(self.sock.fileno()) or self.sock.getblocking() or flags&os.O_ACCMODE!=os.O_RDWR or not flags&os.O_NONBLOCK:raise ValueError(ERROR)

    def creation_credentials(self):
        """Untrusted socketpair creation-time metadata, not live peer identity."""
        try:
            self._check();raw=self.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i'));self._check()
            if len(raw)!=struct.calcsize('3i'):raise ValueError(ERROR)
            return struct.unpack('3i',raw)
        except BaseException:self.failed=True;raise ValueError(ERROR) from None

    def _wait(self,read):
        self._check();remaining=self.deadline-time.monotonic()
        ready=select.select([self.sock] if read else [],[] if read else [self.sock],[],max(0,remaining));self._check()
        if not (ready[0] if read else ready[1]):raise ValueError(ERROR)

    @staticmethod
    def _discard(ancillary):
        failed=False;seen=set()
        for level,kind,data in ancillary:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                size=array.array('i').itemsize;usable=len(data)-(len(data)%size)
                descriptors=array.array('i');descriptors.frombytes(data[:usable])
                if usable!=len(data):failed=True
                for fd in descriptors:
                    if fd in seen:failed=True;continue
                    seen.add(fd)
                    try:os.close(fd)
                    except OSError:failed=True
        if failed:raise ValueError(ERROR)

    def receive(self,expected):
        try:
            if type(expected) is not bytes or expected not in ALLOWED:raise ValueError(ERROR)
            received=bytearray()
            while True:
                self._wait(True)
                try:raw,ancillary,flags,_=self.sock.recvmsg(len(expected)+1-len(received),socket.CMSG_SPACE(64*array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
                except BlockingIOError:continue
                self._discard(ancillary);self._check()
                if ancillary or flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC):raise ValueError(ERROR)
                if not raw:break
                received.extend(raw)
                if len(received)>len(expected) or not expected.startswith(received):raise ValueError(ERROR)
            validate(bytes(received),expected);self._check()
        except BaseException:self.failed=True;raise ValueError(ERROR) from None

    def send(self,message):
        try:
            if type(message) is not bytes or message not in ALLOWED:raise ValueError(ERROR)
            offset=0
            while offset<len(message):
                self._wait(False)
                try:count=self.sock.send(message[offset:],socket.MSG_NOSIGNAL)
                except BlockingIOError:continue
                self._check()
                if count<=0:raise ValueError(ERROR)
                offset+=count
            self.sock.shutdown(socket.SHUT_WR);self._check()
        except BaseException:self.failed=True;raise ValueError(ERROR) from None

    def close(self):
        if self.closed:
            if self.failed:raise ValueError(ERROR)
            return
        self.closed=True
        if self.sock is not None:
            try:
                fd=self.sock.fileno();info=os.fstat(fd)
                if (info.st_dev,info.st_ino,info.st_mode)!=self.identity:raise ValueError(ERROR)
                fd=self.sock.detach();os.close(fd)
            except BaseException:self.failed=True
        if self.failed:raise ValueError(ERROR)
