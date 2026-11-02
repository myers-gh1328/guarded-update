"""Unregistered socket-derived pidfd observation; no authorization authority.

Requires trusted procfs and one PID namespace, exclusive socket/FD ownership,
and a live connected Linux Unix stream. It pins the connection peer only; passed
connections, message senders, unit identity and Root authority are separate.
"""
import math
import os
import platform
import re
import select
import socket
import stat
import struct
import sys
import time

ERROR='Socket peer pidfd unavailable'
SO_PEERPIDFD=77


def parse_fdinfo(raw):
    if type(raw) is not bytes or not 0<len(raw)<=4096:raise ValueError(ERROR)
    values=[line.partition(b':')[2].strip() for line in raw.splitlines() if line.startswith(b'Pid:')]
    if len(values)!=1 or re.fullmatch(rb'[1-9][0-9]{0,9}',values[0]) is None:raise ValueError(ERROR)
    pid=int(values[0])
    if not 1<pid<2**31:raise ValueError(ERROR)
    return pid


def _identity(info):return (info.st_dev,info.st_ino,info.st_mode)


class PeerPin:
    def __init__(self,connection,expected,deadline):
        self.connection=connection;self.fd=None;self.pidfd_identity=None;self.closed=False;self.failed=False
        try:
            if (sys.platform!='linux' or platform.machine() not in ('x86_64','aarch64','armv7l') or
                type(deadline) not in (int,float) or not math.isfinite(deadline) or
                type(expected) is not tuple or len(expected)!=3 or any(type(item) is not int for item in expected) or
                not 1<expected[0]<2**31 or any(not 0<=item<2**32-1 for item in expected[1:])):raise ValueError(ERROR)
            self.deadline=deadline;self.expected=expected
            info=os.fstat(connection.fileno());self.socket_identity=_identity(info)
            if not stat.S_ISSOCK(info.st_mode) or connection.family!=socket.AF_UNIX or connection.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_STREAM:raise ValueError(ERROR)
            if self._credentials()!=expected or time.monotonic()>=deadline:raise ValueError(ERROR)
            raw=connection.getsockopt(socket.SOL_SOCKET,SO_PEERPIDFD,struct.calcsize('i'))
            if type(raw) is not bytes or len(raw)!=struct.calcsize('i'):raise ValueError(ERROR)
            returned=struct.unpack('i',raw)[0]
            if returned<0:raise ValueError(ERROR)
            self.fd=returned
            info=os.fstat(self.fd);self.pidfd_identity=_identity(info)
            os.set_inheritable(self.fd,False)
            self.verify()
        except BaseException:
            self.failed=True
            try:self.close()
            except BaseException:pass
            raise ValueError(ERROR) from None

    def _credentials(self):
        raw=self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('iII'))
        if type(raw) is not bytes or len(raw)!=struct.calcsize('iII'):raise ValueError(ERROR)
        return struct.unpack('iII',raw)

    def _fdinfo(self):
        fd=None;failed=False;raw=b''
        try:
            fd=os.open('/proc/self/fdinfo/'+str(self.fd),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            while len(raw)<=4096:
                chunk=os.read(fd,4097-len(raw))
                if not chunk:break
                raw+=chunk
        except BaseException:failed=True
        finally:
            if fd is not None:
                try:os.close(fd)
                except OSError:failed=True
        if failed:raise ValueError(ERROR)
        return parse_fdinfo(raw)

    def verify(self):
        try:
            if self.closed or self.failed or self.fd is None or time.monotonic()>=self.deadline:raise ValueError(ERROR)
            if _identity(os.fstat(self.connection.fileno()))!=self.socket_identity or self._credentials()!=self.expected:raise ValueError(ERROR)
            if (_identity(os.fstat(self.fd))!=self.pidfd_identity or os.get_inheritable(self.fd) or
                os.readlink('/proc/self/fd/'+str(self.fd))!='anon_inode:[pidfd]'):raise ValueError(ERROR)
            poll=select.poll();poll.register(self.fd,select.POLLIN|select.POLLHUP|select.POLLERR)
            if poll.poll(0) or self._fdinfo()!=self.expected[0] or poll.poll(0):raise ValueError(ERROR)
            if (_identity(os.fstat(self.fd))!=self.pidfd_identity or os.get_inheritable(self.fd) or
                os.readlink('/proc/self/fd/'+str(self.fd))!='anon_inode:[pidfd]' or poll.poll(0) or
                _identity(os.fstat(self.connection.fileno()))!=self.socket_identity or
                self._credentials()!=self.expected or time.monotonic()>=self.deadline):raise ValueError(ERROR)
        except BaseException:self.failed=True;raise ValueError(ERROR) from None

    def close(self):
        if self.closed:
            if self.failed:raise ValueError(ERROR)
            return
        self.closed=True
        if self.fd is not None:
            fd,self.fd=self.fd,None
            try:
                if self.pidfd_identity is not None and _identity(os.fstat(fd))!=self.pidfd_identity:raise ValueError(ERROR)
                os.close(fd)
            except BaseException:self.failed=True
        if self.failed:raise ValueError(ERROR)
