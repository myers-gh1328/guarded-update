"""Bounded private pipe I/O, not delivery ACK, phase or cleanup authority.

Trusted borrowers retain original FD identities and O_NONBLOCK flags and perform
no concurrent I/O/flag mutation. dup shares open file descriptions, not isolation.
The admitted native clock/liveness owner must outlive the final write.
"""
import fcntl
import os
import re
import select
import stat
from inventory_refresh_reporter_protocol import FRAME_LIMIT, MAX_SAFE


class PipeError(ValueError):
    def __init__(self,reason='transport_unavailable'):
        self.reason=reason
        super().__init__('Private reporter transport unavailable: '+reason)


def _require(condition):
    if not condition:raise PipeError()


def _identity(fd,direction):
    item=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL)
    _require(stat.S_ISFIFO(item.st_mode) and flags&os.O_ACCMODE==direction and flags&os.O_NONBLOCK)
    return item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid


class PipeChannel:
    @classmethod
    def admit(cls,read_fd,write_fd,clock):
        self=cls();self._read=None;self._write=None;self._closed=False;self._failed=False
        self._pending=bytearray();self._clock_source=clock;self._boot=None;self._last=None;self._deadline=None
        try:
            _require(type(read_fd) is int and read_fd>=0 and type(write_fd) is int and write_fd>=0 and read_fd!=write_fd)
            self._clock()
            _require(self._last<=MAX_SAFE-120000);self._deadline=self._last+120000
            self._originals=(read_fd,write_fd)
            self._identities=(_identity(read_fd,os.O_RDONLY),_identity(write_fd,os.O_WRONLY))
            _require(self._identities[0][:2]!=self._identities[1][:2])
            self._read=os.dup(read_fd)
            self._write=os.dup(write_fd)
            self._check()
            return self
        except BaseException:self._fail()

    def _clock(self):
        value=self._clock_source()
        _require(type(value) is tuple and len(value)==2)
        boot,now=value
        _require(type(boot) is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot) is not None and
            type(now) is int and 0<=now<=MAX_SAFE and (self._boot is None or boot==self._boot) and
            (self._last is None or now>=self._last) and (self._deadline is None or now<self._deadline))
        self._boot=boot;self._last=now

    def _check(self):
        _require(not self._closed and not self._failed)
        self._clock()
        for original,owned,direction,identity in zip(self._originals,(self._read,self._write),
                (os.O_RDONLY,os.O_WRONLY),self._identities):
            _require(_identity(original,direction)==identity and _identity(owned,direction)==identity)
        self._clock()

    def _wait(self,fd,event):
        self._check()
        poll=select.poll();poll.register(fd,event)
        events=poll.poll(min(50,self._deadline-self._last))
        self._check()
        for actual,flags in events:
            _require(actual==fd and not flags&(select.POLLERR|select.POLLNVAL) and
                not (event==select.POLLOUT and flags&select.POLLHUP))

    def tighten(self,deadline_boottime_ms):
        try:
            self._check()
            _require(type(deadline_boottime_ms) is int and self._last<deadline_boottime_ms<=self._deadline)
            self._deadline=deadline_boottime_ms;self._check()
        except BaseException:self._fail()

    def read_frame(self):
        try:
            while True:
                self._check()
                end=self._pending.find(b'\n')
                if end>=0:
                    _require(end+1<=FRAME_LIMIT)
                    frame=bytes(self._pending[:end+1]);self._check()
                    del self._pending[:end+1]
                    return frame
                _require(len(self._pending)<=FRAME_LIMIT)
                self._check()
                try:raw=os.read(self._read,min(65536,FRAME_LIMIT+1-len(self._pending)))
                except BlockingIOError:
                    self._wait(self._read,select.POLLIN);continue
                self._check();_require(raw)
                self._pending.extend(raw)
        except BaseException:self._fail()

    def write_frame(self,frame):
        try:
            self._check()
            _require(type(frame) is bytes and 0<len(frame)<=FRAME_LIMIT and frame.endswith(b'\n') and frame.count(b'\n')==1)
            offset=0;view=memoryview(frame)
            while offset<len(frame):
                self._check()
                try:count=os.write(self._write,view[offset:])
                except BlockingIOError:
                    self._wait(self._write,select.POLLOUT);continue
                self._check();_require(type(count) is int and 0<count<=len(frame)-offset)
                offset+=count
            self._check()
        except BaseException:self._fail()

    def _fail(self):
        self._failed=True
        try:self.close()
        except BaseException:raise PipeError('cleanup_unconfirmed') from None
        raise PipeError() from None

    def close(self):
        if self._closed:return
        self._closed=True;self._pending.clear();failed=False
        for name in ('_write','_read'):
            owned=getattr(self,name);setattr(self,name,None)
            if owned is not None:
                try:os.close(owned)
                except BaseException:failed=True
        if failed:raise PipeError('cleanup_unconfirmed')
