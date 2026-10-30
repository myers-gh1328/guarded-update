"""Unregistered synthetic drain pipe mechanics; no authentication or readiness.

Caller owns distinct directional pipe descriptions exclusively. Deadlines are
sampled monotonic time, not hard syscall deadlines. Failure retains the caller's
maintenance owner; process crash is not a durable fence.
The frame is a synthetic sender assertion. Receiver EOF does not establish the
sender's successful pipe close; neither peer authentication nor cleanup follows.
"""
import fcntl
import math
import os
import select
import signal
import stat
import time

ERROR='Inventory maintenance control unavailable'
REQUEST=b'DRAIN\n'
RESPONSE=b'DRAINED_CLOSED\n'


class _Pipes:
    def __init__(self,read_fd,write_fd,deadline):
        self._fds=list(dict.fromkeys((read_fd,write_fd)));self.read=read_fd;self.write=write_fd;self.deadline=deadline
        self.failed=False;self.closed=False;self._owned={}
        try:
            if type(deadline) not in (int,float) or not math.isfinite(deadline) or signal.getsignal(signal.SIGPIPE)!=signal.SIG_IGN:raise ValueError(ERROR)
            if read_fd==write_fd:raise ValueError(ERROR)
            identities=[]
            for fd,mode in ((read_fd,os.O_RDONLY),(write_fd,os.O_WRONLY)):
                info=os.fstat(fd);self._owned[fd]=(info.st_dev,info.st_ino,info.st_mode)
                flags=fcntl.fcntl(fd,fcntl.F_GETFL)
                if not stat.S_ISFIFO(info.st_mode) or flags&os.O_ACCMODE!=mode:raise ValueError(ERROR)
                identities.append((info.st_dev,info.st_ino))
                fcntl.fcntl(fd,fcntl.F_SETFL,flags|os.O_NONBLOCK)
                if not fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_NONBLOCK:raise ValueError(ERROR)
            if identities[0]==identities[1]:raise ValueError(ERROR)
            self.identities=identities;self.check()
        except BaseException:
            self.failed=True;self.close();raise ValueError(ERROR) from None

    def check(self):
        if self.closed or self.failed or time.monotonic()>=self.deadline:raise ValueError(ERROR)
        for fd,identity,mode in ((self.read,self.identities[0],os.O_RDONLY),(self.write,self.identities[1],os.O_WRONLY)):
            if fd is None:continue
            info=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL)
            if (not stat.S_ISFIFO(info.st_mode) or (info.st_dev,info.st_ino)!=identity or
                    flags&os.O_ACCMODE!=mode or not flags&os.O_NONBLOCK):raise ValueError(ERROR)

    def wait(self,fd,reading):
        self.check();left=self.deadline-time.monotonic()
        ready=select.select([fd] if reading else [],[] if reading else [fd],[],max(0,left))
        self.check()
        if not (ready[0] if reading else ready[1]):raise ValueError(ERROR)

    def receive(self,expected):
        data=b''
        while True:
            self.wait(self.read,True)
            try:chunk=os.read(self.read,len(expected)+1-len(data))
            except BlockingIOError:continue
            self.check()
            if not chunk:break
            data+=chunk
            if len(data)>len(expected):raise ValueError(ERROR)
        if data!=expected:raise ValueError(ERROR)
        self.close_one('read')

    def send(self,data):
        offset=0
        while offset<len(data):
            self.wait(self.write,False)
            try:count=os.write(self.write,data[offset:])
            except BlockingIOError:continue
            self.check()
            if count<=0:raise ValueError(ERROR)
            offset+=count
        self.close_one('write')

    def close_one(self,name):
        self.check()
        fd=getattr(self,name);setattr(self,name,None)
        self._fds.remove(fd);os.close(fd);self.check()

    def close(self):
        if self.closed:return
        self.closed=True
        for fd in self._fds:
            try:
                info=os.fstat(fd)
                if self._owned.get(fd)!=(info.st_dev,info.st_ino,info.st_mode):
                    self.failed=True;continue
                os.close(fd)
            except OSError:self.failed=True
        self._fds=[]


def serve(runtime,request_fd,response_fd,deadline):
    pipes=_Pipes(request_fd,response_fd,deadline)
    try:
        pipes.receive(REQUEST)
        result=runtime.drain()
        if type(result) is not dict or set(result)!={'state','poll','release'} or result['state']!='drained':raise ValueError(ERROR)
        runtime.close()
        pipes.check();pipes.send(RESPONSE)
    except BaseException:
        pipes.failed=True
    finally:pipes.close()
    if pipes.failed or time.monotonic()>=deadline:raise ValueError(ERROR)


def request(owner,request_fd,response_fd,deadline):
    pipes=_Pipes(response_fd,request_fd,deadline)
    try:
        owner._gate.verify();pipes.send(REQUEST);pipes.receive(RESPONSE)
        pipes.check();owner._gate.verify()
    except BaseException:
        pipes.failed=True
    finally:pipes.close()
    if pipes.failed or time.monotonic()>=deadline:raise ValueError(ERROR)
    try:
        result=owner.try_lifetime();owner._gate.verify()
        if time.monotonic()>=deadline or type(result) is not bool:raise ValueError(ERROR)
        return result
    except BaseException:raise ValueError(ERROR) from None
