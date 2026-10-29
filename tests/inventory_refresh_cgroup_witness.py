"""Borrowed-directory cgroup observation fixture, not liveness or completion authority.

The caller must own and protect the parent chain and prevent concurrent mutation;
this sampled check neither authenticates cgroupfs nor proves future emptiness.
"""
import os
import math
import re
import stat
import time


def observe_empty(parent,name,group,deadline):
    """Require the held and named group and its bounded events file to agree."""
    fd=None;failed=False
    try:
        assert type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,255}',name) and name not in ('.','..')
        assert type(deadline) in (float,int) and math.isfinite(deadline) and time.monotonic()<deadline
        def identity(info):return info.st_dev,info.st_ino,info.st_mode
        before=os.fstat(group);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
        assert stat.S_ISDIR(before.st_mode) and identity(before)==identity(named)
        fd=os.open('cgroup.events',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=group)
        event=os.fstat(fd);assert stat.S_ISREG(event.st_mode) and event.st_dev==before.st_dev
        raw=bytearray()
        while True:
            assert time.monotonic()<deadline
            chunk=os.read(fd,4097-len(raw));assert time.monotonic()<deadline
            if not chunk:break
            raw.extend(chunk);assert len(raw)<=4096
        named_event=os.stat('cgroup.events',dir_fd=group,follow_symlinks=False)
        assert identity(event)==identity(os.fstat(fd))==identity(named_event)
        assert identity(before)==identity(os.fstat(group))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
        assert raw.endswith(b'\n')
        fields={}
        for line in bytes(raw).splitlines():
            pieces=line.split(b' ');assert len(pieces)==2 and pieces[0] not in fields
            fields[pieces[0]]=pieces[1]
        assert set(fields)=={b'populated',b'frozen'} and fields[b'populated']==b'0' and fields[b'frozen'] in (b'0',b'1')
        assert time.monotonic()<deadline
    except BaseException:failed=True
    finally:
        if fd is not None:
            try:os.close(fd)
            except BaseException:failed=True
    if failed or time.monotonic()>=deadline:raise ValueError('Cgroup observation unconfirmed')
