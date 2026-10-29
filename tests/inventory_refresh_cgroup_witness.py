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


def observe_single_process(parent,name,group,pid,deadline):
    """Sample an exclusive caller-protected fixture; no process-lifetime authority."""
    fd=None;failed=False
    try:
        assert type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,255}',name) and name not in ('.','..')
        assert type(pid) is int and 0<pid<=2147483647
        assert type(deadline) in (float,int) and math.isfinite(deadline) and time.monotonic()<deadline
        def identity(info):return info.st_dev,info.st_ino,info.st_mode
        before=os.fstat(group);assert stat.S_ISDIR(before.st_mode)
        def check_group():
            assert identity(before)==identity(os.fstat(group))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
        def members():
            names=[]
            with os.scandir(group) as directory:
                for entry in directory:
                    assert time.monotonic()<deadline and len(names)<512 and len(entry.name)<=255
                    names.append(entry.name)
            assert len(names)==len(set(names))
            entries={}
            for item in names:
                assert time.monotonic()<deadline
                info=os.stat(item,dir_fd=group,follow_symlinks=False)
                assert stat.S_ISREG(info.st_mode) and info.st_dev==before.st_dev
                entries[item]=identity(info)
            return entries
        check_group();first=members()
        fd=os.open('cgroup.procs',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=group)
        file_info=os.fstat(fd);assert stat.S_ISREG(file_info.st_mode) and file_info.st_dev==before.st_dev
        assert first.get('cgroup.procs')==identity(file_info)
        raw=bytearray()
        while True:
            assert time.monotonic()<deadline
            chunk=os.read(fd,4097-len(raw));assert time.monotonic()<deadline
            if not chunk:break
            raw.extend(chunk);assert len(raw)<=4096
        assert bytes(raw)==str(pid).encode('ascii')+b'\n'
        os.lseek(fd,0,os.SEEK_SET);second=bytearray()
        while True:
            assert time.monotonic()<deadline
            chunk=os.read(fd,4097-len(second));assert time.monotonic()<deadline
            if not chunk:break
            second.extend(chunk);assert len(second)<=4096
        assert second==raw
        assert identity(file_info)==identity(os.fstat(fd))==identity(os.stat('cgroup.procs',dir_fd=group,follow_symlinks=False))
        assert members()==first;check_group();assert time.monotonic()<deadline
    except BaseException:failed=True
    finally:
        if fd is not None:
            try:os.close(fd)
            except BaseException:failed=True
    if failed or time.monotonic()>=deadline:raise ValueError('Cgroup process sample unconfirmed')
