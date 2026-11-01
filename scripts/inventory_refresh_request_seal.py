"""Unregistered root-marker observation; no enrollment, legacy or start authority.

The caller supplies an already locked root journal and an independently pinned
lock verifier. These samples do not prove process cleanup, immutable ancestry,
anti-rollback or durable marker creation. No production runtime calls this.
"""
import json
import math
import os
import re
import stat
import sys
import time

from inventory_refresh_observation import _Ancestry

ERROR='Initialized request seal unavailable'


class SealError(ValueError):
    pass


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _pairs(values):
    result={}
    for key,value in values:
        if key in result:raise SealError(ERROR)
        result[key]=value
    return result


def publish(journal,root,owner,group,enrollment,epoch,deadline,verify_lock):
    """Durably create one marker; caller must separately prove producer drain.

    This fixture seam does not authenticate the caller's lock verifier, prove
    cleanup or prevent restart. Failure preserves any partial marker.
    """
    if (type(owner) is not int or type(group) is not int or type(deadline) not in (int,float) or not math.isfinite(deadline) or
            type(enrollment) is not str or re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',enrollment) is None or
            type(epoch) is not str or re.fullmatch(r'[0-9a-f]{32}',epoch) is None or not callable(verify_lock)):
        raise SealError(ERROR)
    ancestry=None;fd=None;failed=False
    try:
        def check():
            verify_lock();now=time.monotonic()
            if not math.isfinite(now) or now>=deadline:raise SealError(ERROR)
        check();before_journal=journal.counter_snapshot();check()
        if before_journal['root_epoch']!=epoch:raise SealError(ERROR)
        ancestry=_Ancestry.open(root,('var','lib','command-center-inventory-refresh'),owner=owner)
        parent=ancestry.fds[-1]
        fd=os.open('initialized-requests',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parent)
        os.fchmod(fd,0o644)
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or before.st_gid!=group or
                stat.S_IMODE(before.st_mode)!=0o644 or before.st_nlink!=1):raise SealError(ERROR)
        raw=json.dumps({'schema_version':1,'enrollment_id':enrollment,'root_epoch':epoch},separators=(',',':'),sort_keys=True).encode('utf-8')
        offset=0
        while offset<len(raw):
            check();count=os.write(fd,raw[offset:]);check()
            if count<=0 or count>len(raw)-offset:raise SealError(ERROR)
            offset+=count
        check();os.fsync(fd);check();os.fsync(parent);check()
        os.lseek(fd,0,os.SEEK_SET);content=bytearray()
        while len(content)<=len(raw):
            check();chunk=os.read(fd,len(raw)+1-len(content));check()
            if not chunk:break
            content.extend(chunk)
        if bytes(content)!=raw:raise SealError(ERROR)
        held=os.fstat(fd);named=os.stat('initialized-requests',dir_fd=parent,follow_symlinks=False)
        if (held.st_dev,held.st_ino)!=(before.st_dev,before.st_ino) or _identity(held)!=_identity(named) or held.st_size!=len(raw):raise SealError(ERROR)
        ancestry.verify();check()
        if journal.counter_snapshot()!=before_journal:raise SealError(ERROR)
        check()
    except BaseException:failed=True
    finally:
        if fd is not None:
            try:os.close(fd)
            except OSError:failed=True
        if ancestry is not None:
            try:ancestry.close()
            except BaseException:failed=True
    if failed:raise SealError(ERROR)


def observe(journal,root,owner,group,enrollment,epoch,deadline,verify_lock):
    """Fixture seam: returns observed metadata only, never an execution permit."""
    if (type(owner) is not int or type(group) is not int or type(deadline) not in (int,float) or not math.isfinite(deadline) or
            type(enrollment) is not str or re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',enrollment) is None or
            type(epoch) is not str or re.fullmatch(r'[0-9a-f]{32}',epoch) is None or not callable(verify_lock)):
        raise SealError(ERROR)
    ancestry=None;fd=None;failed=False;result=None
    try:
        def check():
            verify_lock()
            now=time.monotonic()
            if not math.isfinite(now) or now>=deadline:raise SealError(ERROR)
        check();before_journal=journal.counter_snapshot();check()
        if before_journal['root_epoch']!=epoch:raise SealError(ERROR)
        ancestry=_Ancestry.open(root,('var','lib','command-center-inventory-refresh'),owner=owner)
        parent=ancestry.fds[-1]
        fd=os.open('initialized-requests',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or before.st_gid!=group or
                stat.S_IMODE(before.st_mode)!=0o644 or before.st_nlink!=1 or not 0<before.st_size<=512 or
                _identity(os.stat('initialized-requests',dir_fd=parent,follow_symlinks=False))!=_identity(before)):
            raise SealError(ERROR)
        raw=bytearray()
        while True:
            check();chunk=os.read(fd,513-len(raw));check()
            if not chunk:break
            raw.extend(chunk)
            if len(raw)>512:raise SealError(ERROR)
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs)
        if (type(value) is not dict or set(value)!={'schema_version','enrollment_id','root_epoch'} or
                type(value['schema_version']) is not int or value['schema_version']!=1 or
                value['enrollment_id']!=enrollment or value['root_epoch']!=epoch or len(raw)!=before.st_size or
                _identity(os.fstat(fd))!=_identity(before) or
                _identity(os.stat('initialized-requests',dir_fd=parent,follow_symlinks=False))!=_identity(before)):
            raise SealError(ERROR)
        ancestry.verify();check()
        if journal.counter_snapshot()!=before_journal:raise SealError(ERROR)
        # Presence cannot prove the writer completed fsync or close: a failed
        # publisher may have left a complete-looking record behind.
        check();result={'state':'present_unconfirmed','enrollment_id':enrollment,'root_epoch':epoch}
    except BaseException:failed=True
    finally:
        if fd is not None:
            try:os.close(fd)
            except OSError:failed=True
        if ancestry is not None:
            try:ancestry.close()
            except BaseException:failed=True
    if failed or result is None:raise SealError(ERROR)
    try:
        check()
        if journal.counter_snapshot()!=before_journal:raise SealError(ERROR)
        check()
    except BaseException:raise SealError(ERROR) from None
    return result


def fixed(journal,enrollment,epoch,deadline,verify_lock):
    """Root-only fixed path. Unregistered; this does not provision a seal."""
    if sys.platform!='linux' or os.getresuid()!=(0,0,0) or os.getresgid()!=(0,0,0):raise SealError(ERROR)
    root=None;result=None;failed=False
    try:
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
        result=observe(journal,root,0,0,enrollment,epoch,deadline,verify_lock)
    except BaseException:failed=True
    finally:
        if root is not None:
            try:os.close(root)
            except OSError:failed=True
    if failed or result is None:raise SealError(ERROR)
    return result


def publish_fixed(journal,enrollment,epoch,deadline,verify_lock):
    """Root-only fixed writer; unregistered and not a producer-drain proof."""
    if sys.platform!='linux' or os.getresuid()!=(0,0,0) or os.getresgid()!=(0,0,0):raise SealError(ERROR)
    root=None;failed=False
    try:
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
        publish(journal,root,0,0,enrollment,epoch,deadline,verify_lock)
    except BaseException:failed=True
    finally:
        if root is not None:
            try:os.close(root)
            except OSError:failed=True
    if failed:raise SealError(ERROR)
