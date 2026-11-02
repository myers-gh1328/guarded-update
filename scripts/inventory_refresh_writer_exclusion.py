"""Read-only writer exclusion at a publication boundary, not future attestation.

Reserved refresh UID, cooperating launchers and initial host namespaces are
trusted provisioning prerequisites. Every thread's four kernel UIDs are checked.
A scan cannot prevent a privileged actor launching a new writer afterwards.
"""
import os
import re
import stat
import sys

from inventory_refresh_observation import _Ancestry, _identity
from inventory_refresh_resources import mount_rows, _mount_id, _proc, _Chain

SLICE=('command.slice','command-center.slice','command-center-inventory.slice','command-center-inventory-worker.slice')
MAX_TASKS=32768


def _require(condition):
    if not condition:raise ValueError('Inventory writer exclusion unavailable')


def task_identity(raw,tgid,tid,worker_uid):
    _require(type(raw) is bytes and 0<len(raw)<=65536)
    fields={}
    for line in raw.splitlines():
        name,separator,value=line.partition(b':')
        if name in (b'Tgid',b'Pid',b'Uid'):
            _require(separator and name not in fields);fields[name]=value.split()
    _require(set(fields)=={b'Tgid',b'Pid',b'Uid'} and fields[b'Tgid']==[str(tgid).encode()] and fields[b'Pid']==[str(tid).encode()])
    ids=fields[b'Uid']
    _require(len(ids)==4 and all(re.fullmatch(rb'(0|[1-9][0-9]{0,9})',value) and int(value)<=2**32-1 for value in ids))
    result=tuple(map(int,ids));_require(worker_uid not in result);return result


def proc_mount(raw,*,mount_id,device):
    all_rows=mount_rows(raw)
    _require(not any(re.fullmatch(r'/proc/(?:[0-9]+|self|thread-self)(?:/.*)?',row['path']) for row in all_rows.values()))
    rows=[row for row in all_rows.values() if row['path']=='/proc']
    _require(len(rows)==1)
    row=rows[0]
    _require(row['root']=='/' and row['fs']==b'proc' and row['id']==mount_id and row['device']==device)
    for line in raw.splitlines():
        fields=line.split(b' ')
        if int(fields[0])!=mount_id:continue
        split=fields.index(b'-');options=set(fields[5].split(b',')+fields[split+3].split(b','))
        _require(not any(value.startswith(b'hidepid=') and value!=b'hidepid=0' for value in options))
        _require(not any(value.startswith(b'subset=') and value!=b'subset=all' for value in options))


def _read(directory,name):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        _require(stat.S_ISREG(os.fstat(fd).st_mode))
        result=bytearray()
        while True:
            raw=os.read(fd,65537-len(result))
            if not raw:break
            result.extend(raw);_require(len(result)<=65536)
        return bytes(result)
    finally:os.close(fd)


def _gone(directory,name):
    try:os.stat(name,dir_fd=directory,follow_symlinks=False)
    except FileNotFoundError:return True
    return False


class WriterExclusion:
    def __init__(self):self._proc=None;self._cgroup=None;self._closed=False

    @classmethod
    def fixed(cls,worker_uid):
        _require(sys.platform=='linux' and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0) and type(worker_uid) is int and worker_uid>0)
        value=cls();root=None
        try:
            root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            value._proc=_Ancestry.open(root,('proc',))
            value._cgroup=_Chain(('sys','fs','cgroup')+SLICE)
            value._uid=worker_uid;value.check();return value
        except BaseException:
            try:value.close()
            finally:raise ValueError('Inventory writer exclusion unavailable') from None
        finally:
            if root is not None:
                try:os.close(root)
                except OSError:
                    value.close()
                    raise ValueError('Inventory writer exclusion cleanup unconfirmed') from None

    def _scope(self):
        _require(not self._closed)
        self._proc.verify();self._cgroup.verify()
        proc=self._proc.fds[-1];info=os.fstat(proc)
        proc_mount(_proc('mountinfo',1024*1024),mount_id=_mount_id(proc),device=(os.major(info.st_dev),os.minor(info.st_dev)))
        fields={}
        for line in _read(self._cgroup.fds[-1],'cgroup.events').splitlines():
            key,number=line.split();_require(key not in fields);fields[key]=number
        _require(fields.get(b'populated')==b'0')

    def check(self):
        try:
            self._scope();proc=self._proc.fds[-1];count=0
            with os.scandir(proc) as groups:
                for group in groups:
                    if not re.fullmatch('[1-9][0-9]{0,9}',group.name):continue
                    count+=1;_require(count<=MAX_TASKS)
                    tgid=int(group.name);parent=None;tasks=None;validated=0
                    try:
                        parent=os.open(group.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=proc)
                        tasks=os.open('task',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                        with os.scandir(tasks) as threads:
                            for thread in threads:
                                _require(re.fullmatch('[1-9][0-9]{0,9}',thread.name) is not None)
                                count+=1;_require(count<=MAX_TASKS);task=None
                                try:
                                    task=os.open(thread.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=tasks)
                                    task_identity(_read(task,'status'),tgid,int(thread.name),self._uid)
                                    validated+=1
                                    _require(_identity(os.stat(thread.name,dir_fd=tasks,follow_symlinks=False))==_identity(os.fstat(task)))
                                except FileNotFoundError:
                                    _require(_gone(tasks,thread.name))
                                finally:
                                    if task is not None:os.close(task)
                        _require(_identity(os.stat(group.name,dir_fd=proc,follow_symlinks=False))==_identity(os.fstat(parent)))
                        _require(validated>0)
                    except FileNotFoundError:
                        _require(_gone(proc,group.name))
                    finally:
                        try:
                            if tasks is not None:os.close(tasks)
                        finally:
                            if parent is not None:os.close(parent)
            self._scope()
        except BaseException:
            self._closed=True
            raise ValueError('Inventory writer exclusion unavailable') from None

    def close(self):
        self._closed=True;failure=False
        for name in ('_proc','_cgroup'):
            value=getattr(self,name);setattr(self,name,None)
            if value is not None:
                try:value.close()
                except (OSError,ValueError):failure=True
        if failure:raise ValueError('Inventory writer exclusion cleanup unconfirmed') from None
