"""Bounded synthetic admission controller for disposable native CI only.

Borrows process streams exclusively; launch owner sets O_NONBLOCK and owns unit
retirement/original stream cleanup. EOF/exit0 here is not a durable Rust journal,
closed process-set, source/body or production completion witness. Never signals.
"""
import fcntl
import math
import os
import re
import select
import stat
import subprocess
import time

from inventory_refresh_reporter_protocol import DataDecoder,FRAME_LIMIT,MAX_SAFE,_encode,_load
from inventory_refresh_receipt import observation
from inventory_refresh_protocol import correlator
from inventory_refresh_state import boot,checked_timestamp


class ControllerError(ValueError):
    def __init__(self):super().__init__('Native reporter fixture dialogue unavailable')


def require(condition):
    if not condition:raise ControllerError()


def _safe(value):return type(value) is int and 0<=value<=MAX_SAFE
def _hex(value,size):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None


def _pipe(fd,direction):
    item=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL)
    require(stat.S_ISFIFO(item.st_mode) and flags&os.O_ACCMODE==direction and flags&os.O_NONBLOCK)
    return item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid


class _Pipes:
    def __init__(self,process,deadline):
        self._read=None;self._write=None;self._closed=False;self._pending=bytearray();self._last=None
        self._deadline=deadline
        try:
            now=self._time();require(0<deadline-now<=25)
            self._originals=(process.stdout.fileno(),process.stdin.fileno())
            self._identities=tuple(_pipe(fd,direction) for fd,direction in zip(self._originals,(os.O_RDONLY,os.O_WRONLY)))
            require(self._identities[0][:2]!=self._identities[1][:2])
            self._read=os.dup(self._originals[0]);self._write=os.dup(self._originals[1]);self.check()
        except BaseException:
            self.close();raise ControllerError() from None

    def _time(self):
        now=time.monotonic()
        require(type(now) in (int,float) and math.isfinite(now) and now>=0 and
            type(self._deadline) in (int,float) and math.isfinite(self._deadline) and now<self._deadline and
            (self._last is None or now>=self._last))
        self._last=now;return now

    def check(self):
        require(not self._closed);self._time()
        for original,owned,direction,identity in zip(self._originals,(self._read,self._write),(os.O_RDONLY,os.O_WRONLY),self._identities):
            require(_pipe(original,direction)==identity and _pipe(owned,direction)==identity)
        self._time()

    def _wait(self,fd,event):
        self.check();poll=select.poll();poll.register(fd,event)
        events=poll.poll(min(50,max(1,math.ceil((self._deadline-self._last)*1000))))
        self.check()
        for actual,flags in events:
            require(actual==fd and not flags&(select.POLLERR|select.POLLNVAL) and
                not (event==select.POLLOUT and flags&select.POLLHUP))

    def write(self,value):
        raw=_encode(value);offset=0
        while offset<len(raw):
            self.check()
            try:count=os.write(self._write,raw[offset:])
            except BlockingIOError:self._wait(self._write,select.POLLOUT);continue
            self.check();require(0<count<=len(raw)-offset);offset+=count
        self.check()

    def _read_some(self):
        while True:
            self.check()
            try:raw=os.read(self._read,min(65536,FRAME_LIMIT+1-len(self._pending)))
            except BlockingIOError:self._wait(self._read,select.POLLIN);continue
            self.check();return raw

    def read(self):
        while True:
            self.check();end=self._pending.find(b'\n')
            if end>=0:
                require(end+1<=FRAME_LIMIT);raw=bytes(self._pending[:end+1]);del self._pending[:end+1]
                self.check();return raw
            require(len(self._pending)<=FRAME_LIMIT);raw=self._read_some();require(raw);self._pending.extend(raw)

    def finish(self,process):
        self.check();require(not self._pending)
        require(self._read_some()==b'')  # No valid-prefix surplus, even whitespace.
        while process.poll() is None:
            self.check()
            try:process.wait(timeout=min(.05,self._deadline-self._last))
            except subprocess.TimeoutExpired:continue
        self.check();require(type(process.returncode) is int and process.returncode==0)

    def close(self):
        if self._closed:return
        self._closed=True;descriptors=(self._write,self._read);self._write=self._read=None;failed=False
        for fd in descriptors:
            if fd is not None:
                try:os.close(fd)
                except BaseException:failed=True
        if failed:raise ControllerError()


def _response(raw,identifier,operation,phase,fields=()):
    value=_load(raw)
    require(set(value)=={'schema_version','id','operation','phase'}|set(fields) and
        type(value['schema_version']) is int and value['schema_version']==1 and
        type(value['id']) is int and value['id']==identifier and value['operation']==operation and value['phase']==phase)
    return value


def _context(value):
    require(type(value) is dict and set(value)=={'cache_generation','policy_generation','successful_checked_at','boot_id'} and
        _hex(value['cache_generation'],32) and _hex(value['policy_generation'],64) and boot(value['boot_id']))
    checked_timestamp(value['successful_checked_at'])


def run_reporter_controller(process,*,expected_context,read_root_status,nonce,deadline):
    """Run fixed OBS/query/release fixture; caller still owns all native cleanup.

    read_root_status is a trusted bounded fresh Root status reader. This test-only
    callback and the scan_admitted frame are synthetic, with no journal fsync.
    """
    pipes=None;result=None;failed=False
    try:
        _context(expected_context);context=dict(expected_context)
        require(type(nonce) is str and correlator(nonce.encode('ascii'))[0]==nonce)
        pipes=_Pipes(process,deadline)
        initial=_response(pipes.read(),0,'initialize','pinned',('context',))['context']
        require(type(initial) is dict and set(initial)==set(context)|{'pinned_boottime_ms'} and
            all(initial[key]==value for key,value in context.items()) and _safe(initial['pinned_boottime_ms']))
        def send(identifier,operation,**fields):
            pipes.write(dict(schema_version=1,id=identifier,operation=operation,**fields))
        def root(field):
            pipes.check();status=read_root_status();pipes.check()
            require(type(status) is dict and field in status);return status[field]
        send(1,'publish_observation',nonce=nonce);_response(pipes.read(),1,'publish_observation','published')
        send(2,'await_open');proposal=_response(pipes.read(),2,'await_open','scan_proposed',('offer','scan_started_boottime_ms'))
        offer=observation(proposal['offer']);require(offer==observation(root('observation_lease')))
        require(offer['nonce']==nonce and all(offer[key]==context[key] for key in ('boot_id','cache_generation','policy_generation')))
        started=proposal['scan_started_boottime_ms'];require(_safe(started) and
            initial['pinned_boottime_ms']<=offer['lock_open_boottime_ms']<=started<offer['expires_boottime_ms'])
        send(3,'scan_admitted',scan_started_boottime_ms=started)
        ack=_response(pipes.read(),3,'scan_admitted','scanning',('scan_started_boottime_ms',))
        require(_safe(ack['scan_started_boottime_ms']) and ack['scan_started_boottime_ms']==started)
        decoder=DataDecoder();data={}
        for identifier,operation in ((4,'installed'),(5,'architecture'),(6,'holds'),(7,'policy')):
            send(identifier,operation,**({'packages':['inventory-proof']} if operation=='policy' else {}))
            assembly=decoder.start(identifier,operation)
            try:
                while True:
                    raw=pipes.read();assembly.feed(raw)
                    if _load(raw)['phase']=='data_complete':break
                data[operation]=assembly.take()
            finally:assembly.close()
        require(data['installed'] and re.fullmatch('[a-z0-9][a-z0-9-]*\n',data['architecture']) is not None and
            re.search(r'(?m)^\s*Candidate: 1\.0\s*$',data['policy']) is not None and
            re.search(r'(?m)^\s*(?:\*\*\*\s+)?1\.0\s+123\s*$',data['policy']) is not None)
        send(8,'freeze_scan');scan=_response(pipes.read(),8,'freeze_scan','scan_frozen',('scan',))['scan']
        require(type(scan) is dict and set(scan)=={'scan_started_boottime_ms','scan_finished_boottime_ms','installed_before_sha256','installed_after_sha256'} and
            _safe(scan['scan_started_boottime_ms']) and scan['scan_started_boottime_ms']==started and _safe(scan['scan_finished_boottime_ms']) and
            started<=scan['scan_finished_boottime_ms']<=offer['expires_boottime_ms'] and _hex(scan['installed_before_sha256'],64) and
            scan['installed_before_sha256']==scan['installed_after_sha256'])
        send(9,'publish_release',nonce=nonce);_response(pipes.read(),9,'publish_release','published')
        send(10,'await_receipt');evidence=_response(pipes.read(),10,'await_receipt','prepared',('evidence',))['evidence']
        require(type(evidence) is dict and set(evidence)=={'schema_version','scan_started_boottime_ms','scan_finished_boottime_ms','successful_checked_at','observation_receipt'} and
            type(evidence['schema_version']) is int and evidence['schema_version']==1 and
            evidence['successful_checked_at']==context['successful_checked_at'])
        receipt=observation(evidence['observation_receipt'],True);require(receipt==observation(root('observation_receipt'),True) and receipt['outcome']=='released' and
            all(receipt[key]==value for key,value in offer.items()) and receipt['installed_before_sha256']==scan['installed_before_sha256'] and
            receipt['installed_after_sha256']==scan['installed_after_sha256'] and
            scan['scan_finished_boottime_ms']<=receipt['lock_held_until_boottime_ms'])
        for key in ('scan_started_boottime_ms','scan_finished_boottime_ms'):
            require(_safe(evidence[key]) and evidence[key]==scan[key])
        pipes.finish(process)
        result=dict(context=initial,offer=offer,scan=scan,evidence=evidence,data=data,mechanics_only=True)
    except BaseException:failed=True
    finally:
        if pipes is not None:
            try:pipes.close()
            except BaseException:failed=True
    if failed:raise ControllerError() from None
    return result
