"""Trusted fixed native-reader roles, separately supervised by PID1.

No launch authority is inferred from metadata. Parent must own journal, policy,
cache, actual child/cgroup cleanup and durable restart reconciliation.
"""
import os
import subprocess
import sys
import time

from inventory_refresh_cached_observation import CachedObservation, ObservationResult
from inventory_refresh_channel import ObservationChannel
from inventory_refresh_guardian import supervise, retained_exit, LIB_ROOT, ENV
from inventory_refresh_observation import _Ancestry, ObservationError
from inventory_refresh_protocol import safe_integer
from inventory_refresh_state import boot
from inventory_refresh_storage import CacheReader


def _require(condition):
    if not condition:raise ObservationError('state_inconsistent')


def admit_profile(raw,*,guardian=False):
    _require(type(raw) is bytes and 0<len(raw)<=65536)
    required={'Uid','Gid','Groups','CapPrm','CapEff','CapBnd','CapInh','CapAmb','NoNewPrivs'}
    values={}
    for line in raw.decode('ascii').splitlines():
        key,separator,value=line.partition(':')
        if separator and key in required:
            _require(key not in values);values[key]=value.split()
    _require(set(values)==required)
    for key in ('Uid','Gid'):_require(values[key]==['0']*4)
    _require(values['Groups'] in ([],['0']) and values['NoNewPrivs']==['1'])
    for key in ('CapPrm','CapEff','CapBnd','CapInh','CapAmb'):
        _require(len(values[key])==1 and len(values[key][0])==16 and
                 all(char in '0123456789abcdef' for char in values[key][0]))
        expected=288 if guardian and key in ('CapPrm','CapEff','CapBnd') else 256 if guardian and key=='CapInh' else 0
        _require(int(values[key][0],16)==expected)


def identity(*,guardian=False):
    _require(sys.platform=='linux' and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0))
    with open('/proc/self/status','rb') as handle:admit_profile(handle.read(65537),guardian=guardian)


def kernel_clock():
    with open('/proc/sys/kernel/random/boot_id','rb') as handle:raw=handle.read(64)
    boot_id=raw.decode('ascii').strip()
    _require(boot(boot_id))
    return boot_id,time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000


def admit_job(job):
    boot_id,current=kernel_clock()
    _require(boot_id==job.boot_id and safe_integer(current) and
             job.started_boottime_ms<=current<job.deadline_boottime_ms)


class FixedCache:
    """Borrowed read-only cache descriptor, with full fixed ancestry held."""
    def __init__(self):
        self._ancestry=None
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            self._ancestry=_Ancestry.open(root,('var','cache','command-center-inventory-refresh'))
            self.reader=CacheReader(self._ancestry.fds[-1])
        except BaseException:
            self.close();raise
        finally:os.close(root)

    def __enter__(self):
        try:
            self._ancestry.verify();return self.reader
        except BaseException:
            self.close();raise

    def __exit__(self,*_):self.close()

    def close(self):
        ancestry,self._ancestry=self._ancestry,None
        if ancestry is not None:ancestry.close()


def native_argv():
    return ('/usr/bin/setpriv','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all',
            '--no-new-privs','/usr/bin/python3','-I','-B',LIB_ROOT+'/observation-native.py')


def run_guardian():
    channel=None
    try:
        identity(guardian=True)
        channel=ObservationChannel.fixed();job=channel.read_job();admit_job(job)
        channel.close();channel=None
        def clock():
            boot_id,current=kernel_clock();_require(boot_id==job.boot_id);return current
        def spawn():
            return subprocess.Popen(native_argv(),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,env=ENV,close_fds=True,cwd='/')
        return retained_exit(supervise(job.started_boottime_ms,job.deadline_boottime_ms,spawn,clock=clock))
    except Exception:return 74
    finally:
        if channel is not None:channel.close()


def run_native():
    channel=None;job=None;terminal_attempted=False
    try:
        identity()
        channel=ObservationChannel.fixed();job=channel.read_job();admit_job(job)
        with FixedCache() as reader:
            with CachedObservation.begin(reader,job,kernel_clock) as session:
                channel.write_result(session.opened_result())
                while True:
                    # Fresh actual lock/boot/deadline checks, without rewriting
                    # the frozen opened result or relying on a reporter request.
                    session.opened_result()
                    grant=channel.read_release(expected_job=job)
                    if grant is not None:
                        result=session.finish_granted(grant)
                        terminal_attempted=True
                        channel.write_result(result)
                        return 0
                    time.sleep(0.05)
    except Exception as exc:
        # Owned locks/cache have unwound before any failure metadata is exposed.
        # A release rename/fsync failure may already be visible; never contradict it.
        if channel is not None and job is not None and not terminal_attempted:
            reason=exc.reason if isinstance(exc,ObservationError) else 'state_inconsistent'
            try:channel.write_result(ObservationResult.create(job,'failed',reason=reason))
            except Exception:pass
        return 74
    finally:
        if channel is not None:channel.close()
