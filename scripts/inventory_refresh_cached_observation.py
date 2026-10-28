"""Pinned cache/native reader session and fixed child metadata. No executable IPC.

The parent must persist admission/start before launching this trusted reader,
retain its own policy/cache guard through receipt persistence, and independently
supervise the reader deadline. Matching a job validates data, not child liveness.
"""
from dataclasses import asdict, dataclass, fields
import json

from inventory_refresh_protocol import correlator, safe_integer
from inventory_refresh_state import boot, hexadecimal, checked_timestamp, REASONS
from inventory_refresh_status import PublicStatus
from inventory_refresh_storage import MAX_FILES
from inventory_refresh_observation import NativeReadLocks, Observation, ObservationError

LIMIT=65536


def _require(condition):
    if not condition:
        raise ObservationError('invalid_request')


def _decode(raw):
    _require(type(raw) is bytes and 0<len(raw)<=LIMIT)
    def unique(pairs):
        value={}
        for key,item in pairs:
            _require(key not in value)
            value[key]=item
        return value
    try:
        return json.loads(raw,object_pairs_hook=unique)
    except (ValueError,UnicodeError,RecursionError):
        raise ObservationError('invalid_request') from None


@dataclass(frozen=True,slots=True)
class ObservationJob:
    schema_version:int
    job_id:str
    operation_nonce:str
    helper_sequence:int
    boot_id:str
    cache_generation:str
    policy_generation:str
    successful_checked_at:str
    accepted_boottime_ms:int
    started_boottime_ms:int
    deadline_boottime_ms:int

    def __post_init__(self):
        _require(type(self.schema_version) is int and self.schema_version==1 and
                 hexadecimal(self.job_id,32) and hexadecimal(self.operation_nonce,32) and
                 safe_integer(self.helper_sequence) and self.helper_sequence>0 and boot(self.boot_id) and
                 hexadecimal(self.cache_generation,32) and hexadecimal(self.policy_generation,64) and
                 all(safe_integer(value) for value in (self.accepted_boottime_ms,self.started_boottime_ms,self.deadline_boottime_ms)) and
                 self.accepted_boottime_ms<=self.started_boottime_ms<self.deadline_boottime_ms<=self.accepted_boottime_ms+120000)
        _require(correlator(self.operation_nonce.encode('ascii'))[1]==self.helper_sequence)
        checked_timestamp(self.successful_checked_at)

    @classmethod
    def parse(cls,raw):
        value=_decode(raw)
        _require(cls is ObservationJob and type(value) is dict and set(value)=={field.name for field in fields(cls)})
        return cls(**value)


def _job_from_document(value):
    _require(type(value) is dict and set(value)=={field.name for field in fields(ObservationJob)})
    return ObservationJob(**value)


@dataclass(frozen=True,slots=True)
class ReleaseGrant:
    job:ObservationJob
    requested_boottime_ms:int

    def __post_init__(self):
        _require(type(self.job) is ObservationJob and safe_integer(self.requested_boottime_ms) and
                 self.job.started_boottime_ms<=self.requested_boottime_ms<=self.job.deadline_boottime_ms)

    def encoded(self):
        return json.dumps({'schema_version':1,'job':asdict(self.job),
            'requested_boottime_ms':self.requested_boottime_ms},sort_keys=True,separators=(',',':')).encode('ascii')

    @classmethod
    def parse(cls,raw,*,expected_job):
        value=_decode(raw)
        _require(cls is ReleaseGrant and type(value) is dict and set(value)=={'schema_version','job','requested_boottime_ms'} and
                 type(value['schema_version']) is int and value['schema_version']==1 and type(expected_job) is ObservationJob)
        actual_job=_job_from_document(value['job'])
        _require(actual_job==expected_job)
        return cls(actual_job,value['requested_boottime_ms'])


class ObservationResult:
    __slots__=('_raw',)
    def __new__(cls,*args,**kwargs):
        raise TypeError('Use validated observation result construction')

    @classmethod
    def create(cls,job,phase,*,lease=None,receipt=None,reason=None):
        _require(cls is ObservationResult and type(job) is ObservationJob and type(phase) is str)
        if phase=='failed':
            _require(lease is None and receipt is None and type(reason) is str and reason in REASONS)
        else:
            _require(phase in ('opened','released') and reason is None)
            _require((phase=='opened' and lease is not None and receipt is None) or
                     (phase=='released' and receipt is not None and lease is None))
            # Structural reuse only; this status is never published or treated as
            # a correlated refresh success.
            status=PublicStatus.create({'schema_version':1,'operation_nonce':None,'phase':'unconfirmed',
                'reason':'cache_unavailable','policy_generation':job.policy_generation,
                'cache_generation':job.cache_generation,'successful_checked_at':job.successful_checked_at,
                'started_at':None,'finished_at':None,'attempt':None,
                'observation_lease':lease,'observation_receipt':receipt})
            validated=json.loads(status.encoded())
            lease=validated['observation_lease'];receipt=validated['observation_receipt']
            evidence=lease if phase=='opened' else receipt
            _require(all(evidence[key]==expected for key,expected in (
                ('nonce',job.operation_nonce),('boot_id',job.boot_id),
                ('cache_generation',job.cache_generation),('policy_generation',job.policy_generation))))
            _require(job.started_boottime_ms<=evidence['lock_open_boottime_ms'] and
                     evidence['expires_boottime_ms']<=job.deadline_boottime_ms)
            if phase=='released':
                _require(evidence['outcome']=='released')
        value={'schema_version':1,'job':asdict(job),'phase':phase,'observation_lease':lease,
               'observation_receipt':receipt,'reason':reason}
        raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
        _require(len(raw)<=LIMIT)
        result=object.__new__(cls)
        object.__setattr__(result,'_raw',raw)
        return result

    @classmethod
    def parse(cls,raw,*,expected_job):
        value=_decode(raw)
        _require(type(value) is dict and set(value)=={'schema_version','job','phase','observation_lease','observation_receipt','reason'})
        _require(type(value['schema_version']) is int and value['schema_version']==1 and type(expected_job) is ObservationJob)
        actual_job=_job_from_document(value['job'])
        _require(actual_job==expected_job)
        return cls.create(expected_job,value['phase'],lease=value['observation_lease'],
                          receipt=value['observation_receipt'],reason=value['reason'])

    def encoded(self):
        return self._raw

    def document(self):
        return json.loads(self._raw)

    def __setattr__(self,name,value):
        raise AttributeError('Observation result is immutable')


class CachedObservation:
    def __enter__(self):
        if self._closed:
            raise ObservationError('state_inconsistent')
        return self

    def __exit__(self,*_):
        self.abort()

    @classmethod
    def begin(cls,store,job,clock,*,guard_factory=None):
        _require(type(job) is ObservationJob)
        value=cls()
        value._job=job;value._clock=clock;value._last_time=None
        value._native=None;value._cache=None;value._cache_context=None;value._closed=False
        value._time(before_acquire=True)
        context=store.lease_current()
        try:
            value._cache=context.__enter__()
            value._cache_context=context
            manifest=value._cache.manifest
            _require(type(manifest) is dict and set(manifest)=={'schema_version','cache_generation','policy_generation','successful_checked_at','files'} and
                     type(manifest['schema_version']) is int and manifest['schema_version']==1 and
                     type(manifest['files']) is list and len(manifest['files'])<=MAX_FILES and
                     all(manifest.get(key)==expected for key,expected in (
                ('cache_generation',job.cache_generation),('policy_generation',job.policy_generation),
                ('successful_checked_at',job.successful_checked_at))))
            value._time(before_acquire=True)
            factory=NativeReadLocks.fixed if guard_factory is None else guard_factory
            guard=factory(deadline_ms=job.deadline_boottime_ms,now=value._time)
            # Observation.begin consumes the guard on both success and failure.
            value._native=Observation.begin(guard,job.operation_nonce,job.boot_id,job.cache_generation,
                job.policy_generation,job.accepted_boottime_ms,value._native_clock,deadline_ms=job.deadline_boottime_ms)
            value.opened_result()
            return value
        except BaseException:
            value.abort()
            raise

    def _time(self,*,before_acquire=False):
        try:
            boot_id,current=self._clock()
        except Exception:
            raise ObservationError('state_inconsistent') from None
        if (boot_id!=self._job.boot_id or not safe_integer(current) or current<self._job.started_boottime_ms or
                self._last_time is not None and current<self._last_time):
            raise ObservationError('state_inconsistent')
        self._last_time=current
        if current>self._job.deadline_boottime_ms or before_acquire and current==self._job.deadline_boottime_ms:
            raise ObservationError('lease_expired')
        return current

    def _native_clock(self):
        return self._job.boot_id,self._time()

    def _close_cache(self):
        context,self._cache_context=self._cache_context,None
        self._cache=None
        if context is not None:
            context.__exit__(None,None,None)

    def opened_result(self):
        if self._closed:
            raise ObservationError('state_inconsistent')
        try:
            return ObservationResult.create(self._job,'opened',lease=self._native.lease())
        except BaseException:
            self.abort()
            raise

    def verify_cache_index(self,relative):
        if self._closed:
            raise ObservationError('state_inconsistent')
        try:
            self._native.lease()
            result=self._cache.verify_index(relative)
            self._native.lease()
            return result
        except BaseException:
            self.abort()
            raise

    def finish_granted(self,grant):
        if self._closed:
            raise ObservationError('state_inconsistent')
        # Unrelated or premature grants cannot consume a live observation.
        _require(type(grant) is ReleaseGrant and grant.job==self._job)
        try:
            lease=self._native.lease()
            now=self._time()
        except BaseException:
            self.abort()
            raise
        _require(lease['lock_open_boottime_ms']<=grant.requested_boottime_ms<=now)
        return self.finish(grant.job.operation_nonce)

    def finish(self,nonce):
        if self._closed:
            raise ObservationError('state_inconsistent')
        # An unrelated release cannot consume or unwind this live ownership.
        if type(nonce) is not str or nonce!=self._job.operation_nonce:
            raise ObservationError('invalid_request')
        self._closed=True
        try:
            receipt=self._native.finish(nonce)
            result=ObservationResult.create(self._job,'released',receipt=receipt)
        finally:
            self._close_cache()
        return result

    def abort(self):
        if self._closed:
            return
        self._closed=True
        try:
            if self._native is not None:
                self._native.abort()
        finally:
            self._close_cache()
