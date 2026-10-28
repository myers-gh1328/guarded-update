"""Internal root observation lifecycle; no executable or provisioning authority.

The caller retains one reconciled journal lock and the fixed policy/resource
context throughout this object. A new object never reconstructs process ownership
from durable running metadata. Collaborator injection is for internal tests only.
"""
import os
import secrets

from inventory_refresh_cached_observation import ObservationJob, ObservationResult, ReleaseGrant
from inventory_refresh_coordinator import publish_current_status
from inventory_refresh_guardian import COMPLETED_EXIT
from inventory_refresh_observer import kernel_clock
from inventory_refresh_protocol import correlator, safe_integer
from inventory_refresh_service import ObservationService
from inventory_refresh_state import boot


def _nonce(value):
    try:return correlator(value.encode('ascii'))[0]
    except (ValueError,AttributeError,UnicodeError):
        raise ValueError('Invalid inventory observation request') from None


class ObservationTransaction:
    def __init__(self,journal,policy,resources,store,publisher,writers,channel,*,
                 service_factory=ObservationService,clock=kernel_clock):
        self._journal=journal;self._policy=policy;self._resources=resources;self._store=store
        self._publisher=publisher;self._writers=writers;self._channel=channel
        self._factory=service_factory;self._clock=clock;self._previous=None
        self._service=None;self._pin=None;self._manifest=None;self._job=None
        self._opened=None;self._grant=None;self._phase='idle';self._poisoned=False

    def _time(self):
        identity,now=self._clock()
        if (not boot(identity) or not safe_integer(now) or
                self._previous is not None and (identity!=self._previous[0] or now<self._previous[1]) or
                self._job is not None and identity!=self._job.boot_id):
            raise ValueError('Inventory observation clock unavailable')
        self._previous=(identity,now);return identity,now

    def _context(self):
        self._journal._locked();self._policy.recheck();self._resources.sample()
        if self._journal.snapshot()['unconfirmed']:raise ValueError('Inventory observation unconfirmed')
        identity,now=self._time()
        if self._manifest is not None:
            with self._store.lease_current() as current:
                if current.manifest!=self._manifest:raise ValueError('Inventory observation cache changed')
            if self._policy.generation!=self._manifest['policy_generation']:
                raise ValueError('Inventory observation policy changed')
        return identity,now

    def _status(self,*,lease=None,reason=None):
        try:current_policy=self._policy.generation
        except BaseException:
            if lease is not None:raise
            current_policy=None
        manifest=None
        if self._manifest is not None:
            try:
                with self._store.lease_current() as current:
                    if current.manifest!=self._manifest:raise ValueError('Inventory observation cache changed')
                    manifest=current.manifest
            except BaseException:
                if lease is not None:raise
        publish_current_status(self._journal,self._publisher,boot_id=self._previous[0],
            current_policy=current_policy,manifest=manifest,
            observation_lease=lease,operational_health=reason)

    def _unpin(self):
        pin,self._pin=self._pin,None
        if pin is not None:pin.__exit__(None,None,None)

    def _cleanup(self):
        if self._service is not None:
            # Retain the handle on uncertain close; never infer successful cleanup.
            self._service.close();self._service=None
        self._writers.check()

    def _fatal(self):
        self._poisoned=True;self._phase='unconfirmed'
        try:self._cleanup()
        except BaseException:pass
        try:self._journal.fence_external()
        except BaseException:pass
        try:self._unpin()
        except BaseException:pass
        try:self._status(reason='cleanup_unconfirmed')
        except BaseException:pass

    def begin(self,nonce):
        nonce=_nonce(nonce)
        if self._poisoned:return 'unconfirmed'
        if self._service is not None:
            return 'existing' if nonce==self._job.operation_nonce else 'busy'
        try:
            self._journal._locked()
            if self._journal.snapshot()['unconfirmed']:return 'unconfirmed'
            self._policy.recheck();self._resources.sample();identity,now=self._time()
            # Prior completions are immutable even if their cache later disappears.
            state=self._journal.snapshot()['capabilities']['observation']
            for record in (state['active'],state['terminal']):
                if record is not None and record['correlator']==nonce:return 'existing'
            try:
                os.stat('current.json',dir_fd=self._store.fd,follow_symlinks=False)
            except FileNotFoundError:
                self._pin=None;self._manifest=None;self._status(reason='cache_unavailable');return 'unavailable'
            pin=self._store.lease_current();current=pin.__enter__();self._pin=pin
            self._manifest=current.manifest
            success=self._journal.snapshot()['last_success']
            if (success is None or success['attempt']['boot_id']!=identity or
                    success['attempt']['cache_generation']!=self._manifest['cache_generation'] or
                    success['attempt']['policy_generation']!=self._manifest['policy_generation'] or
                    self._policy.generation!=self._manifest['policy_generation'] or
                    success['successful_checked_at']!=self._manifest['successful_checked_at']):
                self._unpin();self._status(reason='cache_unavailable');return 'unavailable'
            decision=self._journal.receive('observation',nonce,identity,now,self._policy.generation)
            if decision!='new':self._unpin();return decision
            self._writers.check();_,started=self._context()
            if started>=now+120000:raise ValueError('Inventory observation admission expired')
            if not self._journal.start('observation',nonce,identity,started,policy=self._policy.generation):
                raise ValueError('Inventory observation start unavailable')
            self._job=ObservationJob(1,secrets.token_hex(16),nonce,correlator(nonce.encode('ascii'))[1],identity,
                self._manifest['cache_generation'],self._policy.generation,self._manifest['successful_checked_at'],
                now,started,now+120000)
            self._opened=None;self._grant=None
            self._channel.write_job(self._job)
            self._service=self._factory(self._journal,self._channel,self._job)
            self._service.launch();self._phase='opening';self._status();return 'dispatched'
        except BaseException:
            self._fatal();raise ValueError('Inventory observation transaction unconfirmed') from None

    def _live(self):
        result=self._service.live_opened()
        if result is None:
            if self._opened is not None:raise ValueError('Inventory observation offer disappeared')
            return None
        if type(result) is not ObservationResult:raise ValueError('Invalid live observation')
        result=ObservationResult.parse(result.encoded(),expected_job=self._job)
        value=result.document()
        if value['phase']!='opened':raise ValueError('Invalid live observation phase')
        if self._opened is not None and result.encoded()!=self._opened.encoded():
            raise ValueError('Inventory observation offer changed')
        self._opened=result;return value['observation_lease']

    def release(self,nonce):
        nonce=_nonce(nonce)
        # Reporter mistakes cannot terminate a valid unrelated lifecycle.
        if self._job is None or nonce!=self._job.operation_nonce:return 'ignored'
        if self._poisoned:return 'unconfirmed'
        if self._grant is not None:return 'existing'
        if self._service is None:return 'ignored'
        if self._opened is None:return 'not_ready'
        try:
            identity,now=self._context()
            if now>=self._job.deadline_boottime_ms:
                self._fail('lease_expired');return 'not_ready'
            lease=self._live()
            if lease is None:return 'not_ready'
            _,now=self._context()
            if now>=lease['expires_boottime_ms']:
                self._fail('lease_expired');return 'not_ready'
            if self._journal.receive('release',nonce,identity,now,self._policy.generation)!='new':
                raise ValueError('Inventory release cannot be replayed')
            _,started=self._context()
            if started>=lease['expires_boottime_ms']:raise ValueError('Inventory release expired')
            if not self._journal.start('release',nonce,identity,started,policy=self._policy.generation):
                raise ValueError('Inventory release cannot start')
            self._grant=ReleaseGrant(self._job,started)
            self._phase='releasing';self._status()
            self._channel.write_release(self._grant);return 'releasing'
        except BaseException:
            self._fatal();raise ValueError('Inventory observation release unconfirmed') from None

    def _fail(self,reason):
        if reason=='cleanup_unconfirmed':raise ValueError('Native observation cleanup unconfirmed')
        self._cleanup();identity,now=self._context()
        for capability in ('release','observation'):
            record=self._journal.snapshot()['capabilities'][capability]['active']
            if record is not None and record['correlator']==self._job.operation_nonce:
                self._journal.finish(capability,self._job.operation_nonce,identity,now,'failed',reason)
        self._unpin();self._phase='failed';self._status(reason=reason);return 'failed'

    def poll(self):
        if self._poisoned:return 'unconfirmed'
        if self._service is None:return self._phase
        try:
            _,now=self._context()
            result=self._channel.read_result(expected_job=self._job)
            value=None if result is None else result.document()
            if value is not None and value['phase']=='released':
                if self._grant is None or self._opened is None:raise ValueError('Unsolicited observation receipt')
                receipt=value['observation_receipt'];lease=self._opened.document()['observation_lease']
                if (any(receipt[key]!=item for key,item in lease.items()) or
                        not receipt['lock_open_boottime_ms']<=self._grant.requested_boottime_ms<=receipt['lock_held_until_boottime_ms'] or
                        receipt['released_boottime_ms']>now):
                    raise ValueError('Observation receipt does not bind its grant')
                if self._service.wait(timeout=5)!=COMPLETED_EXIT:raise ValueError('Observation termination unconfirmed')
                self._cleanup();self._context()
                self._journal.finish_observation(receipt)
                self._unpin();self._phase='succeeded';self._status();return 'succeeded'
            if now>=self._job.deadline_boottime_ms:return self._fail('lease_expired')
            if value is not None and value['phase']=='failed':return self._fail(value['reason'])
            if self._service.poll() is not None:return self._fail('internal_error')
            if self._grant is not None:return 'releasing'
            lease=self._live()
            if lease is None:return 'opening'
            _,now=self._context()
            if now>=lease['expires_boottime_ms']:return self._fail('lease_expired')
            self._phase='opened';self._status(lease=lease);return 'opened'
        except BaseException:
            self._fatal();raise ValueError('Inventory observation transaction unconfirmed') from None

    def close(self):
        if self._service is not None or self._pin is not None:self._fatal()
