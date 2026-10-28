"""Root refresh composition, not an executable or readiness/provisioning API.

Caller holds the reconciled Journal for the whole lifecycle and supplies actual
fixed-origin resources, cache, policy, status and writer guards. Production
activation must additionally establish trusted namespace/launcher provenance.
Collaborators are injectable only for internal tests; no caller commands/paths.
"""
from datetime import datetime,timezone
import os
import secrets

from inventory_refresh_protocol import correlator,safe_integer
from inventory_refresh_state import boot
from inventory_refresh_coordinator import publish_current_status
from inventory_refresh_materializer import RefreshMaterializer
from inventory_refresh_worker_service import RefreshService
from inventory_refresh_observation import NativeReadLocks,ObservationError
from inventory_refresh_observer import kernel_clock


class RefreshTransaction:
    def __init__(self,journal,policy,resources,store,publisher,writers,*,
                 materializer_factory=RefreshMaterializer.fixed,service_factory=RefreshService,
                 native_factory=NativeReadLocks.fixed,clock=kernel_clock):
        self._journal=journal;self._policy=policy;self._resources=resources;self._store=store
        self._publisher=publisher;self._writers=writers;self._materializer_factory=materializer_factory
        self._service_factory=service_factory;self._native_factory=native_factory;self._clock=clock
        self._previous=None

    def _time(self,expected=None):
        identity,now=self._clock()
        if (not boot(identity) or not safe_integer(now) or expected is not None and identity!=expected or
                self._previous is not None and (identity!=self._previous[0] or now<self._previous[1])):
            raise ValueError('Inventory refresh clock unavailable')
        self._previous=(identity,now);return identity,now

    def _current(self,boot_id):
        self._policy.recheck();self._resources.sample()
        try:os.stat('current.json',dir_fd=self._store.fd,follow_symlinks=False)
        except FileNotFoundError:
            publish_current_status(self._journal,self._publisher,boot_id=boot_id,
                current_policy=self._policy.generation,manifest=None)
        else:
            with self._store.lease_current() as lease:
                self._policy.recheck();self._resources.sample()
                publish_current_status(self._journal,self._publisher,boot_id=boot_id,
                    current_policy=self._policy.generation,manifest=lease.manifest)

    def refresh(self,nonce):
        # Invalid reporter input cannot mutate or globally fence valid root work.
        try:nonce,_=correlator(nonce.encode('ascii'))
        except (ValueError,AttributeError,UnicodeError):raise ValueError('Invalid inventory refresh request') from None
        prepared=None;service=None;native=None
        try:
            self._journal._locked();self._policy.recheck();self._resources.sample()
            boot_id,now=self._time()
            decision=self._journal.receive('refresh',nonce,boot_id,now,self._policy.generation)
            if decision!='new':return decision
            self._writers.check()
            # Probe actual package/executor contention before counting a start.
            try:
                native=self._native_factory(deadline_ms=now+5000,now=lambda:self._time(boot_id)[1])
            except ObservationError as error:
                if error.reason not in ('busy','package_manager_busy','executor_busy'):raise
                self._journal.defer('refresh',nonce,boot_id,error.reason,now=self._time(boot_id)[1])
                self._current(boot_id);return 'deferred'
            native.close();native=None
            self._policy.recheck();self._resources.sample()
            if not self._journal.start('refresh',nonce,boot_id,self._time(boot_id)[1],policy=self._policy.generation):
                self._current(boot_id);return 'deferred'
            prepared=self._materializer_factory()
            job=prepared.prepare(self._journal,self._policy)
            prepared.close();prepared=None
            service=self._service_factory(self._journal,self._policy)
            service.launch()
            self._current(boot_id)
            result=service.wait(timeout=610)
            service.verify_current_inputs()
            service.close();service=None
            self._writers.check();self._resources.sample();self._policy.recheck()
            finished=self._time(boot_id)[1]
            if result!=0 or finished>=job['deadline_boottime_ms']:
                reason='timeout' if result==76 or finished>=job['deadline_boottime_ms'] else (
                    'repository_failed' if result==75 else 'policy_unsupported' if result==74 else 'internal_error')
                self._journal.finish('refresh',nonce,boot_id,finished,'failed',reason)
                self._current(boot_id);return 'failed'
            checked=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
            manifest=self._store.publish(job['staging_token'],secrets.token_hex(16),self._policy.generation,checked)
            # The actual reference/lease must match before durable success.
            with self._store.lease_current() as lease:
                if lease.manifest!=manifest:raise ValueError('Inventory publication changed before acceptance')
                self._writers.check();self._resources.sample();self._policy.recheck()
                finished=self._time(boot_id)[1]
                if finished>=job['deadline_boottime_ms']:raise ValueError('Inventory publication exceeded its deadline')
                self._journal.finish('refresh',nonce,boot_id,finished,'succeeded',cache=manifest['cache_generation'],
                    policy=self._policy.generation,successful_checked_at=checked)
            self._current(boot_id);return 'succeeded'
        except BaseException:
            # No error path regenerates a body, repeats work or infers rollback.
            try:
                for owned in (native,prepared,service):
                    if owned is not None:
                        try:owned.close()
                        except BaseException:pass
            finally:
                try:self._journal.fence_external()
                except BaseException:pass
            raise ValueError('Inventory refresh transaction unconfirmed') from None
