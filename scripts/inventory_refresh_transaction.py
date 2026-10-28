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
from inventory_refresh_guardian import COMPLETED_EXIT
from inventory_refresh_state import boot
from inventory_refresh_coordinator import publish_current_status
from inventory_refresh_materializer import RefreshMaterializer
from inventory_refresh_worker_service import RefreshService
from inventory_refresh_observation import ObservationError
from inventory_refresh_contention import ContentionProbe
from inventory_refresh_observer import kernel_clock


STAGES=frozenset(('admission','writers','native_probe','start','materialize','materializer_cleanup',
    'service_admission','service_launch','running_status','service_wait','current_inputs','service_cleanup',
    'publication_admission','failed_status','sealing','acceptance','final_status'))


DIAGNOSTIC_MODULES=frozenset(name+'.py' for name in (
    'inventory_refresh_transaction','inventory_refresh_worker_service','inventory_refresh_service',
    'inventory_refresh_materializer','inventory_refresh_materialized_policy','inventory_refresh_policy_admission',
    'inventory_refresh_policy','inventory_refresh_state','inventory_refresh_io','inventory_refresh_storage',
    'inventory_refresh_resources','inventory_refresh_writer_exclusion','inventory_refresh_observation',
    'inventory_refresh_contention','worker'))
DIAGNOSTIC_KINDS=frozenset(('ValueError','OSError','PermissionError','FileNotFoundError','NotADirectoryError',
    'TimeoutExpired','PolicyError','ResourceError','ObservationError','IOErrorState','PublicationError'))


def _diagnostics(error):
    """Never inspect args, messages, locals or arbitrary source paths."""
    result=[];seen=set()
    for _ in range(4):
        if not isinstance(error,BaseException) or id(error) in seen:break
        seen.add(id(error));sites=[];frame=error.__traceback__
        for _ in range(64):
            if frame is None:break
            name=os.path.basename(frame.tb_frame.f_code.co_filename)
            if name in DIAGNOSTIC_MODULES and type(frame.tb_lineno) is int and 0<frame.tb_lineno<=65535:
                sites.append({'module':name,'line':frame.tb_lineno})
            frame=frame.tb_next
        kind=type(error).__name__
        number=getattr(error,'errno',None)
        result.append({'kind':kind if kind in DIAGNOSTIC_KINDS else 'unclassified',
            'errno':number if type(number) is int and 0<number<=4095 else None,'sites':sites[-4:]})
        error=error.__cause__ if error.__cause__ is not None else error.__context__
    return tuple(result)


class TransactionError(ValueError):
    def __init__(self,stage,error=None):
        self.diagnostics=_diagnostics(error)
        self.stage=stage if type(stage) is str and stage in STAGES else 'unknown'
        super().__init__('Inventory refresh transaction unconfirmed: '+self.stage)


class RefreshTransaction:
    def __init__(self,journal,policy,resources,store,publisher,writers,*,
                 materializer_factory=RefreshMaterializer.fixed,service_factory=RefreshService,
                 contention_factory=ContentionProbe.fixed,clock=kernel_clock):
        self._journal=journal;self._policy=policy;self._resources=resources;self._store=store
        self._publisher=publisher;self._writers=writers;self._materializer_factory=materializer_factory
        self._service_factory=service_factory;self._contention_factory=contention_factory;self._clock=clock
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
        prepared=None;service=None;native=None;stage='admission'
        try:
            self._journal._locked();self._policy.recheck();self._resources.sample()
            boot_id,now=self._time()
            decision=self._journal.receive('refresh',nonce,boot_id,now,self._policy.generation)
            if decision!='new':return decision
            stage='writers';self._writers.check()
            # Observe kernel contention without taking package/executor locks.
            stage='native_probe'
            try:
                native=self._contention_factory(deadline_ms=now+5000,now=lambda:self._time(boot_id)[1])
            except ObservationError as error:
                if error.reason not in ('busy','package_manager_busy','executor_busy','policy_unsupported','state_inconsistent','lease_expired'):raise
                self._journal.defer('refresh',nonce,boot_id,error.reason,now=self._time(boot_id)[1])
                self._current(boot_id);return 'deferred'
            native.close();native=None
            self._policy.recheck();self._resources.sample()
            stage='start'
            if not self._journal.start('refresh',nonce,boot_id,self._time(boot_id)[1],policy=self._policy.generation):
                self._current(boot_id);return 'deferred'
            stage='materialize';prepared=self._materializer_factory()
            job=prepared.prepare(self._journal,self._policy)
            stage='materializer_cleanup';prepared.close();prepared=None
            stage='service_admission';service=self._service_factory(self._journal,self._policy)
            stage='service_launch';service.launch()
            stage='running_status';self._current(boot_id)
            stage='service_wait';result=service.wait(timeout=610)
            stage='current_inputs';service.verify_current_inputs()
            stage='service_cleanup';service.close();service=None
            stage='publication_admission';self._writers.check();self._resources.sample();self._policy.recheck()
            finished=self._time(boot_id)[1]
            if result!=COMPLETED_EXIT or finished>=job['deadline_boottime_ms']:
                reason='timeout' if result==76 or finished>=job['deadline_boottime_ms'] else (
                    'repository_failed' if result==75 else 'policy_unsupported' if result==74 else 'internal_error')
                self._journal.finish('refresh',nonce,boot_id,finished,'failed',reason)
                stage='failed_status';self._current(boot_id);return 'failed'
            checked=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
            stage='sealing';manifest=self._store.publish(job['staging_token'],secrets.token_hex(16),self._policy.generation,checked)
            # The actual reference/lease must match before durable success.
            stage='acceptance'
            with self._store.lease_current() as lease:
                if lease.manifest!=manifest:raise ValueError('Inventory publication changed before acceptance')
                self._writers.check();self._resources.sample();self._policy.recheck()
                finished=self._time(boot_id)[1]
                if finished>=job['deadline_boottime_ms']:raise ValueError('Inventory publication exceeded its deadline')
                self._journal.finish('refresh',nonce,boot_id,finished,'succeeded',cache=manifest['cache_generation'],
                    policy=self._policy.generation,successful_checked_at=checked)
            stage='final_status';self._current(boot_id);return 'succeeded'
        except BaseException as error:
            # No error path regenerates a body, repeats work or infers rollback.
            try:
                for owned in (native,prepared,service):
                    if owned is not None:
                        try:owned.close()
                        except BaseException:pass
            finally:
                try:self._journal.fence_external()
                except BaseException:pass
            raise TransactionError(stage,error) from None
