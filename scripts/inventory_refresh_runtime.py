"""Fixed root runtime assembly; no executable, initialization or activation API.

Trusted provisioning must establish initial namespaces, reserved identities and
unit provenance. Current resource admission cannot prove historical allocation.
All operational objects close while their original journal lock remains held;
final lock/state-FD release errors are local terminal shutdown uncertainty.
"""
import os
import sys

from inventory_refresh_channel import ObservationChannel
from inventory_refresh_dispatch import RootDispatcher
from inventory_refresh_io import Inbox,StatusPublisher
from inventory_refresh_observation import _Ancestry
from inventory_refresh_observation_transaction import ObservationTransaction
from inventory_refresh_observer import kernel_clock
from inventory_refresh_policy_admission import PolicyGuard
from inventory_refresh_resources import RuntimeResources
from inventory_refresh_state import Journal
from inventory_refresh_storage import Store
from inventory_refresh_transaction import RefreshTransaction
from inventory_refresh_worker_service import _accounts
from inventory_refresh_writer_exclusion import WriterExclusion


def _state():
    root=None;ancestry=None
    try:
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        ancestry=_Ancestry.open(root,('var','lib','command-center-inventory-refresh'))
        closing,root=root,None;os.close(closing)
        return ancestry
    except BaseException:
        if ancestry is not None:
            try:ancestry.close()
            except BaseException:pass
        raise ValueError('Inventory runtime state unavailable') from None
    finally:
        if root is not None:os.close(root)


def _identities(accounts):
    return tuple(value for account in accounts for value in (account.pw_uid,account.pw_gid))


class FixedRuntime:
    def __new__(cls,*args,**kwargs):raise TypeError('Use fixed inventory runtime admission')

    @classmethod
    def fixed(cls):
        return cls._construct(None)

    @classmethod
    def _with_maintenance_for_test(cls,maintenance):
        """Exercise ownership ordering; not registered for production startup."""
        if maintenance is None:raise ValueError('Inventory runtime unavailable')
        maintenance.verify()
        return cls._construct(maintenance)

    @classmethod
    def _construct(cls,maintenance):
        if (cls is not FixedRuntime or sys.platform!='linux' or
                os.getresuid()!=(0,0,0) or os.getresgid()!=(0,0,0)):
            raise ValueError('Inventory runtime unavailable')
        value=object.__new__(cls)
        value._owned=[];value._state=None;value._lock=None;value._held=False
        value._journal=None;value._closed=False;value._failed=False;value._dispatcher=None
        value._maintenance=maintenance
        try:
            # Admission precedes all private policy/cache contents/account lookup.
            value._resources=RuntimeResources.fixed();value._own(value._resources)
            value._policy=PolicyGuard.fixed();value._own(value._policy)
            accounts=_accounts();value._identities=_identities(accounts)
            worker,reporter=accounts
            value._state=_state();value._journal=Journal(value._state.fds[-1])
            value._lock=value._journal.exclusive();value._lock.__enter__();value._held=True
            if value._journal.startup_ready() is not True:
                raise ValueError('Inventory runtime requires reconciled durable state')
            value._writers=WriterExclusion.fixed(worker.pw_uid);value._own(value._writers)
            value._publisher=StatusPublisher.fixed(value._journal);value._own(value._publisher)
            value._store=Store(value._resources._cache.fds[-1],0,reporter.pw_gid,worker.pw_uid)
            value._channel=ObservationChannel.fixed(journal=value._journal);value._own(value._channel)
            value._inboxes={}
            for capability in ('release','observation','refresh'):
                inbox=Inbox.fixed(capability);value._own(inbox);value._inboxes[capability]=inbox
            value._refresh=RefreshTransaction(value._journal,value._policy,value._resources,
                value._store,value._publisher,value._writers)
            value._observation=ObservationTransaction(value._journal,value._policy,value._resources,
                value._store,value._publisher,value._writers,value._channel)
            value._own(value._observation)
            value._dispatcher=RootDispatcher(value._journal,value._inboxes,value._refresh,value._observation)
            value._own(value._dispatcher)
            value._check()
            value._refresh._current(kernel_clock()[0])
            return value
        except BaseException:
            value._fence()
            try:value.close()
            except BaseException:pass
            raise ValueError('Inventory runtime admission unconfirmed') from None

    def _own(self,value):self._owned.append(value.close)

    def _fence(self):
        self._failed=True
        if self._held and self._journal is not None:
            try:self._journal.fence_external()
            except BaseException:pass

    def _check(self):
        if self._closed or not self._held:raise ValueError('Inventory runtime closed')
        if self._maintenance is not None:self._maintenance.verify()
        self._journal._locked();self._resources.sample();self._policy.recheck();self._state.verify()
        if _identities(_accounts())!=self._identities:raise ValueError('Inventory runtime accounts changed')
        if self._journal.snapshot()['unconfirmed']:raise ValueError('Inventory runtime unconfirmed')

    def step(self):
        if self._closed:raise ValueError('Inventory runtime closed')
        try:
            self._check();return self._dispatcher.step()
        except BaseException:
            self._fence()
            try:self.close()
            except BaseException:pass
            raise ValueError('Inventory runtime dispatch unconfirmed') from None

    def drain(self):
        """Enter one-way logical drain while retaining runtime ownership."""
        if self._closed:raise ValueError('Inventory runtime closed')
        try:
            self._check();result=self._dispatcher.drain();self._check();return result
        except BaseException:
            self._fence()
            try:self.close()
            except BaseException:pass
            raise ValueError('Inventory runtime drain unconfirmed') from None

    def close(self):
        if self._closed:
            if self._failed:raise ValueError('Inventory runtime shutdown unconfirmed')
            return
        self._closed=True
        while self._owned:
            callback=self._owned.pop()
            try:callback()
            except BaseException:self._fence()
        # All action-capable objects and late policy/resource closes precede this.
        if self._held:
            self._held=False
            try:self._lock.__exit__(None,None,None)
            except BaseException:self._failed=True
        if self._state is not None:
            state,self._state=self._state,None
            try:state.close()
            except BaseException:self._failed=True
        # A failed teardown must not release the cooperative exclusion early.
        # Retain its descriptor until process exit; this is not cleanup proof.
        if self._maintenance is not None and not self._failed:
            maintenance,self._maintenance=self._maintenance,None
            try:maintenance.close()
            except BaseException:self._failed=True
        if self._failed:raise ValueError('Inventory runtime shutdown unconfirmed')
