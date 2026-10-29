"""Readonly protected status/cache-pin composition, not observation authority.

No writer, OS collector, source execution or controller/report operations are
exposed. Private capability fixtures cannot establish production origin.
"""
import os
import json

from inventory_refresh_resources import _Chain
from inventory_refresh_reporter_parent import ReporterParent
from inventory_refresh_reporter_io import StatusReader,ReporterIOError
from inventory_refresh_storage import CacheReader
from inventory_refresh_reader_session import ReaderSession


class ReporterEnvironmentError(ValueError):
    def __init__(self,reason='state_inconsistent'):
        self.reason=reason
        super().__init__('Readonly reporter environment unavailable: '+reason)


def _require(condition,reason='state_inconsistent'):
    if not condition:raise ReporterEnvironmentError(reason)


class ReporterEnvironment:
    def __new__(cls,*args,**kwargs):raise TypeError('Use fixed reporter environment admission')

    @classmethod
    def _empty(cls):
        _require(cls is ReporterEnvironment)
        value=object.__new__(cls)
        value._closed=False;value._poisoned=False;value._pin_attempted=False
        value._parent=None;value._reader=None;value._cache=None;value._session=None;value._chains={}
        return value

    @classmethod
    def fixed(cls):
        value=cls._empty()
        try:
            value._parent=ReporterParent.fixed()
            for name,parts in (
                ('runtime',('run','command-center-inventory-refresh')),
                ('status',('run','command-center-inventory-refresh','status')),
                ('cache',('var','cache','command-center-inventory-refresh')),
                ('dpkg',('var','lib','dpkg')),
                ('library',('usr','local','libexec','command-center-inventory-refresh'))):
                value._chains[name]=_Chain(parts)
            value._reader=StatusReader(value._chains['status'].fds[-1],os.getresgid()[0])
            value._cache=CacheReader(value._chains['cache'].fds[-1])
            value.verify();return value
        except BaseException as exc:
            value.close();raise ReporterEnvironmentError(value._reason(exc)) from None

    @classmethod
    def _from_capabilities(cls,parent,reader,cache,chains):
        """Private transferred-capability fixture seam, never origin proof."""
        value=cls._empty();value._parent=parent;value._reader=reader;value._cache=cache;value._chains=dict(chains)
        try:value.verify();return value
        except BaseException as exc:
            value.close();raise ReporterEnvironmentError(value._reason(exc)) from None

    @staticmethod
    def _reason(error):
        reason=getattr(error,'reason',None)
        return reason if reason in ('policy_unsupported','resource_limit','cleanup_unconfirmed','cache_unavailable') else 'state_inconsistent'

    def verify(self):
        try:
            _require(not self._closed and not self._poisoned and self._parent is not None)
            self._parent.verify()
            for chain in self._chains.values():chain.verify()
            self._parent.clock()
        except BaseException as exc:self._consume(exc)

    def clock(self):
        try:
            _require(not self._closed and not self._poisoned)
            return self._parent.clock()
        except BaseException as exc:self._consume(exc)

    def read_status(self):
        try:
            self.verify()
            try:value=self._reader.read()
            except ReporterIOError as exc:
                if exc.reason!='publication_changed':raise
                value=None  # Caller may ask for a fresh file; never cached data.
            self.verify()
            return value
        except BaseException as exc:self._consume(exc)

    def pin_current(self):
        try:
            _require(not self._closed and not self._poisoned and not self._pin_attempted)
            self._pin_attempted=True  # Latch before status or any acquisition.
            status=self.read_status();_require(status is not None,'cache_unavailable')
            document=json.loads(status.encoded())
            _require(all(document[key] is not None for key in ('cache_generation','policy_generation','successful_checked_at')),'cache_unavailable')
            boot,_=self.clock()
            self._session=ReaderSession.pin(self._cache,cache_generation=document['cache_generation'],
                policy_generation=document['policy_generation'],successful_checked_at=document['successful_checked_at'],
                boot_id=boot,clock=self._parent.clock)
            return self.pinned_context()
        except BaseException as exc:self._consume(exc)

    def pinned_context(self):
        try:
            self.verify();_require(self._session is not None)
            value=self._session.pinned_context()
            self.verify()
            return value
        except BaseException as exc:self._consume(exc)

    def _consume(self,error):
        self._poisoned=True
        self.close()
        raise ReporterEnvironmentError(self._reason(error)) from None

    def close(self):
        if self._closed:return
        self._closed=True;failed=False
        owned=[]
        for name in ('_session','_reader'):
            value=getattr(self,name);setattr(self,name,None)
            if value is not None:owned.append(value)
        self._cache=None  # Borrowed descriptor belongs to its ancestry owner.
        owned.extend(reversed(tuple(self._chains.values())));self._chains={}
        parent,self._parent=self._parent,None
        if parent is not None:owned.append(parent)
        for value in owned:
            try:value.close()
            except BaseException:failed=True
        if failed:raise ReporterEnvironmentError('cleanup_unconfirmed')
