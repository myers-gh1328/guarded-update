"""Fixed reporter scan/publication phases, not durable request authority.

Parent MUST hold its process lock and fsync current intent inside the journal's
pre-effect gate before calling either port. Publication is not Root acceptance,
cleanup, coherent evidence or report readiness. No executable entry is wired.
"""
import os
import json
import time
from inventory_refresh_protocol import correlator,safe_integer
from inventory_refresh_state import boot
from inventory_refresh_reporter_environment import ReporterEnvironment
from inventory_refresh_reporter_io import ReporterRequestWriter


class ReporterRuntimeError(ValueError):
    def __init__(self,reason='state_inconsistent'):
        self.reason=reason
        super().__init__('Fixed reporter publication unavailable: '+reason)


def _require(condition):
    if not condition:raise ReporterRuntimeError()


class ReporterRuntime:
    def __new__(cls,*args,**kwargs):raise TypeError('Use fixed reporter runtime admission')

    @classmethod
    def _empty(cls):
        _require(cls is ReporterRuntime)
        value=object.__new__(cls);value._closed=False;value._phase='initial';value._nonce=None
        value._environment=None;value._observation=None;value._release=None
        value._boot=None;value._last=None;value._deadline=None
        value._poisoned=False;value._scan_frozen=False
        return value

    @classmethod
    def fixed(cls):
        value=cls._empty()
        try:
            value._environment=ReporterEnvironment.fixed()
            value.clock()
            directory=value._environment._chains['runtime'].fds[-1]
            uid=os.geteuid();gid=os.getegid()
            value._observation=ReporterRequestWriter(directory,'observation',uid,gid)
            value._release=ReporterRequestWriter(directory,'release',uid,gid)
            value._validate_roles();value._verify()
            return value
        except BaseException as error:value._consume(error)

    @classmethod
    def _from_capabilities(cls,environment,observation,release):
        """Private transferred-owner fixture seam, not production origin proof."""
        value=cls._empty();value._environment=environment;value._observation=observation;value._release=release
        try:
            value._validate_roles();value._verify()
            return value
        except BaseException as error:value._consume(error)

    def _validate_roles(self):
        _require(type(self._environment) is ReporterEnvironment and self._observation is not self._release)
        parent=os.fstat(self._environment._chains['runtime'].fds[-1])
        for writer,role in ((self._observation,'observation'),(self._release,'release')):
            _require(type(writer) is ReporterRequestWriter and writer._inbox is not None and writer._inbox._capability==role)
            inbox=writer._inbox;actual=os.fstat(inbox._parent)
            _require((actual.st_dev,actual.st_ino)==(parent.st_dev,parent.st_ino) and
                inbox._owner==parent.st_uid and inbox._reporter==os.geteuid() and inbox._group==os.getegid())

    def _verify(self):
        _require(not self._closed and not self._poisoned)
        self._environment.verify()
        self.clock()
        _require(not self._closed)

    def clock(self):
        try:return self._session_clock()
        except BaseException as error:self._consume(error)

    def _session_clock(self):
        # Leaf operations must unwind their hash FDs/query child BEFORE their
        # cache pin/environment closes. Latch poison here; outer operations
        # consume only after ReaderSession/tool supervisor cleanup has returned.
        try:
            _require(not self._closed and not self._poisoned and not self._environment._closed)
            value=self._environment._parent.clock()
            _require(not self._closed and not self._environment._closed and type(value) is tuple and len(value)==2)
            current_boot,now=value
            _require(boot(current_boot) and safe_integer(now) and (self._boot is None or current_boot==self._boot) and
                (self._last is None or now>=self._last))
            if self._deadline is None:
                _require(now<=9007199254740991-120000);self._deadline=now+120000
            _require(now<self._deadline)
            self._boot=current_boot;self._last=now
            return value
        except BaseException:
            self._poisoned=True
            raise ReporterRuntimeError() from None

    def pin_current(self):
        try:
            _require(not self._closed and self._phase=='initial');self._phase='pinning'
            self._verify();value=self._environment._pin_with_clock(self._session_clock);self._verify()
            self._phase='pinned'
            return value
        except BaseException as error:self._consume(error)

    def publish_observation(self,nonce):
        try:
            _require(not self._closed and self._phase=='pinned' and type(nonce) is str and len(nonce)==32)
            _require(correlator(nonce.encode('ascii'))[0]==nonce)
            self._phase='publishing_observation';self._nonce=nonce
            self._verify();self._observation.publish(nonce);self._verify()
            self._phase='observation_published'
        except BaseException as error:self._consume(error)

    def publish_release(self,nonce):
        try:
            _require(not self._closed and self._phase in ('observation_published','scan_frozen') and type(nonce) is str and nonce==self._nonce)
            self._phase='publishing_release'
            self._verify();self._release.publish(nonce);self._verify()
            self._phase='release_published'
        except BaseException as error:self._consume(error)

    def _wait_status(self,field):
        while True:
            self._verify();status=self._environment.read_status();self._verify()
            if status is not None:
                value=json.loads(status.encoded())[field]
                if value is not None and value['nonce']==self._nonce:return status,value
            time.sleep(.025);self.clock()

    def begin_scan(self,admit_scan):
        try:
            _require(not self._closed and self._phase=='observation_published');self._phase='opening'
            status,offer=self._wait_status('observation_lease')
            self._deadline=min(self._deadline,offer['expires_boottime_ms']);self.clock()
            def admitted(started):
                _require(not self._closed and self._phase=='opening');self._verify()
                accepted=admit_scan(started,dict(offer))
                self._verify();_require(self._phase=='opening' and accepted is True)
                return True
            self._verify();directory=self._environment._chains['dpkg'].fds[-1]
            started=self._environment._session.begin_scan(status,observation_nonce=self._nonce,
                dpkg_fd=directory,owner=os.fstat(directory).st_uid,admit_scan=admitted)
            self._verify();self._phase='scanning'
            return started
        except BaseException as error:self._consume(error)

    def installed(self):return self._data('installed')
    def native_architecture(self):return self._data('native_architecture')
    def holds(self):return self._data('holds')
    def policy(self,packages):return self._data('policy',packages)

    def _data(self,operation,*arguments):
        try:
            _require(not self._closed and self._phase=='scanning');self._phase='querying'
            self._verify()
            methods={'installed':self._environment._session.installed,'native_architecture':self._environment._session.native_architecture,
                'holds':self._environment._session.holds,'policy':self._environment._session.policy}
            value=methods[operation](*arguments)
            self._verify();_require(self._phase=='querying');self._phase='scanning'
            return value
        except BaseException as error:self._consume(error)

    def freeze_scan(self):
        try:
            _require(not self._closed and self._phase=='scanning');self._phase='freezing'
            self._verify();session=self._environment._session
            hashes=session.finish_scan();bounds=session.frozen_scan_bounds();self._verify()
            self._scan_frozen=True;self._phase='scan_frozen'
            return dict(hashes,**bounds)
        except BaseException as error:self._consume(error)

    def prepare_evidence(self):
        try:
            _require(not self._closed and self._phase=='release_published' and self._scan_frozen);self._phase='preparing'
            status,_=self._wait_status('observation_receipt')
            value=self._environment._session.finish(status)
            self._verify();_require(type(value) is bytes and 0<len(value)<=16384)
            self._phase='prepared'
            return value
        except BaseException as error:self._consume(error)

    def _consume(self,error):
        reason=getattr(error,'reason',None)
        self.close()
        allowed=('policy_unsupported','resource_limit','cleanup_unconfirmed','cache_unavailable','persistence_unconfirmed')
        raise ReporterRuntimeError(reason if reason in allowed else 'state_inconsistent') from None

    def close(self):
        if self._closed:return
        self._closed=True;self._phase='closed';self._nonce=None;owned=[]
        for name in ('_release','_observation','_environment'):
            value=getattr(self,name);setattr(self,name,None)
            if value is not None and all(value is not item for item in owned):owned.append(value)
        failed=False
        for value in owned:
            try:value.close()
            except BaseException:failed=True
        if failed:raise ReporterRuntimeError('cleanup_unconfirmed')
