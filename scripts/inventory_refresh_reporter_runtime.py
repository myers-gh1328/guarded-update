"""Fixed one-use reporter publication ports, not durable request authority.

Parent MUST hold its process lock and fsync current intent inside the journal's
pre-effect gate before calling either port. Publication is not Root acceptance,
cleanup, coherent evidence or report readiness. No executable entry is wired.
"""
import os
from inventory_refresh_protocol import correlator
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
        return value

    @classmethod
    def fixed(cls):
        value=cls._empty()
        try:
            value._environment=ReporterEnvironment.fixed()
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
        _require(not self._closed)
        self._environment.verify()
        _require(not self._closed)

    def clock(self):
        try:
            _require(not self._closed)
            value=self._environment.clock();_require(not self._closed)
            return value
        except BaseException as error:self._consume(error)

    def pin_current(self):
        try:
            _require(not self._closed and self._phase=='initial');self._phase='pinning'
            self._verify();value=self._environment.pin_current();self._verify()
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
            _require(not self._closed and self._phase=='observation_published' and type(nonce) is str and nonce==self._nonce)
            self._phase='publishing_release'
            self._verify();self._release.publish(nonce);self._verify()
            self._phase='release_published'
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
