"""Reporter-owned cache pin; no native locks, request submission or activation.

Caller must admit the cache's full ancestry and clock before passing borrowed
capabilities. Pinning is required BEFORE requesting an observation. This module
cannot prove the origin/liveness of a Root status from metadata alone.
"""
import re
import os
import json

from inventory_refresh_storage import READER_DIRECTORY, READER_FILES, MAX_READER_BYTES, MAX_FILES, token, opened
from inventory_refresh_state import boot, checked_timestamp
from inventory_refresh_protocol import safe_integer
from inventory_refresh_observation import ObservationError, installed_fingerprint
from inventory_refresh_status import PublicStatus


def _require(condition):
    if not condition:raise ObservationError('state_inconsistent')


class ReaderSession:
    def __init__(self):
        raise TypeError('Use pinned reader admission')

    @classmethod
    def pin(cls,cache,*,cache_generation,policy_generation,successful_checked_at,boot_id,clock):
        _require(cls is ReaderSession)
        token(cache_generation)
        _require(type(policy_generation) is str and re.fullmatch('[0-9a-f]{64}',policy_generation) is not None and boot(boot_id))
        checked_timestamp(successful_checked_at)
        value=object.__new__(cls)
        value._context=None;value._cache=None;value._closed=False
        value._boot=boot_id;value._clock=clock;value._last_time=None
        value._generation=cache_generation;value._policy=policy_generation
        value._checked=successful_checked_at
        value._phase='pinned';value._offer=None
        value._policy_calls=0;value._policy_bytes=0;value._data_reads=set()
        try:
            value._time()
            context=cache.lease_current()
            value._cache=context.__enter__();value._context=context
            manifest=value._cache.manifest
            _require(type(manifest) is dict and set(manifest)=={'schema_version','cache_generation','policy_generation','successful_checked_at','files'} and
                type(manifest['schema_version']) is int and manifest['schema_version']==1 and
                manifest['cache_generation']==cache_generation and manifest['policy_generation']==policy_generation and
                manifest['successful_checked_at']==successful_checked_at and type(manifest['files']) is list and len(manifest['files'])<=MAX_FILES)
            value._verify_projection()
            value._pinned_at=value._time()
            return value
        except BaseException:
            value.close()
            raise

    def _verify_projection(self):
        directory=opened(self._cache.fd,READER_DIRECTORY,self._cache.owner,directory=True)
        try:
            _require(not os.fstat(directory).st_mode&0o222)
            empty=opened(directory,'empty.d',self._cache.owner,directory=True)
            try:
                _require(not os.fstat(empty).st_mode&0o222)
                with os.scandir(empty) as entries:_require(next(entries,None) is None)
            finally:os.close(empty)
            total=0
            for name in READER_FILES:
                fd=opened(directory,name,self._cache.owner,limit=MAX_READER_BYTES)
                try:_require(not os.fstat(fd).st_mode&0o222)
                finally:os.close(fd)
                raw=self._cache.read_index(READER_DIRECTORY+'/'+name,MAX_READER_BYTES)
                total+=len(raw)
                _require(total<=MAX_READER_BYTES and (not name.startswith('empty-') or not raw))
                self._time()
        finally:os.close(directory)

    def _time(self):
        try:boot_id,current=self._clock()
        except Exception:raise ObservationError('state_inconsistent') from None
        _require(boot_id==self._boot and safe_integer(current) and (self._last_time is None or current>=self._last_time))
        self._last_time=current
        return current

    def _document(self,status):
        _require(type(status) is PublicStatus)
        return json.loads(status.encoded())

    def _scan_time(self):
        current=self._time()
        if current>self._offer['expires_boottime_ms']:
            raise ObservationError('lease_expired')
        return current

    def begin_scan(self,status,*,observation_nonce,dpkg_fd,owner,admit_scan):
        """Trusted caller fsyncs actual scan admission before first installed read.

        Structural status validation does not authenticate its origin: the fixed
        adapter must read Root-owned status and verify its ancestry independently.
        A callback error/anything except True consumes this session. No retry.
        """
        try:
            _require(not self._closed and self._phase=='pinned')
            document=self._document(status);offer=document['observation_lease']
            _require(offer is not None and all(offer[key]==expected for key,expected in (
                ('nonce',observation_nonce),('boot_id',self._boot),('cache_generation',self._generation),
                ('policy_generation',self._policy))) and self._pinned_at<=offer['lock_open_boottime_ms'])
            self._offer=offer
            started=self._scan_time()
            _require(offer['lock_open_boottime_ms']<=started<offer['expires_boottime_ms'])
            self._phase='admitting'
            _require(admit_scan(started) is True)
            _require(not self._closed and self._phase=='admitting')
            self._started=started;self._dpkg=dpkg_fd;self._owner=owner
            self._before=installed_fingerprint(dpkg_fd,owner,offer['expires_boottime_ms'],self._scan_time)
            self._scan_time();self._phase='scanning'
            return started
        except BaseException:
            self.close()
            raise

    def finish_scan(self):
        """Bracket all caller OS reads before submitting release; keeps cache pin."""
        try:
            _require(not self._closed and self._phase=='scanning')
            self._after=installed_fingerprint(self._dpkg,self._owner,self._offer['expires_boottime_ms'],self._scan_time)
            self._verify_projection()
            self._finished=self._scan_time()
            _require(self._before==self._after)
            self._phase='awaiting_receipt'
            return {'installed_before_sha256':self._before,'installed_after_sha256':self._after}
        except BaseException:
            self.close()
            raise

    def policy(self,packages):
        """Fixed read-only query of this pinned generation, never a command API."""
        try:
            _require(not self._closed and self._phase=='scanning' and self._policy_calls<67 and self._policy_bytes<64*1024*1024)
            from inventory_refresh_reader_tools import _policy
            self._phase='querying';self._policy_calls+=1
            self._verify_projection();self._scan_time()
            text=_policy(self._cache,self._generation,packages,self._scan_time,
                self._offer['expires_boottime_ms'],min(16*1024*1024,64*1024*1024-self._policy_bytes))
            self._policy_bytes+=len(text.encode('utf-8'))
            _require(not self._closed and self._phase=='querying')
            self._verify_projection();self._scan_time()
            _require(not self._closed and self._phase=='querying')
            self._phase='scanning'
            return text
        except BaseException:
            self.close()
            raise

    def frozen_scan_bounds(self):
        """Data-only endpoints frozen before release, never a cleanup witness."""
        try:
            _require(not self._closed and self._phase=='awaiting_receipt')
            self._scan_time()
            return {'scan_started_boottime_ms':self._started,'scan_finished_boottime_ms':self._finished}
        except BaseException:
            self.close()
            raise

    def installed(self):
        return self._fixed_data('installed')

    def native_architecture(self):
        return self._fixed_data('architecture')

    def holds(self):
        return self._fixed_data('holds')

    def desktop_owners(self):
        return self._fixed_data('owners')

    def _fixed_data(self,operation):
        try:
            _require(not self._closed and self._phase=='scanning' and operation not in self._data_reads and self._policy_bytes<64*1024*1024)
            from inventory_refresh_reader_tools import _fixed_read
            self._phase='querying';self._data_reads.add(operation)
            self._verify_projection();self._scan_time()
            text=_fixed_read(self._cache,self._generation,operation,self._scan_time,
                self._offer['expires_boottime_ms'],64*1024*1024-self._policy_bytes)
            self._policy_bytes+=len(text.encode('utf-8'))
            _require(not self._closed and self._phase=='querying')
            self._verify_projection();self._scan_time()
            _require(not self._closed and self._phase=='querying')
            self._phase='scanning'
            return text
        except BaseException:
            self.close()
            raise

    def finish(self,status):
        """Return bounded evidence only after matching receipt AND cache close.

        This is no report-ready/cleanup witness for a failed or timed-out Root
        operation. Missing/invalid receipts never become permission to retry.
        """
        try:
            _require(not self._closed and self._phase=='awaiting_receipt')
            current=self._time()
            receipt=self._document(status)['observation_receipt']
            _require(receipt is not None and all(receipt[key]==value for key,value in self._offer.items()) and
                receipt['outcome']=='released' and
                self._offer['lock_open_boottime_ms']<=self._started<=self._finished<=
                receipt['lock_held_until_boottime_ms']<=receipt['released_boottime_ms']<=self._offer['expires_boottime_ms'] and receipt['released_boottime_ms']<=current and
                receipt['installed_before_sha256']==self._before==self._after==receipt['installed_after_sha256'])
            raw=json.dumps({'schema_version':1,'scan_started_boottime_ms':self._started,
                'scan_finished_boottime_ms':self._finished,'successful_checked_at':self._checked,'observation_receipt':receipt},sort_keys=True,separators=(',',':')).encode('ascii')
        finally:
            self.close()
        return raw

    def close(self):
        if self._closed:return
        self._closed=True
        context,self._context=self._context,None
        self._cache=None
        if context is not None:context.__exit__(None,None,None)
