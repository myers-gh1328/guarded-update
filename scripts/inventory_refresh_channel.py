"""Fixed root child metadata channel; no service start or execution authority.

Parent writes require its held reconciled Journal. The runtime must additionally
own the exact child, deadline, policy/cache guards and lifecycle. A typed file or
in-memory phase tracker alone cannot authorize regrant or recovery after restart.
"""
from dataclasses import asdict
import json
import os
import secrets
import stat
import sys

from inventory_refresh_cached_observation import ObservationJob, ObservationResult, ReleaseGrant, LIMIT, _decode
from inventory_refresh_observation import _Ancestry, _identity, _stable


class ChannelError(ValueError):
    def __init__(self,reason='state_inconsistent',*,may_be_visible=False):
        self.reason=reason
        self.may_be_visible=may_be_visible
        super().__init__('Inventory observation channel unavailable: '+reason)


def _require(condition):
    if not condition:
        raise ChannelError()


def _same_lease(opened,released):
    return all(released[key]==value for key,value in opened.items())


def _transition(previous,incoming):
    if previous is None:
        return
    old=previous.document();new=incoming.document()
    if previous.encoded()==incoming.encoded():
        return
    _require(old['phase']=='opened' and new['phase'] in ('released','failed'))
    if new['phase']=='released':
        _require(_same_lease(old['observation_lease'],new['observation_receipt']))


class ObservationChannel:
    def __init__(self,control,results,*,journal=None,owner=0):
        self._control=None;self._results=None;self._ancestry=None
        self._journal=journal;self._owner=owner
        self._tracked_job=None;self._last_result=None
        try:
            self._directory(control);self._directory(results)
            _require(_identity(os.fstat(control))!=_identity(os.fstat(results)))
            self._control=os.dup(control)
            self._results=os.dup(results)
        except BaseException:
            self.close()
            raise

    @classmethod
    def fixed(cls,*,journal=None):
        if sys.platform!='linux' or os.geteuid()!=0:
            raise ChannelError('policy_unsupported')
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        ancestry=None;control=None;results=None;channel=None
        try:
            ancestry=_Ancestry.open(root,('run','command-center-inventory-refresh','observation-private'))
            for name in ('control','results'):
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=ancestry.fds[-1])
                if name=='control':control=fd
                else:results=fd
            channel=cls(control,results,journal=journal)
            channel._ancestry=ancestry;ancestry=None
            channel._verify()
            return channel
        except BaseException:
            if channel is not None:channel.close()
            raise
        finally:
            os.close(root)
            for fd in (control,results):
                if fd is not None:os.close(fd)
            if ancestry is not None:ancestry.close()

    def _directory(self,fd):
        info=os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid==self._owner and stat.S_IMODE(info.st_mode)==0o700)
        return info

    def _verify(self):
        _require(self._control is not None and self._results is not None)
        if self._ancestry is not None:
            self._ancestry.verify()
            self._directory(self._ancestry.fds[-1])
            for name,fd in (('control',self._control),('results',self._results)):
                named=os.stat(name,dir_fd=self._ancestry.fds[-1],follow_symlinks=False)
                _require(stat.S_ISDIR(named.st_mode) and _identity(named)==_identity(os.fstat(fd)))
        self._directory(self._control);self._directory(self._results)

    def _file(self,info,directory,mode):
        _require(stat.S_ISREG(info.st_mode) and info.st_uid==self._owner and
                 info.st_gid==os.fstat(directory).st_gid and stat.S_IMODE(info.st_mode)==mode and
                 info.st_nlink==1 and 0<info.st_size<=LIMIT)

    def _read(self,directory,name,mode,*,durable=False):
        try:
            return self._read_file(directory,name,mode,durable=durable)
        except OSError:
            raise ChannelError('persistence_unconfirmed' if durable else 'state_inconsistent') from None

    def _read_file(self,directory,name,mode,*,durable=False):
        self._verify()
        try:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        except FileNotFoundError:
            return None
        try:
            before=os.fstat(fd);self._file(before,directory,mode)
            data=bytearray()
            while len(data)<=LIMIT:
                chunk=os.read(fd,min(16384,LIMIT+1-len(data)))
                if not chunk:break
                data.extend(chunk)
            after=os.fstat(fd);self._file(after,directory,mode)
            named=os.stat(name,dir_fd=directory,follow_symlinks=False)
            _require(len(data)==before.st_size and _stable(before)==_stable(after)==_stable(named))
            if durable:
                # Parent barrier before accepting child evidence, including a
                # visible result whose producer could not confirm directory sync.
                os.fsync(fd);os.fsync(directory)
                _require(_stable(before)==_stable(os.fstat(fd))==_stable(os.stat(name,dir_fd=directory,follow_symlinks=False)))
            self._verify()
            return bytes(data),_stable(before)
        finally:
            os.close(fd)

    def _reference(self,directory,name,expected):
        try:
            actual=os.stat(name,dir_fd=directory,follow_symlinks=False)
        except FileNotFoundError:
            _require(expected is None)
        else:
            _require(expected is not None and _stable(actual)==expected)

    def _write(self,directory,name,mode,raw):
        self._verify()
        _require(type(raw) is bytes and 0<len(raw)<=LIMIT)
        prior=self._read(directory,name,mode)
        expected=None if prior is None else prior[1]
        temporary='.observation-'+secrets.token_hex(16)
        fd=None;created=False;owned=None;attempted=False;failed=False
        try:
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
            created=True;owned=_identity(os.fstat(fd))
            offset=0
            while offset<len(raw):
                count=os.write(fd,raw[offset:])
                if count<=0:raise OSError('Metadata write made no progress')
                offset+=count
            os.fchown(fd,self._owner,os.fstat(directory).st_gid)
            os.fchmod(fd,mode)
            self._file(os.fstat(fd),directory,mode)
            os.fsync(fd)
            sealed=_stable(os.fstat(fd))
            closing,fd=fd,None
            os.close(closing)
            self._verify()
            self._reference(directory,name,expected)
            _require(_stable(os.stat(temporary,dir_fd=directory,follow_symlinks=False))==sealed)
            attempted=True
            os.replace(temporary,name,src_dir_fd=directory,dst_dir_fd=directory)
            installed=_stable(os.stat(name,dir_fd=directory,follow_symlinks=False))
            # Rename may legitimately change ctime; all content/ownership fields
            # must retain the sealed identity, then the installed reference freezes.
            _require(installed[:-1]==sealed[:-1])
            os.fsync(directory)
            self._reference(directory,name,installed)
            self._verify()
        except (OSError,ValueError):
            failed=True
        finally:
            if fd is not None:
                try:os.close(fd)
                except OSError:failed=True
            if created:
                try:
                    named=os.stat(temporary,dir_fd=directory,follow_symlinks=False)
                except FileNotFoundError:
                    pass
                except OSError:
                    failed=True
                else:
                    if _identity(named)==owned:
                        try:os.unlink(temporary,dir_fd=directory)
                        except OSError:failed=True
        if failed:
            raise ChannelError('persistence_unconfirmed',may_be_visible=attempted) from None

    def _parent_snapshot(self,job):
        _require(self._journal is not None and type(job) is ObservationJob)
        self._journal._locked()
        snapshot=self._journal.snapshot()
        _require(not snapshot['unconfirmed'])
        record=snapshot['capabilities']['observation']['active']
        _require(record is not None and record['phase']=='running' and all(record[key]==value for key,value in (
            ('correlator',job.operation_nonce),('helper_sequence',job.helper_sequence),('boot_id',job.boot_id),
            ('accepted_boottime_ms',job.accepted_boottime_ms),('started_boottime_ms',job.started_boottime_ms),
            ('policy_generation',job.policy_generation))))
        return snapshot

    def write_job(self,job):
        self._parent_snapshot(job)
        previous=self.read_job()
        if previous==job:
            _require(self.read_job(durable=True)==job)
            return
        _require(previous is None or previous.helper_sequence<job.helper_sequence)
        raw=json.dumps(asdict(job),sort_keys=True,separators=(',',':')).encode('ascii')
        self._write(self._control,'job.json',0o400,raw)
        self._tracked_job=job;self._last_result=None

    def read_job(self,*,durable=False):
        raw=self._read(self._control,'job.json',0o400,durable=durable)
        return None if raw is None else ObservationJob.parse(raw[0])

    def write_release(self,grant):
        _require(type(grant) is ReleaseGrant)
        snapshot=self._parent_snapshot(grant.job)
        _require(self.read_job()==grant.job and self._tracked_job==grant.job and self._last_result is not None)
        opened=self._last_result.document()
        _require(opened['phase']=='opened' and opened['observation_lease']['lock_open_boottime_ms']<=grant.requested_boottime_ms)
        record=snapshot['capabilities']['release']['active']
        _require(record is not None and record['phase']=='running' and all(record[key]==value for key,value in (
            ('correlator',grant.job.operation_nonce),('helper_sequence',grant.job.helper_sequence),
            ('boot_id',grant.job.boot_id),('policy_generation',grant.job.policy_generation),
            ('started_boottime_ms',grant.requested_boottime_ms))))
        previous=self.read_release(expected_job=grant.job)
        if previous is not None:
            _require(previous==grant and self.read_release(expected_job=grant.job,durable=True)==grant)
            return
        self._write(self._control,'release.json',0o400,grant.encoded())

    def read_release(self,*,expected_job,durable=False):
        _require(type(expected_job) is ObservationJob and self.read_job()==expected_job)
        raw=self._read(self._control,'release.json',0o400,durable=durable)
        if raw is None:return None
        value=_decode(raw[0]);_require(type(value) is dict and type(value.get('job')) is dict)
        actual=ObservationJob.parse(json.dumps(value['job']).encode('ascii'))
        grant=ReleaseGrant.parse(raw[0],expected_job=actual)
        if actual!=expected_job:
            _require(actual.helper_sequence<expected_job.helper_sequence)
            return None
        return grant

    def _result(self,expected_job,*,durable=False):
        raw=self._read(self._results,'result.json',0o600,durable=durable)
        if raw is None:return None
        value=_decode(raw[0]);_require(type(value) is dict and type(value.get('job')) is dict)
        actual=ObservationJob.parse(json.dumps(value['job']).encode('ascii'))
        result=ObservationResult.parse(raw[0],expected_job=actual)
        if actual!=expected_job:
            _require(actual.helper_sequence<expected_job.helper_sequence)
            return None
        if result.document()['phase']=='released':
            self._check_grant(expected_job,result.document()['observation_receipt'])
        return result

    def _check_grant(self,job,receipt):
        grant=self.read_release(expected_job=job)
        _require(grant is not None and receipt['lock_open_boottime_ms']<=grant.requested_boottime_ms<=receipt['lock_held_until_boottime_ms'])

    def write_result(self,result):
        _require(type(result) is ObservationResult)
        value=result.document()
        job=ObservationJob.parse(json.dumps(value['job']).encode('ascii'))
        _require(self.read_job()==job)
        if value['phase']=='released':
            self._check_grant(job,value['observation_receipt'])
        previous=self._result(job)
        _transition(previous,result)
        if previous is not None and previous.encoded()==result.encoded():
            confirmed=self._result(job,durable=True)
            _require(confirmed is not None and confirmed.encoded()==result.encoded())
            return
        self._write(self._results,'result.json',0o600,result.encoded())

    def read_result(self,*,expected_job):
        _require(type(expected_job) is ObservationJob and self.read_job()==expected_job)
        if self._journal is not None:self._journal._locked()
        if self._tracked_job!=expected_job:
            _require(self._tracked_job is None or self._tracked_job.helper_sequence<expected_job.helper_sequence)
            self._tracked_job=expected_job;self._last_result=None
        result=self._result(expected_job,durable=self._journal is not None)
        if result is not None:
            _transition(self._last_result,result)
            self._last_result=result
        return result

    def close(self):
        fds=(self._control,self._results)
        self._control=None;self._results=None
        ancestry,self._ancestry=self._ancestry,None
        failed=False
        for fd in fds:
            if fd is not None:
                try:os.close(fd)
                except OSError:failed=True
        if ancestry is not None:
            try:ancestry.close()
            except (OSError,ValueError):failed=True
        if failed:
            raise ChannelError('cleanup_unconfirmed')
