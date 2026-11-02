"""Protected reporter status input; no inbox writes or executable interface.

The fixed adapter must admit full Root-owned ancestry before supplying this
borrowed directory, and retain/recheck that ancestry across reads. This library
checks publication metadata/bytes only, not Root liveness or native cleanup.
"""
import json
import os
import stat

from inventory_refresh_observation import _identity, _stable
from inventory_refresh_status import PublicStatus

LIMIT=65536


class ReporterIOError(ValueError):
    def __init__(self,reason='state_inconsistent'):
        self.reason=reason
        super().__init__('Protected inventory status unavailable: '+reason)


def _require(condition):
    if not condition:raise ReporterIOError()


def _close(fd):
    try:os.close(fd)
    except OSError:raise ReporterIOError('cleanup_unconfirmed') from None


class StatusReader:
    def __init__(self,directory,reader_gid,*,owner=0):
        self._directory=None;self._owner=owner;self._group=reader_gid
        try:
            self._directory=os.dup(directory)
            self._identity=_identity(os.fstat(self._directory))
            self._verify()
        except BaseException as error:
            self.close()
            if isinstance(error,OSError):raise ReporterIOError() from None
            raise

    def _verify(self):
        _require(self._directory is not None)
        info=os.fstat(self._directory)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid==self._owner and info.st_gid==self._group and
            stat.S_IMODE(info.st_mode)==0o750 and _identity(info)==self._identity)

    def _file(self,info,*,unlinked=False):
        _require(stat.S_ISREG(info.st_mode) and info.st_uid==self._owner and info.st_gid==self._group and
            stat.S_IMODE(info.st_mode)==0o640 and (info.st_nlink==1 or unlinked and info.st_nlink==0) and 0<info.st_size<=LIMIT and
            info.st_dev==os.fstat(self._directory).st_dev)

    def read(self):
        fd=None
        try:
            self._verify()
            try:fd=os.open('status.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._directory)
            except FileNotFoundError:
                self._verify()
                return None
            before=os.fstat(fd);self._file(before)
            raw=bytearray()
            while True:
                chunk=os.read(fd,min(65536,LIMIT+1-len(raw)))
                if not chunk:break
                raw.extend(chunk)
                _require(len(raw)<=LIMIT)
            _require(len(raw)==before.st_size)
            def unique(pairs):
                value={}
                for key,item in pairs:
                    _require(key not in value);value[key]=item
                return value
            status=PublicStatus.create(json.loads(raw,object_pairs_hook=unique))
            after=os.fstat(fd);self._file(after,unlinked=True)
            named=os.stat('status.json',dir_fd=self._directory,follow_symlinks=False);self._file(named)
            self._verify()
            # Atomic replacement unlinks the old opened inode (nlink/ctime
            # change). Admit no old status: only signal a fresh-read retry when
            # all its other protected metadata/content shape stayed unchanged.
            stable=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_size,info.st_mtime_ns)
            unchanged=_stable(before)==_stable(after) or after.st_nlink==0 and stable(before)==stable(after)
            if _identity(named)!=_identity(before) and unchanged:
                raise ReporterIOError('publication_changed')
            _require(_stable(before)==_stable(after)==_stable(named))
            return status
        except ReporterIOError:raise
        except (OSError,ValueError,TypeError,RecursionError):
            raise ReporterIOError() from None
        finally:
            if fd is not None:_close(fd)

    def close(self):
        fd,self._directory=self._directory,None
        if fd is not None:_close(fd)


class RequestPublicationError(ReporterIOError):
    def __init__(self,may_be_visible,cleanup_uncertain):
        self.may_be_visible=may_be_visible
        self.cleanup_uncertain=cleanup_uncertain
        super().__init__('cleanup_unconfirmed' if cleanup_uncertain else 'persistence_unconfirmed')


class ReporterRequestWriter:
    """Fixed nonce I/O only, never independent request/retry authority.

    Trusted caller retains its existing process lock and MUST fsync current
    intent before publish. Sequence/reference checks are point-in-time, not CAS
    against another publisher. Full named ancestry remains caller-owned. Neither
    success nor failure flags prove Root acceptance, cancellation or NoWork.
    """
    def __init__(self,parent,capability,reporter_uid,reporter_gid,*,owner=0):
        # Optional fixed dependency: a reader-only admitted source closure never
        # imports this module or acquires write capabilities merely by reading.
        from inventory_refresh_io import Inbox
        self._inbox=None
        self._inbox=Inbox(parent,capability,reporter_uid,reporter_gid,owner=owner)

    def _temp(self,info,size):
        inbox=self._inbox
        _require(stat.S_ISREG(info.st_mode) and info.st_uid==inbox._reporter and info.st_gid==inbox._group and
            stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and info.st_size==size and
            info.st_dev==os.fstat(inbox._inbox).st_dev)

    def publish(self,nonce):
        from inventory_refresh_protocol import correlator
        import secrets
        try:
            _require(type(nonce) is str and len(nonce)==32)
            parsed,sequence=correlator(nonce.encode('ascii'));_require(parsed==nonce)
        except (ValueError,UnicodeError):raise ReporterIOError('invalid_request') from None
        fd=None;created=False;identity=None;may_be_visible=False;cleanup_uncertain=False;failed=False
        temporary='.request-'+secrets.token_hex(16)
        try:
            _require(self._inbox is not None)
            inbox=self._inbox;inbox._verify()
            previous=inbox.read_snapshot()
            if previous is not None and previous[1]>=sequence:
                may_be_visible=True
                raise ReporterIOError('invalid_request')
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=inbox._inbox)
            created=True;identity=_identity(os.fstat(fd))
            os.fchmod(fd,0o600);self._temp(os.fstat(fd),0)
            raw=nonce.encode('ascii');offset=0
            while offset<len(raw):
                written=os.write(fd,raw[offset:]);_require(0<written<=len(raw)-offset);offset+=written
            self._temp(os.fstat(fd),32);os.fsync(fd)
            inbox._verify()
            if inbox.read_snapshot()!=previous:
                may_be_visible=True
                raise ReporterIOError('state_inconsistent')
            after=os.fstat(fd);self._temp(after,32)
            named=os.stat(temporary,dir_fd=inbox._inbox,follow_symlinks=False);self._temp(named,32)
            _require(_stable(named)==_stable(after) and _identity(after)==identity)
            may_be_visible=True  # A failed rename may already have taken effect.
            os.replace(temporary,'request',src_dir_fd=inbox._inbox,dst_dir_fd=inbox._inbox)
            os.fsync(inbox._inbox);inbox._verify()
            published=inbox.read_snapshot()
            _require(published is not None and published[:2]==(nonce,sequence) and published[2]==_stable(os.fstat(fd)))
        except BaseException as error:
            failed=True
            if getattr(error,'reason',None)=='cleanup_unconfirmed':cleanup_uncertain=True
        finally:
            if fd is not None:
                closing,fd=fd,None
                try:_close(closing)
                except BaseException:cleanup_uncertain=True
            if created:
                try:
                    named=os.stat(temporary,dir_fd=self._inbox._inbox,follow_symlinks=False)
                    if identity is None or _identity(named)!=identity:
                        cleanup_uncertain=True  # Never remove a foreign replacement.
                    else:
                        os.unlink(temporary,dir_fd=self._inbox._inbox);os.fsync(self._inbox._inbox)
                except FileNotFoundError:pass
                except BaseException:cleanup_uncertain=True
        if failed or cleanup_uncertain:raise RequestPublicationError(may_be_visible,cleanup_uncertain) from None

    def close(self):
        inbox,self._inbox=self._inbox,None
        if inbox is not None:inbox.close()
