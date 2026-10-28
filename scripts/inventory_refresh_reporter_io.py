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
