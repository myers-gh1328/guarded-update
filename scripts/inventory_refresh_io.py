"""Fixed helper I/O primitives. No executable, commands or request authority.

Inputs supply only correlators. Trusted root code selects admitted directories,
capabilities and identities; durable journal acceptance is still mandatory.
"""
import os
import pwd
import secrets
import stat
import sys

from inventory_refresh_observation import _Ancestry, _identity, _stable
from inventory_refresh_protocol import correlator
from inventory_refresh_status import PublicStatus

CAPABILITIES = ('refresh', 'observation', 'release')


class IOErrorState(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__('Fixed inventory helper I/O unavailable: '+reason)


def _parent(fd, owner):
    info=os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:
        raise IOErrorState('state_inconsistent')
    return info


class Inbox:
    def __init__(self, parent, capability, reporter_uid, reporter_gid, *, owner=0):
        self._parent=None
        self._inbox=None
        self._ancestry=None
        self._owner=owner
        self._reporter=reporter_uid
        self._group=reporter_gid
        self._capability=capability
        if type(capability) is not str or capability not in CAPABILITIES:
            raise IOErrorState('invalid_request')
        try:
            _parent(parent,owner)
            self._parent=os.dup(parent)
            self._inbox=os.open(capability,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._parent)
            self._identity=_identity(os.fstat(self._inbox))
            self._verify()
        except BaseException as error:
            self.close()
            if isinstance(error,OSError):
                raise IOErrorState('state_inconsistent') from None
            raise

    @classmethod
    def fixed(cls, capability):
        if sys.platform!='linux' or os.geteuid()!=0:
            raise IOErrorState('policy_unsupported')
        try:
            reporter=pwd.getpwnam('ccinventory')
            if reporter.pw_uid<=0 or reporter.pw_gid<=0:
                raise IOErrorState('policy_unsupported')
        except KeyError:
            raise IOErrorState('policy_unsupported') from None
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        ancestry=None
        reader=None
        try:
            ancestry=_Ancestry.open(root,('run','command-center-inventory-refresh'))
            reader=cls(ancestry.fds[-1],capability,reporter.pw_uid,reporter.pw_gid)
            reader._ancestry=ancestry
            ancestry=None
            reader._verify()
            return reader
        except BaseException:
            if reader is not None:
                reader.close()
            raise
        finally:
            os.close(root)
            if ancestry is not None:
                ancestry.close()

    def _verify(self):
        if self._parent is None or self._inbox is None:
            raise IOErrorState('state_inconsistent')
        try:
            if self._ancestry is not None:
                self._ancestry.verify()
                _traversable(self._ancestry.fds,self._reporter,self._group)
            _parent(self._parent,self._owner)
            _traversable([self._parent,self._inbox],self._reporter,self._group)
            info=os.fstat(self._inbox)
            named=os.stat(self._capability,dir_fd=self._parent,follow_symlinks=False)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=self._owner or
                    info.st_gid!=self._group or stat.S_IMODE(info.st_mode)!=0o770 or
                    _identity(info)!=self._identity or _identity(named)!=self._identity or
                    _stable(info)!=_stable(named)):
                raise IOErrorState('state_inconsistent')
        except OSError:
            raise IOErrorState('state_inconsistent') from None

    def _request(self, info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=self._reporter or
                info.st_gid!=self._group or stat.S_IMODE(info.st_mode)!=0o600 or
                info.st_nlink!=1 or not 0<info.st_size<=64):
            raise IOErrorState('invalid_request')

    def read(self):
        snapshot=self.read_snapshot()
        return None if snapshot is None else snapshot[:2]

    def read_snapshot(self):
        """Verified nonce plus exact file metadata, not an atomic CAS grant."""
        self._verify()
        try:
            fd=os.open('request',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._inbox)
        except FileNotFoundError:
            self._verify()
            return None
        except OSError:
            raise IOErrorState('invalid_request') from None
        try:
            before=os.fstat(fd)
            self._request(before)
            raw=bytearray()
            while len(raw)<65:
                chunk=os.read(fd,65-len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            after=os.fstat(fd)
            self._request(after)
            named=os.stat('request',dir_fd=self._inbox,follow_symlinks=False)
            self._request(named)
            self._verify()
            if len(raw)!=before.st_size or _stable(before)!=_stable(after) or _stable(named)!=_stable(after):
                raise IOErrorState('invalid_request')
            try:
                nonce,sequence=correlator(bytes(raw))
                return nonce,sequence,_stable(after)
            except ValueError:
                raise IOErrorState('invalid_request') from None
        except OSError:
            raise IOErrorState('invalid_request') from None
        finally:
            try:
                os.close(fd)
            except OSError:
                raise IOErrorState('cleanup_unconfirmed') from None

    def close(self):
        fds=[self._inbox,self._parent]
        self._inbox,self._parent=None,None
        failed=False
        for fd in fds:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    failed=True
        ancestry,self._ancestry=self._ancestry,None
        if ancestry is not None:
            try:
                ancestry.close()
            except ValueError:
                failed=True
        if failed:
            raise IOErrorState('cleanup_unconfirmed')


class PublicationError(IOErrorState):
    def __init__(self, may_be_visible):
        self.may_be_visible=may_be_visible
        super().__init__('persistence_unconfirmed')


def _status_directory(fd, owner, reader_gid):
    info=_parent(fd,owner)
    if info.st_gid!=reader_gid or stat.S_IMODE(info.st_mode)!=0o750:
        raise IOErrorState('state_inconsistent')
    return info


class StatusPublisher:
    """Typed public status publisher; byte sink is private to the coordinator."""
    def __init__(self, directory, journal, reader_gid, *, owner=0):
        self._directory=None
        self._ancestry=None
        self._reporter_uid=None
        self._journal=journal
        self._group=reader_gid
        self._owner=owner
        try:
            _status_directory(directory,owner,reader_gid)
            self._directory=os.dup(directory)
        except OSError:
            raise IOErrorState('state_inconsistent') from None

    @classmethod
    def fixed(cls, journal):
        if sys.platform!='linux' or os.geteuid()!=0:
            raise IOErrorState('policy_unsupported')
        try:
            reporter=pwd.getpwnam('ccinventory')
            if reporter.pw_uid<=0 or reporter.pw_gid<=0:
                raise IOErrorState('policy_unsupported')
        except KeyError:
            raise IOErrorState('policy_unsupported') from None
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        ancestry=None
        publisher=None
        try:
            ancestry=_Ancestry.open(root,('run','command-center-inventory-refresh','status'))
            _traversable(ancestry.fds,reporter.pw_uid,reporter.pw_gid)
            publisher=cls(ancestry.fds[-1],journal,reporter.pw_gid)
            publisher._reporter_uid=reporter.pw_uid
            publisher._ancestry=ancestry
            ancestry=None
            publisher._verify()
            return publisher
        except BaseException:
            if publisher is not None:
                publisher.close()
            raise
        finally:
            os.close(root)
            if ancestry is not None:
                ancestry.close()

    def _public_file(self, info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=self._owner or info.st_gid!=self._group or
                stat.S_IMODE(info.st_mode)!=0o640 or info.st_nlink!=1 or not 0<info.st_size<=65536):
            raise IOErrorState('state_inconsistent')

    def _verify(self):
        if self._directory is None:
            raise IOErrorState('state_inconsistent')
        try:
            if self._ancestry is not None:
                self._ancestry.verify()
                _traversable(self._ancestry.fds,self._reporter_uid,self._group)
            _status_directory(self._directory,self._owner,self._group)
            try:
                fd=os.open('status.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._directory)
            except FileNotFoundError:
                return
            try:
                self._public_file(os.fstat(fd))
            finally:
                os.close(fd)
        except OSError:
            raise IOErrorState('state_inconsistent') from None

    def publish(self, status):
        if type(status) is not PublicStatus:
            raise IOErrorState('invalid_request')
        self._publish(status.encoded())

    def _publish(self, raw):
        self._journal._locked()
        if type(raw) is not bytes or not 0<len(raw)<=65536:
            raise IOErrorState('invalid_request')
        self._verify()
        temporary='.status-'+secrets.token_hex(16)
        fd=None
        created=False
        replace_attempted=False
        error=None
        try:
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self._directory)
            created=True
            offset=0
            while offset<len(raw):
                written=os.write(fd,raw[offset:])
                if written<=0:
                    raise IOErrorState('persistence_unconfirmed')
                offset+=written
            os.fchown(fd,self._owner,self._group)
            os.fchmod(fd,0o640)
            self._public_file(os.fstat(fd))
            if os.fstat(fd).st_size!=len(raw):
                raise IOErrorState('persistence_unconfirmed')
            os.fsync(fd)
            self._verify()
            replace_attempted=True
            os.replace(temporary,'status.json',src_dir_fd=self._directory,dst_dir_fd=self._directory)
            self._verify()
            os.fsync(self._directory)
            self._verify()
        except (OSError,ValueError):
            error=PublicationError(replace_attempted)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    error=PublicationError(replace_attempted)
            if created:
                try:
                    os.unlink(temporary,dir_fd=self._directory)
                except FileNotFoundError:
                    pass
                except OSError:
                    error=PublicationError(replace_attempted)
        if error is not None:
            raise error

    def close(self):
        directory,self._directory=self._directory,None
        failed=False
        if directory is not None:
            try:
                os.close(directory)
            except OSError:
                failed=True
        ancestry,self._ancestry=self._ancestry,None
        if ancestry is not None:
            try:
                ancestry.close()
            except ValueError:
                failed=True
        if failed:
            raise IOErrorState('cleanup_unconfirmed')


def _traversable(directories, reporter_uid, reporter_gid):
    try:
        for fd in directories:
            info=os.fstat(fd)
            needed=0o100 if info.st_uid==reporter_uid else 0o010 if info.st_gid==reporter_gid else 0o001
            if not stat.S_ISDIR(info.st_mode) or not info.st_mode&needed:
                raise IOErrorState('state_inconsistent')
    except OSError:
        raise IOErrorState('state_inconsistent') from None
