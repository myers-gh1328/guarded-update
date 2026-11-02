"""Fixed root policy/HMAC descriptor guard; no launch or initialization authority.

All input material is private. The parent must already be charged to its trusted
aggregate slice and retain the root journal/cache guards through rechecks.
"""
import hmac
import os
import stat
import sys

from inventory_refresh_observation import _Ancestry, _stable
from inventory_refresh_policy import PolicyError, parse_policy, policy_generation, render_policy, render_reader_policy, MAX_POLICY

FILES=(('policy.json',MAX_POLICY),('policy-commitment.key',32))


def _require(condition):
    if not condition:raise PolicyError()


class PolicyGuard:
    def __init__(self,directory,*,owner=0,group=0):
        self._fd=None;self._ancestry=None;self._closed=False;self._poisoned=False
        self._policy=None;self._key=None;self._generation=None
        self._owner=owner;self._group=group
        try:
            _require(type(owner) is int and owner>=0 and type(group) is int and group>=0)
            self._directory(directory)
            self._fd=os.dup(directory)
            policy,key=self._admit()
            self._policy=policy;self._key=key;self._generation=policy_generation(key,policy)
        except BaseException:
            try:self.close()
            finally:raise PolicyError() from None

    def __repr__(self):return '<PolicyGuard private-material-redacted>'

    @classmethod
    def fixed(cls):
        if (sys.platform!='linux' or os.getresuid()!=(0,0,0) or os.getresgid()!=(0,0,0)):
            raise PolicyError()
        root=None;ancestry=None;guard=None
        try:
            root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            ancestry=_Ancestry.open(root,('etc','command-center-inventory-refresh'))
            guard=cls(ancestry.fds[-1]);guard._ancestry=ancestry;ancestry=None
            guard.recheck()
            return guard
        except BaseException:
            if guard is not None:
                try:guard.close()
                except BaseException:pass
            raise PolicyError() from None
        finally:
            failure=False
            if root is not None:
                try:os.close(root)
                except OSError:failure=True
            if ancestry is not None:
                try:ancestry.close()
                except (OSError,ValueError):failure=True
            if failure:
                if guard is not None:
                    try:guard.close()
                    except BaseException:pass
                raise PolicyError() from None

    def _directory(self,fd):
        info=os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid==self._owner and not info.st_mode&0o022)

    def _check(self):
        _require(not self._closed and not self._poisoned and self._fd is not None)
        self._directory(self._fd)
        if self._ancestry is not None:self._ancestry.verify()

    def _admit(self):
        self._check();opened=[];values={}
        try:
            for name,limit in FILES:
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._fd)
                opened.append((name,fd,None))
                info=os.fstat(fd);opened[-1]=(name,fd,info)
                _require(stat.S_ISREG(info.st_mode) and info.st_uid==self._owner and info.st_gid==self._group and
                         stat.S_IMODE(info.st_mode) in (0o400,0o600) and info.st_nlink==1 and 0<info.st_size<=limit)
                raw=b''
                while True:
                    chunk=os.read(fd,min(65536,limit+1-len(raw)))
                    if not chunk:break
                    raw+=chunk;_require(len(raw)<=limit)
                _require(len(raw)==info.st_size and _stable(info)==_stable(os.fstat(fd)))
                values[name]=raw
            # Recheck BOTH named references after BOTH reads. Replacing policy
            # while reading its commitment key cannot admit a mixed pair.
            for name,fd,before in opened:
                _require(_stable(before)==_stable(os.fstat(fd)) and
                         _stable(before)==_stable(os.stat(name,dir_fd=self._fd,follow_symlinks=False)))
            self._check()
            _require(len(values['policy-commitment.key'])==32)
            return parse_policy(values['policy.json']),values['policy-commitment.key']
        except BaseException:
            raise PolicyError() from None
        finally:
            failure=False
            for _,fd,_ in reversed(opened):
                try:os.close(fd)
                except (OSError,ValueError):failure=True
            if failure:raise PolicyError() from None

    @property
    def generation(self):
        """Frozen admitted identity; callers must recheck at every authority boundary."""
        try:self._check();return self._generation
        except BaseException:
            self._poisoned=True;raise PolicyError() from None

    def render(self,staging_token):
        try:
            self._check();return render_policy(self._policy,staging_token)
        except BaseException:
            self._poisoned=True;raise PolicyError() from None

    def reader_projection(self,generation):
        try:
            self._check();return render_reader_policy(self._policy,generation,self._generation)
        except BaseException:
            self._poisoned=True;raise PolicyError() from None

    def recheck(self):
        try:
            self._check();policy,key=self._admit()
            _require(hmac.compare_digest(key,self._key) and policy_generation(key,policy)==self._generation)
        except BaseException:
            self._poisoned=True;raise PolicyError() from None

    def __enter__(self):
        try:self.recheck();return self
        except BaseException:
            self.close();raise

    def __exit__(self,*_):self.close()

    def close(self):
        if self._closed:return
        self._closed=True
        fd,self._fd=self._fd,None;ancestry,self._ancestry=self._ancestry,None
        self._key=None;self._policy=None;self._generation=None
        failure=False
        if fd is not None:
            try:os.close(fd)
            except OSError:failure=True
        if ancestry is not None:
            try:ancestry.close()
            except (OSError,ValueError):failure=True
        if failure:raise PolicyError()
