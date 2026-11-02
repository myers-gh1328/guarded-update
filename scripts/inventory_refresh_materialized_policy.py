"""Bind actual fixed APT input objects to the admitted private policy.

No writer, launcher or path/options interface. File identities and bytes remain
frozen across work; a matching config hash alone cannot attest auxiliary inputs.
"""
import hashlib
import hmac
import os
import re
import stat
import sys

from inventory_refresh_observation import _Ancestry, _stable
from inventory_refresh_policy import PolicyError, RenderedAptPolicy, MAX_POLICY, MAX_TRUST
from inventory_refresh_policy_admission import PolicyGuard

REQUIRED={'apt.conf','sources.sources','preferences','auth.conf','proxy.conf','empty-main.conf',
          'empty-trusted.gpg','empty-status','ca-certificates.crt'}


def _require(condition):
    if not condition:raise PolicyError()


class MaterializedPolicy:
    def __init__(self,apt,runtime,rendered,group,*,owner=0):
        self._fds=[];self._files=[];self._dirs=[];self._ancestries=[];self._policy=None
        self._closed=False;self._poisoned=False;self._owner=owner;self._group=group
        self._empty=None;self._config_hash=None
        try:
            _require(type(rendered) is RenderedAptPolicy and type(group) is int and group>=0 and type(owner) is int and owner>=0)
            expected=tuple(rendered.items())
            _require(REQUIRED<=set(name for name,_ in expected) and len(expected)<=256 and
                     all(type(raw) is bytes and len(raw)<=MAX_TRUST for _,raw in expected) and
                     sum(len(raw) for _,raw in expected)<=MAX_POLICY+65536)
            self._directory(apt,group=True);self._directory(runtime)
            self._apt=self._own(os.dup(apt));self._runtime=self._own(os.dup(runtime))
            directories={():self._apt}
            for name,raw in expected:
                _require(type(name) is str)
                parts=tuple(name.split('/'))
                _require(all(re.fullmatch('[A-Za-z0-9_.-]{1,255}',part) is not None and part not in ('.','..') for part in parts))
                if name=='apt.conf':parent=self._runtime;filename='worker-apt.conf'
                else:
                    for depth in range(1,len(parts)):
                        prefix=parts[:depth]
                        if prefix not in directories:
                            parent=directories[prefix[:-1]]
                            child=self._open_directory(parent,prefix[-1]);directories[prefix]=child
                    parent=directories[parts[:-1]];filename=parts[-1]
                fd=self._own(os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent))
                info=os.fstat(fd)
                _require(stat.S_ISREG(info.st_mode) and info.st_uid==owner and info.st_gid==group and
                         stat.S_IMODE(info.st_mode) in (0o440,0o640) and info.st_nlink==1 and info.st_size==len(raw))
                record=(parent,filename,fd,info,raw)
                self._files.append(record);self._verify_file(record)
                if name=='apt.conf':self._config_hash=hashlib.sha256(raw).hexdigest()
            empty=self._open_directory(self._apt,'empty.d')
            self._empty=(empty,os.fstat(empty))
            self.recheck()
        except BaseException:
            try:self.close()
            finally:raise PolicyError() from None

    def __repr__(self):return '<MaterializedPolicy private-material-redacted>'

    @classmethod
    def fixed(cls,policy,staging_token,group,config_sha256):
        _require(sys.platform=='linux' and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0))
        _require(type(policy) is PolicyGuard and policy._owner==0 and policy._group==0 and policy._ancestry is not None and
                 type(group) is int and group>0)
        root=None;ancestries=[];value=None
        try:
            policy.recheck()
            root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            for parts in (('etc','command-center-inventory-refresh','apt'),('run','command-center-inventory-refresh')):
                ancestries.append(_Ancestry.open(root,parts))
            value=cls(ancestries[0].fds[-1],ancestries[1].fds[-1],policy.render(staging_token),group)
            value._ancestries=ancestries;ancestries=[];value._policy=policy
            value.verify_config_hash(config_sha256)
            return value
        except BaseException:
            if value is not None:
                try:value.close()
                except BaseException:pass
            raise PolicyError() from None
        finally:
            failure=False
            if root is not None:
                try:os.close(root)
                except OSError:failure=True
            for ancestry in ancestries:
                try:ancestry.close()
                except (OSError,ValueError):failure=True
            if failure:
                if value is not None:
                    try:value.close()
                    except BaseException:pass
                raise PolicyError() from None

    def _own(self,fd):self._fds.append(fd);return fd

    def _directory(self,fd,*,group=False):
        info=os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid==self._owner and not info.st_mode&0o022)
        if group:_require(info.st_gid==self._group and info.st_mode&0o050==0o050)
        return info

    def _open_directory(self,parent,name):
        fd=self._own(os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent))
        info=self._directory(fd,group=True)
        self._dirs.append((parent,name,fd,(info.st_dev,info.st_ino)))
        return fd

    def _verify_file(self,record):
        parent,name,fd,before,expected=record
        _require(_stable(os.fstat(fd))==_stable(before))
        os.lseek(fd,0,os.SEEK_SET);raw=bytearray()
        while True:
            chunk=os.read(fd,min(65536,len(expected)+1-len(raw)))
            if not chunk:break
            raw.extend(chunk);_require(len(raw)<=len(expected))
        _require(hmac.compare_digest(raw,expected) and _stable(before)==_stable(os.fstat(fd)) and
                 _stable(before)==_stable(os.stat(name,dir_fd=parent,follow_symlinks=False)))

    def _verify_directories(self):
        for ancestry in self._ancestries:ancestry.verify()
        self._directory(self._apt,group=True);self._directory(self._runtime)
        for parent,name,fd,identity in self._dirs:
            info=self._directory(fd,group=True)
            named=os.stat(name,dir_fd=parent,follow_symlinks=False)
            _require(stat.S_ISDIR(named.st_mode) and named.st_uid==self._owner and
                     named.st_gid==self._group and not named.st_mode&0o022 and
                     (info.st_dev,info.st_ino)==identity==(named.st_dev,named.st_ino))

    def recheck(self):
        try:
            _require(not self._closed and not self._poisoned)
            if self._policy is not None:self._policy.recheck()
            self._verify_directories()
            for record in self._files:self._verify_file(record)
            if self._empty is not None:
                fd,before=self._empty
                _require(_stable(os.fstat(fd))==_stable(before))
                with os.scandir(fd) as entries:_require(next(entries,None) is None)
            # All earlier references must still match after later artifacts read.
            for parent,name,fd,before,_ in self._files:
                _require(_stable(before)==_stable(os.fstat(fd))==_stable(os.stat(name,dir_fd=parent,follow_symlinks=False)))
            self._verify_directories()
            if self._policy is not None:self._policy.recheck()
        except BaseException:
            self._poisoned=True;raise PolicyError() from None

    def verify_config_hash(self,expected):
        try:
            self.recheck()
            _require(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected) is not None and
                     hmac.compare_digest(expected,self._config_hash))
        except BaseException:
            self._poisoned=True;raise PolicyError() from None

    def __enter__(self):
        try:self.recheck();return self
        except BaseException:
            self.close();raise

    def __exit__(self,*_):self.close()

    def close(self):
        if self._closed:return
        self._closed=True;failure=False
        fds,self._fds=self._fds,[];ancestries,self._ancestries=self._ancestries,[]
        self._files=[];self._dirs=[];self._empty=None;self._policy=None;self._config_hash=None
        for fd in reversed(fds):
            try:os.close(fd)
            except OSError:failure=True
        for ancestry in ancestries:
            try:ancestry.close()
            except (OSError,ValueError):failure=True
        if failure:raise PolicyError() from None
