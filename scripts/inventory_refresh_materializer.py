"""Fixed refresh input preparation after durable start; no launch authority.

Only trusted code supplies admitted FDs. The production factory accepts no paths,
commands or identities. Failures fence the same journal; never retry started work.
"""
import hashlib
import json
import os
import re
import secrets
import stat
import sys

from inventory_refresh_observation import _Ancestry, _identity, _stable
from inventory_refresh_policy import MAX_POLICY, MAX_TRUST, RenderedAptPolicy
from inventory_refresh_policy_admission import PolicyGuard
from inventory_refresh_materialized_policy import REQUIRED


def _require(value):
    if not value:raise ValueError('Inventory refresh preparation unavailable')


class RefreshMaterializer:
    def __init__(self,apt,runtime,cache,*,worker_uid,worker_gid,owner=0):
        self._fds=[];self._refs=[];self._ancestries=[];self._closed=False;self._attempted=False
        self._owner=owner;self._uid=worker_uid;self._gid=worker_gid;self._journal=None
        try:
            _require(all(type(value) is int and value>=0 for value in (owner,worker_uid,worker_gid)))
            self._apt=self._own(os.dup(apt));self._runtime=self._own(os.dup(runtime));self._cache=self._own(os.dup(cache))
            for fd in self._fds:self._directory(fd)
            self._directory(self._apt,worker_read=True)
        except BaseException:
            try:self.close()
            finally:raise ValueError('Inventory refresh preparation unavailable') from None

    def __repr__(self):return '<RefreshMaterializer private-material-redacted>'

    @classmethod
    def fixed(cls):
        _require(sys.platform=='linux' and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0))
        # Import only the existing fixed account check; no caller-selected UID.
        from inventory_refresh_worker_service import _accounts
        user,_=_accounts();root=None;ancestries=[];value=None
        try:
            root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            for parts in (('etc','command-center-inventory-refresh','apt'),
                          ('run','command-center-inventory-refresh'),('var','cache','command-center-inventory-refresh')):
                ancestries.append(_Ancestry.open(root,parts))
            value=cls(*(item.fds[-1] for item in ancestries),worker_uid=user.pw_uid,worker_gid=user.pw_gid)
            value._ancestries=ancestries;ancestries=[];value._fixed=True
            value._verify();return value
        except BaseException:
            if value is not None:value.close()
            raise ValueError('Inventory refresh preparation unavailable') from None
        finally:
            failure=False
            if root is not None:
                try:os.close(root)
                except OSError:failure=True
            for ancestry in ancestries:
                try:ancestry.close()
                except (OSError,ValueError):failure=True
            if failure:
                if value is not None:value.close()
                raise ValueError('Inventory refresh preparation unavailable') from None

    def _own(self,fd):self._fds.append(fd);return fd

    def _directory(self,fd,*,worker_read=False):
        info=os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid==self._owner and not info.st_mode&0o022)
        if worker_read:_require(info.st_gid==self._gid and info.st_mode&0o050==0o050)
        return info

    def _verify(self):
        _require(not self._closed)
        for ancestry in self._ancestries:ancestry.verify()
        for fd in (self._apt,self._runtime,self._cache):self._directory(fd)
        for parent,name,fd,identity in self._refs:
            opened=self._directory(fd,worker_read=True)
            named=os.stat(name,dir_fd=parent,follow_symlinks=False)
            _require(_identity(opened)==_identity(named)==identity)

    def _subdir(self,parent,name,mode):
        try:os.mkdir(name,mode,dir_fd=parent)
        except FileExistsError:created=False
        else:created=True
        fd=self._own(os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent))
        if created:
            os.fchmod(fd,mode);os.fchown(fd,self._owner,self._gid);os.fsync(fd);os.fsync(parent)
        info=self._directory(fd,worker_read=True)
        self._refs.append((parent,name,fd,_identity(info)))
        self._verify();return fd

    def _existing(self,parent,name):
        try:info=os.stat(name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:return None
        _require(stat.S_ISREG(info.st_mode) and info.st_uid==self._owner and info.st_gid==self._gid and
                 info.st_nlink==1 and stat.S_IMODE(info.st_mode) in (0o440,0o640) and info.st_size<=MAX_POLICY)
        return _stable(info)

    def _write(self,parent,name,raw):
        _require(type(raw) is bytes and len(raw)<=MAX_TRUST)
        self._verify();before=self._existing(parent,name)
        temporary='.materialize-'+secrets.token_hex(16);fd=None;created=False;identity=None
        try:
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);created=True
            identity=_identity(os.fstat(fd))
            offset=0
            while offset<len(raw):
                count=os.write(fd,raw[offset:]);_require(type(count) is int and 0<count<=len(raw)-offset);offset+=count
            os.fchown(fd,self._owner,self._gid);os.fchmod(fd,0o640)
            info=os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid==self._owner and info.st_gid==self._gid and
                     stat.S_IMODE(info.st_mode)==0o640 and info.st_nlink==1 and info.st_size==len(raw))
            os.fsync(fd)
            _require(_stable(info)==_stable(os.fstat(fd))==_stable(os.stat(temporary,dir_fd=parent,follow_symlinks=False)))
            closing,fd=fd,None;os.close(closing)
            self._verify();_require(self._existing(parent,name)==before)
            _require(_stable(info)==_stable(os.stat(temporary,dir_fd=parent,follow_symlinks=False)))
            os.replace(temporary,name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
        finally:
            try:
                if fd is not None:os.close(fd)
            finally:
                if created:
                    try:
                        named=os.stat(temporary,dir_fd=parent,follow_symlinks=False)
                        _require(identity is not None and _identity(named)==identity)
                        os.unlink(temporary,dir_fd=parent)
                    except FileNotFoundError:pass

    def _stage(self,token):
        os.mkdir('staging-'+token,0o700,dir_fd=self._cache)
        stage=os.open('staging-'+token,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self._cache)
        try:
            os.fchmod(stage,0o700)
            for name in ('lists','cache','archives','log','tmp'):
                os.mkdir(name,0o700,dir_fd=stage)
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=stage)
                try:
                    os.fchmod(child,0o700)
                    if name=='lists':
                        os.mkdir('partial',0o700,dir_fd=child)
                        partial=os.open('partial',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=child)
                        try:os.fchmod(partial,0o700);os.fchown(partial,self._uid,self._gid);os.fsync(partial)
                        finally:os.close(partial)
                    os.fchown(child,self._uid,self._gid);os.fsync(child)
                finally:os.close(child)
            # CAP3 cannot chmod after ownership moves away from root.
            os.fchown(stage,self._uid,self._gid);os.fsync(stage);os.fsync(self._cache)
        finally:os.close(stage)

    def prepare(self,journal,policy):
        admitted=False
        try:
            _require(not self._closed and not self._attempted);self._attempted=True
            journal._locked();snapshot=journal.snapshot();record=snapshot['capabilities']['refresh']['active']
            _require(not snapshot['unconfirmed'] and record is not None and record['phase']=='running')
            permit=('refresh',record['correlator'],record['boot_id'],record['policy_generation'])
            _require(permit in journal._launch_permits)
            epoch=journal._launch_epoch;admitted=True;self._journal=journal
            _require(type(policy) is PolicyGuard)
            if getattr(self,'_fixed',False):_require(policy._owner==policy._group==0 and policy._ancestry is not None)
            policy.recheck();_require(record['policy_generation']==policy.generation)
            self._verify();token=secrets.token_hex(16);rendered=policy.render(token)
            _require(type(rendered) is RenderedAptPolicy and REQUIRED<=set(rendered) and len(rendered)<=256 and
                     sum(len(raw) for raw in rendered.values())<=MAX_POLICY+65536)
            self._stage(token)
            empty=self._subdir(self._apt,'empty.d',0o550)
            with os.scandir(empty) as entries:_require(next(entries,None) is None)
            directories={():self._apt}
            for name,raw in rendered.items():
                parts=tuple(name.split('/'))
                _require(all(re.fullmatch('[A-Za-z0-9_.-]{1,255}',part) and part not in ('.','..') for part in parts))
                if name=='apt.conf':parent=self._runtime;filename='worker-apt.conf'
                else:
                    for depth in range(1,len(parts)):
                        prefix=parts[:depth]
                        if prefix not in directories:directories[prefix]=self._subdir(directories[prefix[:-1]],prefix[-1],0o750)
                    parent=directories[parts[:-1]];filename=parts[-1]
                self._write(parent,filename,raw)
            job={'schema_version':1,'staging_token':token,'config_sha256':hashlib.sha256(rendered['apt.conf']).hexdigest(),
                 'policy_generation':policy.generation,'operation_nonce':record['correlator'],'helper_sequence':record['helper_sequence'],
                 'boot_id':record['boot_id'],'accepted_boottime_ms':record['accepted_boottime_ms'],
                 'started_boottime_ms':record['started_boottime_ms'],'deadline_boottime_ms':record['started_boottime_ms']+600000}
            policy.recheck();self._verify()
            _require(journal._launch_epoch is epoch and journal.snapshot()['capabilities']['refresh']['active']==record)
            self._write(self._runtime,'job.json',json.dumps(job,sort_keys=True,separators=(',',':')).encode('ascii'))
            policy.recheck();self._verify()
            _require(journal._launch_epoch is epoch)
            return job
        except BaseException:
            if admitted:
                try:journal.fence_external()
                except BaseException:pass  # The journal's local poison remains armed.
            raise ValueError('Inventory refresh preparation unavailable') from None

    def close(self):
        if self._closed:return
        self._closed=True;failure=False
        fds,self._fds=self._fds,[]
        for fd in reversed(fds):
            try:os.close(fd)
            except OSError:failure=True
        ancestries,self._ancestries=self._ancestries,[]
        for ancestry in ancestries:
            try:ancestry.close()
            except (OSError,ValueError):failure=True
        if failure:
            if self._journal is not None:
                try:self._journal.fence_external()
                except BaseException:pass
            raise ValueError('Inventory refresh preparation cleanup unconfirmed') from None
