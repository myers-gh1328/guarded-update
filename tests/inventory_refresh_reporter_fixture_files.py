"""Protected file staging for disposable native CI, never a device installer.

Caller owns exclusive fixture mutation and must prove its unit recursively empty
before retirement. The Boolean is trusted fixture input, not cleanup authority.
"""
import os
import stat
from inventory_refresh_artifact_fixture import ROOT_MODULES,REPORTER_MODULES,LIB

CORE_NAMES=frozenset(('guardian.py' if name=='inventory_refresh_guardian' else name+'.py') for name in ROOT_MODULES)|{
    'coordinator.py','worker.py','observation-native.py','observation-guardian.py'}
LIBRARY_NAMES=CORE_NAMES|{name+'.py' for name in REPORTER_MODULES}|{'reporter.py'}
FILE_NAMES={LIB+name for name in LIBRARY_NAMES}|{'manifest.json','share/doc/command-center-inventory-refresh/contract.md'}


def require(condition):
    if not condition:raise ValueError('Protected reporter fixture staging unavailable')


def _identity(info):return info.st_dev,info.st_ino
def _metadata(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


class FixtureSources:
    @classmethod
    def fixed(cls,verified):
        require(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true')
        from inventory_refresh_resources import _Chain
        chain=_Chain(('usr','local','libexec','command-center-inventory-refresh'));value=None
        try:
            value=cls._from_directory(chain.fds[-1],verified['files']);value._ancestry=chain;chain=None
            value.verify();return value
        except BaseException:
            if value is not None:value.close()
            raise
        finally:
            if chain is not None:chain.close()

    @classmethod
    def _from_directory(cls,directory,contents,*,owner=(0,0)):
        """Private transferred-data/borrowed-directory fixture, not origin proof."""
        require(cls is FixtureSources)
        value=cls();value._directory=None;value._ancestry=None;value._created=[]
        value._closed=False;value._poisoned=False;value._attempted=False;value._published=False;value._owner=owner
        value._retired=False;value._cleanup_uncertain=False
        try:
            require(type(contents) is dict and set(contents)==FILE_NAMES and type(owner) is tuple and len(owner)==2 and
                all(type(item) is int and item>=0 for item in owner))
            value._expected={name:contents[LIB+name] for name in LIBRARY_NAMES-{'reporter.py'}}
            require(all(type(raw) is bytes and 0<len(raw)<=65536 for raw in value._expected.values()))
            value._directory=os.dup(directory);value._identity=value._directory_info()
            value._missing=set()
            for name in sorted(value._expected):
                if not value._existing(name):
                    require(name not in CORE_NAMES);value._missing.add(name)
            value.verify();return value
        except BaseException:
            value.close();raise ValueError('Protected reporter fixture staging unavailable') from None

    def _directory_info(self):
        info=os.fstat(self._directory)
        require(stat.S_ISDIR(info.st_mode) and (info.st_uid,info.st_gid)==self._owner and not info.st_mode&0o022)
        return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid

    def _check_directory(self):
        require(not self._closed and self._directory_info()==self._identity)
        if self._ancestry is not None:self._ancestry.verify()

    def _file(self,info,size):
        require(stat.S_ISREG(info.st_mode) and (info.st_uid,info.st_gid)==self._owner and stat.S_IMODE(info.st_mode)==0o444 and
            info.st_nlink==1 and info.st_size==size and info.st_dev==self._identity[0])

    def _existing(self,name):
        fd=None
        try:
            try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._directory)
            except FileNotFoundError:return False
            expected=self._expected[name];before=os.fstat(fd);self._file(before,len(expected));raw=bytearray()
            while True:
                chunk=os.read(fd,min(65536,len(expected)+1-len(raw)))
                if not chunk:break
                raw.extend(chunk);require(len(raw)<=len(expected))
            named=os.stat(name,dir_fd=self._directory,follow_symlinks=False)
            require(bytes(raw)==expected and _metadata(before)==_metadata(os.fstat(fd))==_metadata(named))
            return True
        finally:
            if fd is not None:
                try:os.close(fd)
                except BaseException:self._cleanup_uncertain=True;raise

    def verify(self):
        try:
            require(not self._poisoned);self._check_directory()
            for name in sorted(self._expected):
                present=self._existing(name)
                require(present if self._published or name not in self._missing else not present)
            self._check_directory()
        except BaseException:
            self._poisoned=True;raise ValueError('Protected reporter fixture staging unavailable') from None

    def publish(self):
        try:
            require(not self._attempted);self._attempted=True;self.verify()
            for name in sorted(self._missing):
                self._check_directory();raw=self._expected[name];fd=None;record=None
                try:
                    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self._directory)
                    record={'name':name,'identity':None,'metadata':None};self._created.append(record)
                    record['identity']=_identity(os.fstat(fd));offset=0
                    while offset<len(raw):
                        written=os.write(fd,raw[offset:]);require(0<written<=len(raw)-offset);offset+=written
                    os.fchmod(fd,0o444);os.fsync(fd);final=os.fstat(fd);self._file(final,len(raw))
                    require(_identity(final)==record['identity'] and _metadata(final)==_metadata(os.stat(name,dir_fd=self._directory,follow_symlinks=False)))
                    record['metadata']=_metadata(final)
                finally:
                    if fd is not None:
                        if record is None:self._cleanup_uncertain=True
                        elif record['metadata'] is None:
                            try:
                                partial=os.fstat(fd);named=os.stat(name,dir_fd=self._directory,follow_symlinks=False)
                                require(record['identity'] is not None and _identity(partial)==record['identity'] and
                                    stat.S_ISREG(partial.st_mode) and partial.st_nlink==1 and (partial.st_uid,partial.st_gid)==self._owner and
                                    not partial.st_mode&0o022 and 0<=partial.st_size<=len(raw) and _metadata(partial)==_metadata(named))
                                record['metadata']=_metadata(partial)
                            except BaseException:self._cleanup_uncertain=True
                        closing,fd=fd,None
                        try:os.close(closing)
                        except BaseException:self._cleanup_uncertain=True;raise
            os.fsync(self._directory);self._published=True;self.verify()
        except BaseException:
            self._poisoned=True;raise ValueError('Protected reporter fixture publication unconfirmed') from None

    def retire(self,confirmed_empty):
        require(not self._retired and not self._closed);self._retired=True
        records,self._created=self._created,[];failed=type(confirmed_empty) is not bool or not confirmed_empty or self._cleanup_uncertain
        try:
            if not failed:
                for record in reversed(records):
                    try:
                        self._check_directory();info=os.stat(record['name'],dir_fd=self._directory,follow_symlinks=False)
                        require(record['identity'] is not None and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and
                            (info.st_uid,info.st_gid)==self._owner and _identity(info)==record['identity'])
                        require(record['metadata'] is not None and _metadata(info)==record['metadata'])
                        os.unlink(record['name'],dir_fd=self._directory);os.fsync(self._directory)
                    except BaseException:failed=True
        finally:
            try:self.close()
            except BaseException:failed=True
        if failed:raise ValueError('Protected reporter fixture retirement unconfirmed')

    def close(self):
        if self._closed:return
        self._closed=True;directory,self._directory=self._directory,None;chain,self._ancestry=self._ancestry,None;failed=False
        if directory is not None:
            try:os.close(directory)
            except BaseException:failed=True
        if chain is not None:
            try:chain.close()
            except BaseException:failed=True
        if failed:
            self._cleanup_uncertain=True
            raise ValueError('Protected reporter fixture descriptor cleanup unconfirmed')
