"""Private Rust-parent staging mechanics; no Root or build provenance claim.

Caller owns and revalidates both ancestry chains and exclusive mutation. This
test-only constructor does not establish production origin or unit emptiness.
Any uncertain partial publish remains preserved and cannot be relabelled.
"""
import hashlib
import os
import re
import stat

ERROR='Rust parent fixture unavailable'
LIMIT=128*1024*1024
DESTINATION='command-center-inventory'


def require(value):
    if not value:raise ValueError(ERROR)


def _metadata(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
        info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _directory(info,owner):
    require(stat.S_ISDIR(info.st_mode) and (info.st_uid,info.st_gid)==owner and not info.st_mode&0o022)
    return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid


class FixtureBinary:
    @classmethod
    def fixed(cls,artifact):
        """Root-only literal destination, borrowing an admitted runner chain."""
        from inventory_refresh_rust_native_admission import RunnerArtifact
        from inventory_refresh_resources import _Chain
        require(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and type(artifact) is RunnerArtifact)
        chain=None;value=None
        try:
            artifact.verify();chain=_Chain(('usr','local','libexec'));chain.verify()
            value=cls.from_directory(artifact.source_dir,artifact.name,chain.fds[-1],artifact.digest,artifact.size,artifact.owner,(0,0))
            value._source_chain=artifact;value._destination_chain=chain;chain=None
            value._verify_source();return value
        except BaseException:
            if value is not None:
                try:value.close()
                except BaseException:pass
            if chain is not None:
                try:chain.close()
                except BaseException:pass
            raise ValueError(ERROR) from None

    @classmethod
    def from_directory(cls,source_dir,name,destination_dir,digest,size,source_owner,destination_owner):
        """Private fixture seam; borrowed directories do not prove ancestry."""
        value=cls();value._source_dir=None;value._destination_dir=None;value._source=None
        value._closed=False;value._uncertain=False;value._close_failed=False;value._published=False;value._attempted=False;value._retired=False
        value._source_chain=None;value._destination_chain=None
        try:
            require(cls is FixtureBinary and type(name) is str and re.fullmatch('command_center_inventory-[0-9a-f]{16}',name) and
                type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) and type(size) is int and 0<size<=LIMIT and
                type(source_owner) is int and source_owner>=0 and type(destination_owner) is tuple and len(destination_owner)==2 and
                all(type(item) is int and item>=0 for item in destination_owner))
            value._name=name;value._digest=digest;value._size=size;value._source_owner=source_owner;value._destination_owner=destination_owner
            value._source_dir=os.dup(source_dir);value._destination_dir=os.dup(destination_dir)
            src=os.fstat(value._source_dir);dst=os.fstat(value._destination_dir)
            require(stat.S_ISDIR(src.st_mode) and src.st_uid==source_owner and not src.st_mode&0o022)
            value._source_identity=(src.st_dev,src.st_ino,src.st_mode,src.st_uid,src.st_gid)
            value._destination_identity=_directory(dst,destination_owner)
            require(value._source_identity[:2]!=value._destination_identity[:2])
            value._source=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value._source_dir)
            info=os.fstat(value._source)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==source_owner and info.st_nlink==1 and
                info.st_dev==src.st_dev and info.st_size==size and bool(info.st_mode&0o111) and not info.st_mode&0o6022)
            value._source_metadata=_metadata(info);value._verify_source()
            try:os.stat(DESTINATION,dir_fd=value._destination_dir,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise ValueError(ERROR)
            return value
        except BaseException:
            try:value.close()
            except BaseException:pass
            raise ValueError(ERROR) from None

    def _dirs(self):
        require(not self._closed)
        src=os.fstat(self._source_dir);require(stat.S_ISDIR(src.st_mode) and src.st_uid==self._source_owner and not src.st_mode&0o022 and
            (src.st_dev,src.st_ino,src.st_mode,src.st_uid,src.st_gid)==self._source_identity)
        require(_directory(os.fstat(self._destination_dir),self._destination_owner)==self._destination_identity)
        if self._source_chain is not None:self._source_chain.verify()
        if self._destination_chain is not None:self._destination_chain.verify()

    def _hash(self,fd):
        os.lseek(fd,0,os.SEEK_SET);digest=hashlib.sha256();size=0
        while True:
            data=os.read(fd,min(65536,self._size+1-size))
            if not data:break
            size+=len(data);require(size<=self._size);digest.update(data)
        require(size==self._size and digest.hexdigest()==self._digest)

    def _verify_source(self):
        self._dirs();before=os.fstat(self._source)
        require(_metadata(before)==self._source_metadata==_metadata(os.stat(self._name,dir_fd=self._source_dir,follow_symlinks=False)))
        self._hash(self._source)
        require(_metadata(os.fstat(self._source))==self._source_metadata==_metadata(os.stat(self._name,dir_fd=self._source_dir,follow_symlinks=False)))
        self._dirs()

    def _verify_target(self,fd,mode):
        self._dirs();before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and (before.st_uid,before.st_gid)==self._destination_owner and before.st_nlink==1 and
            before.st_dev==self._destination_identity[0] and stat.S_IMODE(before.st_mode)==mode and before.st_size==self._size)
        self._hash(fd)
        require(_metadata(before)==_metadata(os.fstat(fd))==_metadata(os.stat(DESTINATION,dir_fd=self._destination_dir,follow_symlinks=False)))
        self._dirs();return _metadata(before)

    def publish(self):
        fd=None;failed=False
        try:
            require(not self._attempted and not self._closed);self._attempted=True;self._verify_source()
            fd=os.open(DESTINATION,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self._destination_dir)
            initial=os.fstat(fd);require(stat.S_ISREG(initial.st_mode) and initial.st_nlink==1 and
                (initial.st_uid,initial.st_gid)==self._destination_owner and initial.st_dev==self._destination_identity[0])
            os.lseek(self._source,0,os.SEEK_SET);count=0;digest=hashlib.sha256()
            while True:
                chunk=os.read(self._source,min(65536,self._size+1-count))
                if not chunk:break
                count+=len(chunk);require(count<=self._size);digest.update(chunk);offset=0
                while offset<len(chunk):
                    written=os.write(fd,chunk[offset:]);require(0<written<=len(chunk)-offset);offset+=written
            require(count==self._size and digest.hexdigest()==self._digest)
            os.fsync(fd);self._verify_source();metadata=self._verify_target(fd,0o600)
            require(metadata[:2]==(initial.st_dev,initial.st_ino))
            os.fchmod(fd,0o555);os.fsync(fd);metadata=self._verify_target(fd,0o555);self._verify_source()
            require(metadata[:2]==(initial.st_dev,initial.st_ino))
            os.fsync(self._destination_dir);self._dirs();self._target_metadata=metadata
        except BaseException:failed=True
        finally:
            if fd is not None:
                try:os.close(fd)
                except BaseException:failed=True
        if failed:self._uncertain=True;raise ValueError(ERROR) from None
        self._published=True

    def verify_published(self):
        fd=None;failed=False
        try:
            require(self._published and not self._closed and not self._uncertain);self._verify_source()
            fd=os.open(DESTINATION,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._destination_dir)
            require(self._verify_target(fd,0o555)==self._target_metadata);self._verify_source()
        except BaseException:failed=True
        finally:
            if fd is not None:
                try:os.close(fd)
                except BaseException:failed=True
        if failed:self._uncertain=True;raise ValueError(ERROR) from None

    def retire(self,confirmed_empty):
        require(not self._retired and not self._closed);self._retired=True;failed=False;fd=None
        try:
            require(type(confirmed_empty) is bool and confirmed_empty and self._published and not self._uncertain)
            self._verify_source();self._dirs()
            fd=os.open(DESTINATION,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._destination_dir)
            require(self._verify_target(fd,0o555)==self._target_metadata);closing,fd=fd,None;os.close(closing)
            require(_metadata(os.stat(DESTINATION,dir_fd=self._destination_dir,follow_symlinks=False))==self._target_metadata)
            self._dirs();os.unlink(DESTINATION,dir_fd=self._destination_dir);os.fsync(self._destination_dir);self._dirs()
        except BaseException:failed=True
        finally:
            if fd is not None:
                try:os.close(fd)
                except BaseException:failed=True
            try:self.close()
            except BaseException:failed=True
        if failed:raise ValueError(ERROR) from None

    def close(self):
        if self._closed:
            if self._close_failed:raise ValueError(ERROR)
            return
        self._closed=True;failed=False
        for name in ('_source','_source_dir','_destination_dir'):
            fd=getattr(self,name);setattr(self,name,None)
            if fd is not None:
                try:os.close(fd)
                except BaseException:failed=True
        chain,self._destination_chain=self._destination_chain,None
        if chain is not None:
            try:chain.close()
            except BaseException:failed=True
        if failed:self._uncertain=True;self._close_failed=True;raise ValueError(ERROR) from None
