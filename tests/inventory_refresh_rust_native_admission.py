"""Fixed CI runner artifact admission; not trusted release/source provenance.

Real entry uses literal runner path and system account. Private root-FD seam is
for tests only. Runner/toolchain/registry and exclusive mutation are trusted;
successful admission alone conveys neither launch nor cleanup authority.
"""
import hashlib
import json
import os
import pwd
import re
import stat
import time

ERROR='Native Rust runner artifact unavailable'
LIMIT=128*1024*1024
PARTS=('home','runner','work','_temp','inventory-rust-parent','target','debug','deps')


def require(value):
    if not value:raise ValueError(ERROR)


def _meta(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def _dir(info,owner):
    sticky=info.st_uid==0 and bool(info.st_mode&stat.S_ISVTX)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,owner) and (not info.st_mode&0o022 or sticky))
    return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid


def _unique(pairs):
    result={}
    for key,value in pairs:require(key not in result);result[key]=value
    return result


def _constant(_):raise ValueError(ERROR)


class RunnerArtifact:
    @classmethod
    def fixed(cls,archive_commit,deadline):
        # The caller supplies only the existing archive verifier's admitted
        # commit. That verifier's pre-existing Root Git calls still trust the
        # checkout/config/backend; this method executes no Git or network code.
        require(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and
            type(archive_commit) is str and re.fullmatch('[0-9a-f]{40}',archive_commit))
        account=pwd.getpwnam('runner');require(account.pw_uid>0 and account.pw_gid>0 and account.pw_dir=='/home/runner')
        require(time.monotonic()<deadline)
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK);value=None;failed=False
        try:value=cls.from_root(root,PARTS,account.pw_uid,account.pw_gid,archive_commit,None,deadline)
        except BaseException:failed=True
        finally:
            try:os.close(root)
            except BaseException:failed=True
        if failed:
            if value is not None:
                try:value.close()
                except BaseException:pass
            raise ValueError(ERROR) from None
        try:
            value.verify();return value
        except BaseException:
            value.close();raise ValueError(ERROR) from None

    @classmethod
    def from_root(cls,root,parts,owner,group,commit,tree,deadline):
        value=cls();value._fds=[];value._refs=[];value._closed=False;value._close_failed=False;value._poisoned=False;value._deadline=deadline
        try:
            require(cls is RunnerArtifact and type(parts) is tuple and 4<=len(parts)<=32 and
                parts[-4:]==('inventory-rust-parent','target','debug','deps') and
                all(type(part) is str and re.fullmatch('[A-Za-z0-9_.-]{1,255}',part) and part not in ('.','..') for part in parts) and
                type(owner) is int and owner>=0 and type(group) is int and group>=0 and
                type(commit) is str and re.fullmatch('[0-9a-f]{40}',commit) and
                (tree is None or type(tree) is str and re.fullmatch('[0-9a-f]{40}',tree)))
            value.owner=owner;value.group=group;value._commit=commit;value._tree=tree
            fd=os.dup(root);value._fds.append(fd);value._root_identity=_dir(os.fstat(fd),owner);parent=fd
            for part in parts:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);value._fds.append(child)
                identity=_dir(os.fstat(child),owner);require(identity==_dir(os.stat(part,dir_fd=parent,follow_symlinks=False),owner))
                value._refs.append((parent,part,child,identity));parent=child
            value._output=value._fds[len(parts)-3];output=os.fstat(value._output)
            require(output.st_uid==owner and output.st_gid==group and stat.S_IMODE(output.st_mode)==0o700)
            value.source_dir=parent
            value._manifest=os.open('manifest.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value._output);value._fds.append(value._manifest)
            initial=os.fstat(value._manifest)
            require(stat.S_ISREG(initial.st_mode) and initial.st_uid==owner and initial.st_gid==group and initial.st_nlink==1 and
                stat.S_IMODE(initial.st_mode)==0o600 and 0<initial.st_size<=1024 and initial.st_dev==output.st_dev)
            value._manifest_metadata=_meta(initial);raw=value._read_manifest()
            manifest=json.loads(raw,object_pairs_hook=_unique,parse_constant=_constant)
            require(type(manifest) is dict and set(manifest)=={'schema_version','source_commit','tree','binary_name','binary_sha256','binary_size'} and
                type(manifest['schema_version']) is int and manifest['schema_version']==1 and manifest['source_commit']==commit and
                type(manifest['tree']) is str and re.fullmatch('[0-9a-f]{40}',manifest['tree']) and (tree is None or manifest['tree']==tree) and
                type(manifest['binary_name']) is str and re.fullmatch('command_center_inventory-[0-9a-f]{16}',manifest['binary_name']) and
                type(manifest['binary_sha256']) is str and re.fullmatch('[0-9a-f]{64}',manifest['binary_sha256']) and
                type(manifest['binary_size']) is int and 0<manifest['binary_size']<=LIMIT)
            value.name=manifest['binary_name'];value.digest=manifest['binary_sha256'];value.size=manifest['binary_size'];value._manifest_bytes=raw
            value._binary=os.open(value.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value.source_dir);value._fds.append(value._binary)
            info=os.fstat(value._binary)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==owner and info.st_nlink==1 and bool(info.st_mode&0o111) and
                not info.st_mode&0o6022 and info.st_size==value.size and info.st_dev==os.fstat(value.source_dir).st_dev)
            value._binary_metadata=_meta(info);value.verify();return value
        except BaseException:
            try:value.close()
            except BaseException:pass
            raise ValueError(ERROR) from None

    def _clock(self):require(time.monotonic()<self._deadline)
    def _chain(self):
        require(not self._closed);self._clock();require(_dir(os.fstat(self._fds[0]),self.owner)==self._root_identity)
        for parent,name,child,identity in self._refs:
            require(_dir(os.fstat(child),self.owner)==identity==_dir(os.stat(name,dir_fd=parent,follow_symlinks=False),self.owner))
        self._clock()
    def _read_manifest(self):
        self._chain();require(_meta(os.fstat(self._manifest))==self._manifest_metadata==_meta(os.stat('manifest.json',dir_fd=self._output,follow_symlinks=False)))
        os.lseek(self._manifest,0,os.SEEK_SET);raw=bytearray()
        while True:
            self._clock();chunk=os.read(self._manifest,min(1025-len(raw),65536))
            if not chunk:break
            raw.extend(chunk);require(len(raw)<=1024)
        require(len(raw)==self._manifest_metadata[6] and _meta(os.fstat(self._manifest))==self._manifest_metadata==_meta(os.stat('manifest.json',dir_fd=self._output,follow_symlinks=False)))
        self._chain();return bytes(raw)
    def verify(self):
        try:
            require(not self._closed and not self._poisoned and self._read_manifest()==self._manifest_bytes);self._chain()
            require(_meta(os.fstat(self._binary))==self._binary_metadata==_meta(os.stat(self.name,dir_fd=self.source_dir,follow_symlinks=False)))
            os.lseek(self._binary,0,os.SEEK_SET);digest=hashlib.sha256();size=0
            while True:
                self._clock();chunk=os.read(self._binary,min(65536,self.size+1-size))
                if not chunk:break
                size+=len(chunk);require(size<=self.size);digest.update(chunk)
            require(size==self.size and digest.hexdigest()==self.digest and
                _meta(os.fstat(self._binary))==self._binary_metadata==_meta(os.stat(self.name,dir_fd=self.source_dir,follow_symlinks=False)))
            self._chain();self._clock()
        except BaseException:self._poisoned=True;raise ValueError(ERROR) from None
    def close(self):
        if self._closed:
            if self._close_failed:raise ValueError(ERROR)
            return
        self._closed=True;fds,self._fds=self._fds,[];failed=False
        for fd in reversed(fds):
            try:os.close(fd)
            except BaseException:failed=True
        if failed:self._close_failed=True;raise ValueError(ERROR) from None
