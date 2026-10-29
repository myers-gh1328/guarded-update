"""Bounded Git tree snapshot; no compiler, backend isolation or production proof.

The CI runner's Git executable, repository-local configuration and object
backend (including any alternates) remain trusted. Object hashes are checked;
this does not establish their origin. Lazy fetch is disabled when supported.
"""
import hashlib
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

ERROR='Rust committed-source snapshot unavailable'
ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','GIT_CONFIG_NOSYSTEM':'1',
    'GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0','GIT_NO_LAZY_FETCH':'1'}
REQUIRED={'Cargo.toml','Cargo.lock','rust-toolchain.toml','src/inventory_main.rs'}


def require(value):
    if not value:raise ValueError(ERROR)


def git(repo,arguments,maximum,deadline):
    process=None;selector=None;output=bytearray();failed=False
    try:
        require(time.monotonic()<deadline and type(arguments) is tuple)
        process=subprocess.Popen(['/usr/bin/git','--no-replace-objects','-c','core.fsmonitor=false',
            '-c','safe.directory='+str(repo),*arguments],cwd=repo,env=ENV,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        os.set_blocking(process.stdout.fileno(),False)
        selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
        eof=False
        while not eof:
            remaining=deadline-time.monotonic();require(remaining>0)
            for key,_ in selector.select(min(.05,remaining)):
                try:data=os.read(key.fileobj.fileno(),min(65536,maximum+1-len(output)))
                except BlockingIOError:continue
                require(time.monotonic()<deadline)
                if not data:eof=True;break
                output.extend(data);require(len(output)<=maximum)
        remaining=deadline-time.monotonic();require(remaining>0 and process.wait(timeout=remaining)==0 and time.monotonic()<deadline)
    except BaseException:failed=True
    finally:
        if selector is not None:
            try:selector.close()
            except BaseException:failed=True
        if process is not None:
            if process.poll() is None:
                try:process.kill()
                except BaseException:failed=True
                try:process.wait(timeout=2)
                except BaseException:failed=True
            if process.stdout is not None:
                try:process.stdout.close()
                except BaseException:failed=True
    if failed or time.monotonic()>=deadline:raise ValueError(ERROR) from None
    return bytes(output)


def object_id(kind,data):
    return hashlib.sha1(kind+b' '+str(len(data)).encode()+b'\0'+data).hexdigest()


def snapshot(repo):
    """Return Git tree bytes; the output is not an admitted executable."""
    try:
        require(isinstance(repo,Path) and repo.is_absolute() and str(repo)==os.path.normpath(str(repo)))
        deadline=time.monotonic()+60
        require(git(repo,('rev-parse','--show-object-format'),32,deadline)==b'sha1\n')
        commit=git(repo,('rev-parse','--verify','HEAD^{commit}'),128,deadline).decode('ascii').strip()
        require(re.fullmatch('[0-9a-f]{40}',commit) is not None)
        commit_bytes=git(repo,('cat-file','commit',commit),1024*1024,deadline)
        require(object_id(b'commit',commit_bytes)==commit)
        headers=commit_bytes.split(b'\n\n',1)[0].splitlines()
        tree_rows=[line[5:] for line in headers if line.startswith(b'tree ')]
        require(len(tree_rows)==1 and re.fullmatch(rb'[0-9a-f]{40}',tree_rows[0]) is not None)
        tree=tree_rows[0].decode('ascii')
        root_tree=git(repo,('cat-file','tree',tree),1024*1024,deadline)
        require(object_id(b'tree',root_tree)==tree)
        listing=git(repo,('ls-tree','-r','-t','-z','-l','--full-tree',tree),1024*1024,deadline)
        require(listing.endswith(b'\0'));rows=listing[:-1].split(b'\0');require(0<len(rows)<=512)
        entries={};directories={};total=0
        for row in rows:
            metadata,separator,path=row.partition(b'\t');parts=metadata.split()
            require(separator and len(parts)==4 and re.fullmatch(rb'[0-9a-f]{40}',parts[2]) is not None)
            name=path.decode('ascii');segments=name.split('/')
            require(all(re.fullmatch(r'[A-Za-z0-9_.-]{1,255}',part) and part not in ('.','..') for part in segments) and
                '.cargo' not in segments and 'build.rs' not in segments and name not in entries and name not in directories)
            if parts[0]==b'040000' and parts[1]==b'tree' and parts[3]==b'-':
                directories[name]=parts[2].decode('ascii');continue
            require(parts[0] in (b'100644',b'100755') and parts[1]==b'blob' and re.fullmatch(rb'[0-9]{1,7}',parts[3]) is not None)
            size=int(parts[3]);require(0<=size<=1024*1024);total+=size;require(total<=16*1024*1024)
            entries[name]=(parts[0].decode('ascii'),parts[2].decode('ascii'),size)
        require(REQUIRED<=set(entries))
        for oid in directories.values():
            raw=git(repo,('cat-file','tree',oid),1024*1024,deadline)
            require(object_id(b'tree',raw)==oid)
        files={};modes={}
        for name,(mode,oid,size) in entries.items():
            raw=git(repo,('cat-file','blob',oid),size,deadline)
            require(len(raw)==size and object_id(b'blob',raw)==oid)
            files[name]=raw;modes[name]=mode
        require(git(repo,('rev-parse','--verify','HEAD^{commit}'),128,deadline).decode('ascii').strip()==commit)
        require(git(repo,('cat-file','commit',commit),1024*1024,deadline)==commit_bytes)
        require(git(repo,('cat-file','tree',tree),1024*1024,deadline)==root_tree)
        require(git(repo,('ls-tree','-r','-t','-z','-l','--full-tree',tree),1024*1024,deadline)==listing)
        require(time.monotonic()<deadline)
        return dict(source_commit=commit,tree=tree,files=files,modes=modes)
    except BaseException:raise ValueError(ERROR) from None
