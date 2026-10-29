"""Unprivileged CI build recipe; no compiler, delivery or production provenance.

Trusts runner account/toolchain, Git backend and registry. Fresh CARGO_HOME can
download dependencies and run their build scripts as the unprivileged runner.
Pre/post checks assume exclusive mutation; they cannot prove transient absence.
Any failure leaves private trees in place: descendant cleanup is unconfirmed.
"""
import os
from pathlib import Path
import pwd
import selectors
import stat
import subprocess
import time

from inventory_refresh_rust_source_snapshot import snapshot
from inventory_refresh_rust_source_copy import directory,materialize
from inventory_refresh_rust_source_verify import verify
from inventory_refresh_rust_binary_selection import admit

ERROR='Unprivileged Rust fixture build unavailable'
CAP=8*1024*1024


def require(value):
    if not value:raise ValueError(ERROR)


def _absent_configs(source,cargo_home):
    """Cargo searches both source ancestors and CARGO_HOME; reject overrides."""
    for root in (source,*source.parents):
        dot=root/'.cargo'
        try:info=os.lstat(dot)
        except FileNotFoundError:continue
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
        for name in ('config','config.toml'):
            try:os.lstat(dot/name)
            except FileNotFoundError:continue
            raise ValueError(ERROR)
    for name in ('config','config.toml'):
        try:os.lstat(cargo_home/name)
        except FileNotFoundError:continue
        raise ValueError(ERROR)


def _capture(cwd,target,env,deadline):
    """Fixed Cargo invocation; direct child only, no descendant cleanup claim."""
    child=None;selector=None;output=bytearray();failed=False
    try:
        home=Path(pwd.getpwuid(os.geteuid()).pw_dir)
        argv=[str(home/'.cargo'/'bin'/'cargo'),'test','--locked','--no-default-features',
            '--features','inventory-agent','--bin','command-center-inventory','--no-run','--message-format=json']
        require(time.monotonic()<deadline)
        child=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        os.set_blocking(child.stdout.fileno(),False);selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
        eof=False
        while not eof:
            remaining=deadline-time.monotonic();require(remaining>0)
            for key,_ in selector.select(min(.05,remaining)):
                try:data=os.read(key.fileobj.fileno(),min(65536,CAP+1-len(output)))
                except BlockingIOError:continue
                require(time.monotonic()<deadline)
                if not data:eof=True;break
                output.extend(data);require(len(output)<=CAP)
        remaining=deadline-time.monotonic();require(remaining>0 and child.wait(timeout=remaining)==0 and time.monotonic()<deadline)
    except BaseException:failed=True
    finally:
        if selector is not None:
            try:selector.close()
            except BaseException:failed=True
        if child is not None:
            if child.poll() is None:
                try:child.terminate();child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try:child.kill();child.wait(timeout=2)
                    except BaseException:failed=True
                except BaseException:failed=True
            if child.stdout is not None:
                try:child.stdout.close()
                except BaseException:failed=True
    if failed or time.monotonic()>=deadline:raise ValueError(ERROR) from None
    return bytes(output)


def build(repo,output,output_fd,owner):
    descriptors=[];failed=False;result=None;deadline=time.monotonic()+600
    def clock():require(time.monotonic()<deadline)
    try:
        require(os.geteuid()!=0 and type(owner) is int and owner==os.geteuid() and
            isinstance(repo,Path) and repo.is_absolute() and isinstance(output,Path) and output.is_absolute() and
            str(repo)==os.path.normpath(str(repo)) and str(output)==os.path.normpath(str(output)) and type(output_fd) is int)
        root=os.dup(output_fd);descriptors.append(root);root_id=directory(os.fstat(root),owner)
        require(directory(os.stat(output,follow_symlinks=False),owner)==root_id)
        selected=snapshot(repo);clock();materialize(selected,output,root,owner);clock()
        source=output/('source-'+selected['source_commit']);verify(selected,output,root,owner);clock()
        siblings=[]
        for name in ('target','cargo-home'):
            os.mkdir(name,0o700,dir_fd=root);clock()
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=root);descriptors.append(fd)
            identity=directory(os.fstat(fd),owner,root_id[0]);require(identity==directory(os.stat(name,dir_fd=root,follow_symlinks=False),owner,root_id[0]))
            siblings.append((name,fd,identity));os.fsync(root);clock()
        target=output/'target';cargo_home=output/'cargo-home';runner_home=Path(pwd.getpwuid(os.geteuid()).pw_dir)
        require(runner_home.is_absolute());_absent_configs(source,cargo_home);clock()
        env={'PATH':str(runner_home/'.cargo'/'bin')+':/usr/bin:/bin','HOME':str(output),'CARGO_HOME':str(cargo_home),
            'RUSTUP_HOME':str(runner_home/'.rustup'),'CARGO_TARGET_DIR':str(target),'CARGO_INCREMENTAL':'0','LC_ALL':'C','LANG':'C'}
        raw=_capture(source,target,env,deadline);clock();_absent_configs(source,cargo_home);clock()
        verify(selected,output,root,owner);clock()
        final=snapshot(repo);clock();require(final==selected)
        require(directory(os.fstat(root),owner)==root_id==directory(os.stat(output,follow_symlinks=False),owner))
        for name,fd,identity in siblings:
            require(directory(os.fstat(fd),owner,root_id[0])==identity==directory(os.stat(name,dir_fd=root,follow_symlinks=False),owner,root_id[0]))
        candidate=admit(raw,source,target,siblings[0][1],owner);clock()
        _absent_configs(source,cargo_home);verify(selected,output,root,owner);clock()
        result=dict(source_commit=selected['source_commit'],tree=selected['tree'],binary_sha256=candidate['sha256'],
            binary_size=candidate['size'],binary_path=str(target/'debug'/'deps'/candidate['name']))
    except BaseException:failed=True
    finally:
        for fd in reversed(descriptors):
            try:os.close(fd)
            except BaseException:failed=True
    if failed or time.monotonic()>=deadline:raise ValueError(ERROR) from None
    return result
