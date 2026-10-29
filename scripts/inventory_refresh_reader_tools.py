"""Fixed reporter policy query; not an executable or general subprocess API.

The managed reporter must prove its own cgroup teardown separately. A timeout or
failed child cleanup here can never become a Root receipt or retry permission.
"""
from contextlib import contextmanager
import os
import re
import selectors
import subprocess
import time

from inventory_refresh_observation import _Ancestry, ObservationError


def _require(condition):
    if not condition:raise ObservationError('state_inconsistent')


def _ids(packages):
    _require(type(packages) in (list,tuple) and 1<=len(packages)<=300)
    # Match the Rust collector's separate, bounded binary and architecture IDs.
    pattern=r'[a-z0-9][a-z0-9+.-]{0,255}(?::[a-z0-9][a-z0-9+.-]{0,255})?'
    _require(all(type(value) is str and re.fullmatch(pattern,value) is not None for value in packages))
    _require(len(set(packages))==len(packages))
    return tuple(packages)


@contextmanager
def _fixed_generation(cache,generation):
    _require(type(generation) is str and re.fullmatch('[0-9a-f]{32}',generation) is not None)
    root=None;chain=None
    try:
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        chain=_Ancestry.open(root,('var','cache','command-center-inventory-refresh','generation-'+generation))
        def verify():
            chain.verify()
            held=os.fstat(cache.fd);named=os.fstat(chain.fds[-1])
            _require(cache.owner==0 and (held.st_dev,held.st_ino)==(named.st_dev,named.st_ino))
        verify()
        config='/var/cache/command-center-inventory-refresh/generation-'+generation+'/_inventory-reader/apt.conf'
        yield config,verify
        verify()
    finally:
        failed=False
        if chain is not None:
            try:chain.close()
            except BaseException:failed=True
        if root is not None:
            try:os.close(root)
            except BaseException:failed=True
        if failed:raise ObservationError('cleanup_unconfirmed')


def _policy(cache,generation,packages,clock,expiry,limit):
    packages=_ids(packages)
    _require(type(limit) is int and 0<limit<=16*1024*1024)
    # Keep one second of the original observation for finishing/release. This
    # reserve is not a guarantee that Root or reporter cleanup will finish.
    end=time.monotonic()+10
    def remaining():
        budget=min(end-time.monotonic(),(expiry-1000-clock())/1000)
        if budget<=0:raise ObservationError('lease_expired')
        return budget
    with _fixed_generation(cache,generation) as (config,verify):
        remaining();verify();remaining()
        process=None;selector=None;output=bytearray();failed=False
        try:
            process=subprocess.Popen(['/usr/bin/apt-cache','policy',*packages],
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C','APT_CONFIG':config},
                cwd='/',stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                close_fds=True,start_new_session=True)
            _require(process.stdout is not None)
            os.set_blocking(process.stdout.fileno(),False)
            selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
            eof=False
            while True:
                budget=remaining()
                if not eof:
                    for key,_ in selector.select(min(.05,budget)):
                        remaining()
                        try:chunk=os.read(key.fileobj.fileno(),min(65536,limit+1-len(output)))
                        except BlockingIOError:continue
                        if not chunk:
                            selector.unregister(key.fileobj);eof=True
                        else:
                            output.extend(chunk);_require(len(output)<=limit)
                else:time.sleep(min(.01,budget))
                status=process.poll()
                if status is not None:
                    _require(status==0)
                    if eof:break
            remaining()
        except BaseException:
            failed=True
            raise
        finally:
            cleanup_failed=False
            if selector is not None:
                try:selector.close()
                except BaseException:cleanup_failed=True
            if process is not None:
                try:
                    if process.poll() is None:process.kill()
                except BaseException:cleanup_failed=True
                try:process.wait(timeout=1)
                except BaseException:cleanup_failed=True
                if process.stdout is not None:
                    try:process.stdout.close()
                    except BaseException:cleanup_failed=True
            if cleanup_failed:raise ObservationError('cleanup_unconfirmed')
        _require(not failed)
        try:text=output.decode('utf-8')
        except UnicodeError:raise ObservationError('state_inconsistent') from None
        verify();remaining()
    remaining()
    return text
