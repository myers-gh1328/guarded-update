#!/usr/bin/python3
"""Fixed root guardian for the opt-in inventory metadata worker.

PID1 owns the whole service cgroup. Returning from this MAIN process must kill
all descendants; no exit code by itself attests cleanup or permits publication.
No stdin, command, path, option, environment or reporter-selected UID interface.
"""
import os
import pwd
import stat
import subprocess
import sys
import time
import types

LIB_ROOT='/usr/local/libexec/command-center-inventory-refresh'
RUNTIME_ROOT='/run/command-center-inventory-refresh'
MAX_SAFE=9_007_199_254_740_991
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}


def _safe(value):
    return type(value) is int and 0<=value<=MAX_SAFE


def boottime_ms():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000


def worker_argv(uid,gid):
    if type(uid) is not int or type(gid) is not int or not 0<uid<2**32-1 or not 0<gid<2**32-1:
        raise ValueError('Unsupported fixed guardian identity')
    return ('/usr/bin/setpriv','--reuid='+str(uid),'--regid='+str(gid),'--clear-groups',
            '--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',
            '/usr/bin/python3','-I','-B',LIB_ROOT+'/worker.py')


def supervise(started,deadline,spawn,clock=boottime_ms,sleep=time.sleep):
    """Nonblocking owned-child loop; injectable seam has no CLI authority.

    No wait/communicate on timeout: a stopped descendant cannot stall the main
    process exiting and PID1's mandatory control-group cleanup. The coordinator
    must independently prove cgroup empty and worker-UID exclusion afterwards.
    """
    child=None
    try:
        if not _safe(started) or not _safe(deadline) or not started<deadline<=started+600000:
            return 74
        previous=clock()
        if not _safe(previous) or previous<started:
            return 74
        if previous>=deadline:
            return 76
        child=spawn()
        while True:
            now=clock()
            if not _safe(now) or now<previous:
                raise ValueError('Unsupported guardian clock')
            previous=now
            if now>=deadline:
                child.kill()
                return 76
            result=child.poll()
            if result is not None:
                return result if type(result) is int and result in (0,74,75,76) else 74
            sleep(min(0.05,(deadline-now)/1000))
    except (OSError,ValueError,OverflowError):
        if child is not None:
            try:
                child.kill()
            except OSError:
                pass
        return 74


def admit_library():
    """Return exact admitted source bytes; never use module search or pycache."""
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for name in LIB_ROOT.split('/')[1:]:
            current=os.fstat(fd)
            if current.st_uid!=0 or current.st_mode&0o022:
                raise ValueError('Unsupported guardian library')
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            os.close(fd)
            fd=child
        current=os.fstat(fd)
        if current.st_uid!=0 or current.st_mode&0o022:
            raise ValueError('Unsupported guardian library')
        # This executable imports only worker.py; no arbitrary project imports.
        source=os.open('worker.py',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        try:
            item=os.fstat(source)
            if (not stat.S_ISREG(item.st_mode) or item.st_uid!=0 or item.st_nlink!=1 or
                    item.st_mode&0o022 or not 0<item.st_size<=65536):
                raise ValueError('Unsupported guardian library')
            raw=bytearray()
            while len(raw)<=65536:
                chunk=os.read(source,min(16384,65537-len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            def identity(value):
                return (value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode,
                        value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
            after=os.fstat(source)
            named=os.stat('worker.py',dir_fd=fd,follow_symlinks=False)
            if len(raw)!=item.st_size or identity(item)!=identity(after) or identity(item)!=identity(named):
                raise ValueError('Unsupported guardian library')
            return bytes(raw)
        finally:
            os.close(source)
    finally:
        os.close(fd)


def load_worker():
    # Execute exactly the admitted FD bytes. No .so/package/pyc lookup, and no
    # project directory on sys.path to shadow stdlib imports in trusted source.
    raw=admit_library()
    module=types.ModuleType('_command_center_fixed_worker')
    module.__file__=LIB_ROOT+'/worker.py'
    exec(compile(raw,module.__file__,'exec',dont_inherit=True),module.__dict__)
    return module


def guardian_main():
    try:
        if (sys.platform!='linux' or len(sys.argv)!=1 or not sys.flags.isolated or
                os.getresuid()!=(0,0,0) or os.getresgid()!=(0,0,0)):
            return 74
        worker=load_worker()
        user=pwd.getpwnam('ccrefresh')
        reporter=pwd.getpwnam('ccinventory')
        if (user.pw_uid<=0 or user.pw_gid<=0 or reporter.pw_uid<=0 or reporter.pw_gid<=0 or
                user.pw_uid==reporter.pw_uid or user.pw_gid==reporter.pw_gid or
                user.pw_gid in os.getgrouplist('ccinventory',reporter.pw_gid)):
            return 74
        job=worker.parse_job(worker.root_file(RUNTIME_ROOT+'/job.json',user.pw_gid))
        with open('/proc/sys/kernel/random/boot_id','r',encoding='ascii') as source:
            if source.read(64).strip()!=job['boot_id']:
                return 74
        argv=worker_argv(user.pw_uid,user.pw_gid)
        def spawn():
            return subprocess.Popen(argv,env=ENV,cwd='/',close_fds=True,
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return supervise(job['started_boottime_ms'],job['deadline_boottime_ms'],spawn)
    except (OSError,ValueError,KeyError,ImportError,AttributeError):
        return 74


if __name__=='__main__':
    raise SystemExit(guardian_main())
