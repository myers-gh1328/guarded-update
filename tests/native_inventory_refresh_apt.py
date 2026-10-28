#!/usr/bin/env python3
"""Disposable hosted proof of the fixed worker against a synthetic signed TLS repo.

This is never packaged. It creates/removes only its own helper paths/accounts on
an isolated CI VM. It does not prove real-device repository fit or a coordinator.
"""
import base64
from datetime import datetime, timedelta, timezone
import email.utils
import errno
import functools
import gzip
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import marshal
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import ssl
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from inventory_refresh_policy import parse_policy, render_policy, policy_generation, POLICY_ROOT, CACHE_ROOT, RUNTIME_ROOT
from inventory_refresh_storage import Store
from inventory_refresh_worker import validate_kernel_identity
from inventory_refresh_guardian import worker_argv, load_worker
from inventory_refresh_observation import prepare_fixed_executor_guard
from inventory_refresh_cached_observation import ObservationJob, CachedObservation, ObservationResult, ReleaseGrant
from inventory_refresh_channel import ObservationChannel
from inventory_refresh_state import Journal
from inventory_refresh_io import Inbox

WORKER = 60001
READER = 60002
PARENT_SLICE = 'command-center-inventory.slice'
WORKER_SLICE = 'command-center-inventory-worker.slice'
WORKER_UNIT = 'command-center-inventory-refresh-worker.service'
LIB_ROOT = Path('/usr/local/libexec/command-center-inventory-refresh')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
PASSWORD = 'synthetic-proof-password'


def command(args, timeout=60):
    result = subprocess.run(args, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode != 0:
        # All commands here are controlled fixture setup, never real repository secrets.
        raise RuntimeError('Disposable fixture command failed: '+result.stderr.decode(errors='replace')[-6000:])
    return result.stdout


def fingerprint(paths):
    result = hashlib.sha256()
    for path in paths:
        path = Path(path)
        for entry in sorted(path.rglob('*')) if path.is_dir() else [path]:
            result.update(str(entry).encode())
            if entry.is_symlink():
                result.update(os.readlink(entry).encode())
            elif entry.is_file():
                with open(entry, 'rb') as source:
                    while chunk := source.read(65536):
                        result.update(chunk)
    return result.digest()


def cgroup(unit):
    raw = command(['/bin/systemctl', 'show', '--property=ControlGroup', '--value', unit]).decode().strip()
    if not raw.startswith('/') or '..' in raw.split('/') or not raw.endswith('/'+unit):
        raise AssertionError('Unexpected fixed proof cgroup')
    return Path('/sys/fs/cgroup')/raw.lstrip('/')


def empty_worker():
    result = subprocess.run(['/bin/systemctl', 'stop', WORKER_UNIT], env=ENV,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    assert result.returncode in [0, 5]
    values = dict(line.split() for line in (cgroup(WORKER_SLICE)/'cgroup.events').read_text().splitlines())
    assert values['populated'] == '0', 'Owned worker cgroup cleanup unconfirmed'
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = dict(line.split(':', 1) for line in (entry/'status').read_text().splitlines())
            if WORKER in [int(value) for value in fields['Uid'].split()]:
                assert fields['State'].strip().startswith('Z'), 'Refresh UID writer escaped its owned cgroup'
        except (FileNotFoundError, ProcessLookupError):
            pass


def certificate(directory, identity):
    key, cert = directory/(identity+'.key'), directory/(identity+'.crt')
    command(['/usr/bin/openssl', 'req', '-new', '-x509', '-nodes', '-newkey', 'rsa:2048',
             '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
             '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', str(key), '-out', str(cert)])
    key.chmod(0o600)
    return key, cert


def signer(directory, identity):
    home = directory/identity
    home.mkdir(mode=0o700)
    command(['/usr/bin/gpg', '--homedir', str(home), '--batch', '--pinentry-mode', 'loopback',
             '--passphrase', '', '--quick-generate-key', 'Inventory Fixture <fixture@example.invalid>',
             'ed25519', 'sign', '0'])
    public = command(['/usr/bin/gpg', '--homedir', str(home), '--batch', '--export'])
    return home, public


def repository(web, home, architecture, expired=False):
    release_root = web/'repo/dists/proof'
    packages = release_root/('main/binary-'+architecture)
    packages.mkdir(parents=True, exist_ok=True)
    content = ('Package: inventory-proof\nVersion: 1.0\nArchitecture: '+architecture+
               '\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Synthetic metadata proof\n'
               'Filename: pool/inventory-proof.deb\nSize: 1\nSHA256: '+'a'*64+'\n\n').encode()
    (packages/'Packages').write_bytes(content)
    (packages/'Packages.gz').write_bytes(gzip.compress(content, mtime=0))
    now = datetime.now(timezone.utc)
    valid = now-timedelta(hours=1) if expired else now+timedelta(days=1)
    release = ('Origin: InventoryFixture\nLabel: InventoryFixture\nSuite: proof\nCodename: proof\n'
               'Date: '+email.utils.format_datetime(now, usegmt=True)+'\nValid-Until: '+
               email.utils.format_datetime(valid, usegmt=True)+'\nArchitectures: '+architecture+
               '\nComponents: main\nDescription: Synthetic signed repository\nSHA256:\n')
    for filename in ['Packages', 'Packages.gz']:
        data = (packages/filename).read_bytes()
        release += ' '+hashlib.sha256(data).hexdigest()+' '+str(len(data))+' main/binary-'+architecture+'/'+filename+'\n'
    (release_root/'Release').write_text(release)
    command(['/usr/bin/gpg', '--homedir', str(home), '--batch', '--yes', '--pinentry-mode', 'loopback',
             '--passphrase', '', '--digest-algo', 'SHA256', '--clearsign',
             '--output', str(release_root/'InRelease'), str(release_root/'Release')])


def write_root(path, data, mode=0o640):
    path.parent.mkdir(parents=True, exist_ok=True)
    current = path.parent
    while str(current).startswith(POLICY_ROOT) or str(current).startswith(RUNTIME_ROOT):
        os.chown(current, 0, WORKER)
        # Shared traversal only; worker payloads stay0640 and private channel
        # siblings remain0700. Reporter has no write permission on this ancestor.
        current.chmod(0o755 if str(current)==RUNTIME_ROOT else 0o750)
        current = current.parent
    temporary = path.with_name('.new-'+secrets.token_hex(8))
    with open(temporary, 'xb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.chown(temporary, 0, WORKER)
    temporary.chmod(mode)
    temporary.replace(path)


def prove_cache_pinned_observation(store,base):
    """Actual channel/cache/native-FD integration; no process containment claim."""
    assert sys.platform=='linux' and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    def clock():
        return boot,time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
    for capability in ['observation','release']:
        path=Path(RUNTIME_ROOT)/capability
        path.mkdir(mode=0o770)
        os.chown(path,0,READER);path.chmod(0o770)
    private=Path(RUNTIME_ROOT)/'observation-private'
    private.mkdir(mode=0o700)
    for name in ['control','results']:(private/name).mkdir(mode=0o700)
    nonce='0000000000000001'+secrets.token_hex(8)
    # Disposable fixture actor: write only permitted inbox bytes; private paths
    # must reject traversal and replacement. No live endpoint is contacted.
    probe='''import os,sys
private=sys.argv[1]
try:
 fd=os.open(private+'/control/job.json',os.O_RDONLY)
except PermissionError: pass
else:
 os.close(fd)
 sys.exit(91)
try: os.rename(private,private+'-replaced')
except PermissionError: pass
else: sys.exit(92)
path=sys.argv[2]+'/request'
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try: os.write(fd,sys.argv[3].encode('ascii'))
finally: os.close(fd)
'''
    prefix=list(worker_argv(READER,READER)[:-1])
    result=subprocess.run(prefix+['-c',probe,str(private),str(Path(RUNTIME_ROOT)/'observation'),nonce],
        env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
    assert result.returncode==0, 'Reporter inbox/private channel separation failed'
    inbox=Inbox.fixed('observation')
    try: incoming=inbox.read()
    finally: inbox.close()
    assert incoming==(nonce,1)
    state=base/'observation-state'
    state.mkdir(mode=0o700)
    state_fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY)
    journal=Journal(state_fd)
    parent=None;child=None
    try:
        with journal.exclusive():
            journal.initialize(secrets.token_hex(16))
            with store.lease_current() as lease:
                manifest=lease.manifest
                indexes=[row for row in manifest['files'] if '_Packages' in row['path']]
                assert indexes, 'No actual package index in admitted cache'
            accepted=clock()[1]
            assert journal.receive('observation',nonce,boot,accepted,manifest['policy_generation'])=='new'
            started=clock()[1]
            assert journal.start('observation',nonce,boot,started,policy=manifest['policy_generation'])
            job=ObservationJob.parse(json.dumps({'schema_version':1,'job_id':secrets.token_hex(16),
                'operation_nonce':nonce,'helper_sequence':1,'boot_id':boot,
                'cache_generation':manifest['cache_generation'],'policy_generation':manifest['policy_generation'],
                'successful_checked_at':manifest['successful_checked_at'],'accepted_boottime_ms':accepted,
                'started_boottime_ms':started,'deadline_boottime_ms':accepted+120000}).encode())
            parent=ObservationChannel.fixed(journal=journal)
            child=ObservationChannel.fixed()
            parent.write_job(job)
            assert child.read_job()==job
            prepare_fixed_executor_guard()
            with CachedObservation.begin(store,child.read_job(),clock) as session:
                child.write_result(session.opened_result())
                opened=parent.read_result(expected_job=job)
                for row in indexes:
                    count,digest=session.verify_cache_index(row['path'])
                    assert count==row['size'] and digest==row['sha256']
                # The actual reporter release inbox is still unprivileged. Only
                # parent journal admission may produce the private root grant.
                release_code="import os,sys;fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.write(fd,sys.argv[2].encode('ascii'));os.close(fd)"
                result=subprocess.run(prefix+['-c',release_code,str(Path(RUNTIME_ROOT)/'release/request'),nonce],
                    env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
                assert result.returncode==0, 'Reporter release inbox write failed'
                release_inbox=Inbox.fixed('release')
                try: request=release_inbox.read()
                finally: release_inbox.close()
                assert request==(nonce,1)
                requested=clock()[1]
                assert journal.receive('release',nonce,boot,requested,job.policy_generation)=='new'
                granted=clock()[1]
                assert journal.start('release',nonce,boot,granted,policy=job.policy_generation)
                parent.write_release(ReleaseGrant(job,granted))
                grant=child.read_release(expected_job=job)
                child.write_result(session.finish_granted(grant))
                released=parent.read_result(expected_job=job)
            active=opened.document()['observation_lease']
            receipt=released.document()['observation_receipt']
            assert all(receipt[key]==value for key,value in active.items())
            assert receipt['outcome']=='released' and receipt['installed_before_sha256']==receipt['installed_after_sha256']
            journal.finish_observation(receipt)
    finally:
        try:
            if child is not None:child.close()
        finally:
            try:
                if parent is not None:parent.close()
            finally:os.close(state_fd)
    return {'cache_pinned_native_observation_verified':True,'actual_packages_verified_during_native_observation':True,
            'typed_observation_child_job_and_result_verified':True,'observation_receipt':receipt,
            'root_observation_channel_roundtrip_verified':True,'reporter_private_channel_separation_verified':True,
            'observation_admission_before_native_open_verified':True,
            'observation_independent_deadline_verified':False,'durable_observation_coordinator_verified':False,
            'observation_process_containment_verified':False}


def prove_observation_process(store,base,*,stopped_child=False):
    """Separate fixed guardian/native processes; no full parent activation."""
    from inventory_refresh_entry import SOURCES
    from inventory_refresh_observer import admit_profile
    from inventory_refresh_service import ObservationService, UNIT
    for _,filename in SOURCES:
        source=ROOT/'scripts'/('inventory_refresh_guardian.py' if filename=='guardian.py' else filename)
        shutil.copyfile(source,LIB_ROOT/filename);(LIB_ROOT/filename).chmod(0o444)
    for filename in ('observation-native.py','observation-guardian.py'):
        shutil.copyfile(ROOT/'scripts/inventory_refresh_entry.py',LIB_ROOT/filename)
        (LIB_ROOT/filename).chmod(0o444)
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    now=lambda:time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
    state=base/('observation-stopped-state' if stopped_child else 'observation-process-state');state.mkdir(mode=0o700)
    fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY);journal=Journal(fd)
    unit=UNIT
    private=Path(RUNTIME_ROOT)/'observation-private'
    parent=None;launcher=None
    try:
        with journal.exclusive():
            journal.initialize(secrets.token_hex(16))
            with store.lease_current() as pin:
                manifest=pin.manifest
                sequence=3 if stopped_child else 2
                nonce=f'{sequence:016x}'+secrets.token_hex(8)
                accepted=now()
                assert journal.receive('observation',nonce,boot,accepted,manifest['policy_generation'])=='new'
                started=now()
                assert journal.start('observation',nonce,boot,started,policy=manifest['policy_generation'])
                job=ObservationJob(1,secrets.token_hex(16),nonce,sequence,boot,manifest['cache_generation'],
                    manifest['policy_generation'],manifest['successful_checked_at'],accepted,started,accepted+(8000 if stopped_child else 120000))
                parent=ObservationChannel.fixed(journal=journal);parent.write_job(job)
                launcher=ObservationService(journal,parent,job).launch()
                opened=None;limit=time.monotonic()+15
                while time.monotonic()<limit and launcher.poll() is None:
                    opened=parent.read_result(expected_job=job)
                    if opened is not None:break
                    time.sleep(0.02)
                assert opened is not None and opened.document()['phase']=='opened', 'Separate native process did not open observation (exit='+str(launcher.poll())+')'
                owned=cgroup(unit)
                guardian=int(command(['/bin/systemctl','show','--property=MainPID','--value',unit]))
                admit_profile(Path('/proc',str(guardian),'status').read_bytes(),guardian=True)
                native=None
                for pid in (owned/'cgroup.procs').read_text().split():
                    status=Path('/proc',pid,'status').read_bytes()
                    if b'PPid:\t'+str(guardian).encode()+b'\n' in status:
                        admit_profile(status)
                        argv=Path('/proc',pid,'cmdline').read_bytes().split(b'\0')
                        assert argv[:-1]==[b'/usr/bin/python3',b'-I',b'-B',str(LIB_ROOT/'observation-native.py').encode()]
                        native=int(pid)
                assert native is not None and now()<job.deadline_boottime_ms
                # Actual masked namespace: configured policy root and parent state
                # do not exist there. No host secret is read by this proof.
                assert not Path('/proc',str(native),'root'+POLICY_ROOT).exists()
                assert not Path('/proc',str(native),'root'+str(state)).exists()
                # Follow the actual child's mount namespace through procfs.
                # Opening without truncation cannot alter file contents even if
                # the expected read-only mount is accidentally missing.
                for path in (private/'control/job.json',Path('/var/lib/dpkg/status'),
                             Path('/run/guarded-update-executor.lock'),Path(CACHE_ROOT)/'current.json'):
                    try:
                        check=os.open(Path('/proc',str(native),'root'+str(path)),os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                    except OSError as exc:assert exc.errno==errno.EROFS, 'Native fixed input did not fail read-only'
                    else:
                        os.close(check)
                        raise AssertionError('Native fixed input is writable through actual child mount')
                if stopped_child:
                    # Only this disposable CI-created transient unit's own
                    # direct native reader, root identity but all capabilities
                    # empty. Never signal the guardian, mutate memory limits or
                    # use a numeric PID fallback.
                    assert sys.platform=='linux' and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
                    assert command(['/bin/systemctl','show','--property=Transient','--value',unit]).strip()==b'yes'
                    def recheck():
                        raw=Path('/proc',str(native),'status').read_bytes()
                        admit_profile(raw)
                        return (str(native) in (owned/'cgroup.procs').read_text().split() and
                            b'PPid:\t'+str(guardian).encode()+b'\n' in raw and
                            Path('/proc',str(native),'cmdline').read_bytes().split(b'\0')[:-1]==
                                [b'/usr/bin/python3',b'-I',b'-B',str(LIB_ROOT/'observation-native.py').encode()])
                    stop_owned_child(native,recheck)
                    assert launcher.wait(timeout=12)==76
                    finished=now()
                    assert job.deadline_boottime_ms<=finished<=job.deadline_boottime_ms+3000
                    assert dict(line.split() for line in (cgroup(WORKER_SLICE)/'cgroup.events').read_text().splitlines())['populated']=='0'
                    # Actual exclusive writer locks in a separate process,
                    # without creating or writing any file. Another SH reader
                    # must prevent this probe; shared reacquisition is weaker.
                    writer_probe="""import fcntl,os
fds=[]
try:
 for path,native in [('/run/guarded-update-executor.lock',False),('/var/lib/dpkg/lock-frontend',True),('/var/lib/dpkg/lock',True)]:
  fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK);fds.append(fd)
  if native:fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  else:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
finally:
 for fd in fds:os.close(fd)
"""
                    command(['/usr/bin/python3','-I','-B','-c',writer_probe],timeout=5)
                    residue=parent.read_result(expected_job=job)
                    assert residue.document()['phase']=='opened'
                    return {'observation_independent_deadline_verified':True,
                        'stopped_native_reader_cleanup_verified':True,
                        'native_exclusive_writer_locks_after_cleanup_verified':True,
                        'stopped_observation_deadline_ms':job.deadline_boottime_ms,
                        'stopped_observation_cleanup_ms':finished}
                requested=now()
                assert journal.receive('release',nonce,boot,requested,job.policy_generation)=='new'
                granted=now();assert journal.start('release',nonce,boot,granted,policy=job.policy_generation)
                parent.write_release(ReleaseGrant(job,granted))
                assert launcher.wait(timeout=10)==0, 'Separate native/guardian rejected release'
                # PID1 main exit tears down its descendants before completion.
                assert dict(line.split() for line in (cgroup(WORKER_SLICE)/'cgroup.events').read_text().splitlines())['populated']=='0'
                released=parent.read_result(expected_job=job);receipt=released.document()['observation_receipt']
                assert released.document()['phase']=='released' and all(receipt[key]==value for key,value in opened.document()['observation_lease'].items())
                assert receipt['installed_before_sha256']==receipt['installed_after_sha256']
                with store.lease_current() as current:assert current.manifest==manifest
                journal.finish_observation(receipt)
                return {'observation_separate_native_process_verified':True,
                    'observation_native_zero_capabilities_verified':True,
                    'observation_masked_policy_and_parent_state_verified':True,
                    'observation_actual_input_write_denial_verified':True,
                    'separate_process_observation_receipt':receipt}
    finally:
        try:
            if launcher is not None:launcher.close()
        finally:
            try:
                if parent is not None:parent.close()
            finally:os.close(fd)


def is_live_worker(raw,*,parent=None):
    try:
        validate_kernel_identity(raw,WORKER,WORKER)
        states=[line.split(b':',1)[1].strip() for line in raw.splitlines() if line.startswith(b'State:')]
        if parent is not None:
            parents=[line.split(b':',1)[1].strip() for line in raw.splitlines() if line.startswith(b'PPid:')]
            if parents!=[str(parent).encode('ascii')]:
                return False
        return len(states)==1 and not states[0].startswith((b'Z',b'X',b'x'))
    except ValueError:
        return False


def prove_privilege_transition():
    # Disposable CI ONLY. Read current-process credentials; no signals, service
    # property changes, package operations or live-device invocation.
    assert sys.platform=='linux' and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    try:
        load_worker()
    except (OSError,ValueError,ImportError):
        checks=[]
        for index,path in enumerate([Path('/'),Path('/usr'),Path('/usr/local'),Path('/usr/local/libexec'),LIB_ROOT,LIB_ROOT/'worker.py']):
            value=path.lstat()
            checks.append((index,value.st_uid==0,not bool(value.st_mode&0o022),not path.is_symlink()))
        raise AssertionError('Fixed source admission rejected; component ownership/mode/link checks='+repr(checks)) from None
    code="import sys;sys.stdout.buffer.write(open('/proc/self/status','rb').read(65537))"
    fixed=list(worker_argv(WORKER,WORKER)[:-1])+['-c',code]
    probe=LIB_ROOT/'transition-probe.py'
    # A diagnostic-only nested Python launch reproduces the guardian's process
    # boundary and exact sandbox. Its child only reads /proc/self/status.
    source=('import subprocess,sys\n'
            'state=dict(line.split(":",1) for line in open("/proc/self/status") if ":" in line)\n'
            'print("guardian_kernel_masks="+":".join(str(int(state[key],16)) for key in ["CapPrm","CapEff","CapBnd","CapInh","CapAmb"])+":"+state["NoNewPrivs"].strip(),file=sys.stderr)\n'
            'assert all(state[key].split()==["0"]*4 for key in ["Uid","Gid"])\n'
            'assert all(int(state[key],16)==480 for key in ["CapPrm","CapEff","CapBnd"])\n'
            'assert int(state["CapInh"],16)==384 and int(state["CapAmb"],16)==128\n'
            'assert state["NoNewPrivs"].strip()=="1"\n'
            'result=subprocess.run('+repr(fixed)+',env='+repr(ENV)+',stdin=subprocess.DEVNULL,'
            'stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)\n'
            'sys.stdout.buffer.write(result.stdout)\n'
            'raise SystemExit(result.returncode)\n')
    probe.write_text(source)
    probe.chmod(0o444)
    args=['/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe',
        '--unit=command-center-inventory-privilege-proof','--slice='+WORKER_SLICE,
        '-p','User=root','-p','Group=root','-p','NoNewPrivileges=yes',
        '-p','CapabilityBoundingSet=CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP',
        '-p','AmbientCapabilities=CAP_SETUID',
        '-p','ProtectSystem=strict','-p','ProtectHome=yes','-p','ProtectControlGroups=yes',
        '-p','RestrictNamespaces=yes','-p','PrivateDevices=yes','-p','PrivateTmp=yes',
        '-p','InaccessiblePaths=/tmp /var/tmp /dev/shm',
        '/usr/bin/python3','-I','-B',str(probe)]
    result=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    masks=re.findall(rb'guardian_kernel_masks=[0-9:]{1,140}',result.stderr)
    assert result.returncode==0, 'Exact guardian capability profile or fixed transition rejected: '+repr(masks[:1])
    assert is_live_worker(result.stdout), 'Kernel privilege state rejected after fixed transition'


def stop_owned_child(pid,recheck):
    # Pin the kernel task before the final membership/identity check; never use
    # a numeric signal fallback if it exits or pidfds are unavailable.
    pidfd=os.pidfd_open(pid)
    try:
        assert recheck(), 'Fixture child changed before signal'
        signal.pidfd_send_signal(pidfd,signal.SIGSTOP)
    finally:
        os.close(pidfd)


def stopped_child_proof(args,job):
    """CI-owned transient service only; never callable on a user endpoint."""
    if not (sys.platform=='linux' and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'):
        raise RuntimeError('Disposable hosted Linux root runner required')
    # main() has refused existing installations/accounts and created this exact
    # fixture. Check both its fixed identities before any fixture-owned signal.
    assert pwd.getpwnam('ccrefresh').pw_uid==WORKER
    assert pwd.getpwnam('ccinventory').pw_uid==READER
    assert args[0]=='/usr/bin/systemd-run' and '--unit='+WORKER_UNIT in args
    launcher=subprocess.Popen(args,env=ENV,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        limit=time.monotonic()+5
        worker=None
        while time.monotonic()<limit and launcher.poll() is None:
            try:
                owned=cgroup(WORKER_UNIT)
                transient=command(['/bin/systemctl','show','--property=Transient','--value',WORKER_UNIT]).strip()
                assert transient==b'yes', 'Refuse non-fixture persistent service'
                guardian=int(command(['/bin/systemctl','show','--property=MainPID','--value',WORKER_UNIT]))
                for pid in (owned/'cgroup.procs').read_text().split():
                    if is_live_worker(Path('/proc',pid,'status').read_bytes(),parent=guardian):
                        worker=int(pid)
                        break
                if worker is not None:
                    break
            except (AssertionError,FileNotFoundError,ProcessLookupError,ValueError):
                pass
            time.sleep(0.01)
        assert worker is not None, 'No live fixture worker found'
        # Recheck cgroup membership and complete unprivileged kernel identity
        # immediately before stopping only the disposable owned child.
        def recheck():
            return (str(worker) in (owned/'cgroup.procs').read_text().split() and
                    is_live_worker(Path('/proc',str(worker),'status').read_bytes(),parent=guardian))
        stop_owned_child(worker,recheck)
        status=launcher.wait(timeout=12)
        released=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
        assert status==76 and job['deadline_boottime_ms']<=released<=job['deadline_boottime_ms']+3000
        empty_worker()
        return status
    finally:
        try:
            empty_worker()
        finally:
            if launcher.poll() is None:
                launcher.kill()
            launcher.wait(timeout=5)


def run_worker(policy, number, *, stopped_child=False):
    empty_worker()
    token = f'{number:032x}'
    stage = Path(CACHE_ROOT)/('staging-'+token)
    stage.mkdir(mode=0o700)
    os.chown(stage, WORKER, WORKER)
    for relative in ['lists', 'lists/partial', 'cache', 'archives', 'log', 'tmp']:
        directory = stage/relative
        directory.mkdir(mode=0o700)
        os.chown(directory, WORKER, WORKER)
    rendered = render_policy(policy, token)
    for relative, data in rendered.items():
        target = Path(RUNTIME_ROOT)/'worker-apt.conf' if relative == 'apt.conf' else Path(POLICY_ROOT)/'apt'/relative
        write_root(target, data)
    empty = Path(POLICY_ROOT)/'apt/empty.d'
    empty.mkdir(exist_ok=True)
    os.chown(empty, 0, WORKER)
    empty.chmod(0o550)
    assert not any(empty.iterdir())
    now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
    nonce = f'{number:016x}'+secrets.token_hex(8)
    job = {'schema_version': 1, 'staging_token': token,
           'config_sha256': hashlib.sha256(rendered['apt.conf']).hexdigest(),
           'policy_generation': policy_generation(b'k'*32, policy),
           'operation_nonce': nonce, 'helper_sequence': number,
           'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
           'accepted_boottime_ms': now, 'started_boottime_ms': now, 'deadline_boottime_ms': now+(8000 if stopped_child else 600000)}
    write_root(Path(RUNTIME_ROOT)/'job.json', json.dumps(job).encode())
    # PID1 protects the root MAIN guardian; setpriv permanently drops its fixed child.
    args = ['/usr/bin/systemd-run', '--quiet', '--wait', '--collect', '--pipe', '--unit='+WORKER_UNIT,
        '--slice='+WORKER_SLICE, '-p', 'User=root', '-p', 'Group=root',
        '-p', 'Type=exec', '-p', 'ExitType=main', '-p', 'RemainAfterExit=no', '-p', 'Restart=no',
        '-p', 'KillMode=control-group', '-p', 'KillSignal=SIGKILL', '-p', 'SendSIGKILL=yes',
        '-p', 'OOMPolicy=kill', '-p', 'MemoryAccounting=yes',
        '-p', 'NoNewPrivileges=yes', '-p', 'CapabilityBoundingSet=CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP',
        '-p', 'AmbientCapabilities=CAP_SETUID',
        '-p', 'ProtectSystem=strict',
        '-p', 'ProtectHome=yes', '-p', 'ProtectControlGroups=yes', '-p', 'RestrictNamespaces=yes',
        '-p', 'PrivateDevices=yes', '-p', 'PrivateTmp=yes', '-p', 'InaccessiblePaths=/tmp /var/tmp /dev/shm',
        '-p', 'ReadWritePaths='+str(stage), '-p', 'RuntimeMaxSec=610', '-p', 'TimeoutStopSec=1',
        '/usr/bin/python3', '-I', '-B', str(LIB_ROOT/'guardian.py')]
    if stopped_child:
        return stopped_child_proof(args,job),token,job['policy_generation']
    result = subprocess.run(args, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=610)
    status = result.returncode
    empty_worker()
    if status not in [0, 74, 75, 76]:
        # Publish only a fixed classification and numeric fixture identity; never native output.
        collision = b'already exists' in result.stderr or b'already loaded' in result.stderr
        reason = 'unit_name_in_use' if collision else 'unclassified_launcher_failure'
        raise AssertionError(f'Fixed worker failed outside its safe exit contract (iteration={number}, exit={status}, reason={reason})')
    if status!=0:
        stages=re.findall(rb'inventory_guardian_stage=(?:identity|library|accounts|job|boot|spawn|clock|child)(?::[0-9-]{1,4})?',result.stderr)
        if stages:
            print('Native fixture diagnostic: '+b' '.join(stages[:4]).decode('ascii'),file=sys.stderr)
    return status, token, job['policy_generation']


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
    for path in [Path(POLICY_ROOT), Path(CACHE_ROOT), Path(RUNTIME_ROOT), LIB_ROOT]:
        assert not path.exists(), 'Refuse to adopt an existing helper installation'
    unit_files = [Path('/run/systemd/system')/name for name in [PARENT_SLICE, WORKER_SLICE]]
    assert all(not path.exists() for path in unit_files)
    base = Path('/run')/('inventoryaptproof'+secrets.token_hex(6))
    base.mkdir(mode=0o700)
    web = base/'web'
    web.mkdir()
    accounts = []
    mounted = False
    server = None
    signers = []
    hook = Path('/etc/apt/apt.conf.d/99inventory-isolation-proof')
    assert not hook.exists()
    before = fingerprint(['/var/lib/dpkg/status', '/var/lib/apt/lists', '/etc/apt'])
    try:
        for account, identity in [('ccrefresh', WORKER), ('ccinventory', READER)]:
            try:
                pwd.getpwnam(account)
            except KeyError:
                pass
            else:
                raise AssertionError('Refuse to adopt an existing reporting account')
            try:
                pwd.getpwuid(identity)
            except KeyError:
                pass
            else:
                raise AssertionError('Proof UID is already allocated')
            command(['/usr/sbin/groupadd', '--system', '--gid', str(identity), account])
            command(['/usr/sbin/useradd', '--system', '--uid', str(identity), '--gid', account,
                     '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', account])
            accounts.append(account)
        for path in [Path(POLICY_ROOT), Path(CACHE_ROOT), Path(RUNTIME_ROOT), LIB_ROOT]:
            path.mkdir(parents=True, mode=0o755)
        shutil.copyfile(ROOT/'scripts/inventory_refresh_worker.py', LIB_ROOT/'worker.py')
        (LIB_ROOT/'worker.py').chmod(0o444)
        shutil.copyfile(ROOT/'scripts/inventory_refresh_guardian.py', LIB_ROOT/'guardian.py')
        (LIB_ROOT/'guardian.py').chmod(0o444)
        # Root loader must execute admitted worker.py bytes, never these other
        # matching project import candidates. -B alone would still read pycache.
        poison=b"raise RuntimeError('Unadmitted project import executed')\n"
        (LIB_ROOT/'json.py').write_bytes(poison)
        package=LIB_ROOT/'worker'
        package.mkdir()
        (package/'__init__.py').write_bytes(poison)
        package.chmod(0o777)
        bytecode=Path(importlib.util.cache_from_source(str(LIB_ROOT/'worker.py')))
        bytecode.parent.mkdir()
        source_metadata=(LIB_ROOT/'worker.py').stat()
        bytecode.write_bytes(importlib.util.MAGIC_NUMBER+struct.pack('<III',0,
            int(source_metadata.st_mtime)&0xffffffff,source_metadata.st_size&0xffffffff)+
            marshal.dumps(compile(poison,str(LIB_ROOT/'worker.py'),'exec')))
        bytecode.chmod(0o666)
        for file, limit in zip(unit_files, [True, False]):
            file.write_text('[Unit]\nDescription=Disposable trusted-policy proof\nStopWhenUnneeded=no\n'
                            '[Slice]\nMemoryAccounting=yes\n'+
                            ('MemoryMax=256M\nMemorySwapMax=0\nTasksMax=64\n' if limit else ''))
        command(['/bin/systemctl', 'daemon-reload'])
        command(['/bin/systemctl', 'start', PARENT_SLICE, WORKER_SLICE])
        command(['/bin/mount', '-t', 'tmpfs', '-o', 'size=128m,nr_inodes=32768,mode=0755,nosuid,nodev,noexec',
                 'inventory-apt-proof', CACHE_ROOT])
        mounted = True
        key, ca = certificate(base, 'server')
        _, wrong_ca = certificate(base, 'wrong-ca')
        home, public = signer(base, 'signer')
        other_home, wrong_public = signer(base, 'wrong-signer')
        signers.extend([home, other_home])
        architecture = command(['/usr/bin/dpkg', '--print-architecture']).decode().strip()
        repository(web, home, architecture)
        authorization = 'Basic '+base64.b64encode(('fixture:'+PASSWORD).encode()).decode()
        class Handler(SimpleHTTPRequestHandler):
            requests = 0
            hold = False
            def do_GET(self):
                if Handler.hold:
                    time.sleep(10)
                    return
                if self.headers.get('Authorization') != authorization:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="synthetic-fixture"')
                    self.end_headers()
                    return
                assert not self.path.endswith('.deb'), 'Metadata worker attempted an archive download'
                Handler.requests += 1
                return super().do_GET()
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Handler, directory=str(web)))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ca, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        uri = 'https://127.0.0.1:'+str(server.server_port)+'/repo'
        def policy(certificate_path=ca, signing_key=public, password=PASSWORD, missing=False):
            value = {'schema_version': 1, 'architectures': [architecture],
                'sources': [{'id': 'fixture', 'type': 'deb', 'uri': uri, 'suites': ['proof'],
                             'components': ['main'], 'architectures': [architecture], 'signed_by': ['fixture']}],
                'trust': {'keys': [{'id': 'fixture', 'format': 'gpg',
                                    'content_base64': base64.b64encode(signing_key).decode()}],
                          'tls_ca_base64': base64.b64encode(certificate_path.read_bytes()).decode()},
                'pins': [], 'proxy': {'http': 'DIRECT', 'https': 'DIRECT'},
                'auth': [{'machine': uri, 'login': 'fixture', 'password': password}]}
            if missing:
                extra = dict(value['sources'][0], id='missing', uri=uri+'/missing')
                value['sources'].append(extra)
            return parse_policy(json.dumps(value).encode())
        # If host config leaked, this hook would be allowed to write the first active stage.
        marker = Path(CACHE_ROOT)/('staging-'+f'{1:032x}')/'host-hook-ran'
        hook.write_text('APT::Update::Pre-Invoke { "/usr/bin/touch '+str(marker)+'"; };\n')
        good = policy()
        prove_privilege_transition()
        status, stage, generation = run_worker(good, 1)
        assert status == 0, f'Valid signed TLS/authenticated repository refresh failed (exit={status})'
        assert Handler.requests > 0 and not marker.exists(), 'Host APT configuration leaked'
        lists = Path(CACHE_ROOT)/('staging-'+stage)/'lists'
        assert any('_Packages' in path.name for path in lists.iterdir()), 'No binary package index was acquired'
        cache = os.open(CACHE_ROOT, os.O_RDONLY | os.O_DIRECTORY)
        store = Store(cache, 0, READER, WORKER)
        try:
            store.publish(stage, 'a'*32, generation, datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
            observation=prove_cache_pinned_observation(store,base)
            observation.update(prove_observation_process(store,base))
            observation.update(prove_observation_process(store,base,stopped_child=True))
            previous = (Path(CACHE_ROOT)/'current.json').read_bytes()
            for number, candidate in [(2, policy(certificate_path=wrong_ca)),
                                      (3, policy(signing_key=wrong_public)),
                                      (4, policy(password='synthetic-wrong-password')),
                                      (5, policy(missing=True))]:
                status, _, _ = run_worker(candidate, number)
                assert status == 75, 'Invalid trust/auth or failed repository was accepted'
                assert (Path(CACHE_ROOT)/'current.json').read_bytes() == previous
            repository(web, home, architecture, expired=True)
            status, _, _ = run_worker(good, 6)
            assert status == 75, 'Expired signed metadata was accepted'
            assert (Path(CACHE_ROOT)/'current.json').read_bytes() == previous
            with store.lease_current() as lease:
                assert lease.manifest['policy_generation'] == generation
        finally:
            os.close(cache)
        Handler.hold=True
        run_worker(good,7,stopped_child=True)
        Handler.hold=False
        proof = {'schema_version': 1, 'scope': 'fixed_worker_trusted_policy',
            'synthetic_repository_only': True, 'target_repository_fit_proven': False,
            'coordinator_exercised': False, 'apt_refresh_exercised': True,
            'root_guardian_fixed_privilege_drop_exercised': True,
            'exact_guardian_capability_masks_verified': True,
            'unadmitted_package_sibling_and_matching_bytecode_ignored': True,
            'independent_deadline_fault_proof': True,
            'native_fault_job_budget_ms': 8000,
            'stopped_child_killed_by_boottime_deadline': True,
            'guardian_death_and_oom_fault_proof': False,
            'binary_packages_acquired': True, 'valid_tls_gpg_auth_accepted': True,
            'wrong_ca_rejected': True, 'wrong_gpg_key_rejected': True,
            'wrong_auth_rejected': True, 'expired_metadata_rejected': True,
            'any_failed_repository_rejected': True, 'host_hook_excluded': True,
            'previous_current_retained_after_failure': True,
            'worker_memory_peak': int((cgroup(PARENT_SLICE)/'memory.peak').read_text()),**observation}
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if mounted:
            empty_worker()
            command(['/bin/umount', CACHE_ROOT])
        for name in [WORKER_SLICE, PARENT_SLICE]:
            subprocess.run(['/bin/systemctl', 'stop', name], env=ENV,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        for path in unit_files:
            if path.exists():
                path.unlink()
        command(['/bin/systemctl', 'daemon-reload'])
        if hook.exists():
            hook.unlink()
        for path in [Path(POLICY_ROOT), Path(CACHE_ROOT), Path(RUNTIME_ROOT), LIB_ROOT]:
            if path.exists():
                shutil.rmtree(path)
        for home in signers:
            command(['/usr/bin/gpgconf', '--homedir', str(home), '--kill', 'gpg-agent'])
        for account in reversed(accounts):
            command(['/usr/sbin/userdel', account])
            subprocess.run(['/usr/sbin/groupdel', account], env=ENV,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        shutil.rmtree(base)
    assert fingerprint(['/var/lib/dpkg/status', '/var/lib/apt/lists', '/etc/apt']) == before
    proof['host_apt_state_unchanged'] = True
    proof['owned_worker_cgroup_empty_before_publish'] = True
    print(json.dumps(proof, sort_keys=True))


if __name__ == '__main__':
    main()
