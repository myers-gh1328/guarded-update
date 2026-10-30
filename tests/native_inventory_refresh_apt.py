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
import fcntl
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
import select
import shutil
import signal
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import tempfile

from inventory_refresh_artifact_fixture import verify_archive
from inventory_refresh_reporter_fixture_files import FixtureSources
from inventory_refresh_rust_native_admission import RunnerArtifact
from inventory_refresh_rust_parent_fixture import FixtureBinary

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from inventory_refresh_resources import _Chain
from inventory_refresh_cgroup_witness import observe_single_process
from inventory_refresh_process_snapshot import ProcessProbe
from inventory_refresh_policy import parse_policy, render_policy, policy_generation, POLICY_ROOT, CACHE_ROOT, RUNTIME_ROOT, STATE_ROOT
from inventory_refresh_storage import Store
from inventory_refresh_worker import validate_kernel_identity
from inventory_refresh_guardian import worker_argv, load_worker
from inventory_refresh_observation import prepare_fixed_executor_guard
from inventory_refresh_cached_observation import ObservationJob, CachedObservation, ObservationResult, ReleaseGrant
from inventory_refresh_channel import ObservationChannel
from inventory_refresh_state import Journal
from inventory_refresh_io import Inbox
from inventory_refresh_policy_admission import PolicyGuard
from inventory_refresh_materialized_policy import MaterializedPolicy
from inventory_refresh_worker_service import RefreshService, refresh_argv

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


def assert_worker_empty():
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


def empty_worker():
    result = subprocess.run(['/bin/systemctl', 'stop', WORKER_UNIT], env=ENV,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    assert result.returncode in [0, 5]
    assert_worker_empty()


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


def prove_observation_process(store,base,*,stopped_child=False,sequence=None):
    """Separate fixed guardian/native processes; no full parent activation."""
    from inventory_refresh_entry import SOURCES
    from inventory_refresh_observer import admit_profile
    from inventory_refresh_service import ObservationService, UNIT, pidfds_live
    for _,filename in SOURCES:
        source=ROOT/'scripts'/('inventory_refresh_guardian.py' if filename=='guardian.py' else filename)
        shutil.copyfile(source,LIB_ROOT/filename);(LIB_ROOT/filename).chmod(0o444)
    for filename in ('observation-native.py','observation-guardian.py'):
        shutil.copyfile(ROOT/'scripts/inventory_refresh_entry.py',LIB_ROOT/filename)
        (LIB_ROOT/filename).chmod(0o444)
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    now=lambda:time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
    sequence=(3 if stopped_child else 2) if sequence is None else sequence
    assert type(sequence) is int and sequence in (2,3,4)
    state=base/('observation-process-state-'+str(sequence));state.mkdir(mode=0o700)
    fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY);journal=Journal(fd)
    unit=UNIT
    private=Path(RUNTIME_ROOT)/'observation-private'
    parent=None;launcher=None
    try:
        with journal.exclusive():
            journal.initialize(secrets.token_hex(16))
            with store.lease_current() as pin:
                manifest=pin.manifest
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
                    opened=launcher.live_opened()
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
                    try:launcher.live_opened()
                    except ValueError:pass
                    else:raise AssertionError('Stopped native child retained active offer')
                    assert launcher.wait(timeout=12)==76
                    try:pidfds_live(tuple(launcher._pidfds.values()))
                    except ValueError:pass
                    else:raise AssertionError('Exited pinned tasks retained active readiness')
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
                    launcher.close();launcher=None
                    return {'observation_independent_deadline_verified':True,
                        'stopped_native_reader_cleanup_verified':True,
                        'native_exclusive_writer_locks_after_cleanup_verified':True,
                        'stopped_and_exited_native_offer_rejected':True,
                        'stopped_observation_deadline_ms':job.deadline_boottime_ms,
                        'stopped_observation_cleanup_ms':finished}
                requested=now()
                assert journal.receive('release',nonce,boot,requested,job.policy_generation)=='new'
                try:launcher.live_opened()
                except ValueError:pass
                else:raise AssertionError('Durable release admission reoffered old opened result')
                granted=now();assert journal.start('release',nonce,boot,granted,policy=job.policy_generation)
                parent.write_release(ReleaseGrant(job,granted))
                assert launcher.wait(timeout=10)==90, 'Separate native/guardian rejected release'
                # PID1 main exit tears down its descendants before completion.
                assert dict(line.split() for line in (cgroup(WORKER_SLICE)/'cgroup.events').read_text().splitlines())['populated']=='0'
                released=parent.read_result(expected_job=job);receipt=released.document()['observation_receipt']
                assert released.document()['phase']=='released' and all(receipt[key]==value for key,value in opened.document()['observation_lease'].items())
                assert receipt['installed_before_sha256']==receipt['installed_after_sha256']
                with store.lease_current() as current:assert current.manifest==manifest
                launcher.close();launcher=None
                journal.finish_observation(receipt)
                return {'observation_separate_native_process_verified':True,
                    'observation_native_zero_capabilities_verified':True,
                    'observation_masked_policy_and_parent_state_verified':True,
                    'observation_actual_input_write_denial_verified':True,
                    'observation_owned_live_child_offer_verified':True,
                    'observation_durable_release_offer_fence_verified':True,
                    'fixed_observation_service_adapter_verified':True,
                    'separate_process_observation_receipt':receipt}
    finally:
        try:
            if launcher is not None:
                # Failure cleanup retains only the old owned scope, never a
                # new launch; acknowledgement still requires the root lock.
                with journal.exclusive():launcher.close()
        finally:
            try:
                if parent is not None:parent.close()
            finally:os.close(fd)


def prove_resource_admission(expected_generation):
    """Read-only new probe starts inside the fixed aggregate before Python."""
    from inventory_refresh_resources import UNIT
    assert sys.platform=='linux' and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    show=subprocess.run(['/bin/systemctl','show','--property=LoadState','--value',UNIT],
        env=ENV,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3)
    assert show.returncode in (0,4) and show.stdout.strip()==b'not-found', 'Refuse existing coordinator unit'
    modules=('inventory_refresh_protocol','inventory_refresh_observation','inventory_refresh_policy',
             'inventory_refresh_policy_admission','inventory_refresh_resources','inventory_refresh_storage')
    for name in modules:
        shutil.copyfile(ROOT/'scripts'/(name+'.py'),LIB_ROOT/(name+'.py'))
        (LIB_ROOT/(name+'.py')).chmod(0o444)
    # Test-only fixed entry. Admit the whole literal source batch before any
    # projectexec, with no project sys.path or package/bytecode lookup.
    source=r"""import json,os,stat,sys,types
assert sys.platform=='linux' and len(sys.argv)==1 and sys.flags.isolated and sys.flags.dont_write_bytecode
assert os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0)
base='/usr/local/libexec/command-center-inventory-refresh'
names=('inventory_refresh_protocol','inventory_refresh_observation','inventory_refresh_policy','inventory_refresh_policy_admission','inventory_refresh_resources','inventory_refresh_storage')
def stable(info):return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
fds=[];refs=[];sources={}
try:
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
 for part in ('usr','local','libexec','command-center-inventory-refresh'):
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
  fds.append(child);refs.append((fd,part,child));fd=child
 for opened in fds:
  info=os.fstat(opened);assert info.st_uid==0 and not info.st_mode&0o022 and stat.S_ISDIR(info.st_mode)
 for name in names:
  filename=name+'.py';opened=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
  try:
   info=os.fstat(opened)
   assert info.st_uid==0 and not info.st_mode&0o022 and info.st_nlink==1 and stat.S_ISREG(info.st_mode) and 0<info.st_size<=65536
   raw=b''
   while True:
    chunk=os.read(opened,65537-len(raw))
    if not chunk:break
    raw+=chunk;assert len(raw)<=65536
   assert len(raw)==info.st_size and stable(info)==stable(os.fstat(opened))==stable(os.stat(filename,dir_fd=fd,follow_symlinks=False))
   sources[name]=raw
  finally:os.close(opened)
 for parent,name,child in refs:
  a=os.stat(name,dir_fd=parent,follow_symlinks=False);b=os.fstat(child)
  assert stat.S_ISDIR(a.st_mode) and a.st_uid==0 and not a.st_mode&0o022 and (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)
finally:
 failure=None
 for fd in reversed(fds):
  try:os.close(fd)
  except OSError as exc:failure=exc
 if failure is not None:raise failure
compiled={name:compile(raw,base+'/'+name+'.py','exec',dont_inherit=True) for name,raw in sources.items()}
for name in names:
 assert name not in sys.modules
 module=types.ModuleType(name);module.__file__=base+'/'+name+'.py';sys.modules[name]=module
 exec(compiled[name],module.__dict__)
from inventory_refresh_resources import RuntimeResources
from inventory_refresh_policy_admission import PolicyGuard
with RuntimeResources.fixed() as resources:
 before=resources.sample()
 with PolicyGuard.fixed() as guard:
  guard.recheck();generation=guard.generation
 after=resources.sample()
print(json.dumps({'fixed_resource_profile_currently_admitted':True,'policy_admission_inside_fixed_aggregate_probe':True,
 'all_allocators_charged_from_startup_verified':False,'generation':generation,'metrics':after},sort_keys=True))
"""
    probe=LIB_ROOT/'resource-admission-proof.py'
    probe.write_text(source);probe.chmod(0o444)
    info=probe.lstat();assert info.st_uid==0 and info.st_nlink==1 and info.st_mode&0o777==0o444
    args=['/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe','--unit='+UNIT,'--slice='+PARENT_SLICE,
        '-p','User=0','-p','Group=0','-p','Type=exec','-p','ExitType=main','-p','Restart=no',
        '-p','KillMode=control-group','-p','KillSignal=SIGKILL','-p','TimeoutStopSec=1','-p','RuntimeMaxSec=30',
        '-p','OOMPolicy=kill','-p','MemoryAccounting=yes','-p','NoNewPrivileges=yes',
        '-p','CapabilityBoundingSet=','-p','AmbientCapabilities=','-p','ProtectSystem=full',
        '-p','ProtectHome=yes','-p','PrivateDevices=yes','-p','RestrictNamespaces=yes',
        '/usr/bin/python3','-I','-B',str(probe)]
    result=json.loads(command(args,timeout=40))
    assert result['generation']==expected_generation
    assert result['fixed_resource_profile_currently_admitted'] and result['policy_admission_inside_fixed_aggregate_probe']
    assert not result['all_allocators_charged_from_startup_verified']
    return {'fixed_resource_profile_currently_admitted':True,'policy_admission_inside_fixed_aggregate_probe':True,
        'all_allocators_charged_from_startup_verified':False,'aggregate_resource_probe_metrics':result['metrics']}


def prove_publisher_profile(base,expected_generation):
    """Scoped CAP3 namespace/sealing proof; not a coordinator activation."""
    from inventory_refresh_publisher_profile import publisher_properties
    from inventory_refresh_resources import UNIT
    prepare_fixed_executor_guard()
    Path(STATE_ROOT).chmod(0o700)
    apt=Path(POLICY_ROOT)/'apt'
    apt.mkdir(mode=0o750);os.chown(apt,0,WORKER)
    for path in (CACHE_ROOT,STATE_ROOT,RUNTIME_ROOT,str(apt),POLICY_ROOT,
                 '/etc/passwd','/etc/group','/etc/nsswitch.conf','/etc/hosts',
                 '/run/systemd/private','/var/lib/dpkg','/run/guarded-update-executor.lock'):
        Path(path).lstat()  # All fixed bind sources must exist before PID1 namespace setup.
    token='e'*32;stage=Path(CACHE_ROOT)/('staging-'+token)
    (stage/'lists').mkdir(parents=True,mode=0o700)
    for path in (stage,stage/'lists'):
        os.chown(path,WORKER,WORKER);path.chmod(0o700)
    index=stage/'lists/synthetic_profile_Packages'
    index.write_bytes(b'synthetic publisher profile index');os.chown(index,WORKER,WORKER);index.chmod(0o600)
    sentinel=base/'publisher-private-sentinel';sentinel.write_bytes(b'synthetic-private-sentinel');sentinel.chmod(0o600)
    original=(LIB_ROOT/'resource-admission-proof.py').read_text()
    bootstrap,marker,_=original.partition('from inventory_refresh_resources import RuntimeResources')
    assert marker, 'Missing admitted fixed probe bootstrap'
    body=r"""from inventory_refresh_resources import RuntimeResources,ResourceError,mount_rows,CACHE
from inventory_refresh_policy_admission import PolicyGuard
from inventory_refresh_storage import Store
from datetime import datetime,timezone
import errno,subprocess
stage='identity'
fields=dict(line.split(':',1) for line in open('/proc/self/status').read().splitlines())
masks={name:int(fields[name].strip(),16) for name in ('CapPrm','CapEff','CapBnd','CapInh','CapAmb')}
if masks!={'CapPrm':3,'CapEff':3,'CapBnd':3,'CapInh':0,'CapAmb':0} or fields['NoNewPrivs'].split()!=['1']:
 print('publisher_profile_masks='+json.dumps(masks,sort_keys=True),file=sys.stderr)
 raise SystemExit(74)
stage='resources'
try:
 resources=RuntimeResources.fixed()
except ResourceError as error:
 raw=open('/proc/self/mountinfo','rb').read(1024*1024+1)
 rows=[{'id':row['id'],'parent':row['parent'],'device':row['device'],'root':row['root']} for row in mount_rows(raw).values() if row['path']==CACHE]
 print('publisher_cache_mount_diagnostic='+json.dumps({'reason':error.reason,'rows':rows[:8]},sort_keys=True),file=sys.stderr)
 raise SystemExit(74)
with resources:
 stage='policy'
 with PolicyGuard.fixed() as policy:
  generation=policy.generation
  stage='read_only_inputs'
  for path in ('/etc/command-center-inventory-refresh/policy.json','/etc/command-center-inventory-refresh/policy-commitment.key','/etc/passwd','/var/lib/dpkg/status'):
   try:fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   except OSError as error:assert error.errno==errno.EROFS
   else:
    os.close(fd);raise AssertionError('Publisher read-only input is writable')
  stage='writable_outputs'
  for directory in ('/var/lib/command-center-inventory-refresh','/run/command-center-inventory-refresh','/etc/command-center-inventory-refresh/apt'):
   path=directory+'/publisher-profile-fixture'
   fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   try:os.write(fd,b'synthetic profile state');os.fsync(fd)
   finally:os.close(fd)
   os.unlink(path)
  stage='masked_sentinel'
  assert not os.path.exists(@SENTINEL@)
  stage='manager_marker'
  with os.scandir('/run/systemd/system') as entries:assert next(entries,None) is None
  try:fd=os.open('/run/systemd/system/synthetic-create',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  except OSError as error:assert error.errno==errno.EROFS
  else:
   os.close(fd);raise AssertionError('Private marker is writable')
  assert not os.path.exists('/run/systemd/system/.publisher-profile-synthetic')
  stage='manager_socket'
  result=subprocess.run(('/bin/systemctl','show','--property=LoadState','--value','command-center-inventory-refresh-worker.service'),env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,timeout=3)
  assert result.returncode in (0,4) and result.stdout.strip()==b'not-found'
  stage='sealing'
  cache=os.open(CACHE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   store=Store(cache,0,60002,60001)
   manifest=store.publish('e'*32,'f'*32,generation,datetime.now(timezone.utc).isoformat().replace('+00:00','Z'))
   with store.lease_current() as lease:
    assert lease.read_index('synthetic_profile_Packages')==b'synthetic publisher profile index'
   policy.recheck()
  finally:os.close(cache)
 stage='resource_sample'
 metrics=resources.sample()
print(json.dumps({'publisher_cap3_sealing_and_scoped_filesystem_verified':True,'publisher_fixed_pid1_socket_query_verified':True,'generation':generation,'metrics':metrics,'all_allocators_charged_from_startup_verified':False},sort_keys=True))
""".replace('@SENTINEL@',repr(str(sentinel)))
    body="stage='imports'\ntry:\n"+''.join(' '+line+'\n' for line in body.splitlines())+"except BaseException as error:\n print('publisher_probe_failure='+json.dumps({'stage':stage,'kind':type(error).__name__,'errno':getattr(error,'errno',None)},sort_keys=True),file=sys.stderr)\n raise SystemExit(74)\n"
    probe=LIB_ROOT/'publisher-profile-proof.py'
    compile(bootstrap+body,str(probe),'exec',dont_inherit=True)
    probe.write_text(bootstrap+body);probe.chmod(0o444)
    info=probe.lstat();assert info.st_uid==0 and info.st_nlink==1 and info.st_mode&0o777==0o444
    args=['/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe','--unit='+UNIT,'--slice='+PARENT_SLICE]
    for property in publisher_properties():args+=['-p',property]
    args+=['-p','RuntimeMaxSec=30','/usr/bin/python3','-I','-B',str(probe)]
    host_marker=Path('/run/systemd/system/.publisher-profile-synthetic')
    with host_marker.open('xb') as output:output.write(b'synthetic host unit directory sentinel')
    try:completed=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
    finally:host_marker.unlink()
    if completed.returncode:
        diagnostics=[]
        for line in (completed.stdout+b'\n'+completed.stderr).splitlines():
            if line.startswith((b'publisher_profile_masks=',b'publisher_cache_mount_diagnostic=',b'publisher_probe_failure=')):
                diagnostics.append(line[:2048].decode('ascii',errors='replace'))
        raise RuntimeError('Publisher probe exit='+str(completed.returncode)+' '+ ' '.join(diagnostics[:2]))
    result=json.loads(completed.stdout)
    assert result['generation']==expected_generation and result['publisher_cap3_sealing_and_scoped_filesystem_verified']
    return {'publisher_cap3_sealing_and_scoped_filesystem_verified':True,'publisher_fixed_pid1_socket_query_verified':True,'publisher_empty_systemd_marker_verified':True,
            'publisher_profile_probe_metrics':result['metrics']}


def prove_readonly_contention():
    """Disposable actual kernel writers only; no parent package lock taken."""
    from inventory_refresh_contention import ContentionProbe
    from inventory_refresh_observation import ObservationError
    assert sys.platform=='linux' and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    assert pwd.getpwnam('ccrefresh').pw_uid==WORKER and pwd.getpwnam('ccinventory').pw_uid==READER
    assert os.path.ismount(CACHE_ROOT), 'Fresh disposable helper fixture required'
    now=lambda:time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
    prefix=['/usr/bin/setpriv','--clear-groups','--inh-caps=-all','--ambient-caps=-all',
            '--bounding-set=-all','--no-new-privs','/usr/bin/python3','-I','-B','-c']
    identity=r"""import os,sys,fcntl,ctypes,select
fields=dict(line.split(':',1) for line in open('/proc/self/status').read().splitlines())
assert fields['Uid'].split()==['0']*4 and fields['Gid'].split()==['0']*4
assert not fields['Groups'].split() and fields['NoNewPrivs'].split()==['1']
assert all(int(fields[key].strip(),16)==0 for key in ('CapPrm','CapEff','CapBnd','CapInh','CapAmb'))
"""
    for kind,expected in (('posix','package_manager_busy'),('ofd','package_manager_busy'),('flock','executor_busy')):
        source=identity+r"""
kind=@KIND@
path='/run/guarded-update-executor.lock' if kind=='flock' else '/var/lib/dpkg/lock-frontend'
fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 if kind=='flock':fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 elif kind=='posix':fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB,1,17)
 else:
  class Flock(ctypes.Structure):
   _fields_=[('kind',ctypes.c_short),('whence',ctypes.c_short),('start',ctypes.c_longlong),('length',ctypes.c_longlong),('pid',ctypes.c_int)]
  assert ctypes.sizeof(ctypes.c_void_p)==8 and ctypes.sizeof(Flock)==32
  assert (Flock.start.offset,Flock.length.offset,Flock.pid.offset)==(8,16,24)
  lock=Flock(fcntl.F_WRLCK,os.SEEK_SET,64,64,0)
  fcntl.fcntl(fd,fcntl.F_OFD_SETLK,bytes(lock))
 print('ready',flush=True)
 poller=select.poll();poller.register(sys.stdin.fileno(),select.POLLIN|select.POLLHUP|select.POLLERR)
 assert poller.poll(5000), 'Synthetic writer release deadline expired'
 assert os.read(sys.stdin.fileno(),1)==b'x'
finally:os.close(fd)
""".replace('@KIND@',repr(kind))
        writer=subprocess.Popen(prefix+[source],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env=ENV,close_fds=True)
        try:
            poller=select.poll();poller.register(writer.stdout.fileno(),select.POLLIN|select.POLLHUP|select.POLLERR)
            assert poller.poll(5000), 'Synthetic writer readiness timed out'
            assert os.read(writer.stdout.fileno(),32)==b'ready\n', 'Synthetic kernel writer failed to acquire its fixed lock'
            try:owned=ContentionProbe.fixed(deadline_ms=now()+5000,now=now)
            except ObservationError as error:assert error.reason==expected, 'Kernel write contention was not classified'
            else:
                owned.close();raise AssertionError('Observed kernel writer incorrectly reported clear')
        finally:
            try:
                if writer.stdin is not None:
                    try:writer.stdin.write(b'x');writer.stdin.flush()
                    except BrokenPipeError:pass
                    finally:writer.stdin.close()
            finally:
                try:status=writer.wait(timeout=6)
                finally:
                    if writer.stdout is not None:writer.stdout.close()
        assert status==0
    # While every parent O_PATH pin remains open, a separate caps-empty root
    # writer must still take the exact exclusive package/executor locks.
    owned=ContentionProbe.fixed(deadline_ms=now()+5000,now=now)
    try:
        source=identity+r"""
fds=[]
try:
 for path,native in [('/run/guarded-update-executor.lock',False),('/var/lib/dpkg/lock-frontend',True),('/var/lib/dpkg/lock',True)]:
  fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK);fds.append(fd)
  if native:fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  else:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
finally:
 for fd in fds:os.close(fd)
"""
        command(prefix+[source],timeout=5)
    finally:owned.close()
    return {'readonly_kernel_posix_and_ofd_package_contention_verified':True,
        'readonly_kernel_executor_flock_contention_verified':True,
        'parent_probe_holds_no_package_or_executor_locks_verified':True}


def prove_root_refresh_transaction(expected_generation):
    """Actual fixed production components in one CAP3 publisher, synthetic only."""
    from inventory_refresh_publisher_profile import publisher_properties
    from inventory_refresh_resources import UNIT
    from inventory_refresh_root_entry import SOURCES
    for name,filename in SOURCES:
        shutil.copyfile(ROOT/'scripts'/(name+'.py'),LIB_ROOT/filename);(LIB_ROOT/filename).chmod(0o444)
    shutil.copyfile(ROOT/'scripts/inventory_refresh_root_entry.py',LIB_ROOT/'coordinator.py')
    (LIB_ROOT/'coordinator.py').chmod(0o444)
    # All earlier observation scopes have been independently confirmed empty.
    for filename in ('observation-native.py','observation-guardian.py'):
        shutil.copyfile(ROOT/'scripts/inventory_refresh_entry.py',LIB_ROOT/filename);(LIB_ROOT/filename).chmod(0o444)
    # Synthetic actor files only; the production dispatcher cannot create them.
    for capability in ('refresh','observation','release'):
        directory=Path(RUNTIME_ROOT)/capability
        directory.mkdir(mode=0o770,exist_ok=True);os.chown(directory,0,READER);directory.chmod(0o770)
        (directory/'request').unlink(missing_ok=True)
    request=Path(RUNTIME_ROOT)/'refresh/request'
    request.write_bytes(('0000000000000001'+'a'*16).encode('ascii'));request.chmod(0o600);os.chown(request,READER,READER)
    status=Path(RUNTIME_ROOT)/'status';status.mkdir(mode=0o750);os.chown(status,0,READER);status.chmod(0o750)
    state=os.open(STATE_ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        journal=Journal(state)
        with journal.exclusive():journal.initialize(secrets.token_hex(16))
    finally:os.close(state)
    original=(LIB_ROOT/'resource-admission-proof.py').read_text()
    bootstrap,marker,_=original.partition('from inventory_refresh_resources import RuntimeResources')
    assert marker
    # Test wrapper pre-admits the fixed entry itself. That actual entry's loader
    # then admits/compiles every root module; no fixture module-list bootstrap.
    bootstrap=re.sub(r'^names=.*$', "names=('inventory_refresh_root_entry',)",bootstrap,count=1,flags=re.MULTILINE)
    bootstrap=bootstrap.replace("filename=name+'.py'", "filename='coordinator.py'")
    bootstrap+="root_sources=sys.modules['inventory_refresh_root_entry'].RootSources.fixed()\ntry:root_sources.execute()\nfinally:root_sources.close()\n"
    body=r"""from inventory_refresh_runtime import FixedRuntime
from inventory_refresh_writer_exclusion import WriterExclusion
import secrets
import time
fields=dict(line.split(':',1) for line in open('/proc/self/status').read().splitlines())
assert {name:int(fields[name].strip(),16) for name in ('CapPrm','CapEff','CapBnd','CapInh','CapAmb')}=={'CapPrm':3,'CapEff':3,'CapBnd':3,'CapInh':0,'CapAmb':0}
assert fields['NoNewPrivs'].split()==['1']
assert sys.flags.no_site
stage='runtime_admission';runtime=FixedRuntime.fixed()
try:
 journal=runtime._journal;store=runtime._store;resources=runtime._resources;policy=runtime._policy
 assert policy.generation==@GENERATION@
 nonce='0000000000000001'+'a'*16
 stage='transaction'
 assert runtime.step()['refresh']=='succeeded'
 value=journal.snapshot();success=value['last_success']
 assert not value['unconfirmed'] and success['attempt']['correlator']==nonce
 assert value['capabilities']['refresh']['active'] is None
 with store.lease_current() as lease:
  assert lease.manifest['cache_generation']==success['attempt']['cache_generation']
  assert lease.manifest['policy_generation']==policy.generation
  indexes=[row for row in lease.manifest['files'] if '_Packages' in row['path']]
  assert indexes
  for index in indexes:lease.verify_index(index['path'])
 status_path='/run/command-center-inventory-refresh/status/status.json'
 status=open(status_path,'rb').read(65537);assert len(status)<=65536
 public=json.loads(status)
 assert public['phase']=='succeeded' and public['operation_nonce']==nonce
 assert public['cache_generation']==success['attempt']['cache_generation']
 assert public['successful_checked_at']==success['successful_checked_at']
 assert runtime.step()['refresh']=='existing'
 assert open(status_path,'rb').read(65537)==status
 stage='observation_admission'
 def synthetic_request(capability,nonce):
  # Test-only actor: complete bounded bytes, chmod before transferring owner.
  directory=os.open('/run/command-center-inventory-refresh/'+capability,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  temporary='.fixture-'+secrets.token_hex(16)
  try:
   fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
   try:
    raw=nonce.encode('ascii');assert os.write(fd,raw)==len(raw)
    os.fchmod(fd,0o600);os.fchown(fd,60002,60002);os.fsync(fd)
   finally:os.close(fd)
   os.rename(temporary,'request',src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
  finally:os.close(directory)
 observed_nonce='0000000000000005'+'d'*16
 synthetic_request('observation',observed_nonce)
 assert runtime.step()['observation']=='dispatched'
 stage='observation_opening';limit=time.monotonic()+10
 while True:
  phase=runtime.step()['poll']
  if phase=='opened':break
  assert phase=='opening' and time.monotonic()<limit
  time.sleep(.02)
 offer=json.loads(open(status_path,'rb').read(65537))['observation_lease']
 assert offer['nonce']==observed_nonce and offer['cache_generation']==success['attempt']['cache_generation']
 with store.lease_current() as lease:
  for index in lease.manifest['files']:lease.verify_index(index['path'])
 stage='observation_release'
 synthetic_request('release',observed_nonce)
 assert runtime.step()['release']=='releasing'
 assert json.loads(open(status_path,'rb').read(65537))['observation_lease'] is None
 assert runtime.step()['release']=='existing'
 stage='observation_acceptance';limit=time.monotonic()+10
 while True:
  phase=runtime.step()['poll']
  if phase=='succeeded':break
  assert phase=='releasing' and time.monotonic()<limit
  time.sleep(.02)
 value=journal.snapshot();accepted=value['last_observation'];receipt=accepted['receipt']
 assert not value['unconfirmed'] and value['last_success']==success
 assert all(value['capabilities'][name]['active'] is None and accepted[name]['phase']=='succeeded' for name in ('observation','release'))
 assert all(receipt[key]==item for key,item in offer.items())
 assert receipt['installed_before_sha256']==receipt['installed_after_sha256']
 public=json.loads(open(status_path,'rb').read(65537))
 assert public['observation_receipt']==receipt and public['observation_lease'] is None
 assert public['cache_generation']==success['attempt']['cache_generation']
 frozen=journal.snapshot();assert runtime.step()['observation']=='existing' and journal.snapshot()==frozen
 stage='final_checks'
 runtime._writers.check();resources.sample();policy.recheck()
 metrics=resources.sample()
finally:runtime.close()
assert not journal._held
postclose=WriterExclusion.fixed(60001)
try:postclose.check()
finally:postclose.close()
print(json.dumps({'fixed_publisher_refresh_transaction_verified':True,'fixed_publisher_observation_transaction_verified':True,
 'fixed_publisher_inbox_dispatch_verified':True,'fixed_publisher_runtime_verified':True,'fixed_publisher_root_bootstrap_verified':True,'generation':@GENERATION@,'metrics':metrics,
 'coordinator_exercised':False,'all_allocators_charged_from_startup_verified':False},sort_keys=True))
""".replace('@GENERATION@',repr(expected_generation))
    body="stage='imports'\ntry:\n"+''.join(' '+line+'\n' for line in body.splitlines())+"except BaseException as error:\n print('publisher_transaction_failure='+json.dumps({'stage':stage,'operation_stage':getattr(error,'stage',None),'diagnostics':getattr(error,'diagnostics',None),'kind':type(error).__name__,'errno':getattr(error,'errno',None)},sort_keys=True),file=sys.stderr)\n raise SystemExit(74)\n"
    probe=LIB_ROOT/'publisher-transaction-proof.py'
    compile(bootstrap+body,str(probe),'exec',dont_inherit=True)
    probe.write_text(bootstrap+body);probe.chmod(0o444)
    args=['/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe','--unit='+UNIT,'--slice='+PARENT_SLICE]
    for property in publisher_properties():args+=['-p',property]
    args+=['-p','RuntimeMaxSec=120','/usr/bin/python3','-I','-B','-S',str(probe)]
    completed=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=130)
    if completed.returncode:
        lines=[line[:2048].decode('ascii',errors='replace') for line in (completed.stdout+b'\n'+completed.stderr).splitlines() if line.startswith(b'publisher_transaction_failure=')]
        raise RuntimeError('Publisher transaction exit='+str(completed.returncode)+' '+' '.join(lines[:1]))
    result=json.loads(completed.stdout)
    assert result['generation']==expected_generation and result['fixed_publisher_refresh_transaction_verified']
    assert not result['coordinator_exercised'] and not result['all_allocators_charged_from_startup_verified']
    assert result['fixed_publisher_observation_transaction_verified'] and result['fixed_publisher_inbox_dispatch_verified'] and result['fixed_publisher_runtime_verified'] and result['fixed_publisher_root_bootstrap_verified']
    return {'fixed_publisher_refresh_transaction_verified':True,'fixed_publisher_observation_transaction_verified':True,'fixed_publisher_inbox_dispatch_verified':True,'fixed_publisher_runtime_verified':True,'fixed_publisher_root_bootstrap_verified':True,'publisher_refresh_transaction_metrics':result['metrics']}



REPORTER_INBOX_CODE=r"""import os,re,stat,sys
assert len(sys.argv)==3 and sys.argv[1] in ('observation','release')
nonce=sys.argv[2];assert re.fullmatch('[0-9a-f]{32}',nonce) and int(nonce[:16],16)>0
fields=dict(line.split(':',1) for line in open('/proc/self/status').read().splitlines())
assert all(fields[key].split()==['60002']*4 for key in ('Uid','Gid'))
assert not fields['Groups'].split() and fields['NoNewPrivs'].split()==['1']
assert all(int(fields[key].strip(),16)==0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
directory=os.open('/run/command-center-inventory-refresh/'+sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
temporary='.actor-'+os.urandom(8).hex();fd=None;created=False
try:
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory);created=True
 raw=nonce.encode('ascii');offset=0
 while offset<len(raw):
  count=os.write(fd,raw[offset:]);assert count>0;offset+=count
 info=os.fstat(fd)
 assert stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==60002 and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1
 os.fsync(fd);closing,fd=fd,None;os.close(closing)
 os.rename(temporary,'request',src_dir_fd=directory,dst_dir_fd=directory);created=False;os.fsync(directory)
finally:
 try:
  if fd is not None:os.close(fd)
 finally:
  try:
   if created:os.unlink(temporary,dir_fd=directory)
  finally:os.close(directory)
"""



PROJECTED_READER_CODE=r"""import fcntl,hashlib,json,os,re,stat,subprocess,sys,time,types
assert len(sys.argv)==6 and re.fullmatch('[0-9a-f]{32}',sys.argv[1]) and re.fullmatch('[0-9a-f]{64}',sys.argv[2])
assert re.fullmatch('[0-9a-f-]{36}',sys.argv[3]) and re.fullmatch('[0-9]+',sys.argv[4]) and re.fullmatch('[0-9a-f]{32}',sys.argv[5])
deadline=int(sys.argv[4]);assert 0<deadline<=9007199254740991
assert open('/proc/sys/kernel/random/boot_id').read().strip()==sys.argv[3]
previous=None
def clock():
 global previous
 now=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000
 assert (previous is None or now>=previous) and now<=deadline
 previous=now;return now
scan_started=clock()
fields=dict(line.split(':',1) for line in open('/proc/self/status').read().splitlines())
assert all(fields[key].split()==['60002']*4 for key in ('Uid','Gid'))
assert fields['Groups'].split() in ([],['60002']) and fields['NoNewPrivs'].split()==['1']
assert all(int(fields[key].strip(),16)==0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
assert open('/proc/self/cgroup').read()=='0::/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory-reader-proof.service\n'
stage='private_inputs'
for path in ('/etc/command-center-inventory-refresh/policy.json','/etc/command-center-inventory-refresh/policy-commitment.key','/etc/command-center-inventory-refresh/apt/auth.conf'):
 try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 except PermissionError:pass
 else:
  os.close(fd);raise ValueError('Root private reader boundary failed')
stage='generation';fds=[];lease=None;dpkg=None
try:
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
 for part in ('var','cache','command-center-inventory-refresh','generation-'+sys.argv[1]):
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(child);fd=child
  info=os.fstat(fd);assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
 generation=fd;device=os.fstat(generation).st_dev
 def read(directory,name,limit):
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
  try:
   info=os.fstat(fd);assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022 and info.st_nlink==1 and info.st_dev==device and info.st_size<=limit
   raw=b''
   while True:
    part=os.read(fd,min(65536,limit+1-len(raw)))
    if not part:break
    raw+=part;assert len(raw)<=limit
   assert len(raw)==info.st_size;return raw
  finally:os.close(fd)
 lease=os.open('_inventory-lease',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=generation)
 info=os.fstat(lease);assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022 and info.st_nlink==1 and info.st_dev==device
 fcntl.flock(lease,fcntl.LOCK_SH|fcntl.LOCK_NB)
 stage='manifest'
 manifest=json.loads(read(generation,'_inventory-manifest.json',4*1024*1024))
 assert manifest['cache_generation']==sys.argv[1] and manifest['policy_generation']==sys.argv[2]
 reader=os.open('_inventory-reader',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=generation);fds.append(reader)
 info=os.fstat(reader);assert info.st_uid==0 and not info.st_mode&0o022 and info.st_dev==device
 stage='config'
 for name in ('apt.conf','sources.sources','preferences','empty-main.conf','empty-trusted.gpg','empty-auth.conf'):
  raw=read(reader,name,4*1024*1024);rows=[row for row in manifest['files'] if row['path']=='_inventory-reader/'+name]
  assert len(rows)==1 and rows[0]['sha256']==hashlib.sha256(raw).hexdigest() and rows[0]['size']==len(raw)
  assert b'synthetic-proof-password' not in raw and b'password ' not in raw
 stage='helper_source';source_refs=[]
 fd=fds[0]
 for part in ('usr','local','libexec','command-center-inventory-refresh'):
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(child);source_refs.append((fd,part,child));fd=child
  info=os.fstat(fd);assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
 source='inventory_refresh_observation.py';source_fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
 def stable(info):return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
 try:
  info=os.fstat(source_fd);assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022 and info.st_nlink==1 and 0<info.st_size<=65536
  raw=b''
  while True:
   chunk=os.read(source_fd,65537-len(raw))
   if not chunk:break
   raw+=chunk;assert len(raw)<=65536
  assert len(raw)==info.st_size
  path='/usr/local/libexec/command-center-inventory-refresh/'+source
  compiled=compile(raw,path,'exec',dont_inherit=True)
  assert stable(os.fstat(source_fd))==stable(info)==stable(os.stat(source,dir_fd=fd,follow_symlinks=False))
  for parent,part,child in source_refs:
   named=os.stat(part,dir_fd=parent,follow_symlinks=False);opened=os.fstat(child)
   assert stat.S_ISDIR(named.st_mode) and named.st_uid==0 and not named.st_mode&0o022 and (named.st_dev,named.st_ino)==(opened.st_dev,opened.st_ino)
  name='inventory_refresh_observation';assert name not in sys.modules
  observation=types.ModuleType(name);observation.__file__=path;sys.modules[name]=observation
  exec(compiled,observation.__dict__)
 finally:os.close(source_fd)
 dpkg=observation._Ancestry.open(fds[0],('var','lib','dpkg'));dpkg.verify()
 stage='installed_before'
 installed_before=observation.installed_fingerprint(dpkg.fds[-1],0,deadline,clock)
 config='/var/cache/command-center-inventory-refresh/generation-'+sys.argv[1]+'/_inventory-reader/apt.conf'
 env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C','APT_CONFIG':config}
 stage='query'
 result=subprocess.run(['/usr/bin/apt-cache','policy','inventory-proof'],env=env,cwd='/',stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
 stage='query_result'
 assert result.returncode==0 and len(result.stdout)<=65536
 stage='candidate'
 assert re.search(rb'(?m)^\s*Candidate: 1\.0\s*$',result.stdout)
 stage='pin'
 assert re.search(rb'(?m)^\s*(?:\*\*\*\s+)?1\.0\s+123\s*$',result.stdout)
 stage='installed_after'
 installed_after=observation.installed_fingerprint(dpkg.fds[-1],0,deadline,clock);dpkg.verify()
 assert installed_before==installed_after
 scan_finished=clock()
 print(json.dumps({'schema_version':1,'observation_nonce':sys.argv[5],'boot_id':sys.argv[3],
  'cache_generation':sys.argv[1],'policy_generation':sys.argv[2],'scan_started_boottime_ms':scan_started,
  'scan_finished_boottime_ms':scan_finished,'installed_before_sha256':installed_before,'installed_after_sha256':installed_after},sort_keys=True))
finally:
 try:
  if dpkg is not None:dpkg.close()
 finally:
  try:
   if lease is not None:os.close(lease)
  finally:
   for fd in reversed(fds):os.close(fd)
"""


def projected_reader_program():
    # Controlled stage/kind only: no exception text, APT output or policy bytes.
    return "import json,sys\nstage='identity'\ntry:\n"+''.join(' '+line+'\n' for line in PROJECTED_READER_CODE.splitlines())+"except BaseException as error:\n allowed=('identity','private_inputs','generation','manifest','config','query','query_result','candidate','pin','helper_source','installed_before','installed_after')\n kind=type(error).__name__\n print('projected_reader_failure='+json.dumps({'stage':stage if stage in allowed else 'unknown','kind':kind if kind in ('AssertionError','OSError','ValueError','PermissionError','FileNotFoundError','TimeoutExpired') else 'unclassified'},sort_keys=True),file=sys.stderr)\n raise SystemExit(74)\n"


def prove_projected_reader_query(offer):
    """Actual non-acquiring apt-cache under the aggregate and restricted UID."""
    unit='command-center-inventory-reader-proof.service'
    args=['/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe','--unit='+unit,'--slice='+PARENT_SLICE]
    for value in ('User=60002','Group=60002','Type=exec','ExitType=main','Restart=no','RemainAfterExit=no',
        'KillMode=control-group','KillSignal=SIGKILL','TimeoutStopSec=1','RuntimeMaxSec=15','OOMPolicy=kill',
        'MemoryAccounting=yes','TasksMax=8','NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=',
        'ProtectSystem=strict','ProtectHome=yes','ProtectControlGroups=yes','PrivateDevices=yes','PrivateTmp=yes','PrivateNetwork=yes'):
        args+=['-p',value]
    args+=['/usr/bin/python3','-I','-B','-S','-c',projected_reader_program(),offer['cache_generation'],offer['policy_generation'],offer['boot_id'],str(offer['expires_boottime_ms']),offer['nonce']]
    result=subprocess.run(args,env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    if result.returncode:
        lines=[line.decode('ascii') for line in result.stderr.splitlines() if line.startswith(b'projected_reader_failure=') and len(line)<=256]
        raise ValueError('Projected native reader failed: '+str(result.returncode)+' '+(' '.join(lines[:1])))
    assert len(result.stdout)<=2048
    return json.loads(result.stdout)

def match_projected_reader_receipt(offer,reader,receipt):
    fields={'schema_version','observation_nonce','boot_id','cache_generation','policy_generation',
        'scan_started_boottime_ms','scan_finished_boottime_ms','installed_before_sha256','installed_after_sha256'}
    assert type(reader) is dict and set(reader)==fields and type(reader['schema_version']) is int and reader['schema_version']==1
    for field in ('boot_id','cache_generation','policy_generation'):assert reader[field]==offer[field]
    assert reader['observation_nonce']==offer['nonce'] and all(receipt[key]==value for key,value in offer.items())
    assert receipt['outcome']=='released'
    values=[reader['installed_before_sha256'],reader['installed_after_sha256'],receipt['installed_before_sha256'],receipt['installed_after_sha256']]
    assert all(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) for value in values) and len(set(values))==1
    times=[reader['scan_started_boottime_ms'],reader['scan_finished_boottime_ms']]
    assert all(type(value) is int and 0<=value<=9007199254740991 for value in times)
    assert offer['lock_open_boottime_ms']<=times[0]<=times[1]<=receipt['lock_held_until_boottime_ms']<=receipt['released_boottime_ms']<=offer['expires_boottime_ms']
    return True


def decode_reporter_phase(raw,expected):
    def require(condition):
        if not condition:raise ValueError('Invalid restricted reporter phase')
    require(type(raw) is bytes and 0<len(raw)<=4096 and raw.endswith(b'\n') and raw.count(b'\n')==1)
    def unique(pairs):
        value={}
        for key,item in pairs:require(key not in value);value[key]=item
        return value
    try:value=json.loads(raw,object_pairs_hook=unique)
    except (ValueError,UnicodeError,RecursionError):raise ValueError('Invalid restricted reporter phase') from None
    require(expected in ('pinned','scan_finished','complete') and type(value) is dict and value.get('phase')==expected)
    required={'phase','evidence'} if expected=='complete' else {'phase','cache_generation','policy_generation','boot_id'} if expected=='pinned' else {'phase'}
    require(set(value)==required)
    if expected=='complete':require(type(value['evidence']) is dict)
    return value


def reporter_request_program():
    """Trusted native fixture: actual writer, synthetic caller authorization."""
    prefix=(ROOT/'scripts/inventory_refresh_root_entry.py').read_text().split('\ndef main():',1)[0]
    modules=('inventory_refresh_protocol','inventory_refresh_receipt','inventory_refresh_state','inventory_refresh_storage',
        'inventory_refresh_status','inventory_refresh_observation','inventory_refresh_io','inventory_refresh_reader_session','inventory_refresh_reporter_io')
    body=r'''
assert len(sys.argv)==3 and sys.argv[1] in ('observation','release') and re.fullmatch('[0-9a-f]{32}',sys.argv[2])
fields=dict(line.split(':',1) for line in open('/proc/self/status').read().splitlines())
assert all(fields[key].split()==['60002']*4 for key in ('Uid','Gid'))
assert fields['Groups'].split() in ([],['60002']) and fields['NoNewPrivs'].split()==['1']
assert all(int(fields[key].strip(),16)==0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
sources=None;writer=None;ancestry=None;root=None
try:
 sources=RootSources.fixed();loaded=sources.execute();closing,sources=sources,None;closing.close()
 root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 ancestry=loaded['inventory_refresh_observation']._Ancestry.open(root,('run','command-center-inventory-refresh'))
 writer=loaded['inventory_refresh_reporter_io'].ReporterRequestWriter(ancestry.fds[-1],sys.argv[1],60002,60002)
 ancestry.verify()
 # Parent fixture ordering supplies synthetic intent, not production admission.
 writer.publish(sys.argv[2]);ancestry.verify()
finally:
 failed=False
 for owned in (writer,ancestry,sources):
  if owned is not None:
   try:owned.close()
   except BaseException:failed=True
 if root is not None:
  try:os.close(root)
  except OSError:failed=True
 if failed:raise ValueError('Restricted request actor cleanup unconfirmed')
'''
    return prefix+'\nSOURCES='+repr(tuple((name,name+'.py') for name in modules))+'\n'+body


def reporter_library_program():
    # Trusted disposable fixture only: use the actual source-admission/compile
    # implementation with a fixed reader-only closure, not a production entry.
    prefix=(ROOT/'scripts/inventory_refresh_root_entry.py').read_text().split('\ndef main():',1)[0]
    modules=('inventory_refresh_protocol','inventory_refresh_receipt','inventory_refresh_state','inventory_refresh_storage',
        'inventory_refresh_status','inventory_refresh_observation','inventory_refresh_resources','inventory_refresh_reporter_resources',
        'inventory_refresh_reader_tools','inventory_refresh_reader_session','inventory_refresh_reporter_io')
    body=r'''
import json,subprocess
assert len(sys.argv)==2 and re.fullmatch('[0-9a-f]{32}',sys.argv[1])
nonce=sys.argv[1]
fields=dict(line.split(':',1) for line in open('/proc/self/status').read().splitlines())
assert all(fields[key].split()==['60002']*4 for key in ('Uid','Gid'))
assert fields['Groups'].split() in ([],['60002']) and fields['NoNewPrivs'].split()==['1']
assert all(int(fields[key].strip(),16)==0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
assert open('/proc/self/cgroup').read()=='0::/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory.service\n'
boot=open('/proc/sys/kernel/random/boot_id').read().strip()
budget=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000+15000
previous=None
def clock():
 global previous
 current=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000
 assert (previous is None or current>=previous) and current<budget
 assert open('/proc/sys/kernel/random/boot_id').read().strip()==boot
 previous=current;return boot,current
sources=None;reader=None;session=None;root=None;chains=[];resources=None
try:
 stage='sources';sources=RootSources.fixed();loaded=sources.execute();closing,sources=sources,None;closing.close()
 stage='resources';resources=loaded['inventory_refresh_reporter_resources'].ReporterResources.fixed()
 observation=loaded['inventory_refresh_observation'];root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 for parts in (('run','command-center-inventory-refresh','status'),('var','cache','command-center-inventory-refresh'),('var','lib','dpkg')):
  chains.append(observation._Ancestry.open(root,parts))
 reader=loaded['inventory_refresh_reporter_io'].StatusReader(chains[0].fds[-1],60002)
 def public():
  chains[0].verify()
  try:value=reader.read()
  except loaded['inventory_refresh_reporter_io'].ReporterIOError as error:
   if error.reason!='publication_changed':raise
   value=None  # Next loop reads a NEW file, never reuses old status.
  chains[0].verify();return value
 def document(value):return json.loads(value.encoded()) if value is not None else None
 while True:
  clock();initial=document(public())
  if initial is not None:break
  time.sleep(.01)
 stage='pin';session=loaded['inventory_refresh_reader_session'].ReaderSession.pin(
  loaded['inventory_refresh_storage'].CacheReader(chains[1].fds[-1]),cache_generation=initial['cache_generation'],
  policy_generation=initial['policy_generation'],successful_checked_at=initial['successful_checked_at'],boot_id=boot,clock=clock)
 chains[1].verify()
 print(json.dumps({'phase':'pinned','cache_generation':initial['cache_generation'],'policy_generation':initial['policy_generation'],'boot_id':boot}),flush=True)
 stage='lease'
 while True:
  clock();value=public();current=document(value)
  if current is not None and current['observation_lease'] is not None and current['observation_lease']['nonce']==nonce:break
  time.sleep(.01)
 for chain in chains:chain.verify()
 # Synthetic seam only: this is NOT a durable reporting RequestJournal proof.
 stage='scan';session.begin_scan(value,observation_nonce=nonce,dpkg_fd=chains[2].fds[-1],owner=0,admit_scan=lambda _:True)
 records=session.installed()
 rows=[line.split('\t') for line in records.splitlines() if line.startswith('installed\t')]
 assert rows and all(len(row)==4 and all(row[1:]) for row in rows)
 architecture=session.native_architecture().strip()
 assert re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',architecture)
 holds=session.holds().splitlines()
 assert all(re.fullmatch('[a-z0-9][a-z0-9+.-]{0,255}(?::[a-z0-9][a-z0-9+.-]{0,255})?',name) for name in holds)
 # Independent native selection reference only, not a second normalizer. Empty
 # real hold sets stay empty; no package selection is changed for this proof.
 with open('/var/lib/dpkg/status','rb') as source:selection_bytes=source.read(64*1024*1024+1)
 assert len(selection_bytes)<=64*1024*1024
 selected=set()
 for paragraph in selection_bytes.decode('utf-8').split('\n\n'):
  fields=dict(line.split(': ',1) for line in paragraph.splitlines() if ': ' in line and not line.startswith((' ','\t')))
  if fields.get('Status','').split(' ',1)[0]=='hold':selected.add(fields['Package'])
 assert {name.split(':')[0] for name in holds}==selected
 result=session.policy(['inventory-proof'])
 assert re.search(r'(?m)^\s*Candidate: 1\.0\s*$',result)
 assert re.search(r'(?m)^\s*(?:\*\*\*\s+)?1\.0\s+123\s*$',result)
 for chain in chains:chain.verify()
 resources.sample()
 session.finish_scan()
 frozen=session.frozen_scan_bounds()
 print(json.dumps({'phase':'scan_finished'}),flush=True)
 stage='receipt'
 while True:
  clock();value=public();current=document(value)
  if current is not None and current['observation_receipt'] is not None and current['observation_receipt']['nonce']==nonce:break
  time.sleep(.01)
 for chain in chains:chain.verify()
 resources.sample()
 stage='finish';evidence=json.loads(session.finish(value));session=None
 assert all(evidence[key]==value for key,value in frozen.items())
finally:
 failed=False
 for owned in (session,reader,sources,*reversed(chains),resources):
  if owned is not None:
   try:owned.close()
   except BaseException:failed=True
 if root is not None:
  try:os.close(root)
  except OSError:failed=True
 if failed:stage='cleanup';raise ValueError('Restricted reader cleanup unconfirmed')
print(json.dumps({'phase':'complete','evidence':evidence}),flush=True)
'''
    stages=('setup','sources','resources','pin','lease','scan','receipt','finish','cleanup')
    wrapped="stage='setup'\ntry:\n"+''.join(' '+line+'\n' for line in body.splitlines())
    wrapped+="except BaseException:\n stage=stage if stage in "+repr(stages)+" else 'setup'\n sys.stdout.write('{\"phase\":\"failed\",\"stage\":\"'+stage+'\"}\\n');sys.stdout.flush()\n raise SystemExit(74)\n"
    return prefix+'\nSOURCES='+repr(tuple((name,name+'.py') for name in modules))+'\n'+wrapped


def read_reporter_phase(stream,expected,deadline):
    import select
    raw=bytearray();poll=select.poll();poll.register(stream.fileno(),select.POLLIN|select.POLLHUP|select.POLLERR)
    while not raw.endswith(b'\n'):
        remaining=deadline-time.monotonic()
        assert remaining>0 and poll.poll(max(1,int(remaining*1000)))
        byte=os.read(stream.fileno(),1)
        assert byte and len(raw)<4096
        raw.extend(byte)
    for stage in ('setup','sources','resources','pin','lease','scan','receipt','finish','cleanup'):
        if bytes(raw)==('{"phase":"failed","stage":"'+stage+'"}\n').encode('ascii'):
            print('Native fixture reporter library stage='+stage,file=sys.stderr)
            raise ValueError('Restricted reporter fixture failed')
    return decode_reporter_phase(bytes(raw),expected)


def finish_reporter_output(process,deadline):
    import select
    remaining=deadline-time.monotonic()
    assert remaining>0 and process.wait(timeout=remaining)==0
    remaining=deadline-time.monotonic()
    poll=select.poll();poll.register(process.stdout.fileno(),select.POLLIN|select.POLLHUP|select.POLLERR)
    assert remaining>0 and poll.poll(max(1,int(remaining*1000)))
    assert os.read(process.stdout.fileno(),1)==b''


def close_reporter_parent(stream,group):
    try:stream.close()
    finally:
        if group is not None:os.close(group)


def parent_mechanics_program():
    # Synthetic trusted Parent only: prove the actual readonly admission
    # mechanics, never a production Rust lifecycle or source-bootstrap claim.
    prefix=(ROOT/'scripts/inventory_refresh_root_entry.py').read_text().split('\ndef main():',1)[0]
    modules=('inventory_refresh_resources','inventory_refresh_reporter_resources','inventory_refresh_reporter_parent')
    body=r'''
import json
assert len(sys.argv)==1
sources=None;owner=None
try:
 sources=RootSources.fixed();loaded=sources.execute();closing,sources=sources,None;closing.close()
 owner=loaded['inventory_refresh_reporter_parent'].ReporterParent.fixed()
 owner.verify();boot,now=owner.clock();owner.verify()
finally:
 failed=False
 for value in (owner,sources):
  if value is not None:
   try:value.close()
   except BaseException:failed=True
 if failed:raise ValueError('Parent mechanics cleanup unconfirmed')
print(json.dumps({'phase':'complete','evidence':{'parent_origin_mechanics':True,'boot_id':boot,'boottime_ms':now}}),flush=True)
'''
    return prefix+'\nSOURCES='+repr(tuple((name,name+'.py') for name in modules))+'\n'+body


def environment_mechanics_program():
    # Fixed readonly composition proof, not a production runtime or Root scope.
    prefix=(ROOT/'scripts/inventory_refresh_root_entry.py').read_text().split('\ndef main():',1)[0]
    modules=('inventory_refresh_protocol','inventory_refresh_receipt','inventory_refresh_state','inventory_refresh_storage',
        'inventory_refresh_status','inventory_refresh_observation','inventory_refresh_resources','inventory_refresh_reporter_resources',
        'inventory_refresh_reporter_parent','inventory_refresh_reader_tools','inventory_refresh_reader_session',
        'inventory_refresh_reporter_io','inventory_refresh_reporter_environment')
    body=r'''
import json
assert len(sys.argv)==1
sources=None;owner=None
try:
 sources=RootSources.fixed();loaded=sources.execute();closing,sources=sources,None;closing.close()
 owner=loaded['inventory_refresh_reporter_environment'].ReporterEnvironment.fixed()
 pinned=owner.pin_current();owner.verify();boot,now=owner.clock()
 assert pinned==owner.pinned_context() and pinned['boot_id']==boot
finally:
 failed=False
 for value in (owner,sources):
  if value is not None:
   try:value.close()
   except BaseException:failed=True
 if failed:raise ValueError('Environment mechanics cleanup unconfirmed')
print(json.dumps({'phase':'complete','evidence':{'environment_pin_mechanics':True,'boot_id':boot,'boottime_ms':now,'pinned_context':pinned}}),flush=True)
'''
    return prefix+'\nSOURCES='+repr(tuple((name,name+'.py') for name in modules))+'\n'+body


def publish_parent_fixture_file(fixture,directory,name,raw,mode):
    assert (name,mode) in (('command-center-inventory',0o555),('reporter-parent-proof.py',0o444),('reporter.py',0o444))
    assert type(raw) is bytes and 0<len(raw)<=1024*1024
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
    try:
        info=os.fstat(fd)
        fixture['files'].append((directory,name,(info.st_dev,info.st_ino)))
        assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.geteuid()
        offset=0
        while offset<len(raw):
            written=os.write(fd,raw[offset:]);assert written>0;offset+=written
        os.fchmod(fd,mode);os.fsync(fd)
        final=os.fstat(fd);named=os.stat(name,dir_fd=directory,follow_symlinks=False)
        assert (final.st_dev,final.st_ino)==(named.st_dev,named.st_ino)==(info.st_dev,info.st_ino)
        assert final.st_size==len(raw) and final.st_nlink==1 and stat.S_IMODE(final.st_mode)==mode
    finally:os.close(fd)
    os.fsync(directory)


def retire_parent_fixture(fixture,confirmed_empty):
    files,fixture['files']=fixture['files'],[]
    directories,fixture['directories']=fixture['directories'],[]
    failed=not confirmed_empty
    try:
        if confirmed_empty:
            for directory,name,identity in reversed(files):
                try:
                    info=os.stat(name,dir_fd=directory,follow_symlinks=False)
                    assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and (info.st_dev,info.st_ino)==identity
                    os.unlink(name,dir_fd=directory);os.fsync(directory)
                except BaseException:failed=True
    finally:
        for directory in reversed(directories):
            try:directory.close()
            except BaseException:failed=True
    assert not failed,'Synthetic parent fixture cleanup unconfirmed'


def parent_fixture_c_source(reporter=False):
    assert type(reporter) is bool
    # Two literal CI-only cases, no forwarded program/argument or signal.
    source=r'''
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
int main(void) {
 char *args[] = {"/usr/bin/python3", "-I", "-B", "-S", "/usr/local/libexec/command-center-inventory-refresh/reporter-parent-proof.py", 0};
 char *env[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", 0};
 pid_t child=fork(); if(child<0) return 74;
 if(child==0) {execve(args[0],args,env);_exit(74);}
 int status=0;
 while(waitpid(child,&status,0)<0) {if(errno!=EINTR) return 74;}
 return WIFEXITED(status)?WEXITSTATUS(status):74;
}
'''
    return source.replace('reporter-parent-proof.py','reporter.py') if reporter else source


def install_parent_fixture(program,*,reporter=False):
    from inventory_refresh_resources import _Chain
    assert sys.platform=='linux' and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and type(reporter) is bool
    name='reporter.py' if reporter else 'reporter-parent-proof.py'
    fixture={'files':[],'directories':[]}
    try:
        binary=_Chain(('usr','local','libexec'));fixture['directories'].append(binary)
        library=_Chain(('usr','local','libexec','command-center-inventory-refresh'));fixture['directories'].append(library)
        for directory,filename in ((binary.fds[-1],'command-center-inventory'),(library.fds[-1],name)):
            try:os.stat(filename,dir_fd=directory,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise AssertionError('Fixed synthetic parent path already exists')
        source=parent_fixture_c_source(reporter)
        with tempfile.TemporaryDirectory(prefix='inventory-parent-mechanics-') as temporary:
            root=Path(temporary);(root/'parent.c').write_text(source)
            command(['/usr/bin/cc','-Wall','-Wextra','-Werror','-o',str(root/'parent'),str(root/'parent.c')],timeout=15)
            with (root/'parent').open('rb') as compiled:raw=compiled.read(1024*1024+1)
            publish_parent_fixture_file(fixture,binary.fds[-1],'command-center-inventory',raw,0o555)
        publish_parent_fixture_file(fixture,library.fds[-1],name,program.encode(),0o444)
        return fixture
    except BaseException:
        retire_parent_fixture(fixture,True)  # This installer never starts Parent.
        raise


def stage_reporter_artifact_fixture(archive):
    # Verification is read-only and precedes all protected publication. This
    # helper never starts a unit, so partial staging can retire with empty=True.
    verified=verify_archive(ROOT,archive)
    fixture={'verified':verified,'sources':None,'parent':None,'retirement_attempted':False}
    try:
        fixture['sources']=FixtureSources.fixed(verified)
        fixture['sources'].publish()
        entry=verified['files']['libexec/command-center-inventory-refresh/reporter.py'].decode('utf-8')
        fixture['parent']=install_parent_fixture(entry,reporter=True)
        return fixture
    except BaseException:
        retire_reporter_artifact_fixture(fixture,True)
        raise


def retire_reporter_artifact_fixture(fixture,confirmed_empty):
    assert not fixture.get('retirement_attempted',False),'Reporter artifact fixture already retired or uncertain'
    fixture['retirement_attempted']=True
    valid_confirmation=type(confirmed_empty) is bool
    confirmed_empty=confirmed_empty if valid_confirmation else False
    parent,fixture['parent']=fixture['parent'],None
    sources,fixture['sources']=fixture['sources'],None
    failed=not valid_confirmation
    try:
        if parent is not None:retire_parent_fixture(parent,confirmed_empty)
    except BaseException:failed=True
    finally:
        if sources is not None:
            try:sources.retire(confirmed_empty)
            except BaseException:failed=True
    assert not failed,'Reporter artifact fixture retirement unconfirmed'


def validate_rust_proof_output(raw,physical_sample=False):
    assert type(physical_sample) is bool
    assert type(raw) is bytes and len(raw)<=8192
    lines=raw.decode('ascii').splitlines()
    lines=[line for line in lines if line]
    assert len(lines)==3 and lines[0]=='running 1 test'
    name='sample' if physical_sample else 'roundtrip'
    assert lines[1]=='test inventory::reporter_obs::tests::hosted_real_reporter_rust_journal_'+name+' ... ok'
    assert re.fullmatch(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s',lines[2])


def stage_rust_reporter_artifact_fixture(archive,deadline):
    # All uncertain partial publications are retained, including before launch.
    verified=verify_archive(ROOT,archive)
    fixture={'verified':verified,'artifact':None,'sources':None,'binary':None,'retirement_attempted':False}
    try:
        fixture['artifact']=RunnerArtifact.fixed(verified['source_commit'],deadline)
        fixture['sources']=FixtureSources.fixed(verified,include_entry=True)
        fixture['sources'].publish()
        fixture['binary']=FixtureBinary.fixed(fixture['artifact'])
        fixture['binary'].publish();fixture['binary'].verify_published()
        return fixture
    except BaseException:
        for owner in (fixture['binary'],fixture['sources'],fixture['artifact']):
            if owner is not None:
                try:owner.close()
                except BaseException:pass
        raise ValueError('Rust reporter fixture staging unconfirmed') from None


def retire_rust_reporter_artifact_fixture(fixture,confirmed_empty):
    assert not fixture.get('retirement_attempted',False),'Rust reporter fixture retirement already attempted'
    fixture['retirement_attempted']=True
    valid=type(confirmed_empty) is bool and confirmed_empty
    if valid:
        try:
            fixture['artifact'].verify();fixture['sources'].verify();fixture['binary'].verify_published()
        except BaseException:valid=False
    failed=not valid
    binary,fixture['binary']=fixture['binary'],None
    sources,fixture['sources']=fixture['sources'],None
    artifact,fixture['artifact']=fixture['artifact'],None
    if binary is not None:
        try:binary.retire(valid)
        except BaseException:failed=True;valid=False
    if sources is not None:
        try:sources.retire(valid)
        except BaseException:failed=True
    if artifact is not None:
        try:artifact.close()
        except BaseException:failed=True
    assert not failed,'Rust reporter fixture retirement unconfirmed'


def run_reporter_parent_fixture(program):
    from inventory_refresh_unit_status import PROPERTIES
    for name in ('inventory_refresh_reporter_parent',):
        target=LIB_ROOT/(name+'.py');shutil.copyfile(ROOT/'scripts'/(name+'.py'),target);target.chmod(0o444)
    unit='command-center-inventory.service';description='Synthetic parent admission '+secrets.token_hex(16)
    expected='/command.slice/command-center.slice/command-center-inventory.slice/'+unit
    def properties():
        result=subprocess.run(['/bin/systemctl','show','--property='+','.join(PROPERTIES),unit],env=ENV,
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2)
        assert result.returncode in (0,4) and len(result.stdout)<=4096
        values={}
        for line in result.stdout.decode('ascii').splitlines():
            key,separator,value=line.partition('=');assert separator and key in PROPERTIES and key not in values;values[key]=value
        assert set(values)==set(PROPERTIES);return values
    def empty():
        value=properties()
        if value['LoadState']!='not-found':
            assert value['Description']==description and value['ActiveState'] in ('inactive','failed')
        try:group=os.open('/sys/fs/cgroup'+expected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        except FileNotFoundError:return True
        try:
            fd=os.open('cgroup.events',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=group)
            try:assert b'populated 0' in os.read(fd,4096).splitlines()
            finally:os.close(fd)
        finally:os.close(group)
        return True
    assert properties()['LoadState']=='not-found'
    fixture=install_parent_fixture(program);process=None
    try:
        args=['/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe','--unit='+unit,'--slice='+PARENT_SLICE,'--description='+description]
        for item in ('User=60002','Group=60002','Type=exec','Restart=no','RemainAfterExit=no','KillMode=control-group',
            'KillSignal=SIGKILL','TimeoutStopSec=1','RuntimeMaxSec=20','OOMPolicy=kill','TasksMax=8','MemoryAccounting=yes',
            'NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=','ProtectSystem=strict',
            'ProtectHome=yes','ProtectControlGroups=yes','ProtectKernelTunables=yes','PrivateDevices=yes','PrivateTmp=yes','PrivateNetwork=yes'):
            args+=['-p',item]
        args+=['/usr/local/libexec/command-center-inventory']
        process=subprocess.Popen(args,env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+25
        evidence=read_reporter_phase(process.stdout,'complete',deadline)['evidence']
        finish_reporter_output(process,deadline)
        assert evidence['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        assert type(evidence['boottime_ms']) is int and 0<=evidence['boottime_ms']<=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000
        assert empty()
        return evidence
    finally:
        confirmed=False
        try:
            if process is not None:process.wait(timeout=25)
            confirmed=empty()
        finally:
            try:retire_parent_fixture(fixture,confirmed)
            finally:
                if process is not None:process.stdout.close()


def prove_reporter_parent_mechanics():
    evidence=run_reporter_parent_fixture(parent_mechanics_program())
    assert set(evidence)=={'parent_origin_mechanics','boot_id','boottime_ms'} and evidence['parent_origin_mechanics'] is True


def prove_reporter_environment_mechanics(public):
    target=LIB_ROOT/'inventory_refresh_reporter_environment.py'
    shutil.copyfile(ROOT/'scripts/inventory_refresh_reporter_environment.py',target);target.chmod(0o444)
    before=public();evidence=run_reporter_parent_fixture(environment_mechanics_program())
    assert set(evidence)=={'environment_pin_mechanics','boot_id','boottime_ms','pinned_context'} and evidence['environment_pin_mechanics'] is True
    pinned=evidence['pinned_context']
    assert set(pinned)=={'cache_generation','policy_generation','successful_checked_at','boot_id','pinned_boottime_ms'}
    assert all(pinned[key]==before[key] for key in ('cache_generation','policy_generation','successful_checked_at'))
    assert pinned['boot_id']==evidence['boot_id'] and type(pinned['pinned_boottime_ms']) is int and 0<=pinned['pinned_boottime_ms']<=evidence['boottime_ms']


def prove_reporter_library_roundtrip(actor,public):
    """Native library seam; synthetic admission, not executable-client readiness."""
    from inventory_refresh_unit_status import PROPERTIES
    for name in ('inventory_refresh_reporter_resources','inventory_refresh_reader_tools','inventory_refresh_reader_session','inventory_refresh_reporter_io'):
        target=LIB_ROOT/(name+'.py');shutil.copyfile(ROOT/'scripts'/(name+'.py'),target);target.chmod(0o444)
    unit='command-center-inventory.service';description='Disposable reporter session '+secrets.token_hex(16)
    nonce='0000000000000007'+'e'*16
    def properties():
        result=subprocess.run(['/bin/systemctl','show','--property='+','.join(PROPERTIES),unit],env=ENV,
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2)
        assert result.returncode in (0,4) and len(result.stdout)<=4096
        value={}
        for line in result.stdout.decode('ascii').splitlines():
            key,separator,item=line.partition('=');assert separator and key in PROPERTIES and key not in value;value[key]=item
        assert set(value)==set(PROPERTIES);return value
    assert properties()['LoadState']=='not-found'
    args=['/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe','--unit='+unit,'--slice='+PARENT_SLICE,'--description='+description]
    for item in ('User=60002','Group=60002','Type=exec','ExitType=main','Restart=no','RemainAfterExit=no',
        'KillMode=control-group','KillSignal=SIGKILL','TimeoutStopSec=1','RuntimeMaxSec=20','OOMPolicy=kill',
        'MemoryAccounting=yes','TasksMax=8','NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=',
        'ProtectSystem=strict','ProtectHome=yes','ProtectControlGroups=yes','PrivateDevices=yes','PrivateTmp=yes','PrivateNetwork=yes'):
        args+=['-p',item]
    args+=['/usr/bin/python3','-I','-B','-S','-c',reporter_library_program(),nonce]
    process=subprocess.Popen(args,env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    group=None;invocation=None;group_identity=None
    try:
        deadline=time.monotonic()+25
        pinned=read_reporter_phase(process.stdout,'pinned',deadline)
        before=public()
        assert pinned['cache_generation']==before['cache_generation'] and pinned['policy_generation']==before['policy_generation']
        assert pinned['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        value=properties()
        assert value['LoadState']=='loaded' and value['Description']==description and re.fullmatch('[0-9a-f]{32}',value['InvocationID'])
        expected='/command.slice/command-center.slice/command-center-inventory.slice/'+unit
        assert value['ControlGroup']==expected
        invocation=value['InvocationID'];group=os.open('/sys/fs/cgroup'+expected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        info=os.fstat(group);group_identity=(info.st_dev,info.st_ino)
        actor('observation',nonce)
        read_reporter_phase(process.stdout,'scan_finished',deadline)
        actor('release',nonce)
        final=read_reporter_phase(process.stdout,'complete',deadline)['evidence']
        finish_reporter_output(process,deadline)  # Bounded EOF: no valid-prefix surplus.
        value=properties()
        if value['LoadState']!='not-found':
            assert value['Description']==description and value['InvocationID']==invocation and value['ActiveState'] in ('inactive','failed')
        try:named=os.stat('/sys/fs/cgroup'+expected,follow_symlinks=False)
        except FileNotFoundError:pass
        else:
            assert (named.st_dev,named.st_ino)==group_identity
            fd=os.open('cgroup.events',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=group)
            try:assert b'populated 0' in os.read(fd,4096).splitlines()
            finally:os.close(fd)
        receipt=public()['observation_receipt']
        assert set(final)=={'schema_version','scan_started_boottime_ms','scan_finished_boottime_ms','successful_checked_at','observation_receipt'}
        assert type(final['schema_version']) is int and final['schema_version']==1 and final['observation_receipt']==receipt and receipt['nonce']==nonce
        assert final['successful_checked_at']==before['successful_checked_at']
        for key in ('cache_generation','policy_generation','boot_id'):assert receipt[key]==pinned[key]
        offer={key:receipt[key] for key in ('nonce','boot_id','cache_generation','policy_generation','lock_open_boottime_ms','expires_boottime_ms')}
        reader={'schema_version':1,'observation_nonce':nonce,**{key:receipt[key] for key in ('boot_id','cache_generation','policy_generation','installed_before_sha256','installed_after_sha256')},
            'scan_started_boottime_ms':final['scan_started_boottime_ms'],'scan_finished_boottime_ms':final['scan_finished_boottime_ms']}
        assert match_projected_reader_receipt(offer,reader,receipt)
        return receipt
    finally:
        try:
            # The known transient has its own kernel/PID1 deadline. Never let
            # coordinator cleanup stand in for reporter termination or pin close.
            process.wait(timeout=25)
        finally:
            closing,group=group,None
            close_reporter_parent(process.stdout,closing)


def prove_packaged_reporter_roundtrip(archive,public):
    """Synthetic-parent mechanics only; no durable Rust or completion claim."""
    from inventory_refresh_unit_status import PROPERTIES
    from inventory_refresh_reporter_controller import run_reporter_controller
    unit='command-center-inventory.service';description='Packaged reporter proof '+secrets.token_hex(16)
    expected='/command.slice/command-center.slice/command-center-inventory.slice/'+unit
    def properties():
        result=subprocess.run(['/bin/systemctl','show','--property='+','.join(PROPERTIES),unit],env=ENV,
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2)
        assert result.returncode in (0,4) and len(result.stdout)<=4096
        values={}
        for line in result.stdout.decode('ascii').splitlines():
            key,separator,value=line.partition('=');assert separator and key in PROPERTIES and key not in values;values[key]=value
        assert set(values)==set(PROPERTIES);return values
    assert properties()['LoadState']=='not-found'
    fixture=stage_reporter_artifact_fixture(archive);process=None;group=None;identity=None;invocation=None;confirmed=False
    try:
        args=['/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe','--unit='+unit,'--slice='+PARENT_SLICE,'--description='+description]
        for item in ('User=60002','Group=60002','Type=exec','Restart=no','RemainAfterExit=no','KillMode=control-group',
            'KillSignal=SIGKILL','TimeoutStopSec=1','RuntimeMaxSec=20','OOMPolicy=kill','TasksMax=8','MemoryAccounting=yes','NoNewPrivileges=yes','CapabilityBoundingSet=',
            'AmbientCapabilities=','ProtectSystem=strict','ProtectHome=yes','ProtectControlGroups=yes',
            'ProtectKernelTunables=yes','PrivateDevices=yes','PrivateTmp=yes','PrivateNetwork=yes',
            'ReadWritePaths=/run/command-center-inventory-refresh/observation /run/command-center-inventory-refresh/release'):
            args+=['-p',item]
        args+=['/usr/local/libexec/command-center-inventory']
        deadline=time.monotonic()+25
        process=subprocess.Popen(args,env=ENV,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        while True:
            value=properties()
            if value['LoadState']=='loaded' and value['InvocationID'] and value['ControlGroup']==expected:
                assert value['Description']==description and re.fullmatch('[0-9a-f]{32}',value['InvocationID'])
                invocation=value['InvocationID'];group=os.open('/sys/fs/cgroup'+expected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                info=os.fstat(group);identity=(info.st_dev,info.st_ino);break
            assert value['LoadState'] in ('loaded','not-found') and process.poll() is None and time.monotonic()<deadline
            time.sleep(.02)
        fds=(process.stdout.fileno(),process.stdin.fileno());identities=[]
        for fd,direction in zip(fds,(os.O_RDONLY,os.O_WRONLY)):
            info=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL)
            assert stat.S_ISFIFO(info.st_mode) and flags&os.O_ACCMODE==direction
            identities.append((info.st_dev,info.st_ino))
        assert identities[0]!=identities[1]
        for fd in fds:os.set_blocking(fd,False)
        before=public();nonce='0000000000000008'+'d'*16
        context={key:before[key] for key in ('cache_generation','policy_generation','successful_checked_at')}
        context['boot_id']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        result=run_reporter_controller(process,expected_context=context,read_root_status=public,nonce=nonce,deadline=deadline)
        result['artifact']={key:fixture['verified'][key] for key in ('source_commit','archive_sha256','entry_sha256')}
        return result
    finally:
        failed=False
        if process is not None:
            try:process.wait(timeout=max(0,deadline-time.monotonic()))
            except BaseException:failed=True
            for stream in (process.stdin,process.stdout):
                if stream is not None:
                    try:stream.close()
                    except BaseException:failed=True
        try:
            value=properties()
            if invocation is not None:
                if value['LoadState']!='not-found':
                    assert value['Description']==description and value['InvocationID']==invocation and value['ActiveState'] in ('inactive','failed')
                assert group is not None and (os.fstat(group).st_dev,os.fstat(group).st_ino)==identity
                try:named=os.stat('/sys/fs/cgroup'+expected,follow_symlinks=False)
                except FileNotFoundError:pass
                else:
                    assert (named.st_dev,named.st_ino)==identity
                    fd=os.open('cgroup.events',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=group)
                    try:assert b'populated 0' in os.read(fd,4096).splitlines()
                    finally:os.close(fd)
                confirmed=not failed
            elif process is None:confirmed=value['LoadState']=='not-found'
        except BaseException:failed=True
        finally:
            if group is not None:
                try:os.close(group)
                except BaseException:failed=True;confirmed=False
            try:retire_reporter_artifact_fixture(fixture,confirmed)
            except BaseException:failed=True
        if failed:raise ValueError('Packaged reporter fixture cleanup unconfirmed')


def rust_unit_properties(deadline,properties):
    # Never signal a Root-owned systemctl child on timeout; preserve uncertainty.
    import select
    child=None;failed=False;raw=bytearray()
    try:
        child=subprocess.Popen(['/bin/systemctl','show','--property='+','.join(properties),'command-center-inventory.service'],
            env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        fd=child.stdout.fileno();os.set_blocking(fd,False);poller=select.poll();poller.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR)
        while True:
            remaining=deadline-time.monotonic();assert remaining>0 and poller.poll(max(1,int(remaining*1000)))
            try:chunk=os.read(fd,4097-len(raw))
            except BlockingIOError:continue
            assert time.monotonic()<deadline
            if not chunk:break
            raw.extend(chunk);assert len(raw)<=4096
        remaining=deadline-time.monotonic();assert remaining>0 and child.wait(timeout=remaining) in (0,4) and time.monotonic()<deadline
    except BaseException:failed=True
    finally:
        if child is not None:
            try:child.stdout.close()
            except BaseException:failed=True
    if failed:raise ValueError('Rust unit status unconfirmed')
    try:
        values={}
        for line in bytes(raw).decode('ascii').splitlines():
            key,separator,value=line.partition('=');assert separator and key in properties and key not in values;values[key]=value
        assert set(values)==set(properties) and time.monotonic()<deadline
        return values
    except BaseException:raise ValueError('Rust unit status unconfirmed') from None


def read_rust_barrier_marker(fd,deadline):
    marker=b'INVENTORY-BARRIER-1\n';received=bytearray();poller=select.poll()
    poller.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR)
    while len(received)<len(marker):
        remaining=deadline-time.monotonic();assert remaining>0 and poller.poll(max(1,int(remaining*1000)))
        try:chunk=os.read(fd,len(marker)+1-len(received))
        except BlockingIOError:continue
        assert chunk and time.monotonic()<deadline;received.extend(chunk);assert marker.startswith(received)
    assert bytes(received)==marker and time.monotonic()<deadline


def write_rust_barrier_ack(fd,deadline):
    ack=b'ACK-1\n';offset=0;poller=select.poll();poller.register(fd,select.POLLOUT|select.POLLHUP|select.POLLERR)
    while offset<len(ack):
        remaining=deadline-time.monotonic();assert remaining>0 and poller.poll(max(1,int(remaining*1000)))
        try:written=os.write(fd,ack[offset:])
        except BlockingIOError:continue
        assert written>0 and written<=len(ack)-offset and time.monotonic()<deadline;offset+=written


def sample_rust_unit_processes(unit,description,expected,invocation,identity,deadline,properties):
    value=properties()
    assert value['Description']==description and value['InvocationID']==invocation and value['ControlGroup']==expected
    assert value['ActiveState']=='active' and value['Delegate']=='no' and value['ProtectControlGroups']=='yes' and value['MemoryPressureWatch']=='off'
    assert re.fullmatch('[1-9][0-9]{0,9}',value['MainPID']);pid=int(value['MainPID'])
    group_chain=None;probe=None
    try:
        group_chain=_Chain(('sys','fs','cgroup')+tuple(expected.strip('/').split('/')))
        group_chain.verify();held=os.fstat(group_chain.fds[-1]);assert (held.st_dev,held.st_ino)==identity
        probe=ProcessProbe.fixed(pid,(os.major(held.st_dev),os.minor(held.st_dev)),deadline)
        start=probe.sample()
        observe_single_process(group_chain.fds[-2],unit,group_chain.fds[-1],pid,deadline)
        assert probe.sample()==start;group_chain.verify()
        again=properties()
        assert again['Description']==description and again['InvocationID']==invocation and again['ControlGroup']==expected
        assert again['MainPID']==str(pid) and again['ActiveState']=='active' and again['Delegate']=='no' and again['ProtectControlGroups']=='yes' and again['MemoryPressureWatch']=='off'
        assert time.monotonic()<deadline
    finally:
        try:
            if probe is not None:probe.close()
        finally:
            if group_chain is not None:group_chain.close()


def prove_rust_reporter_roundtrip(archive,public,physical_sample=False):
    """Hosted fixture mechanics; no production or process-set completion witness."""
    import select
    from inventory_refresh_unit_status import PROPERTIES
    assert type(physical_sample) is bool
    unit='command-center-inventory.service';description='Rust reporter proof '+secrets.token_hex(16)
    expected='/command.slice/command-center.slice/command-center-inventory.slice/'+unit
    deadline=time.monotonic()+60
    def properties():return rust_unit_properties(min(deadline,time.monotonic()+2),PROPERTIES+(('Delegate','ProtectControlGroups','MemoryPressureWatch') if physical_sample else ()))
    assert properties()['LoadState']=='not-found'
    fixture=stage_rust_reporter_artifact_fixture(archive,deadline)
    process=None;group=None;identity=None;invocation=None;confirmed=False;completed=False
    try:
        args=['/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe','--unit='+unit,'--slice='+PARENT_SLICE,
            '--description='+description,'--setenv=GITHUB_ACTIONS=true','--setenv=GUARDED_UPDATE_NATIVE_RUST_PROOF=1']
        for item in ('User=60002','Group=60002','Type=exec','Restart=no','RemainAfterExit=no','KillMode=control-group',
            'KillSignal=SIGKILL','TimeoutStopSec=1','RuntimeMaxSec=20','OOMPolicy=kill','TasksMax=8','MemoryAccounting=yes','NoNewPrivileges=yes','CapabilityBoundingSet=',
            'AmbientCapabilities=','ProtectSystem=strict','ProtectHome=yes','ProtectControlGroups=yes',
            'ProtectKernelTunables=yes','PrivateDevices=yes','PrivateTmp=yes','PrivateNetwork=yes',
            'ReadWritePaths=/run/command-center-inventory-refresh/observation /run/command-center-inventory-refresh/release'):
            args+=['-p',item]
        if physical_sample:
            args+=['--setenv=GUARDED_UPDATE_NATIVE_BARRIER_PROOF=1','-p','Delegate=no',
                '-p','ReadOnlyPaths=/sys/fs/cgroup','-p','MountFlags=private','-p','MemoryPressureWatch=off']
        test_name=('inventory::reporter_obs::tests::hosted_real_reporter_rust_journal_sample' if physical_sample else
            'inventory::reporter_obs::tests::hosted_real_reporter_rust_journal_roundtrip')
        args+=['/usr/local/libexec/command-center-inventory','--exact',test_name,'--ignored','--test-threads=1','--nocapture']
        fixture['binary'].verify_published();assert time.monotonic()<deadline
        process=subprocess.Popen(args,env=ENV,stdin=subprocess.PIPE if physical_sample else subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if physical_sample else subprocess.DEVNULL)
        while True:
            value=properties()
            if value['LoadState']=='loaded' and value['InvocationID'] and value['ControlGroup']==expected:
                assert value['Description']==description and re.fullmatch('[0-9a-f]{32}',value['InvocationID'])
                invocation=value['InvocationID'];group=os.open('/sys/fs/cgroup'+expected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                info=os.fstat(group);identity=(info.st_dev,info.st_ino);break
            assert value['LoadState'] in ('loaded','not-found') and process.poll() is None and time.monotonic()<deadline
            time.sleep(.02)
        if physical_sample:
            # The control stream is separate from libtest output and every endpoint
            # is checked before changing shared open-file-description flags.
            endpoints=((process.stdin,os.O_WRONLY),(process.stdout,os.O_RDONLY),(process.stderr,os.O_RDONLY));identities=[]
            for stream,direction in endpoints:
                info=os.fstat(stream.fileno());flags=fcntl.fcntl(stream.fileno(),fcntl.F_GETFL)
                assert stat.S_ISFIFO(info.st_mode) and flags&os.O_ACCMODE==direction
                identities.append((info.st_dev,info.st_ino))
            assert len(set(identities))==3
            for stream,_ in endpoints:os.set_blocking(stream.fileno(),False)
            read_rust_barrier_marker(process.stderr.fileno(),deadline)
            sample_rust_unit_processes(unit,description,expected,invocation,identity,deadline,properties)
            write_rust_barrier_ack(process.stdin.fileno(),deadline)
            process.stdin.close();process.stdin=None
        fd=process.stdout.fileno();info=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL)
        assert stat.S_ISFIFO(info.st_mode) and flags&os.O_ACCMODE==os.O_RDONLY
        os.set_blocking(fd,False);output=bytearray();poller=select.poll();poller.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR)
        while True:
            remaining=deadline-time.monotonic();assert remaining>0 and poller.poll(max(1,int(remaining*1000)))
            try:chunk=os.read(fd,min(8193-len(output),8193))
            except BlockingIOError:continue
            assert time.monotonic()<deadline
            if not chunk:break
            output.extend(chunk);assert len(output)<=8192
        if physical_sample:
            poller=select.poll();poller.register(process.stderr.fileno(),select.POLLIN|select.POLLHUP|select.POLLERR)
            remaining=deadline-time.monotonic();assert remaining>0 and poller.poll(max(1,int(remaining*1000)))
            assert os.read(process.stderr.fileno(),1)==b'' and time.monotonic()<deadline
        assert process.wait(timeout=max(0,deadline-time.monotonic()))==0 and time.monotonic()<deadline
        validate_rust_proof_output(bytes(output),physical_sample)
        status=public();receipt=status['observation_receipt']
        assert status['observation_lease'] is None and receipt['nonce']=='0000000000000009'+'d'*16 and receipt['outcome']=='released'
        assert time.monotonic()<deadline
        completed=True
        return receipt
    finally:
        failed=False
        if process is not None:
            try:process.wait(timeout=max(0,deadline-time.monotonic()))
            except BaseException:failed=True
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream is not None:
                    try:stream.close()
                    except BaseException:failed=True
        try:
            value=properties()
            if invocation is not None:
                if value['LoadState']!='not-found':
                    assert value['Description']==description and value['InvocationID']==invocation and value['ActiveState'] in ('inactive','failed')
                assert group is not None and (os.fstat(group).st_dev,os.fstat(group).st_ino)==identity
                try:named=os.stat('/sys/fs/cgroup'+expected,follow_symlinks=False)
                except FileNotFoundError:pass
                else:
                    assert (named.st_dev,named.st_ino)==identity
                    fd=os.open('cgroup.events',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=group)
                    try:assert b'populated 0' in os.read(fd,4096).splitlines()
                    finally:os.close(fd)
                confirmed=completed and not failed and time.monotonic()<deadline
        except BaseException:failed=True
        finally:
            if group is not None:
                try:os.close(group)
                except BaseException:failed=True;confirmed=False
            try:retire_rust_reporter_artifact_fixture(fixture,confirmed)
            except BaseException:failed=True
        if time.monotonic()>=deadline:failed=True
        if failed:raise ValueError('Rust reporter fixture cleanup unconfirmed')


def prove_actual_coordinator_entry_loop(archive,physical_sample=False):
    """GHA-only actual entry, restricted inbox actor and controlled policy refusal."""
    assert type(physical_sample) is bool
    from inventory_refresh_publisher_profile import publisher_properties
    from inventory_refresh_resources import UNIT,SELF_CGROUP
    from inventory_refresh_unit_status import PROPERTIES,inert
    from inventory_refresh_writer_exclusion import WriterExclusion
    assert sys.platform=='linux' and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    source=LIB_ROOT/'coordinator.py';expected=(ROOT/'scripts/inventory_refresh_root_entry.py').read_bytes()
    # Admit exact entry before starting it; self-validation is not its provenance.
    root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);ancestry=None
    try:
        from inventory_refresh_observation import _Ancestry,_stable
        ancestry=_Ancestry.open(root,('usr','local','libexec','command-center-inventory-refresh'))
        fd=os.open('coordinator.py',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=ancestry.fds[-1])
        try:
            info=os.fstat(fd);assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o022
            assert 0<info.st_size<=65536
            raw=os.read(fd,65537);assert raw==expected and len(raw)==info.st_size
            assert _stable(os.fstat(fd))==_stable(info) and _stable(os.stat('coordinator.py',dir_fd=ancestry.fds[-1],follow_symlinks=False))==_stable(info)
            ancestry.verify()
        finally:os.close(fd)
    finally:
        try:
            if ancestry is not None:ancestry.close()
        finally:os.close(root)
    def properties():
        result=subprocess.run(['/bin/systemctl','show','--property='+','.join(PROPERTIES),UNIT],env=ENV,
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2)
        assert result.returncode in (0,4) and len(result.stdout)<=4096
        value={}
        for line in result.stdout.decode('ascii').splitlines():
            key,separator,item=line.partition('=');assert separator and key in PROPERTIES and key not in value;value[key]=item
        assert set(value)==set(PROPERTIES);return value
    assert properties()['LoadState']=='not-found'
    nonce='0000000000000006'+'f'*16;description='Disposable inventory entry '+secrets.token_hex(16)
    policy=Path(POLICY_ROOT)/'policy.json';original=policy.read_bytes();policy_info=policy.stat()
    control=Path(STATE_ROOT)/'control.json';before=json.loads(control.read_bytes())
    prior_success=before['last_success'];prior_refresh=before['capabilities']['refresh']
    status_path=Path(RUNTIME_ROOT)/'status/status.json'
    def public():
        with status_path.open('rb') as status:raw=status.read(65537)
        assert len(raw)<=65536;return json.loads(raw)
    def actor(capability,operation=nonce):
        code=REPORTER_INBOX_CODE if operation==nonce else reporter_request_program()
        result=subprocess.run(list(worker_argv(READER,READER)[:-1])+['-S','-c',code,capability,operation],
            env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        assert result.returncode==0,'Restricted synthetic inbox actor failed'
    def write_policy(data):
        fd=os.open(policy,os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd);assert info.st_uid==policy_info.st_uid==0 and stat.S_IMODE(info.st_mode)==stat.S_IMODE(policy_info.st_mode)==0o600
            offset=0
            while offset<len(data):
                count=os.write(fd,data[offset:]);assert count>0;offset+=count
            os.fsync(fd)
        finally:os.close(fd)
        directory=os.open(policy.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    args=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--unit='+UNIT,'--slice='+PARENT_SLICE,'--description='+description]
    for item in publisher_properties():args+=['-p',item]
    args+=['-p','CollectMode=inactive','-p','RuntimeMaxSec=30','/usr/bin/python3','-I','-B','-S',str(source)]
    launcher=subprocess.Popen(args,env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    invocation=None;group=None;group_identity=None;changed=False;receipt=None;proved=False
    def invalidate_policy():
        nonlocal changed
        changed=True  # O_TRUNC/write/fsync can mutate before reporting failure.
        write_policy(b'{}')
    def pin(value):
        nonlocal invocation,group,group_identity
        assert value['LoadState']=='loaded' and value['Transient']=='yes' and value['Description']==description
        assert re.fullmatch('[0-9a-f]{32}',value['InvocationID'])
        if invocation is None:invocation=value['InvocationID']
        assert value['InvocationID']==invocation and value['ControlGroup'] in (SELF_CGROUP,'')
        if group is None and value['ControlGroup']==SELF_CGROUP:
            group=os.open('/sys/fs/cgroup'+SELF_CGROUP,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            info=os.fstat(group);group_identity=(info.st_dev,info.st_ino)
    def confirm_inert():
        value=properties();pin(value);assert inert(value)
        assert group is not None and (os.fstat(group).st_dev,os.fstat(group).st_ino)==group_identity
        try:named=os.stat('/sys/fs/cgroup'+SELF_CGROUP,follow_symlinks=False)
        except FileNotFoundError:pass
        else:
            assert (named.st_dev,named.st_ino)==group_identity
            fd=os.open('cgroup.events',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=group)
            try:assert b'populated 0' in os.read(fd,4096).splitlines()
            finally:os.close(fd)
        final=properties();assert final['Description']==description and final['InvocationID']==invocation and inert(final)
        guard=WriterExclusion.fixed(WORKER)
        try:guard.check()
        finally:guard.close()
        state=os.open(STATE_ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            journal=Journal(state)
            with journal.exclusive():
                frozen=journal._decode_snapshot(journal._read('initialized-epoch'),journal._read('control.json'))
                assert frozen['unconfirmed']  # Main must fence before this verification barrier.
                assert journal.startup_ready() is False
                value=journal.snapshot();assert value['unconfirmed'] and value['last_success']==prior_success
                assert value['capabilities']['refresh']==prior_refresh
                if receipt is not None:assert value['last_observation']['receipt']==receipt
        finally:os.close(state)
        assert public()['observation_lease'] is None
        return final
    try:
        limit=time.monotonic()+5
        while True:
            value=properties()
            if value['LoadState']=='loaded':
                assert value['Transient']=='yes' and value['Description']==description
                # StartTransientUnit can expose the registered object before
                # its start job assigns InvocationID. Waiting grants no ownership.
                if value['InvocationID']:
                    pin(value)
                    if group is not None:break
            else:assert value['LoadState']=='not-found'
            assert launcher.poll() is None and time.monotonic()<limit;time.sleep(.02)
        assert group is not None
        actor('observation');limit=time.monotonic()+10
        while True:
            value=public();offer=value['observation_lease']
            if offer is not None and offer['nonce']==nonce:break
            assert launcher.poll() is None and time.monotonic()<limit;time.sleep(.02)
        cache=os.open(CACHE_ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            with Store(cache,0,READER,WORKER).lease_current() as lease:
                assert lease.manifest['cache_generation']==offer['cache_generation']
                for item in lease.manifest['files']:lease.verify_index(item['path'])
                reader_proof=prove_projected_reader_query(offer)
        finally:os.close(cache)
        actor('release');limit=time.monotonic()+10
        while True:
            value=public();receipt=value['observation_receipt']
            if receipt is not None and receipt['nonce']==nonce:break
            receipt=None;assert launcher.poll() is None and time.monotonic()<limit;time.sleep(.02)
        assert value['observation_lease'] is None and all(receipt[key]==item for key,item in offer.items())
        assert match_projected_reader_receipt(offer,reader_proof,receipt)
        receipt=None  # The attempt may replace the last observation before failing.
        receipt=prove_reporter_library_roundtrip(actor,public)
        prove_reporter_parent_mechanics()
        prove_reporter_environment_mechanics(public)
        packaged=prove_packaged_reporter_roundtrip(archive,public)
        receipt=packaged['evidence']['observation_receipt']
        assert receipt['nonce']=='0000000000000008'+'d'*16 and packaged['mechanics_only'] is True
        # The Rust attempt may publish a newer receipt even when its witness
        # fails. Do not demand the obsolete OBS8 receipt during failure cleanup.
        receipt=None
        receipt=prove_rust_reporter_roundtrip(archive,public,physical_sample)
        assert receipt['nonce']=='0000000000000009'+'d'*16
        invalidate_policy()
        assert launcher.wait(timeout=35)==74
        final=confirm_inert();assert final['ExecMainCode']=='1' and final['ExecMainStatus']=='74' and final['Result']=='exit-code'
        proved=True
    finally:
        try:
            if launcher.poll() is None:
                if not changed:invalidate_policy()
                launcher.wait(timeout=35)
            if changed:
                confirm_inert()  # Never restore into an unknown/live invocation.
                write_policy(original);changed=False
            if invocation is not None:
                value=properties();assert value['Description']==description and value['InvocationID']==invocation and inert(value)
                command(['/bin/systemctl','reset-failed',UNIT],timeout=3)
        finally:
            if group is not None:os.close(group)
    assert proved
    result={'fixed_coordinator_entry_loop_and_controlled_policy_refusal_verified':True,
        'restricted_reporter_actual_entry_observation_receipt_verified':True,
        'projected_reader_policy_native_query_verified':True,
        'restricted_reporter_fingerprint_matches_root_receipt_verified':True,
        'restricted_reporter_session_root_status_roundtrip_verified':True,
        'restricted_reporter_current_readonly_resource_admission_verified':True,
        'restricted_reporter_parent_origin_clock_mechanics_verified':True,
        'restricted_reporter_protected_environment_pin_mechanics_verified':True,
        'restricted_reporter_artifact_dialogue_roundtrip_mechanics_verified':True,
        'restricted_rust_parent_real_reporter_journal_mechanics_verified':True,
        'restricted_reporter_artifact':packaged['artifact'],
        'restricted_reporter_request_writer_roundtrip_verified':True}
    result['restricted_rust_parent_sampled_process_profile_verified']=physical_sample
    return result

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


def stopped_child_proof(args,job,*,owner=None):
    """CI-owned transient service only; never callable on a user endpoint."""
    if not (sys.platform=='linux' and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'):
        raise RuntimeError('Disposable hosted Linux root runner required')
    # main() has refused existing installations/accounts and created this exact
    # fixture. Check both its fixed identities before any fixture-owned signal.
    assert pwd.getpwnam('ccrefresh').pw_uid==WORKER
    assert pwd.getpwnam('ccinventory').pw_uid==READER
    assert args[0]=='/usr/bin/systemd-run' and '--unit='+WORKER_UNIT in args
    launcher=owner if owner is not None else subprocess.Popen(args,env=ENV,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
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
            if owner is not None:
                from inventory_refresh_worker_service import show_unit
                owner._same_invocation(show_unit())
            return (str(worker) in (owned/'cgroup.procs').read_text().split() and
                    is_live_worker(Path('/proc',str(worker),'status').read_bytes(),parent=guardian))
        stop_owned_child(worker,recheck)
        if owner is not None:
            # Host prerequisites are present; inspect only their absence through
            # the exact owned guardian's namespace, never read private bytes.
            masked=[Path(POLICY_ROOT)/'policy.json',Path(POLICY_ROOT)/'policy-commitment.key',
                    Path('/etc/apt'),Path('/var/lib/dpkg'),Path('/run/systemd/private')]
            for path in masked:
                assert path.exists(), 'Missing host prerequisite invalidates mask proof'
                assert not Path('/proc',str(guardian),'root'+str(path)).exists(), 'Unneeded host state visible to guardian'
            required=[Path('/etc/passwd'),Path('/etc/group'),Path('/etc/nsswitch.conf'),Path('/etc/hosts'),
                      Path('/etc/resolv.conf'),Path(POLICY_ROOT)/'apt/sources.sources',
                      Path(RUNTIME_ROOT)/'job.json',Path(RUNTIME_ROOT)/'worker-apt.conf']
            for path in required:
                info=Path('/proc',str(guardian),'root'+str(path)).lstat()
                assert stat.S_ISREG(info.st_mode), 'Fixed regular-file bind missing in guardian namespace'
        status=launcher.wait(timeout=12)
        released=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
        assert status==76 and job['deadline_boottime_ms']<=released<=job['deadline_boottime_ms']+3000
        if owner is None:empty_worker()
        else:assert_worker_empty()
        return status
    finally:
        if owner is not None:
            try:owner.close()
            finally:assert_worker_empty()
        else:
            try:
                empty_worker()
            finally:
                if launcher.poll() is None:
                    launcher.kill()
                launcher.wait(timeout=5)


def run_worker(policy,number,*,stopped_child=False,policy_guard=None):
    if policy_guard is None:
        return _run_worker(policy,number,stopped_child=stopped_child)
    # This fixture proves real durable start admission, not a complete deployed
    # coordinator. Publication/other fixtures still have separate journal scope.
    state=Path(RUNTIME_ROOT)/('refresh-admission-proof-'+f'{number:032x}')
    state.mkdir(mode=0o700)
    fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY);journal=Journal(fd)
    try:
        with journal.exclusive():
            journal.initialize(secrets.token_hex(16))
            boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            accepted=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
            nonce=f'{number:016x}'+secrets.token_hex(8)
            assert journal.receive('refresh',nonce,boot,accepted,policy_guard.generation)=='new'
            started=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
            assert journal.start('refresh',nonce,boot,started,policy=policy_guard.generation)
            context={'boot':boot,'accepted':accepted,'started':started,'nonce':nonce}
            return _run_worker(policy,number,stopped_child=stopped_child,policy_guard=policy_guard,
                               journal=journal,admission=context)
    finally:os.close(fd)


def _run_worker(policy, number, *, stopped_child=False, policy_guard=None,journal=None,admission=None):
    if policy_guard is not None:policy_guard.recheck()
    empty_worker()
    token = f'{number:032x}'
    stage = Path(CACHE_ROOT)/('staging-'+token)
    stage.mkdir(mode=0o700)
    os.chown(stage, WORKER, WORKER)
    for relative in ['lists', 'lists/partial', 'cache', 'archives', 'log', 'tmp']:
        directory = stage/relative
        directory.mkdir(mode=0o700)
        os.chown(directory, WORKER, WORKER)
    rendered = render_policy(policy, token) if policy_guard is None else policy_guard.render(token)
    for relative, data in rendered.items():
        target = Path(RUNTIME_ROOT)/'worker-apt.conf' if relative == 'apt.conf' else Path(POLICY_ROOT)/'apt'/relative
        write_root(target, data)
    empty = Path(POLICY_ROOT)/'apt/empty.d'
    empty.mkdir(exist_ok=True)
    os.chown(empty, 0, WORKER)
    empty.chmod(0o550)
    assert not any(empty.iterdir())
    now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
    nonce = f'{number:016x}'+secrets.token_hex(8) if admission is None else admission['nonce']
    job = {'schema_version': 1, 'staging_token': token,
           'config_sha256': hashlib.sha256(rendered['apt.conf']).hexdigest(),
           'policy_generation': policy_generation(b'k'*32, policy) if policy_guard is None else policy_guard.generation,
           'operation_nonce': nonce, 'helper_sequence': number,
           'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip() if admission is None else admission['boot'],
           'accepted_boottime_ms': now if admission is None else admission['accepted'],
           'started_boottime_ms': now if admission is None else admission['started'],
           'deadline_boottime_ms': (now if admission is None else admission['started'])+(8000 if stopped_child else 600000)}
    write_root(Path(RUNTIME_ROOT)/'job.json', json.dumps(job).encode())
    # PID1 protects the root MAIN guardian; setpriv permanently drops its fixed child.
    args=list(refresh_argv(token))
    binding=MaterializedPolicy.fixed(policy_guard,token,WORKER,job['config_sha256']) if policy_guard is not None else None
    try:
        if binding is not None:binding.recheck()
        if stopped_child:
            owner=RefreshService(journal,policy_guard).launch() if journal is not None else None
            return stopped_child_proof(args,job,owner=owner),token,job['policy_generation']
        if policy_guard is not None:policy_guard.recheck()
        if journal is not None:
            owned=RefreshService(journal,policy_guard).launch()
            try:
                status=owned.wait(timeout=610)
                assert_worker_empty()
                owned.verify_current_inputs()
            finally:owned.close()
            # No native output is used as authority or leaked on this path.
            result=subprocess.CompletedProcess((),status,stdout=b'',stderr=b'')
        else:
            # Only legacy fault fixtures use host system-bus wait/stdio. The
            # actual production adapters use private PID1 and raw retained status.
            args=args[:1]+['--wait','--collect','--pipe']+args[1:]
            args=['CollectMode=inactive-or-failed' if value=='CollectMode=inactive' else value for value in args]
            result = subprocess.run(args, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=610)
            status = result.returncode
            empty_worker()
        if binding is not None:binding.recheck()
        if policy_guard is not None:policy_guard.recheck()
        # Physical empty/UID checks above precede this fixture-only translation.
        if status==90:status=0
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
    finally:
        if binding is not None:binding.close()


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
    assert len(sys.argv)==2
    archive=Path(sys.argv[1])
    for path in [Path(POLICY_ROOT), Path(CACHE_ROOT), Path(RUNTIME_ROOT), Path(STATE_ROOT), LIB_ROOT]:
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
    private_policy_guard = None
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
        for path in [Path(POLICY_ROOT), Path(CACHE_ROOT), Path(RUNTIME_ROOT), Path(STATE_ROOT), LIB_ROOT]:
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
        def policy(certificate_path=ca, signing_key=public, password=PASSWORD, missing=False, raw=False):
            value = {'schema_version': 1, 'architectures': [architecture],
                'sources': [{'id': 'fixture', 'type': 'deb', 'uri': uri, 'suites': ['proof'],
                             'components': ['main'], 'architectures': [architecture], 'signed_by': ['fixture']}],
                'trust': {'keys': [{'id': 'fixture', 'format': 'gpg',
                                    'content_base64': base64.b64encode(signing_key).decode()}],
                          'tls_ca_base64': base64.b64encode(certificate_path.read_bytes()).decode()},
                'pins': [{'package':'inventory-proof','match':{'version':'1.0'},'priority':123}], 'proxy': {'http': 'DIRECT', 'https': 'DIRECT'},
                'auth': [{'machine': uri, 'login': 'fixture', 'password': password}]}
            if missing:
                extra = dict(value['sources'][0], id='missing', uri=uri+'/missing')
                value['sources'].append(extra)
            data=json.dumps(value).encode()
            return data if raw else parse_policy(data)
        # If host config leaked, this hook would be allowed to write the first active stage.
        marker = Path(CACHE_ROOT)/('staging-'+f'{1:032x}')/'host-hook-ran'
        hook.write_text('APT::Update::Pre-Invoke { "/usr/bin/touch '+str(marker)+'"; };\n')
        good = policy()
        for name,data in [('policy.json',policy(raw=True)),('policy-commitment.key',b'k'*32)]:
            target=Path(POLICY_ROOT)/name;target.write_bytes(data);os.chown(target,0,0);target.chmod(0o600)
        private_policy_guard=PolicyGuard.fixed()
        assert private_policy_guard.generation==policy_generation(b'k'*32,good)
        resource_proof=prove_resource_admission(private_policy_guard.generation)
        resource_proof.update(prove_publisher_profile(base,private_policy_guard.generation))
        # Real low-privilege UIDs must not read either private root input. The
        # probe checks actual kernel IDs/capabilities before attempting access.
        probe="""import os,sys
identity=sys.argv[1]
fields=dict(line.split(':',1) for line in open('/proc/self/status').read().splitlines())
assert all(fields[key].split()==[identity]*4 for key in ('Uid','Gid'))
assert not fields['Groups'].split() and fields['NoNewPrivs'].split()==['1']
assert all(int(fields[key].strip(),16)==0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
for path in sys.argv[2:]:
 try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except PermissionError:pass
 else:
  os.close(fd);sys.exit(91)
"""
        for identity in (WORKER,READER):
            result=subprocess.run(list(worker_argv(identity,identity)[:-1])+['-c',probe,str(identity),
                str(Path(POLICY_ROOT)/'policy.json'),str(Path(POLICY_ROOT)/'policy-commitment.key')],
                env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            assert result.returncode==0, 'Private root input UID/capability exclusion failed'
        resource_proof.update(prove_readonly_contention())
        prove_privilege_transition()
        status, stage, generation = run_worker(good, 1,policy_guard=private_policy_guard)
        assert status == 0, f'Valid signed TLS/authenticated repository refresh failed (exit={status})'
        assert Handler.requests > 0 and not marker.exists(), 'Host APT configuration leaked'
        lists = Path(CACHE_ROOT)/('staging-'+stage)/'lists'
        assert any('_Packages' in path.name for path in lists.iterdir()), 'No binary package index was acquired'
        cache = os.open(CACHE_ROOT, os.O_RDONLY | os.O_DIRECTORY)
        store = Store(cache, 0, READER, WORKER)
        try:
            config_hash=hashlib.sha256(private_policy_guard.render(stage)['apt.conf']).hexdigest()
            with MaterializedPolicy.fixed(private_policy_guard,stage,WORKER,config_hash) as publication_binding:
                private_policy_guard.recheck()
                store.publish(stage, 'a'*32, generation, datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
                private_policy_guard.recheck()
                observation=prove_cache_pinned_observation(store,base)
                observation.update(prove_observation_process(store,base))
                observation.update(prove_observation_process(store,base,stopped_child=True))
                observation.update(prove_observation_process(store,base,sequence=4))
                observation['observation_failed_unit_acknowledgement_and_reuse_verified']=True
                private_policy_guard.recheck()
                publication_binding.recheck()
            resource_proof.update(prove_root_refresh_transaction(generation))
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
        run_worker(good,7,stopped_child=True,policy_guard=private_policy_guard)
        Handler.hold=False
        repository(web,home,architecture)
        recovered,_,_=run_worker(good,8,policy_guard=private_policy_guard)
        assert recovered==0, 'Owned failed refresh unit was not acknowledged for the next job'
        assert (Path(CACHE_ROOT)/'current.json').read_bytes()==previous
        barrier_marker=os.environ.get('GUARDED_UPDATE_NATIVE_BARRIER_PROOF')
        assert barrier_marker in (None,'1')
        resource_proof.update(prove_actual_coordinator_entry_loop(archive,barrier_marker=='1'))
        proof = {'schema_version': 1, 'scope': 'fixed_worker_trusted_policy',
            'synthetic_repository_only': True, 'target_repository_fit_proven': False,
            'coordinator_exercised': False, 'apt_refresh_exercised': True,
            'root_guardian_fixed_privilege_drop_exercised': True,
            'fixed_root_policy_guard_and_current_commitment_verified':True,
            'full_rendered_policy_bound_during_worker_and_publication_verified':True,
            'fixed_refresh_service_new_durable_start_verified':True,
            'fixed_refresh_service_deadline_fault_verified':True,
            'fixed_refresh_failed_unit_acknowledgement_and_reuse_verified':True,
            'fixed_refresh_guardian_private_inputs_host_state_and_sockets_masked':True,
            'fixed_refresh_guardian_required_nss_resolver_and_apt_file_binds_verified':True,
            'external_dns_resolution_fit_proven':False,
            'worker_and_reporter_private_policy_key_read_denied':True,
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
            'worker_memory_peak': int((cgroup(PARENT_SLICE)/'memory.peak').read_text()),**observation,**resource_proof}
    finally:
        try:
            if private_policy_guard is not None:private_policy_guard.close()
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
            for path in [Path(POLICY_ROOT), Path(CACHE_ROOT), Path(RUNTIME_ROOT), Path(STATE_ROOT), LIB_ROOT]:
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
