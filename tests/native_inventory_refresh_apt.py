#!/usr/bin/env python3
"""Disposable hosted proof of the fixed worker against a synthetic signed TLS repo.

This is never packaged. It creates/removes only its own helper paths/accounts on
an isolated CI VM. It does not prove real-device repository fit or a coordinator.
"""
import base64
from datetime import datetime, timedelta, timezone
import email.utils
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
        current.chmod(0o750)
        current = current.parent
    temporary = path.with_name('.new-'+secrets.token_hex(8))
    with open(temporary, 'xb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.chown(temporary, 0, WORKER)
    temporary.chmod(mode)
    temporary.replace(path)


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
    errors=['keep process capabilities failed','activate capabilities','reactivate capabilities',
            'apply bounding set','apply capabilities','setresuid failed','setresgid failed',
            'setgroups failed','disallow granting new privileges failed','failed to execute',
            'Operation not permitted','Invalid argument','Permission denied']
    source=('import subprocess,sys\n'
            'state=dict(line.split(":",1) for line in open("/proc/self/status") if ":" in line)\n'
            'uidmap=open("/proc/self/uid_map").read().split()\n'
            'print("parent_state="+str(bool(int(state["CapEff"],16)&128))+":"+str(uidmap==["0","0","4294967295"]),file=sys.stderr)\n'
            'result=subprocess.run('+repr(fixed)+',env='+repr(ENV)+',stdin=subprocess.DEVNULL,'
            'stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)\n'
            'if result.returncode:\n'
            ' labels=[label for label in '+repr(errors)+' if label.encode() in result.stderr]\n'
            ' print("transition_failure="+str(result.returncode)+":"+(",".join(labels) if labels else "unclassified"),file=sys.stderr)\n'
            'sys.stdout.buffer.write(result.stdout)\n'
            'raise SystemExit(result.returncode)\n')
    probe.write_text(source)
    probe.chmod(0o444)
    args=['/usr/bin/systemd-run','--quiet','--wait','--collect','--pipe',
        '--unit=command-center-inventory-privilege-proof','--slice='+WORKER_SLICE,
        '-p','User=root','-p','Group=root','-p','NoNewPrivileges=yes',
        '-p','CapabilityBoundingSet=CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP',
        '-p','ProtectSystem=strict','-p','ProtectHome=yes','-p','ProtectControlGroups=yes',
        '-p','RestrictNamespaces=yes','-p','PrivateDevices=yes','-p','PrivateTmp=yes',
        '-p','InaccessiblePaths=/tmp /var/tmp /dev/shm',
        '/usr/bin/python3','-I','-B',str(probe)]
    result=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    if result.returncode!=0:
        labels=re.findall(rb'(?:transition_failure=[0-9]{1,3}:[a-zA-Z ,]+|parent_state=(?:True|False):(?:True|False))',result.stderr)
        # Diagnostic-only read-only bisection on this disposable VM. No helper
        # metadata, APT operation, signal or persistent unit is involved.
        sandbox=['ProtectSystem=strict','ProtectHome=yes','ProtectControlGroups=yes','RestrictNamespaces=yes',
                 'PrivateDevices=yes','PrivateTmp=yes','InaccessiblePaths=/tmp /var/tmp /dev/shm']
        for index,property_value in enumerate(sandbox):
            isolated=args[:]
            for value in sandbox:
                location=isolated.index(value)
                del isolated[location-1:location+1]
            location=isolated.index('/usr/bin/python3')
            isolated[location:location]=['-p',property_value]
            check=subprocess.run(isolated,env=ENV,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=10)
            details=re.findall(rb'(?:transition_failure=[0-9]{1,3}:[a-zA-Z ,]+|parent_state=(?:True|False):(?:True|False))',check.stderr)
            labels.append(('property_'+str(index)+'_exit_'+str(check.returncode)).encode())
            labels.extend(details[:2])
        raise AssertionError('Fixed full-sandbox privilege transition failed: '+repr(labels))
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
            'worker_memory_peak': int((cgroup(PARENT_SLICE)/'memory.peak').read_text())}
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
