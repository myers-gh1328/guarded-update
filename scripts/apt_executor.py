#!/usr/bin/python3
"""Root APT adapter. Controller traffic is transported by an unprivileged broker."""
import argparse
import email.utils
import hashlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import secrets
import stat
import subprocess
import sys
import time

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l"}
MAX = 2 * 1024 * 1024


def checked(path, directory=False, limit=MAX):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Absolute normalized path required')
    for ancestor in path.parents:
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe path ancestry: ' + str(ancestor))
    before = path.lstat()
    if before.st_uid != 0 or before.st_mode & 0o022:
        raise ValueError('Unsafe root ownership or permissions')
    if directory:
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError('Unsafe directory')
        return path
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError('Unsafe or oversized file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError('File changed during open')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Oversized file')
        return data
    finally:
        os.close(fd)


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        parent = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(fd)


def command(args, timeout=120):
    result = subprocess.run(args, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        raise ValueError('Executor prerequisite command failed: ' + Path(args[0]).name)
    if len(result.stdout) > 16 * MAX:
        raise ValueError('Executor prerequisite output exceeds limit')
    return result.stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def repository_file(path):
    # Raspberry Pi OS ships root-owned .gpg aliases to sibling .pgp keyrings.
    # Accept aliases only in read-only repository fingerprints, never config,
    # controller pins, archive paths or journal files. Every hop and parent is
    # root controlled, and the final descriptor still passes checked().
    path = Path(path)
    for _ in range(8):
        info = path.lstat()
        if not stat.S_ISLNK(info.st_mode):
            return checked(path, limit=512 * 1024 * 1024)
        if info.st_uid != 0 or path.parent != Path('/usr/share/keyrings'):
            raise ValueError('Repository alias must be a root-owned system keyring')
        for ancestor in path.parents:
            checked(ancestor, directory=True)
        target = Path(os.readlink(path))
        if '..' in target.parts:
            raise ValueError('Parent traversal in repository alias is unsupported')
        path = target if target.is_absolute() else path.parent / target
        if path.parent != Path('/usr/share/keyrings') or path.suffix not in ('.gpg', '.pgp'):
            raise ValueError('Repository alias must stay within system keyrings')
    raise ValueError('Repository alias chain exceeds limit')


def tree_hash(roots, repository=False):
    digest = hashlib.sha256()
    count = 0
    for root in roots:
        root = Path(root)
        paths = sorted(root.rglob('*')) if root.is_dir() else [root]
        for path in paths:
            if path.name == 'lock' or 'partial' in path.parts or 'auxfiles' in path.parts:
                continue
            if path.is_dir():
                checked(path, directory=True)
                continue
            if not path.exists():
                continue
            data = repository_file(path) if repository else checked(path, limit=512 * 1024 * 1024)
            digest.update(str(path).encode() + b'\0' + hashlib.sha256(data).digest())
            count += 1
    if not count:
        raise ValueError('Required local state missing')
    return digest.hexdigest()


def package_hash():
    if command(['/usr/bin/dpkg', '--audit']).strip():
        raise ValueError('Dpkg state requires reconciliation')
    return tree_hash(['/var/lib/dpkg/status', '/var/lib/dpkg/updates', '/var/lib/dpkg/arch'])


def repository_hash():
    return tree_hash(['/var/lib/apt/lists', '/etc/apt', '/usr/share/keyrings'], repository=True)


def holds():
    return sorted(command(['/usr/bin/apt-mark', 'showhold']).decode().splitlines())


def version(value):
    return {'version': value.version, 'architecture': value.architecture, 'multi_arch': value.record.get('Multi-Arch', 'none')}


def expiry(now):
    # Local freshness policy is stricter than APT's unlimited default for archives
    # without Valid-Until: signed Date may be at most seven days old. This is a
    # local acceptance deadline, not an invented upstream expiry.
    deadlines = [now + 3600]
    releases = list(Path('/var/lib/apt/lists').glob('*InRelease')) + list(Path('/var/lib/apt/lists').glob('*_Release'))
    if not releases:
        raise ValueError('No authenticated repository metadata')
    for path in releases:
        signed_date = None
        for line in checked(path, limit=16 * MAX).decode().splitlines():
            if line.startswith('Valid-Until: '):
                deadlines.append(int(email.utils.parsedate_to_datetime(line[13:]).timestamp()))
            if line.startswith('Date: '):
                signed_date = int(email.utils.parsedate_to_datetime(line[6:]).timestamp())
        if signed_date is None:
            raise ValueError('Authenticated repository Date missing')
        if signed_date > now + 300:
            raise ValueError('Repository metadata is from the future')
        deadlines.append(signed_date + 7 * 86400)
    end = min(deadlines)
    if end <= now:
        raise ValueError('Repository metadata expired under local freshness policy')
    return end


def request(config, kind, body, claim_id=None):
    identity = secrets.token_hex(16)
    value = {'schema_version': 1, 'kind': kind, 'request_id': identity, 'expires_at_unix': int(time.time()) + 120, 'body': body}
    if claim_id is not None:
        value['claim_id'] = claim_id
    path = Path(config['broker_dir']) / (identity + '.json')
    write_new(path, encode(value), 0o640)
    os.chown(path, 0, Path(config['broker_dir']).stat().st_gid)
    return identity


def response(config, identity, timeout=90):
    path = Path(config['responses_dir']) / (identity + '.json')
    end = time.monotonic() + timeout
    try:
        while time.monotonic() < end:
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                time.sleep(1)
                continue
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX:
                    raise ValueError('Invalid broker response')
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    raw = stream.read(MAX + 1)
                if len(raw) > MAX:
                    raise ValueError('Broker response too large')
                result = json.loads(raw)
            finally:
                os.close(fd)
            if result.get('schema_version') != 1 or result.get('request_id') != identity or result.get('http_status') not in (200, 201):
                raise ValueError('Controller rejected request')
            return result['body']
        raise ValueError('Controller unavailable; transaction remains held')
    finally:
        (Path(config['broker_dir']) / (identity + '.json')).unlink(missing_ok=True)


def load(config_path):
    if os.geteuid() != 0:
        raise ValueError('Executor requires root')
    config = json.loads(checked(config_path, limit=16384))
    fields = {'device_id', 'proposal_id', 'state_dir', 'broker_dir', 'responses_dir', 'approval_public_key_file', 'validator_binary', 'packages'}
    if set(config) != fields:
        raise ValueError('Unknown or missing configuration fields')
    if len(config['proposal_id']) != 32 or any(c not in '0123456789abcdef' for c in config['proposal_id']):
        raise ValueError('Invalid proposal identity')
    if not isinstance(config['packages'], list) or not config['packages'] or len(config['packages']) > 100 or any(not isinstance(p, str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', p) for p in config['packages']):
        raise ValueError('Explicit bounded package allowlist required')
    checked(config['state_dir'], directory=True)
    checked(config['broker_dir'], directory=True)
    checked(config['approval_public_key_file'], limit=16384)
    checked(config['validator_binary'], limit=64 * MAX)
    return config


def ensure_authenticated_sources(source_roots=None):
    source_roots = source_roots or [Path('/etc/apt/sources.list'), Path('/etc/apt/sources.list.d')]
    for root in source_roots:
        root = Path(root)
        paths = sorted(root.iterdir()) if root.is_dir() else [root]
        for path in paths:
            if not path.exists() or (path.suffix not in ('.list', '.sources') and path.name != 'sources.list'):
                continue
            text = '\n'.join(line.split('#', 1)[0] for line in checked(path).decode().splitlines()).lower()
            if re.search(r'(?:trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)\s*(?:=|:)\s*(?:yes|true|1)\b', text):
                raise ValueError('Repository authentication bypass is configured')
            if re.search(r'(?:check-valid-until|check-date)\s*(?:=|:)\s*(?:no|false|0)\b', text):
                raise ValueError('Repository freshness bypass is configured')


def select_changes(cache, packages):
    for name in packages:
        if name not in cache or cache[name].candidate is None or not cache[name].is_upgradable:
            raise ValueError('Selected package has no upgrade candidate')
        cache[name].mark_install(auto_fix=True, auto_inst=True, from_user=True)
    changes = cache.get_changes()
    if any(package.marked_delete for package in changes):
        raise ValueError('Dependency resolution proposes removals')
    return changes


def prepare(config):
    import apt
    ensure_authenticated_sources()
    command(['/usr/bin/apt-get', '-o', 'APT::Update::Error-Mode=any', '-o', 'APT::Sandbox::User=_apt', '-o', 'Acquire::Max-ValidTime=604800', '-o', 'Acquire::Check-Date=true', '-o', 'Acquire::AllowInsecureRepositories=false', '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false', '-o', 'APT::Get::AllowUnauthenticated=false', '-o', 'Acquire::Check-Valid-Until=true', '-o', 'Acquire::Check-Date=true', '-o', 'Acquire::AllowWeakRepositories=false', 'update'], timeout=600)
    now = int(time.time())
    valid_until = expiry(now)
    state_hash, repo_hash, held = package_hash(), repository_hash(), holds()
    cache = apt.Cache()
    if cache.broken_count:
        raise ValueError('Broken dependencies require reconciliation')
    changes = select_changes(cache, config['packages'])
    if not changes or len(changes) > 5000:
        raise ValueError('No bounded upgrade transaction available')
    total = sum(package.candidate.size for package in changes if package.candidate is not None)
    if total > 1024 * 1024 * 1024 or shutil.disk_usage(config['state_dir']).free < total * 3 + 512 * 1024 * 1024:
        raise ValueError('Archive budget or free disk headroom exceeded')
    archives = Path(config['state_dir']) / 'archives' 
    archives.mkdir(mode=0o700, exist_ok=False)
    manifest_changes = []
    for package in sorted(changes, key=lambda p: p.name):
        candidate = package.candidate
        if package.marked_delete or package.name in held or candidate is None:
            raise ValueError('Removal or held change is prohibited')
        if not candidate.origins or not all(origin.trusted for origin in candidate.origins):
            raise ValueError('Untrusted package origin')
        if package.installed is not None:
            import apt_pkg
            if apt_pkg.version_compare(package.installed.version, candidate.version) >= 0:
                raise ValueError('Downgrade or reinstall prohibited')
        expected = candidate.record.get('SHA256', '')
        if len(expected) != 64:
            raise ValueError('Authenticated archive SHA256 required')
        account = pwd.getpwnam('_apt')
        staging = checked('/var/cache/guarded-update', directory=True)
        stage = staging / secrets.token_hex(16)
        stage.mkdir(mode=0o700)
        os.chown(stage, account.pw_uid, account.pw_gid)
        command(['/usr/sbin/runuser', '-u', '_apt', '--', '/usr/bin/python3', '-I', str(Path(__file__).resolve()), 'download', '--directory', str(stage), '--package', package.name, '--version', candidate.version], timeout=600)
        candidates = list(stage.glob('*.deb'))
        if len(candidates) != 1:
            raise ValueError('Expected one acquired archive')
        fd = os.open(candidates[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError('Archive is not regular')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                archive = stream.read(512 * 1024 * 1024 + 1)
        finally:
            os.close(fd)
        if len(archive) > 512 * 1024 * 1024 or sha(archive) != expected:
            raise ValueError('Archive hash mismatch')
        write_new(archives / (expected + '.deb'), archive)
        candidates[0].unlink()
        stage.rmdir()
        manifest_changes.append({'package': package.name.split(':')[0], 'old': version(package.installed) if package.installed else None, 'new': version(candidate), 'archive_sha256': expected})
    if state_hash != package_hash() or repo_hash != repository_hash():
        raise ValueError('Local state changed during preparation')
    manifest = {'schema_version': 1, 'kind': 'apt-execution-manifest', 'device_id': config['device_id'], 'proposal_id': config['proposal_id'], 'generated_at_unix': now, 'metadata_checked_at_unix': now, 'metadata_valid_until_unix': valid_until, 'repository_identity_verified': True, 'package_state_sha256': state_hash, 'repository_state_sha256': repo_hash, 'held_packages': held, 'changes': manifest_changes}
    raw = encode(manifest)
    if len(raw) > MAX:
        raise ValueError('Manifest too large')
    write_new(Path(config['state_dir']) / 'manifest.json', raw)
    identity = request(config, 'manifest', {'schema_version': 1, 'proposal_id': config['proposal_id'], 'manifest_json': raw.decode()})
    response(config, identity)


def download(args):
    import apt
    if os.geteuid() != pwd.getpwnam('_apt').pw_uid:
        raise ValueError('Acquisition must run as _apt')
    cache = apt.Cache()
    candidate = next((v for v in cache[args.package].versions if v.version == args.version), None)
    if candidate is None or not candidate.origins or not all(origin.trusted for origin in candidate.origins):
        raise ValueError('Authenticated candidate unavailable')
    candidate.fetch_binary(args.directory, allow_unauthenticated=False)


def inspect_archive(path):
    data = checked(path, limit=512 * 1024 * 1024)
    fields = command(['/usr/bin/dpkg-deb', '--field', str(path), 'Package', 'Version', 'Architecture', 'Multi-Arch']).decode().splitlines()
    record = dict(line.split(': ', 1) for line in fields)
    return {'package': record['Package'], 'version': {'version': record['Version'], 'architecture': record['Architecture'], 'multi_arch': record.get('Multi-Arch', 'none')}, 'sha256': sha(data)}


def hook(config):
    if os.environ.get('APT_HOOK_INFO_FD') != '0' or os.environ.get('DPKG_FRONTEND_LOCKED') != 'true':
        raise ValueError('APT hook lock context missing')
    stream = sys.stdin.buffer.read(8 * MAX + 1)
    if len(stream) > 8 * MAX:
        raise ValueError('APT hook stream too large')
    raw = checked(Path(config['state_dir']) / 'manifest.json')
    manifest = json.loads(raw)
    nonce = secrets.token_hex(16)
    identity = request(config, 'claim', {'schema_version': 1, 'proposal_id': manifest['proposal_id'], 'manifest_sha256': sha(raw), 'claim_nonce': nonce})
    claim = response(config, identity)
    if claim.get('allow_service_restarts') is not True:
        raise ValueError('Explicit service-restart approval required')
    evidence = {'device_id': config['device_id'], 'now_unix': int(time.time()), 'package_state_sha256': package_hash(), 'repository_state_sha256': repository_hash(), 'held_packages': holds(), 'repository_identity_verified': True, 'metadata_checked_at_unix': manifest['metadata_checked_at_unix'], 'metadata_valid_until_unix': manifest['metadata_valid_until_unix'], 'package_state_clean': True}
    archive_map = {}
    for change in manifest['changes']:
        path = Path(config['state_dir']) / 'archives' / (change['archive_sha256'] + '.deb')
        archive_map[str(path)] = inspect_archive(path)
    value = {'manifest': raw.decode(), 'evidence': evidence, 'stream': stream.decode(), 'archives': archive_map, 'claim': claim, 'nonce': nonce, 'manifest_sha256': sha(raw)}
    validation = Path(config['state_dir']) / ('validation-' + nonce + '.json')
    write_new(validation, encode(value))
    journal = Path(config['state_dir']) / 'journal'
    journal.mkdir(mode=0o700, exist_ok=True)
    command([config['validator_binary'], 'validate-execution', '--input', str(validation), '--key', config['approval_public_key_file'], '--journal', str(journal)], timeout=30)
    write_new(Path(config['state_dir']) / 'execution-started.json', encode({'claim_id': claim['claim_id'], 'claim_nonce': nonce, 'started_at_unix': int(time.time())}))


def execute(config, config_path):
    state = Path(config['state_dir'])
    if (state / 'execution-started.json').exists() or (state / 'execution-attempted.json').exists():
        raise ValueError('Previous attempt requires reconciliation; automatic replay prohibited')
    raw = checked(state / 'manifest.json')
    manifest = json.loads(raw)
    archives = [str(state / 'archives' / (c['archive_sha256'] + '.deb')) for c in manifest['changes']]
    for path in archives:
        inspect_archive(path)
    write_new(state / 'execution-attempted.json', encode({'manifest_sha256': sha(raw), 'attempted_at_unix': int(time.time())}))
    helper = str(Path(__file__).resolve())
    for path in (helper, str(config_path)):
        if any(c not in '/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-' for c in path):
            raise ValueError('Unsupported hook path')
    hook_command = '/usr/bin/python3 -I ' + helper + ' hook --config ' + str(config_path)
    args = ['/usr/bin/apt-get', '--yes', '--no-remove', '-o', 'APT::Get::AllowUnauthenticated=false', '-o', 'DPkg::Pre-Install-Pkgs::=' + hook_command, '-o', 'DPkg::Tools::Options::/usr/bin/python3::Version=3', '-o', 'DPkg::Tools::Options::/usr/bin/python3::InfoFD=0', 'install'] + archives
    result = 'failed'
    try:
        command(args, timeout=None)
        result = 'succeeded'
    except subprocess.TimeoutExpired:
        result = 'interrupted'
        raise
    except BaseException:
        result = 'interrupted'
        raise
    finally:
        write_new(state / 'execution-result.json', encode({'status': result, 'finished_at_unix': int(time.time()), 'manifest_sha256': sha(raw)}))
        if (state / 'execution-started.json').exists():
            started = json.loads(checked(state / 'execution-started.json'))
            request(config, 'result', {'schema_version': 1, 'status': result, 'manifest_sha256': sha(raw)}, claim_id=started['claim_id'])


def cycle(config, config_path):
    state = Path(config['state_dir'])
    if (state / 'execution-attempted.json').exists():
        if (state / 'execution-result.json').exists() and (state / 'execution-started.json').exists():
            resend_result(config)
        # Terminal or uncertain attempts never start again automatically.
        return
    if not (state / 'manifest.json').exists():
        prepare(config)
    raw = checked(state / 'manifest.json')
    manifest = json.loads(raw)
    identity = request(config, 'status', {'schema_version': 1, 'proposal_id': manifest['proposal_id']})
    status = response(config, identity)
    if status.get('manifest_sha256') != sha(raw):
        raise ValueError('Controller status does not match prepared manifest')
    if status.get('status') == 'approved':
        # Status is merely a trigger. Only the fresh signed claim inside the
        # mandatory APT hook can authorize a package mutation.
        execute(config, config_path)


def reconcile(config):
    state = Path(config['state_dir'])
    active = subprocess.run(['/usr/bin/pgrep', '-x', 'dpkg'], env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if active.returncode != 1:
        raise ValueError('Dpkg remains active')
    observed_state = package_hash()
    raw = checked(state / 'manifest.json')
    digest = sha(raw)
    terminal_path = state / 'execution-result.json'
    if terminal_path.exists():
        terminal = json.loads(checked(terminal_path))
        if terminal.get('status') not in ('succeeded', 'failed', 'interrupted') or terminal.get('manifest_sha256') != digest:
            raise ValueError('Durable terminal result does not match manifest')
    else:
        # Matching installed versions cannot prove completion of maintainer scripts
        # or service health after a crash. Never upgrade uncertainty to success.
        terminal = {'status': 'interrupted', 'finished_at_unix': int(time.time()), 'manifest_sha256': digest}
        write_new(terminal_path, encode(terminal))
    identity = secrets.token_hex(16)
    write_new(state / ('reconciliation-' + identity + '.json'), encode({'status': terminal['status'], 'observed_package_state_sha256': observed_state, 'observed_at_unix': int(time.time())}))
    started = json.loads(checked(state / 'execution-started.json'))
    request(config, 'result', {'schema_version': 1, 'status': terminal['status'], 'manifest_sha256': digest}, claim_id=started['claim_id'])


def resend_result(config):
    state = Path(config['state_dir'])
    if (state / 'result-reported.json').exists():
        return
    result = json.loads(checked(state / 'execution-result.json'))
    started = json.loads(checked(state / 'execution-started.json'))
    identity = request(config, 'result', {'schema_version': 1, 'status': result['status'], 'manifest_sha256': result['manifest_sha256']}, claim_id=started['claim_id'])
    response(config, identity)
    write_new(state / 'result-reported.json', encode({'claim_id': started['claim_id'], 'reported_at_unix': int(time.time())}))


def executor_lock():
    path = Path('/run/guarded-update-executor.lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        os.close(fd)
        raise ValueError('Unsafe executor lock')
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('prepare', 'hook', 'execute', 'download', 'reconcile', 'report-result', 'cycle'))
    parser.add_argument('--config', type=Path)
    parser.add_argument('--directory')
    parser.add_argument('--package')
    parser.add_argument('--version')
    args = parser.parse_args()
    if args.operation == 'download':
        download(args)
        return
    if args.config is None:
        raise ValueError('Explicit executor config required')
    config = load(args.config)
    lock = None if args.operation == 'hook' else executor_lock()
    try:
        {'cycle': lambda: cycle(config, args.config), 'prepare': lambda: prepare(config), 'hook': lambda: hook(config), 'execute': lambda: execute(config, args.config), 'reconcile': lambda: reconcile(config), 'report-result': lambda: resend_result(config)}[args.operation]()
    finally:
        if lock is not None:
            os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        sys.stderr.write('guarded-update executor held: ' + type(error).__name__ + '\n')
        raise SystemExit(1)
