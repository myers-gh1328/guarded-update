#!/usr/bin/python3
"""Actual APT upgrades confined to isolated roots on disposable GitHub Linux."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import uuid


def run(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout


def write(path, data):
    path.write_text(json.dumps(data, separators=(',', ':')))
    path.chmod(0o600)


def hook(config_path):
    config = json.loads(Path(config_path).read_text())
    base = Path(config['base'])
    now, nonce = int(time.time()), secrets.token_hex(16)
    archive = Path(config['archive'])
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    old = dict(version='1', architecture='all', multi_arch='none')
    new = dict(old, version='2')
    manifest = dict(schema_version=1, kind='apt-execution-manifest', device_id='synthetic-fixture', proposal_id='a'*32, generated_at_unix=now, metadata_checked_at_unix=now, metadata_valid_until_unix=now+3600, repository_identity_verified=True, package_state_sha256='b'*64, repository_state_sha256='c'*64, held_packages=[], changes=[dict(package='guarded-update-upgrade-fixture', old=old, new=new, archive_sha256=digest)])
    raw = json.dumps(manifest, separators=(',', ':'))
    manifest_hash = hashlib.sha256(raw.encode()).hexdigest()
    claim = dict(schema_version=1, claim_id=str(uuid.uuid4()), device_id=manifest['device_id'], proposal_id=manifest['proposal_id'], manifest_sha256=manifest_hash, claim_nonce=nonce, issued_at_unix=now, expires_at_unix=now+120, allow_service_restarts=True, execution_allowed=True, allow_reboot=False)
    case = config['case']
    if case == 'expired':
        claim.update(issued_at_unix=now-121, expires_at_unix=now-1)
    if case == 'mismatch':
        claim['manifest_sha256'] = '0'*64
    if case == 'no-ack':
        claim['allow_service_restarts'] = False
    message = '\n'.join(str(x).lower() if isinstance(x, bool) else str(x) for x in ['guarded-update-execution-claim-v1', claim['claim_id'], claim['device_id'], claim['proposal_id'], claim['manifest_sha256'], nonce, claim['issued_at_unix'], claim['expires_at_unix'], claim['allow_service_restarts'], True, False])
    signature = run(['/usr/bin/openssl', 'dgst', '-sha256', '-sign', str(base/'private.pem')], input=message.encode())
    claim['signature'] = signature.hex() if case != 'invalid-signature' else 'ab'*70
    evidence = dict(device_id=manifest['device_id'], now_unix=now, package_state_sha256='b'*64, repository_state_sha256='c'*64, held_packages=[], repository_identity_verified=True, metadata_checked_at_unix=now, metadata_valid_until_unix=now+3600, package_state_clean=True)
    if case == 'drift':
        evidence['package_state_sha256'] = 'e'*64
    if case == 'stale':
        evidence['metadata_valid_until_unix'] = now-1
    if case == 'held':
        evidence['held_packages'] = ['guarded-update-upgrade-fixture']
    archive_evidence = dict(package='guarded-update-upgrade-fixture', version=new, sha256=digest)
    if case == 'archive':
        archive_evidence['sha256'] = '0'*64
    data = dict(manifest=raw, evidence=evidence, stream=sys.stdin.read(), archives={str(archive): archive_evidence}, claim=claim, nonce=nonce, manifest_sha256=manifest_hash)
    validation = base/'validation.json'
    write(validation, data)
    args = [config['binary'], 'validate-execution', '--input', str(validation), '--key', str(base/'public.pem'), '--journal', str(base/'journal')]
    if case == 'replay':
        run(args)
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        sys.stderr.write(result.stdout.decode(errors='replace'))
    return result.returncode


def main(binary):
    required = {'GUARDED_UPDATE_DISPOSABLE_TEST': '1', 'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'}
    if sys.platform != 'linux' or os.geteuid() != 0 or any(os.environ.get(k) != v for k, v in required.items()):
        raise SystemExit('Requires opted-in root on disposable GitHub-hosted Linux')
    parent = Path('/var/lib/guarded-update-ci')
    parent.mkdir(mode=0o700, exist_ok=True)
    base = parent/secrets.token_hex(16)
    base.mkdir(mode=0o700)
    binary_copy, script_copy = base/'guarded-update', base/'integration.py'
    shutil.copyfile(Path(binary).resolve(), binary_copy)
    binary_copy.chmod(0o755)
    shutil.copyfile(Path(__file__).resolve(), script_copy)
    script_copy.chmod(0o755)
    host_status = Path('/var/lib/dpkg/status')
    system_hash = hashlib.sha256(host_status.read_bytes()).digest()
    archives = []
    for version in ('1', '2'):
        package = base/('package'+version)
        (package/'DEBIAN').mkdir(parents=True)
        (package/'DEBIAN/control').write_text(f'Package: guarded-update-upgrade-fixture\nVersion: {version}\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Synthetic isolated upgrade\n')
        payload = package/'usr/share/guarded-update-upgrade-fixture'
        payload.mkdir(parents=True)
        (payload/'marker').write_text(version)
        archive = base/('fixture'+version+'.deb')
        run(['/usr/bin/dpkg-deb', '--build', '--root-owner-group', str(package), str(archive)])
        archives.append(archive)
    for case in ('expired', 'mismatch', 'no-ack', 'invalid-signature', 'drift', 'stale', 'held', 'archive', 'replay', 'approved'):
        directory = base/case
        directory.mkdir(mode=0o700)
        for name in ('root', 'dpkg', 'state/lists/partial', 'cache/archives/partial', 'etc/parts', 'etc/sources', 'journal'):
            (directory/name).mkdir(parents=True, mode=0o700)
        (directory/'dpkg/status').touch()
        for name in ('sources.list', 'main.conf'):
            (directory/'etc'/name).touch()
        run(['/usr/bin/dpkg', '--root='+str(directory/'root'), '--admindir='+str(directory/'dpkg'), '--install', str(archives[0])])
        private = directory/'private.pem'
        private.write_bytes(run(['/usr/bin/openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout']))
        private.chmod(0o600)
        (directory/'public.pem').write_bytes(run(['/usr/bin/openssl', 'pkey', '-in', str(private), '-pubout']))
        config = directory/'hook.json'
        write(config, dict(base=str(directory), archive=str(archives[1]), case=case, binary=str(binary_copy)))
        hook_script = directory/'hook'
        hook_script.write_text(f'#!/bin/sh\nset -eu\n[ "${{APT_HOOK_INFO_FD:-}}" = 0 ]\n[ "${{DPKG_FRONTEND_LOCKED:-}}" = true ]\nexec /usr/bin/python3 -I {script_copy} --hook {config}\n')
        hook_script.chmod(0o700)
        apt_config = directory/'apt.conf'
        apt_config.write_text(f'''Dir::State "{directory}/state";
Dir::State::status "{directory}/dpkg/status";
Dir::Cache "{directory}/cache";
Dir::Log "{directory}/log";
Dir::Etc::main "{directory}/etc/main.conf";
Dir::Etc::parts "{directory}/etc/parts";
Dir::Etc::sourcelist "{directory}/etc/sources.list";
Dir::Etc::sourceparts "{directory}/etc/sources";
APT::Sandbox::User "root";
DPkg::Options {{ "--root={directory}/root"; "--admindir={directory}/dpkg"; }};
DPkg::Pre-Install-Pkgs {{ "{hook_script}"; }};
DPkg::Tools::Options::{hook_script}::Version "3";
DPkg::Tools::Options::{hook_script}::InfoFD "0";
''')
        env = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C', APT_CONFIG=str(apt_config), DEBIAN_FRONTEND='noninteractive')
        result = subprocess.run(['/usr/bin/apt-get', '--yes', 'install', str(archives[1])], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        marker = directory/'root/usr/share/guarded-update-upgrade-fixture/marker'
        expected = '2' if case == 'approved' else '1'
        if (result.returncode == 0) != (case == 'approved') or marker.read_text() != expected:
            raise AssertionError(f'{case}: unexpected upgrade outcome: {result.stdout.decode()} {result.stderr.decode()}')
        if hashlib.sha256(host_status.read_bytes()).digest() != system_hash or Path('/usr/share/guarded-update-upgrade-fixture/marker').exists():
            raise AssertionError('Fixture escaped isolated root')
        print(f'{case}: payload version {expected}, host dpkg state unchanged', flush=True)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--hook':
        sys.exit(hook(sys.argv[2]))
    if len(sys.argv) != 2:
        raise SystemExit('Usage: test-execution-upgrade.py /absolute/executor-binary')
    main(sys.argv[1])
