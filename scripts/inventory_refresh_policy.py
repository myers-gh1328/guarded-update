"""Pure trusted APT policy admission/rendering; no I/O, commands or activation.

Only the privileged coordinator may admit/materialize these secret-bearing bytes.
Its fixed APT_CONFIG must be loaded before APT's host parts/main configuration.
Native TLS/GPG verification and descriptor/ownership admission are separate gates.
"""
from collections.abc import Mapping
from dataclasses import dataclass
import base64
import binascii
import ipaddress
import json
import re
from urllib.parse import unquote, urlsplit

from inventory_refresh_protocol import policy_commitment

POLICY_ROOT = '/etc/command-center-inventory-refresh'
CACHE_ROOT = '/var/cache/command-center-inventory-refresh'
RUNTIME_ROOT = '/run/command-center-inventory-refresh'
STATE_ROOT = '/var/lib/command-center-inventory-refresh'
APT_CONFIG_PATH = RUNTIME_ROOT + '/worker-apt.conf'
REFRESH_ACCOUNT = 'ccrefresh'
MAX_POLICY = 8 * 1024 * 1024
MAX_TRUST = 4 * 1024 * 1024
_APT_ROOT = POLICY_ROOT + '/apt'


class PolicyError(ValueError):
    """Static public error; never append input values or native diagnostics."""

    def __init__(self):
        super().__init__('Unsupported trusted APT policy')


def _require(condition):
    if not condition:
        raise PolicyError()


def _object(value, fields):
    _require(type(value) is dict and set(value) == set(fields))


def _array(value, minimum, maximum):
    _require(type(value) is list and minimum <= len(value) <= maximum)


def _text(value, pattern, maximum=256):
    _require(type(value) is str and 0 < len(value) <= maximum and re.fullmatch(pattern, value, re.ASCII) is not None)
    return value


def _unique_strings(value, pattern, minimum=1, maximum=32, length=128):
    _array(value, minimum, maximum)
    _require(all(type(item) is str for item in value) and len(set(value)) == len(value))
    for item in value:
        _text(item, pattern, length)
    return value


def _decode(value, maximum):
    _require(type(value) is str and len(value) <= ((maximum + 2)//3)*4)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise PolicyError() from None
    _require(0 < len(decoded) <= maximum)
    return decoded


def _public_packets(raw):
    """Reject secret/compressed/indeterminate packets; native GPG checks crypto."""
    position, tags = 0, []
    while position < len(raw):
        header = raw[position]
        position += 1
        _require(header & 0x80)
        if header & 0x40:
            tag = header & 0x3f
            _require(position < len(raw))
            first = raw[position]
            position += 1
            if first < 192:
                size = first
            elif first < 224:
                _require(position < len(raw))
                size = ((first - 192) << 8) + raw[position] + 192
                position += 1
            elif first == 255:
                _require(position + 4 <= len(raw))
                size = int.from_bytes(raw[position:position+4], 'big')
                position += 4
            else:
                raise PolicyError()
        else:
            tag, kind = (header >> 2) & 15, header & 3
            _require(kind != 3)
            width = (1, 2, 4)[kind]
            _require(position + width <= len(raw))
            size = int.from_bytes(raw[position:position+width], 'big')
            position += width
        _require(tag in (2, 6, 13, 14, 17) and size > 0 and position + size <= len(raw))
        if tag in (6, 14):
            _require(size >= 6 and raw[position] in (4, 5, 6))
        tags.append(tag)
        position += size
    _require(tags and tags[0] == 6)


def _trust_key(entry):
    _object(entry, ('id', 'format', 'content_base64'))
    identity = _text(entry['id'], r'[a-z0-9][a-z0-9-]{0,63}', 64)
    _require(entry['format'] in ('gpg', 'asc'))
    raw = _decode(entry['content_base64'], MAX_TRUST)
    packets = raw
    if entry['format'] == 'asc':
        try:
            text = raw.decode('ascii')
        except UnicodeError:
            raise PolicyError() from None
        match = re.fullmatch(r'-----BEGIN PGP PUBLIC KEY BLOCK-----\r?\n(?:[A-Za-z][A-Za-z-]*: [ -~]*\r?\n)*\r?\n([A-Za-z0-9+/=\r\n]+?)(?:=[A-Za-z0-9+/]{4}\r?\n)?-----END PGP PUBLIC KEY BLOCK-----\r?\n?', text)
        _require(match is not None)
        try:
            packets = base64.b64decode(''.join(match[1].splitlines()), validate=True)
        except (ValueError, binascii.Error):
            raise PolicyError() from None
    _public_packets(packets)
    return identity, 'trust/' + identity + '.' + entry['format'], raw


def _der_item(raw, start):
    _require(start + 2 <= len(raw))
    tag, length = raw[start], raw[start+1]
    position = start + 2
    if length & 0x80:
        width = length & 0x7f
        _require(1 <= width <= 4 and position + width <= len(raw) and raw[position] != 0)
        length = int.from_bytes(raw[position:position+width], 'big')
        _require(length >= 128)
        position += width
    end = position + length
    _require(end <= len(raw))
    return tag, position, end


def _certificate_structure(raw):
    # Certificate ::= SEQUENCE { tbsCertificate SEQUENCE,
    # signatureAlgorithm SEQUENCE, signatureValue BIT STRING }. Private PKCS#8,
    # RSA and EC keys start with a version INTEGER and cannot pass this gate.
    tag, begin, end = _der_item(raw, 0)
    _require(tag == 0x30 and end == len(raw))
    first, _, next_item = _der_item(raw, begin)
    second, _, last_item = _der_item(raw, next_item)
    third, signature, finish = _der_item(raw, last_item)
    _require(first == second == 0x30 and third == 0x03 and finish == end and signature < finish and raw[signature] <= 7)


def _ca_bundle(raw):
    try:
        text = raw.decode('ascii')
    except UnicodeError:
        raise PolicyError() from None
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+?)-----END CERTIFICATE-----', text)
    _require(0 < len(blocks) <= 4096)
    remainder = re.sub(r'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+?-----END CERTIFICATE-----', '', text)
    _require(not remainder.strip())
    for block in blocks:
        try:
            der = base64.b64decode(''.join(block.splitlines()), validate=True)
        except (ValueError, binascii.Error):
            raise PolicyError() from None
        _certificate_structure(der)


def _uri(value, proxy=False):
    _text(value, r'[^\s"\\<>]+', 2048)
    _require(value.isascii())
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        raise PolicyError() from None
    _require(parsed.scheme in ('http', 'https') and value.startswith(parsed.scheme+'://') and host and '%' not in host and '@' not in parsed.netloc and not parsed.query and not parsed.fragment)
    _require(port is None or 1 <= port <= 65535)
    if ':' in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise PolicyError() from None
    else:
        _require(len(host) <= 253 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in host.split('.')))
    path = unquote(parsed.path)
    _require(all(ord(character) >= 33 and ord(character) != 127 for character in path) and '\\' not in path)
    _require('..' not in path.split('/') and (not proxy or path in ('', '/')))
    return parsed


def _frame(items):
    result = bytearray()
    for name, raw in items:
        encoded = name.encode('ascii')
        result.extend(len(encoded).to_bytes(8, 'big'))
        result.extend(encoded)
        result.extend(len(raw).to_bytes(8, 'big'))
        result.extend(raw)
    return bytes(result)


# These choices are committed along with all rendered policy bytes. The only
# variable is a coordinator-generated generation token, never caller configuration.
_CONFIG_TEMPLATE = '''#clear APT;
#clear Acquire;
#clear DPkg;
#clear Binary;
#clear Dir;
Dir "/";
Dir::Etc "@POLICY@";
Dir::Etc::parts "@POLICY@/empty.d";
Dir::Etc::main "@POLICY@/empty-main.conf";
Dir::Etc::sourcelist "@POLICY@/sources.sources";
Dir::Etc::sourceparts "@POLICY@/empty.d";
Dir::Etc::trusted "@POLICY@/empty-trusted.gpg";
Dir::Etc::trustedparts "@POLICY@/empty.d";
Dir::Etc::preferences "@POLICY@/preferences";
Dir::Etc::preferencesparts "@POLICY@/empty.d";
Dir::Etc::netrc "@POLICY@/auth.conf";
Dir::Etc::netrcparts "@POLICY@/empty.d";
Dir::State "@STAGING@";
Dir::State::lists "@STAGING@/lists";
Dir::State::status "@POLICY@/empty-status";
Dir::State::extended_states "@STAGING@/extended_states";
Dir::Cache "@STAGING@/cache";
Dir::Cache::archives "@STAGING@/archives";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Dir::Log "@STAGING@/log";
Dir::Bin::methods "/usr/lib/apt/methods";
APT::Sandbox::User "ccrefresh";
APT::Update::Error-Mode "any";
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::AllowWeakRepositories "false";
Acquire::Check-Date "true";
Acquire::Check-Valid-Until "true";
Acquire::Max-ValidTime "604800";
Acquire::http::AllowRedirect "false";
Acquire::https::AllowRedirect "false";
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";
Acquire::https::CaInfo "@POLICY@/ca-certificates.crt";
Acquire::IndexTargets::deb::Packages::MetaKey "$(COMPONENT)/binary-$(ARCHITECTURE)/Packages";
Acquire::IndexTargets::deb::Packages::flatMetaKey "Packages";
Acquire::IndexTargets::deb::Packages::ShortDescription "Packages";
Acquire::IndexTargets::deb::Packages::Description "$(RELEASE)/$(COMPONENT) $(ARCHITECTURE) Packages";
Acquire::IndexTargets::deb::Packages::flatDescription "$(RELEASE) Packages";
Acquire::IndexTargets::deb::Packages::Optional "false";
Acquire::IndexTargets::deb::Packages::KeepCompressed "true";
Acquire::Languages "none";
Acquire::Retries "0";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
'''.replace('@POLICY@', _APT_ROOT)


# Loaded through APT_CONFIG before any host main/parts. No acquisition operation
# is exposed by the fixed reader; its only command is apt-cache policy.
_READER_DIRECTORY = '_inventory-reader'
_READER_CONFIG_TEMPLATE = """// Command Center inventory reader policy v1
#clear APT;
#clear Acquire;
#clear DPkg;
#clear Binary;
#clear Dir;
Dir "/";
Dir::Etc "@READER@";
Dir::Etc::parts "@READER@/empty.d";
Dir::Etc::main "@READER@/empty-main.conf";
Dir::Etc::sourcelist "@READER@/sources.sources";
Dir::Etc::sourceparts "@READER@/empty.d";
Dir::Etc::trusted "@READER@/empty-trusted.gpg";
Dir::Etc::trustedparts "@READER@/empty.d";
Dir::Etc::preferences "@READER@/preferences";
Dir::Etc::preferencesparts "@READER@/empty.d";
Dir::Etc::netrc "@READER@/empty-auth.conf";
Dir::Etc::netrcparts "@READER@/empty.d";
Dir::State "@ROOT@";
Dir::State::lists "@ROOT@";
Dir::State::status "/var/lib/dpkg/status";
Dir::State::extended_states "/dev/null";
Dir::Cache "/dev/null";
Dir::Cache::archives "/dev/null";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Dir::Log "/dev/null";
Acquire::IndexTargets::deb::Packages::MetaKey "$(COMPONENT)/binary-$(ARCHITECTURE)/Packages";
Acquire::IndexTargets::deb::Packages::flatMetaKey "Packages";
Acquire::IndexTargets::deb::Packages::ShortDescription "Packages";
Acquire::IndexTargets::deb::Packages::Description "$(RELEASE)/$(COMPONENT) $(ARCHITECTURE) Packages";
Acquire::IndexTargets::deb::Packages::flatDescription "$(RELEASE) Packages";
Acquire::IndexTargets::deb::Packages::Optional "false";
Acquire::IndexTargets::deb::Packages::KeepCompressed "true";
Acquire::Languages "none";
"""


@dataclass(frozen=True, repr=False)
class TrustedAptPolicy:
    _files: tuple
    _architectures: bytes
    _proxy: bytes
    _sections: tuple
    _template: bytes
    _reader_template: bytes

    def __repr__(self):
        return '<TrustedAptPolicy schema=1 private-material-redacted>'


class RenderedAptPolicy(Mapping):
    """Secret-bearing material intended only for privileged FD materialization."""

    __slots__ = ('_files',)

    def __init__(self, files):
        self._files = tuple(files)

    def __getitem__(self, key):
        for name, raw in self._files:
            if key == name:
                return raw
        raise KeyError('Unknown trusted policy artifact')

    def __iter__(self):
        return (name for name, _ in self._files)

    def __len__(self):
        return len(self._files)

    def __repr__(self):
        return '<RenderedAptPolicy private-material-redacted>'


def parse_policy(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_POLICY)
    def pairs(items):
        result = {}
        for name, value in items:
            _require(name not in result)
            result[name] = value
        return result
    def constant(_):
        raise PolicyError()
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise PolicyError() from None
    _object(value, ('schema_version', 'sources', 'trust', 'pins', 'architectures', 'proxy', 'auth'))
    _require(type(value['schema_version']) is int and value['schema_version'] == 1)
    architectures = _unique_strings(value['architectures'], r'[a-z0-9][a-z0-9-]{0,63}', maximum=16, length=64)
    _require('all' not in architectures)
    arch_config = ('APT::Architecture "' + architectures[0] + '";\nAPT::Architectures { ' + ' '.join('"'+arch+'";' for arch in architectures) + ' };\n').encode()
    _object(value['trust'], ('keys', 'tls_ca_base64'))
    _array(value['trust']['keys'], 1, 64)
    trust, trust_files = {}, []
    for entry in value['trust']['keys']:
        identity, filename, data = _trust_key(entry)
        _require(identity not in trust)
        trust[identity] = filename
        trust_files.append((filename, data))
    ca = _decode(value['trust']['tls_ca_base64'], MAX_TRUST)
    _ca_bundle(ca)
    trust_files.append(('ca-certificates.crt', ca))
    _require(sum(len(data) for _, data in trust_files) <= MAX_TRUST)
    _array(value['sources'], 1, 128)
    sources, ids, endpoints = [], set(), []
    for source in value['sources']:
        _object(source, ('id', 'type', 'uri', 'suites', 'components', 'architectures', 'signed_by'))
        identity = _text(source['id'], r'[a-z0-9][a-z0-9-]{0,63}', 64)
        _require(identity not in ids and source['type'] == 'deb')
        ids.add(identity)
        endpoints.append(_uri(source['uri']))
        suites = _unique_strings(source['suites'], r'[A-Za-z0-9][A-Za-z0-9.+_/-]{0,127}|\./', length=128)
        _require(all('..' not in suite.split('/') for suite in suites))
        flat = any(suite.endswith('/') for suite in suites)
        components = _unique_strings(source['components'], r'[a-z0-9][a-z0-9+.-]{0,63}', minimum=0 if flat else 1, length=64)
        _require(not flat or not components)
        arches = _unique_strings(source['architectures'], r'[a-z0-9][a-z0-9-]{0,63}', maximum=16, length=64)
        _require(set(arches).issubset(architectures))
        signed = _unique_strings(source['signed_by'], r'[a-z0-9][a-z0-9-]{0,63}', maximum=64, length=64)
        _require(set(signed).issubset(trust))
        sources.append('\n'.join(('Types: deb', 'URIs: '+source['uri'], 'Suites: '+' '.join(suites),
                                  'Components: '+' '.join(components), 'Architectures: '+' '.join(arches),
                                  'Signed-By: '+' '.join(_APT_ROOT+'/'+trust[name] for name in signed),
                                  'Allow-Insecure: no', 'Allow-Weak: no', 'Allow-Downgrade-To-Insecure: no',
                                  'Check-Valid-Until: yes', 'Check-Date: yes'))+'\n\n')
    source_bytes = ''.join(sources).encode()
    _array(value['pins'], 0, 512)
    pins = []
    for pin in value['pins']:
        _object(pin, ('package', 'match', 'priority'))
        package = _text(pin['package'], r'[a-z0-9*?][a-z0-9+.*?_-]*(?::[a-z0-9][a-z0-9-]*)?', 256)
        _require(type(pin['priority']) is int and -32768 <= pin['priority'] <= 32767 and pin['priority'] != 0)
        _require(type(pin['match']) is dict and len(pin['match']) == 1)
        kind, match = next(iter(pin['match'].items()))
        if kind == 'release':
            _require(type(match) is dict and 1 <= len(match) <= 7 and set(match).issubset({'a', 'n', 'o', 'l', 'c', 'v', 'b'}))
            rendered = 'release '+','.join(name+'='+_text(match[name], r'[A-Za-z0-9*?][A-Za-z0-9*? ._+~/-]*', 128) for name in sorted(match))
        elif kind == 'version':
            rendered = 'version '+_text(match, r'[A-Za-z0-9*?][A-Za-z0-9.*?+~:_-]*', 256)
        elif kind == 'origin':
            rendered = 'origin "'+_text(match, r'[A-Za-z0-9][A-Za-z0-9.-]*', 253)+'"'
        else:
            raise PolicyError()
        pins.append('Package: '+package+'\nPin: '+rendered+'\nPin-Priority: '+str(pin['priority'])+'\n\n')
    pin_bytes = ''.join(pins).encode()
    _object(value['proxy'], ('http', 'https'))
    proxy = []
    for scheme in ('http', 'https'):
        target = value['proxy'][scheme]
        if target != 'DIRECT':
            endpoints.append(_uri(target, proxy=True))
        proxy.append('Acquire::'+scheme+'::Proxy "'+target+'";\n')
    proxy_bytes = ''.join(proxy).encode()
    _array(value['auth'], 0, 256)
    auth, machines = [], set()
    for entry in value['auth']:
        _object(entry, ('machine', 'login', 'password'))
        machine = _uri(entry['machine'])
        _require(machine.scheme == 'https')
        identity = (machine.scheme, machine.hostname, machine.port, machine.path)
        _require(identity not in machines)
        machines.add(identity)
        _require(any(endpoint.scheme == machine.scheme and endpoint.hostname == machine.hostname and endpoint.port == machine.port and endpoint.path.startswith(machine.path) for endpoint in endpoints))
        login = _text(entry['login'], r'[!-~]+', 1024)
        password = _text(entry['password'], r'[!-~]+', 1024)
        _require(not any(character in login+password for character in '\\"#'))
        auth.append('machine '+entry['machine']+' login '+login+' password '+password+'\n')
    auth_bytes = ''.join(auth).encode()
    files = [('sources.sources', source_bytes), ('preferences', pin_bytes), ('auth.conf', auth_bytes),
             ('proxy.conf', proxy_bytes), ('empty-main.conf', b''), ('empty-trusted.gpg', b''), ('empty-status', b'')] + sorted(trust_files)
    template = _CONFIG_TEMPLATE.replace('@STAGING@', CACHE_ROOT+'/staging-@TOKEN@').encode()
    schema = _frame((('version', b'2'), ('apt_config_path', APT_CONFIG_PATH.encode()),
                     ('policy_root', POLICY_ROOT.encode()), ('cache_root', CACHE_ROOT.encode()),
                     ('runtime_root', RUNTIME_ROOT.encode()), ('state_root', STATE_ROOT.encode()),
                     ('refresh_account', REFRESH_ACCOUNT.encode()), ('config_template', template),
                     ('reader_template', _READER_CONFIG_TEMPLATE.encode()),('reader_directory',_READER_DIRECTORY.encode())))
    sections = (('schema', schema), ('sources', source_bytes),
                ('trust', _frame(sorted(trust_files))), ('pins', pin_bytes),
                ('architectures', arch_config), ('proxy', proxy_bytes), ('auth', auth_bytes))
    _require(all(len(data) <= MAX_TRUST for _, data in sections) and sum(len(data) for _, data in sections) <= MAX_POLICY)
    return TrustedAptPolicy(tuple(files), arch_config, proxy_bytes, sections, template, _READER_CONFIG_TEMPLATE.encode())


def render_policy(policy, staging_token):
    _require(type(policy) is TrustedAptPolicy and type(staging_token) is str and re.fullmatch(r'[a-f0-9]{32}', staging_token) is not None)
    config = policy._template.replace(b'@TOKEN@', staging_token.encode()) + policy._architectures + policy._proxy
    return RenderedAptPolicy((('apt.conf', config),) + policy._files)


def policy_generation(key, policy):
    _require(type(policy) is TrustedAptPolicy and type(key) is bytes and len(key) == 32)
    try:
        return policy_commitment(key, dict(policy._sections))
    except ValueError:
        raise PolicyError() from None


def render_reader_policy(policy,generation,commitment):
    """Noncredential immutable projection; root PolicyGuard supplies commitment."""
    from inventory_refresh_storage import ReaderProjection,READER_DIRECTORY
    _require(type(policy) is TrustedAptPolicy and type(generation) is str and
             re.fullmatch('[0-9a-f]{32}',generation) is not None and type(commitment) is str and
             re.fullmatch('[0-9a-f]{64}',commitment) is not None)
    _require(READER_DIRECTORY==_READER_DIRECTORY)
    root=CACHE_ROOT+'/generation-'+generation;reader=root+'/'+_READER_DIRECTORY
    config=policy._reader_template.replace(b'@ROOT@',root.encode()).replace(b'@READER@',reader.encode())+policy._architectures
    selected=dict(policy._files)
    return ReaderProjection._from_policy(generation,commitment,(
        ('apt.conf',config),('sources.sources',selected['sources.sources']),('preferences',selected['preferences']),
        ('empty-main.conf',b''),('empty-trusted.gpg',b''),('empty-auth.conf',b'')))
