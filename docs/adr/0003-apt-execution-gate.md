# ADR-0003: Dormant APT execution transaction gate

Status: accepted for pure validation only. No package execution, root service,
provisioning, key generation, or live APT command is implemented by this slice.

## Build boundary

The optional `apt-executor` Cargo feature implies `apt-remote`. Only that artifact
compiles `execution_gate`; default, local reporting, and remote reporting artifacts
exclude it. It adds no crates, CLI commands, root path, or external tools. Existing
personal updater behavior is unchanged. Module-wide dead-code allowance is
intentional while this gate has no production caller.

## Contract

`ExecutionManifest` is a strict versioned JSON object, separately named from the
reporting proposal. Its bounded decoder rejects unknown fields, including command
or path payloads. It identifies one device and proposal and contains the complete
approved dependency transaction. Each change contains bare package name, optional
old version/architecture/Multi-Arch tuple, exact new tuple, and archive SHA-256.
The manifest also binds package-state and authenticated repository-state hashes,
held packages, creation time, metadata verification time, and validity deadline.
A repository-state hash must eventually cover repository identity, signing-key
identity, authenticated Release/index hashes and package mappings, source/pinning
configuration and target architecture. A timestamp alone cannot prove freshness.

`LocalEvidence` is independently collected trusted evidence, not copied from a
server request. Package state must be clean; device, package-state hash,
repository-state hash, verified provenance and freshness must match. Evidence is
limited to one hour and must not be expired or from the future. Initial scope
rejects downgrades, reinstallations, removals, architecture transitions, and held
package changes. Every dependency must appear explicitly; extra or missing actions
fail closed. The full transaction must contain exactly one unpack and one
configure record per approved package/architecture. More complex valid APT streams
are conservatively unsupported until demonstrated by integration evidence.

## APT protocol

Primary references:

- [APT apt.conf documentation](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html)
- [APT 2.6.1 SendPkgsInfo source](https://github.com/Debian/apt/blob/2.6.1/apt-pkg/deb/dpkgpm.cc#L274-L374)

Version 3 has nine space-separated fields: package, old version, old architecture,
old Multi-Arch, comparison direction, new version, new architecture, new Multi-Arch,
action. Missing version and architecture use `-`; absent version Multi-Arch is
`none`. `no` and `none` normalize equivalently. The header must be exactly
`VERSION 3`; an opaque key=value configuration section ends at a blank line.
Configuration is never executed or applied. Supported actions are absolute .deb
references and configuration records; removal records parse but cannot validate.
Unknown actions, duplicate action phases, absent final newline, unsupported
protocol versions and oversized/malformed streams fail closed.

An injected `ArchiveInspector` must verify archive package metadata and SHA-256
from a trusted pinned handle; the stream filename is untrusted. It must implement
Debian version ordering, including epochs, revisions and tilde, independently of
the hook comparison symbol. There is deliberately no production adapter yet.
No archive, key, file or command is read or executed by this module.

## What validation does not authorize

`ValidatedTransaction` is private-state evidence, not a claim or apply permit.
The reporting protocol's `execution_allowed:false` approval cannot authorize it.
Before dispatch exists, a separate controller-signed single-use claim must bind
this manifest, device, approval, fresh executor nonce and short expiration. The
controller atomically claims or revokes; claim acceptance defines execution start.
Root must journal consumption durably. Interrupted operations require explicit
reconciliation, never automatic replay or a blind repair command.

A future production gate must run as a mandatory APT protocol-v3 pre-install hook
while APT owns package locks, retain immutable trusted archives through dpkg use,
verify hook/lock context and complete action coverage, clear inherited environment,
and enforce root-owned descriptor-safe configuration/state paths. A separate
simulation followed by an unlocked install is insufficient. Root networking is
excluded; an unprivileged poller transports bounded claim requests/responses.

## Verification and next slice

Tests use only synthetic manifests, fake archive inspection, and hook strings.
They cover protocol downgrade/truncation, bounds, dependency completeness,
duplicates, removals, downgrade/reinstall, holds, stale/unverified repositories,
local drift and archive substitution. Failing tests were run before implementation.

Next: implement the independent archive/repository evidence adapter and validate
real protocol-v3 streams in disposable Linux, then signed single-use claims and
crash reconciliation. No business endpoint deployment or package change is
permitted by this ADR or this slice.

## Disposable Linux integration harness

`scripts/test-apt-hook.sh` is restricted to an explicitly opted-in, root,
GitHub-hosted Linux runner. It creates one synthetic local archive with no
dependencies or maintainer scripts. APT uses empty isolated package state,
cache, configuration and sources. Only the locally supplied archive is available
for acquisition; `--no-download` cannot be used because APT then emits an unset
archive error for this volatile local package. Dpkg
options additionally redirect the root and administrative directory into scratch.
The mandatory version-3 hook checks its protocol descriptor and APT's frontend
lock indicator, captures the actual stream, and exits unsuccessfully. The harness
requires failure and unchanged isolated and host dpkg status hashes plus absent
fixture payloads in both roots. It never exports host status contents.

The harness requires a new `GUARDED_UPDATE_HOOK_OUTPUT` child of `RUNNER_TEMP`.
It exports only `fixture.deb` and `hook-stream`, readable by the ordinary runner.
No Rust tool runs as root. A separate unprivileged step sets:

```sh
GUARDED_UPDATE_DISPOSABLE_TEST=1 \
GUARDED_UPDATE_HOOK_STREAM_FILE="$RUNNER_TEMP/apt-hook-fixture/hook-stream" \
GUARDED_UPDATE_FIXTURE_ARCHIVE="$RUNNER_TEMP/apt-hook-fixture/fixture.deb" \
cargo test --locked --features apt-executor \
  execution_gate::gate_tests::disposable_linux_real_apt_hook_stream_matches_archive \
  -- --ignored --exact
```

That explicitly ignored test inspects only the exported fixture with test-only
`dpkg-deb` and `sha256sum` adapters and verifies its real hook transaction, then
rejects a substituted expected hash. Device/package/repository evidence remains
synthetic; this test does not prove production provenance, freshness, claim
authorization, interrupted recovery, or archive immutability through installation.
Scratch disappears with runner teardown. This harness must never run on managed
endpoints. Verified by the disposable Ubuntu CI job in PR #10: actual protocol-v3
transaction validation and substituted-hash rejection pass; the mandatory hook
rejects before dpkg, with both status hashes unchanged and fixture payload absent.
Native executor suites pass on macOS ARM64 and Linux ARM64. This evidence covers
the synthetic new-package transaction only, not production update execution.

## Authorized executor follow-up

The optional `apt-executor` profile now adds a strict signed claim verifier,
root-owned durable consumption journal, system Python `python3-apt` adapter and
unprivileged broker. Legacy and reporting-only artifacts keep their boundaries.
Root-owned configuration selects a nonempty package batch; libapt determines its
complete dependency closure and authenticated package record hashes. Root copies
hash-verified archives from acquisition running as `_apt` into a private store.
Authentication or freshness bypasses in repository sources are rejected. Fresh
strict authenticated refresh is required; the local acceptance policy limits
signed Release Date to seven days, upstream Valid-Until when supplied, and
prepared evidence to one hour. A local deadline is not an upstream expiry claim.

Prepared transactions cannot execute after state or archive drift. A mandatory
APT hook validates actual actions while APT owns locks, obtains a fresh signed
claim through the broker, verifies it and durably consumes authority before
release. Root never holds device/controller private signing keys. A global local
lock and persistent attempt records prevent overlapping or automatic repeated
executions; interrupted outcomes require manual reconciliation. Durable terminal
results cannot be contradicted by a later observation. No automatic reboot or
root execution timer is included. Provisioning starts with reporting only.

The disposable integration job checks real isolated upgrades and rejections for
expired, mismatched, unacknowledged, invalidly signed, drifted, stale, held,
substituted and replayed authority. Production hook cases use a synthetic signed
controller response and actual root adapter; acquisition provenance remains a
separate preparation check. CI must pass before executor deployment.

Verified executor follow-up: all ten checks passed in CI run39894575730,
including production hook accepted/expired cases, all negative transaction
cases, ARMv7 packaging and disabled unit verification. ARMv7 binaries measured
461996bytes local, 761004bytes remote-reporting and920748bytes executor. These
are CI artifacts, not a tagged release. Executor cycle polls approval status
without consuming it; only the mandatory hook's fresh signed claim authorizes
execution. Root attempt records prohibit automatic replay; result retries are
independent. All units remain disabled until explicit provisioning.
