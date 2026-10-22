# ADR-0002: Minimal APT proposal build

Status: implemented locally; not released or deployed.

## Decision

An opt-in `apt-agent` Cargo feature selects an independent entry point. It
compiles common command execution, redaction and output modules, plus APT proposal
code. Homebrew, macOS, AI, and legacy scheduling modules are excluded. No new
crates, runtimes, or host dependencies are installed. The default CLI is unchanged.

The initial command is `propose`: read explicit APT holds and simulate an upgrade
using cached indexes with a fixed C locale. Versioned JSON describes the resolver
transaction, including newly installed dependencies and removals. Validate summary
counts, package identities, configuration targets and holds before output.
Installed-to-target transitions are labelled `replace`, not presumed to be
version increases. Future execution needs Debian version comparison.

## Limits

This is not all available candidates: held and deferred candidates may be omitted
by the resolver. Repository identity is unverified; metadata freshness and service
restart impact are unknown. No installation, root execution, service changes or
reboots exist in either minimal build. The local `apt-agent` build has no polling
or key authentication; the opt-in `apt-remote` build adds the exchange below. The existing personal-only/no-root
boundaries remain in force until a separate execution contract is implemented.

The accepted-output size limit is checked after the common runner buffers process
output; it does not bound subprocess-output memory usage. Simulation fixtures are
synthetic; supported APT versions need validation on representative Linux systems.

## Future direction

Owner requested an approval-only Linux agent with outbound polling and dashboard
review, including business devices. This requires a separate privilege and device
authentication contract, durable replay protection, transaction revalidation,
restart policy and an explicit amendment to the current execution boundaries.
Implementation planning is kept outside this public repository.

## Remote-only signed approval exchange

The `apt-remote` feature includes `apt-agent` and adds TOML configuration, outbound
HTTPS reporting/polling, per-device ECDSA P-256 SHA256 request signing through the
existing system OpenSSL CLI, and verification of controller-signed approvals.
The device request private key stays on the device; the controller approval private
key stays on the controller. Corresponding public keys are pinned during separate
provisioning. No private keys are compiled or distributed in artifacts. Local builds
exclude the remote module entirely. No new Rust dependencies are added.

`sync --config <absolute-path>` runs one report/poll cycle for a systemd timer.
Reports are collected hourly by default and retried byte-for-byte between checks.
A five-minute timer is supplied only as a remote example, never installed by the
local CLI. Requests bind method, path/query, device, timestamp, random nonce and
exact body digest. Approvals bind device, report identity/digest, validity and restart
permissions. Current approvals always have `execution_allowed:false`, and remote
code rejects any execution-enabled response. Unknown versions, malformed replies,
verification failures or offline controllers leave work held.

A private directory holds a lock and atomically replaced versioned state. Unverified
approvals are never persisted as verified. Report and state bounds are separate so
a large valid report remains readable. No shell commands are received from the
controller. Canonical Node-generated signature fixtures verify cross-language
compatibility using OpenSSL tests.

Future execution requires a fresh single-use authorization/claim that closes the
revocation race; a cached phase-2 signature never authorizes installation. ARMv7
linking and runtime verification remain required before release/deployment.
