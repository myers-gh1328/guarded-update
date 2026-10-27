# Isolated inventory metadata capability — proposed implementation contract

This implements the approved fixed refresh/publisher design. It is a reviewable
contract for the next implementation slice, not an enabled endpoint capability.
Reporting continues when refresh is unavailable. Existing update execution,
package archives, host APT lists/configuration and prepared transactions remain
outside this capability.

## Fixed local interfaces

The reporter has no sudo or service-control access. Ansible owns every path,
policy, executable, mount and unit. The reporting UID and refresh-worker UID are
different. The root trigger/publisher cannot access reporting or update keys.

| Interface | Accepted input | Output / authority |
| --- | --- | --- |
| Fixed refresh inbox | Exactly 32 lowercase hex bytes plus optional newline | One bounded metadata refresh under fixed root policy |
| Fixed observation-lease inbox | Same opaque nonce format | Temporarily holds native package read locks for the fixed collector |
| Fixed observation-release inbox | Same lease nonce | Releases only that observation lease |
| Root-owned local status | No caller input | One capped JSON document, read-only to the reporter |
| Root-owned current-generation reference | No caller input | One capped immutable manifest identity, read-only to the reporter |

These are separate fixed filenames beneath an Ansible-owned runtime root. The
caller never supplies a command, package, URL, environment, policy, path or
resource limit. Inbox directories alone are reporter-writable. Read each request
relative to an admitted directory FD using no-follow/nonblocking opens; require
regular file, one link, reporter UID, private mode and at most 64 bytes. Reject
unknown bytes/fields and aliases. Revalidate the opened descriptor, not a later
path lookup. Publication/status directories remain root-owned. No arbitrary
file from an inbox is copied into privileged storage or parsed as configuration.

The 32-hex correlator contains a 16-hex monotonic counter (range
1..Number.MAX_SAFE_INTEGER) followed by 16 random hex characters; it conveys no
command or path. Each fixed inbox capability has an independent durable counter.
The reporter journals the counter/correlator before submission. The helper burns
its high-water mark and persists bounded active/last-terminal metadata before
starting. Re-delivery of the exact active/last-terminal correlator returns existing
state. A correlator at/below the high-water mark that is no longer retained returns
`state_inconsistent` without starting work. Thus bounded retention cannot reopen
an old operation. A different correlator during active work returns `busy`; it
never replaces work. Missing/reset durable helper counters require explicit
operator recovery, not silent initialization. A 15-minute monotonic minimum interval applies to actual refresh
starts. Reboot/cache loss is explicit; a reused nonce cannot imply an earlier
cache generation survived. This local capability does not grant remote requests
any broader authority.

## Status schema, bounds and server mapping

Local status uses schema_version 1, strict known fields, no duplicate keys and a
maximum encoded size of 64 KiB. It contains:

```text
schema_version: 1
operation_nonce: lowercase hex[32] | null
phase: received | running | succeeded | deferred | failed | unconfirmed
reason: null | enum below
policy_generation: lowercase sha256 | null
cache_generation: lowercase hex[32] | null
successful_checked_at: RFC3339 | null
started_at: RFC3339 | null
finished_at: RFC3339 | null
observation_lease: null | {
  nonce: hex[32], boot_id: UUID, expires_boottime_ms: safe integer
}
```

Reasons are `busy`, `package_manager_busy`, `executor_busy`, `minimum_interval`,
`policy_unsupported`, `policy_changed`, `repository_failed`, `timeout`,
`resource_limit`, `cleanup_unconfirmed`, `cache_unavailable`, `state_inconsistent`,
`invalid_request`, `lease_expired` or `internal_error`. No raw output, repository
URLs, credentials, filenames or arbitrary exception strings enter status/logs.
Status and helper counter files are each capped at 64 KiB. Publication uses
fsync plus atomic replacement of a root-owned bounded file.

The refresh operation record remains independently intact while observation
leases are granted/released; an observation request never overwrites a pending or
terminal refresh result. Helper operational metadata is durable outside tmpfs;
only index generations and runtime lease handles are disposable. Reboot clears
leases, changes boot_id and invalidates successful cache evidence until refresh.

The agent maps the controller's request UUID/delivery sequence to its own opaque
local nonce in its durable bounded journal; helper status never controls fleet,
source generation or controller enrollment. Agent refresh-status maps local
received/running/deferred/failed/unconfirmed directly to those protocol states.
Local `succeeded` only permits building a report with successful metadata evidence;
it does not mean the controller request is Complete. Only a durable matching
server receipt can complete that request. Timeout/uncertain cleanup never starts
a replacement operation blindly. Supersession retains only ID/hash/counter
metadata, never another full inventory report.

## Worker and policy isolation

The worker runs only the fixed trusted native APT refresh command, as its own
non-login UID. It writes only a newly allocated staging generation. A root-owned
APT_CONFIG is loaded before normal host configuration; disable automatic host
main/parts loading. Ansible provides only reviewed sources, trust, pins,
architectures and proxy/auth policy. Reject executable hooks, custom acquisition
methods, proxy-discovery commands, unknown options and unsupported source types.
No caller environment is inherited. Only reviewed OS acquisition methods are
executable. TLS/signatures and repository expiry remain strict. Any failed
repository makes the entire generation unsuccessful; index mtimes never mean
successful refresh.

Policy-generation SHA-256 covers the exact admitted sources/trust/pins/arch/
proxy/auth configuration without exposing private bytes. The same generation is
checked before work, before publication and by the reader. A policy change
invalidates evidence and does not silently mix generations. Root policy paths are
fixed; no helper CLI option points elsewhere. Repository credentials are readable
only by the refresh UID/root and never by the reporter or public artifact.

## Cache, publication and reader leases

All current, staging, retained-old and open-but-unlinked index files live on one
dedicated tmpfs: initial hard limit 128 MiB and 32,768 inodes, no automatic growth.
All refresh, publisher and reader processes run in one dedicated inventory slice;
its aggregate memory limit accounts for tmpfs pages and process memory. Initial
review profile is 256 MiB, not a support claim. Insufficient target headroom,
unsupported cgroup/mount primitives or repository size leaves refresh disabled
with an explicit reason. A larger per-device profile is an Ansible policy change,
never a caller field. No fallback to host APT directories is permitted.

The root publisher opens the staging directory and files by stable no-follow
FDs, validates types, link counts, ownership, manifest and aggregate bounds, and
proves all worker descendants stopped. It converts completed data to root-owned,
read-only files inaccessible for writes by worker/reporter before atomic current
reference publication. No path-based validation followed by privileged reopen.
Failure leaves the previous successful reference and generation intact.

A reader opens the current reference and generation by admitted FDs, obtains a
shared lock on its root-owned lease file, and rechecks the reference before using
it. The publisher must obtain a nonblocking exclusive lease before removing an
old generation. It never evicts current or leased data to force space. All reader
FDs remain charged to the same tmpfs; no copying generations to unaccounted disk
or memory. Lease failure, changing head or missing cache yields honest Unknown.

## Coherent package observation and bounded work

Before candidate comparison, the fixed root observation coordinator acquires
native shared package-state locks nonblocking and checks the enrolled executor's
real activity guard. Lock-file existence is not evidence. Busy native/executor
state defers without deleting locks, killing a package process or reading an
incoherent state. The helper does not read or change executor transaction data.

The root coordinator pins the published reference and holds its native read locks
for at most 120 seconds, returning the nonce/boot/monotonic deadline in status.
The reporter must already lease that exact completed generation, verify matching
policy/head and compare installed-state fingerprints before/after collection.
It releases the observation nonce when finished. Root releases on the fixed
deadline even if the reporter disappears; no renewed/extended lock via nonce
replay. A report whose observation lease expired or whose fingerprints changed
keeps useful installed inventory only if coherent, with candidate reliability
Unknown and `state_inconsistent`/`lease_expired`. There is no root caller-command
execution or inventory signing in this coordinator.

A refresh operation has a 600-second overall bound. Containment stops only its
owned cgroup descendants. If descendant cleanup cannot be proved, retain the
busy/unconfirmed guard and require reconciliation; never kill unrelated APT,
executor, print or DNS services. Resource exhaustion, failed repository, lease
contention and timeout preserve old successful evidence and report continuity.

## Implementation sequence and verification checklist

1. Test strict nonce/status/policy parsers, restart/duplicate/rate-limit state and
   monotonic deadlines before implementation. Keep all units disabled. Publish
   this local contract for independent review before adding privileged behavior.
2. Add a distinct opt-in refresh helper artifact with no reporting keys or update
   authority. Reuse the existing bounded process/output patterns and system tools;
   add no Rust crate. Enforce descriptor-based admission/publication and immutable
   worker-to-publisher handover with adversarial symlink/hardlink/race tests.
3. In native hosted disposable Linux, prove strict APT policy isolation, failed
   repository preservation, native lock contention, timeout/owned cleanup and
   reboot/cache-loss behavior. Hash host package/list/config and prepared executor
   fixtures before/after each refresh; all remain unchanged.
4. Demonstrate actual cgroup memory and tmpfs byte/inode enforcement with current
   plus staging, leased old and open-unlinked files. Test exhausted resources and
   unsupported primitives fail closed. Record measured peaks and target-profile
   fit, not only configured limits. Verify ordinary updater/executor profiles.
5. Connect the unprivileged collector to read-only completed generations and
   observation leases; verify native Debian version semantics, installed-state
   consistency, Unknown after failure/cache loss and no report/key authority
   crossing. Add private disabled Ansible policy and hosted architecture artifacts.

The refresh helper cannot activate on devices until its independent review,
hosted containment tests, per-device policy/repository fit and rollout dependency
checks are complete. A passing transport mock or cache-size declaration does not
satisfy those gates.
