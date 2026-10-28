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
an old operation. A different correlator during started work returns `busy`; it never replaces
started or uncertain work. A received operation that has durably never started may be explicitly abandoned
by a higher correlator, retaining its failed not-started record. A completed
no-work deferral instead retains its entire original Deferred phase, reason,
boot/acceptance/policy and decision endpoint unchanged when replaced. Duplicate
redelivery returns that same decision and can never start that physical nonce.
Retrying the same logical controller request requires a fresh higher local helper
correlator after canonical no-work acknowledgement; its original logical expiry
and request identity remain unchanged. A deferred refresh does not block coherent cached observation.
Only a release with the exact running observation's nonce/boot/policy may join
that observation to close its locks. Missing/reset durable helper counters require explicit
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
attempt: null | {
  correlator: lowercase hex[32], helper_sequence: safe integer,
  boot_id: UUID, accepted_boottime_ms: safe integer,
  started_boottime_ms: safe integer | null,
  finished_boottime_ms: safe integer | null
}
observation_lease: null | {
  nonce: hex[32], boot_id: UUID, cache_generation: hex[32],
  policy_generation: lowercase sha256, lock_open_boottime_ms: safe integer,
  expires_boottime_ms: safe integer
}
observation_receipt: null | {
  nonce: hex[32], boot_id: UUID, cache_generation: hex[32],
  policy_generation: lowercase sha256, expires_boottime_ms: safe integer,
  lock_open_boottime_ms: safe integer, lock_held_until_boottime_ms: safe integer,
  released_boottime_ms: safe integer, outcome: released | expired | unconfirmed,
  installed_before_sha256: lowercase sha256,
  installed_after_sha256: lowercase sha256
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
Before submitting a new controller request, the agent durably records its
request UUID, delivery sequence, local boot ID, acceptance CLOCK_BOOTTIME value
and newly allocated helper correlator, frozen with enrollment/source revision.
This `local_accepted_boottime_ms` is distinct from the root helper's
`accepted_boottime_ms`. Evidence fields may only fill previously null values;
request/correlator/boot/sequence identity never changes. The helper persists its own acceptance
and actual-start monotonic times before work. A request may use helper success
only when the exact correlator matches, the same boot ID applies, and the monotonic chain is local acceptance <= root helper acceptance <= actual
start <= helper finish. Root observation, scan and release then require helper
finish <= native lock open <= scan start <= scan finish <= confirmed lock-held
until <= lease expiry, all on the same boot and exact cache/policy generation.
Final proof binds the exact retained report ID/hash before upload. Metadata from
an earlier root observation or a different attempt cannot be substituted. A helper already running when
a request arrived is not retroactively attached: return deferred/busy, reconcile
that older attempt separately, and allocate a later attempt only after its
terminal result proves whether work started. Wall-clock timestamps alone never
establish this ordering. Helpers that return no attempt/start evidence cannot
satisfy a manual refresh request. Report/status metadata exposes only these
bounded identifiers/times, not helper paths or commands. New protocol fields
require explicit per-client/enrollment negotiation; v0.1.9 exact wire remains
unchanged until a separately versioned compatible client is enrolled.

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

The public policy_generation is HMAC-SHA256, not an unsalted configuration
hash. A device-generated 256-bit random policy-commitment key is root-only, never
readable by reporter/worker or exported. The publisher HMACs a domain-separated,
length-framed canonical sequence of the exact admitted source/trust/pin/arch/
proxy/auth bytes and schema. This covers private auth changes without making the
public digest an offline verifier for low-entropy repository credentials. The
worker receives the resulting identifier, not the commitment key. Private key
loss/rotation invalidates cache generations and requires explicit recovery; it
never silently reuses a raw-auth digest. Test that changing private auth changes
the generation while a reporter lacking the key cannot reproduce the commitment
from guessed credentials. The same generation is
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

One fixed root lock serializes all publication, current-reference changes and
retirement. The coordinator prevents any same-worker-UID writer outside its
contained worker subtree; an empty child process alone does not prove that
precondition. A status/fsync failure is unconfirmed, never succeeded.

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
After the last read/fingerprint, the reporter submits the fixed release nonce
and requires a matching root-owned observation_receipt with outcome `released`.
The coordinator computes its fixed native-state fingerprints under the held read
locks, samples `lock_held_until_boottime_ms` immediately before unlock, samples
`released_boottime_ms` after unlock and persists a matching bounded receipt before
releasing the root coordination guard. Only the confirmed lock-held endpoint can
bound a scan; the later actual-release timestamp cannot extend the claimed lock
interval. A failed receipt fsync leaves the operation unconfirmed and blocks new
work pending reconciliation. The receipt binds the exact
cache/policy generation, boot and native-lock-held start/end interval. Merely
seeing an unexpired active status is insufficient. A deadline expiry or unknown
cleanup cannot produce a successful observation receipt. Root releases on the fixed
deadline even if the reporter disappears; no renewed/extended lock via nonce
replay. A report whose observation lease expired or whose fingerprints changed
keeps useful installed inventory only if coherent, with candidate reliability
Unknown and `state_inconsistent`/`lease_expired`. There is no root caller-command
execution or inventory signing in this coordinator.

The actual-start record is fsynced before spawning any worker, even when a
received record already exists. Before taking ownership, publishing or unlocking
a helper guard, prove the fixed worker cgroup is empty; a process exit code alone
is insufficient. Unknown descendant cleanup preserves the guard and old data.

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

Implementation references: [APT configuration loading order](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html)
requires parts/main overrides in APT_CONFIG itself; [systemd resource control](https://www.freedesktop.org/software/systemd/man/257/systemd.resource-control.html)
defines slice-wide memory accounting and MemoryMax. Actual enforcement remains a
native hosted test requirement.

## Hosted native evidence, 2026-10-28 UTC

The native containment job succeeded for source
`7942e88fc64386f9a00ac6bd392ac056e1bba5d2` in
[CI run 40611107422](https://github.com/myers-gh1328/guarded-update/actions/runs/40611107422).
The workflow later failed at the ARM artifact service upload after five request
timeouts. Full CI remains a merge gate; the following evidence is scoped to the
successful native job.

The fixed worker acquired binary package indexes from a synthetic signed HTTPS
repository with authentication. Wrong CA, signing key, authentication, expired
metadata and any failed repository were rejected. Every rejection preserved the
previous current generation. The host APT hook was excluded, host APT state stayed
unchanged, and the owned worker cgroup was empty before publication.

The separate storage proof enforced the 128 MiB tmpfs byte limit, 32,768 inode
limit and 256 MiB cgroup memory limit. It covered separate-UID immutability,
retained readers, open unlinked storage accounting and preservation of current
state after resource failure. The synthetic APT workload's observed memory peak
was 14,901,248 bytes. This does not establish actual target-repository capacity.

Verified artifact SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| `native-refresh-apt-proof.json` | `d17bd61d7d61f3ca0e02e79b6ce81c0838d6bb1ea6e498b162846b51675d3c7b` |
| `native-refresh-storage-proof.json` | `a1efc19c237fc27a1b09c98e23d618fda1e2298f24abf7bc176d378d40ce2045` |

The proof does not exercise the root coordinator, observation lifecycle, reporter
adapter or a real device's repositories. Those implementation and rollout gates
remain open. No device capability was enabled by this evidence.

## Native observation primitives

The staged `inventory_refresh_observation.py` library holds actual POSIX shared
locks on both native dpkg lock files, together with a shared flock on the existing
executor guard. These are distinct lock namespaces; package exclusion uses the
same fcntl record-lock mechanism as [APT's native GetLock implementation](https://github.com/Debian/apt/blob/main/apt-pkg/contrib/fileutl.cc).
A process-wide owner prevents a second handle from opening/closing a native lock
inode and inadvertently releasing its process-owned POSIX lock.

The fixed Linux root adapter admits and retains full directory ancestry by FD,
and checks that the named directories and lock files still identify those objects.
Installed-state fingerprints cover only fixed status, optional architecture and
bounded numeric update entries. Framed names/types distinguish missing and empty
state. Reads stream within 64 MiB and 4,096 update entries, checking native deadline
throughout enumeration and reads. Unsafe ownership, writable state, links,
replacement, changed bytes or expired time cannot produce successful evidence.

Observation identity is frozen before collection. An unrelated release nonce
preserves the active observation. An exact release consumes it once, fingerprints
under the held locks, verifies continuity, samples held-until before unlock and
released after unlock. Success requires equal fingerprints and monotonic ordering
within the fixed 120-second deadline. A failed matching release cleans up only its
owned descriptors and produces no successful receipt. Unknown descriptor cleanup
retains the process guard rather than permitting replacement work.

Local regressions exercise real child-process package/executor contention and
partial-acquisition cleanup against synthetic files. The hosted native proof
exercises actual runner package locks, native clock and installed-state reads.
Its cache/policy identifiers are explicitly synthetic: it does not establish
cache pinning, durable coordinator/status publication or independent deadline
containment. Those integration gates remain required before activation.

The primitive native proof also passed for `f989b048a14046126d65ba511bb1472b8b006c07`
in [CI run 40635358769](https://github.com/myers-gh1328/guarded-update/actions/runs/40635358769).
The retrieved `native-refresh-observation-proof.json` SHA-256 is
`6f98fd62741f8779af06ff82363a6e9b99a789f7f617b599fa1c6435263341b3`.
It confirms actual runner package/executor writer exclusion and matching native
installed-state fingerprints through a released observation; its explicit false
integration flags remain rollout gates.

## Fixed inbox and status I/O primitives

The staged I/O library reads only `request` beneath the fixed runtime root's
`refresh`, `observation` and `release` directories. Each inbox is root-owned,
mode 0770 with the reporting group; all parents remain nonwritable by reporter.
A request must be reporter-owned, mode 0600, single-link regular data. Reading
retains the original file, caps total data at 65 bytes to detect growth, rechecks
descriptor/named identity and then parses the exact bounded correlator. This does
not grant work: durable high-water/lifecycle admission still follows separately.

The fixed public output is `status/status.json` beneath that runtime root. Its
directory is root-owned mode 0750 with the reporting group; each fixed ancestor
must permit reporter traversal. These permissions and full named ancestry are
rechecked at use. The public file is root-owned mode 0640 with the reporting
group. Unsafe existing files are rejected without following, repairing or
changing their ownership.

The private byte publisher requires the held root journal lock. It creates an
exclusive private temporary file, writes bounded bytes, verifies final ownership,
mode/type/link count, fsyncs, atomically replaces the fixed public name and fsyncs
the directory. A failed exclusive creation never removes another private file.
Any attempted replacement is classified as possibly visible on failure; directory
fsync failure does not promise rollback to old bytes. The strict public-status
schema builder and coordinator ordering remain mandatory before exposing this
trusted byte sink through an operational helper. There is no executable I/O
entrypoint or enabled capability in this slice.

The active observation lease includes the actual frozen native lock-opening time.
This staged-contract field lets the agent persist its observation and scan-start
identity before native collection; it must not infer opening from expiry or attach
it retroactively from the later release receipt. No active client capability was
in use when this local schema was clarified.

## Strict public status construction

Operational publication accepts an immutable `PublicStatus` constructed from the
exact documented fields. A normal constructor cannot wrap arbitrary bytes. The
builder copies known fields, validates typed phases/reasons, UTC calendar values,
positive bounded nonce counters, safe integers and helper identity/time ordering,
then freezes the encoded bytes. Unknown fields, private policy objects, arrays in
scalar fields and nonfinite values produce a static rejection. A successful helper
requires its correlated start/finish attempt, bounded interval and successful
cache evidence. Non-success states can retain prior successful cache metadata.

Observation leases and last receipts form a separate domain from refresh attempts.
An active lease must bind the available cache/policy and actual opening/deadline;
a retained older receipt can remain historical. A released receipt requires equal
fingerprints and release within its bounded lock interval. Expired/unconfirmed
outcomes never pass those success checks. A current lease and terminal receipt
cannot claim the same observation nonce simultaneously.

This builder validates public data; it does not infer lifecycle outcomes or
attest OS/cache evidence. The root coordinator must still derive each value from
its durable journal, pinned policy/cache, native handles and confirmed publication.

## Durable no-work decisions

The private bounded operation record includes `decision_boottime_ms`. Deferring
known unstarted work persists an explicit same-boot decision endpoint before
returning no-work evidence. The endpoint is separate from actual work finish:
`started_boottime_ms` and `finished_boottime_ms` remain null. A minimum-interval
decision follows the same rule. Repeated calls cannot change the reason, policy,
identity or time, and that nonce is permanently barred from starting later.

Only a fresh helper correlator can request a later physical attempt. Replacing a
known no-work record preserves it as Deferred in last-terminal metadata; oldnonce
replay returns its original decision, and replay after bounded pruning is stale.
No timestamp is synthesized from status polling. The public coordinator can map a
persisted Deferred decision endpoint to its no-work attempt endpoint, matching the
agent's existing no-work acknowledgement/retry contract. This does not describe
an actual native process finish.

The private helper format remains staged and unactivated. Incompatible or missing
state fails closed; this change does not reset, migrate or reseed device counters.

A newly opened journal handle must pass an explicit durability reconciliation
before snapshots, mutation or public status publication. Every private state save
re-arms this guard before writing and clears it only after the file, replacement,
directory sync and owned-temporary cleanup succeed. A failed sync can leave new
bytes visible; visibility alone is not a durable no-work acknowledgement.

Reconciliation holds the root control lock, validates the exact no-follow control
file and epoch, checks descriptor/named metadata continuity, syncs that same file
and its private directory, then closes the descriptor before clearing uncertainty.
If prior started work exists, marking it Unconfirmed is another guarded durable
save. Parse, sync or cleanup failure leaves snapshots/starts/publication blocked.
This neither initializes missing state nor retries native work. Reporting and
retained inventory uploads remain independent of helper availability.

The observer now opens the existing executor guard read-only without creation.
Only trusted parent/provisioning code prepares the one fixed guard beforehand;
it preserves existing bytes and rejects unsafe objects or permissions without
repair. This lets shared native/executor locks work within a read-only observer
filesystem sandbox. A separate hosted read-only proof verifies actual writable
access denial plus successful shared acquisition/fingerprinting/release. It does
not claim writer contention inside that namespace; the ordinary host proof tests
actual writers independently.

An admitted root job's absolute deadline is checked before native guard attempts
and caps the actual observation identity to the earlier of that deadline and
`lock_open + 120 seconds`. Active lease and release receipt carry this same bound.
This prevents a delayed launch from advertising a fresh full interval. Independent
guardian/process containment remains a separate required integration proof.

### Fixed root guardian and worker privilege transition

The staged refresh guardian is a separate root MAIN process. It accepts no
command-line arguments and reads the fixed root-owned job only. The job freezes
`deadline_boottime_ms`, strictly after the recorded start and at most 600 seconds
later. Missing or oversized deadlines fail closed. Its independent
CLOCK_BOOTTIME loop uses nonblocking child polling; deadline expiry kills the
owned direct child and exits without waiting on a stopped descendant. PID1 must
then kill the entire service cgroup. The coordinator must still independently
prove empty cgroup and all-four-UID writer exclusion before publication; a
successful guardian exit is not cleanup evidence.

The fixed worker transition uses `/usr/bin/setpriv` with numeric admitted
ccrefresh IDs, cleared supplementary groups, empty inheritable, ambient and
bounding capability sets, and no-new-privileges. No direct-exec fallback exists.
The guardian retains only KILL, SETUID, SETGID and SETPCAP capabilities in its
service profile; SETPCAP is needed to drop the child's bounding set. Before any
job or APT work, the worker verifies the actual four kernel UID/GID columns,
empty supplementary groups, all five capability sets zero and NNP=1. See the
[util-linux source](https://github.com/util-linux/util-linux/blob/master/sys-utils/setpriv.c)
and [option contract](https://github.com/util-linux/util-linux/blob/master/sys-utils/setpriv.1.adoc).

The guardian runs with isolated Python and executes only bounded source bytes
read from its admitted root-owned, single-link, nofollow `worker.py` descriptor,
with metadata and named-reference continuity checks. It does not add the project
library to module search or load project bytecode. The disposable signed-repo
proof plants a conflicting package, sibling module and matching malicious
bytecode to exercise this distinction. The exact service profile uses
Type=exec, ExitType=main, RemainAfterExit=no, Restart=no, KillMode=control-group,
KillSignal=SIGKILL, TimeoutStopSec=1, SendSIGKILL=yes and OOMPolicy=kill.

This source remains opt-in and unactivated. Native signed-repository CI runs the
actual guardian, but independent stopped-child deadline, signal-isolation and
OOM fault proofs remain separate required integration evidence. No coordinator,
observation guardian, installed helper artifact or real-device resource fit is
implied by these unit tests or by a worker exit code.

The guardian service explicitly requests AmbientCapabilities=CAP_SETUID inside
its existing KILL/SETUID/SETGID/SETPCAP bounding set. systemd's seccomp setup drops
SETUID unless it is requested in the ambient set; both PrivateDevices and
RestrictNamespaces exercise this path. A disposable read-only property matrix
reproduced missing effective SETUID and setresuid EPERM. See the
[systemd implementation](https://github.com/systemd/systemd/blob/v255/src/core/exec-invoke.c#L4484-L4490).
The full-sandbox preflight verifies actual root UID/GID, effective/permitted/
bounding masks exactly those four capabilities, inherited SETUID/SETPCAP,
ambient SETUID only, and NNP=1. After setpriv, all five worker capability masks must be zero. The
namespace and device restrictions remain part of the service profile.

The native root profile records inheritable SETUID plus SETPCAP (mask384):
systemd's seccomp setup retains SETPCAP in that set while applying its filters.
The same run verifies permitted/effective/bounding mask480, ambient mask128,
and NNP=1. This is parent supervision authority; setpriv must still clear every
worker capability set. See the
[capability helper](https://github.com/systemd/systemd/blob/v255/src/basic/capability-util.c#L337-L359).

### Durable retained refresh success

The unactivated private helper journal now uses schema2. It retains one
`last_success` independently of later active/terminal refresh attempts: the exact
completed refresh operation plus `successful_checked_at` from its sealed cache
manifest. Terminal success and retained evidence commit in the same guarded
journal save. Strict calendar UTC, nonce/high-water, completed-start and
600-second checks apply; a duplicate cannot rewrite the checked timestamp.
Failure, deferral or another capability cannot erase prior success.

Private schema1/missing fields fail closed and require explicit recovery; runtime
never resets or silently migrates counters. No deployed helper state exists.
Public helper status remains schema1. Retained metadata alone never proves that
the cache survived reboot, still exists or matches current admitted policy;
coordinator projection must obtain a fresh snapshot under its held lock and
verify all those bindings before advertising usable cache evidence.

### Journal, cache and public status coordination

`publish_current_status` obtains a fresh reconciled journal snapshot under the
held root lock and publishes through the same journal's typed status writer.
The fixed OS runtime must supply actual boot identity, current admitted policy
and metadata from an actual held cache lease; this function grants no OS or
process authority. Available cache metadata must match retained success in
boot, cache generation, policy and checked timestamp, including current policy.
A manifest alone is insufficient. Later failed/deferred attempts retain that
matching prior cache time; execution wall times remain null when not captured.
No-work completion uses only its durable decision time.

Operational uncertainty, missing policy, policy mismatch in any refresh phase,
and cache loss/reboot after success produce an uncorrelated health status:
`operation_nonce` and `attempt` are null. The private refresh record remains
unchanged. Clients must not merge that health into an existing correlated helper
proof. Active observation cannot be granted through uncertain or unavailable
state. Observation receipts remain independent typed historical evidence.
Top-level prior-cache metadata is not evidence that a failed/deferred attempt
produced a generation; the client adapter must not fill that attempt's helper
cache/policy proof from retained cache fields.

This slice connects actual journal durability and atomic public-file I/O.
Fixed OS admission, native child-result validation, policy/cache pinning across
the physical lifecycle and the executable reporter adapter remain required
before activation. The projection tests do not claim those integration gates.

### Cache-pinned native observation and child metadata

The staged observation reader session pins an actual immutable cache lease
before acquiring native locks. Its strict schema1 job freezes an opaque job ID,
operation nonce/sequence, boot, cache/policy/checked time and accepted/start/
deadline times; start must precede the deadline, bounded by acceptance+120s.
Fresh time is checked again after cache admission. No request paths, commands,
URLs, credentials or options exist in this metadata.

Typed child results contain that exact full job plus either an actual opened
lease, an actual successful release receipt, or a static failure reason. Parsing
revalidates nested types before comparing the expected job; numeric/boolean
aliases cannot bypass identity checks. Result identity, actual open>=start,
expiry<=job deadline, equal installed-state fingerprints and successful release
ordering are mandatory. Results are immutable snapshots; expected-job matching
alone does not establish child liveness or prevent same-job opened-result replay.
The parent must enforce phase progression, current BOOTTIME and owned-child state.

The session holds the cache pin through native unlock. Wrong release nonce
preserves both scopes; owned failures abort native ownership before closing the
cache pin, and cleanup failure cannot return success. Index verification uses
the actual pinned cache and rechecks the native lease before and after reading.
Root current policy admission/rechecks and durable parent coordination remain
separate responsibilities.

The disposable signed-repository proof now also exercises actual cache pinning,
actual published Packages hashes, native installed-state fingerprints and typed
release results together. Independent observation supervision, observation
process containment, durable observation coordination and real target fit remain
explicitly unproven. This library/source integration activates no capability.

### Fixed root observation channel

The observation process channel uses the separate root-only runtime sibling
`observation-private/{control,results}`, each directory0700. It never nests
privileged files below the reporter-writable observation inbox. The shared
runtime ancestor permits traversal, while worker configurations stay0640 in
worker group and private channel ancestry remains inaccessible to reporter.

Fixed job/release files are root0400 and the result is root0600, each bounded to
64KiB, single-link regular files with stable descriptor/named-reference checks.
Parent job/grant writes require the same held, reconciled Journal and matching
running observation/release records. A root grant binds the exact job and its
frozen release-start time after actual lock opening. The native session's
`finish_granted` checks that identity and timing before one-use release.
Reporter inbox bytes cannot directly become a native-reader release.

Atomic writes use owned exclusive temporaries, complete writes, file sync,
rename and directory sync. Any attempted rename failure remains possibly visible;
cleanup errors preserve that uncertainty. Identical acknowledgements perform an
exact-file/directory durability barrier. Parent result acceptance also syncs the
exact child file and directory before updating its in-memory progression.
Released evidence requires its matching root grant on both writer and reader.
Old lower-counter residue cannot match a new job; changed opened data,
contradictory terminals and opened-after-terminal are rejected.

This channel is metadata I/O, not service/execution authority. The parent must
still enforce current owned-child state, actual deadline, release-issued state,
policy/cache pins, durable receipt and cleanup before publishing completion.
The in-memory tracker cannot authorize restart recovery or same-job regrant.
The disposable native proof tests actual separate reporter UID permissions and
inbox→journal→job→opened→root grant→released I/O with the real cache/native
session. Observation process containment and independent guardian remain separate
unactivated integration gates.

### Fixed observation processes (not activated)

The observation entry source is copied to two fixed root-owned entry scripts,
`observation-guardian.py` and `observation-native.py`. The parent must admit the
entry and its ancestry before PID1 executes it. The isolated bootstrap admits
and compiles every fixed project module before executing any project bytes;
project search paths, adjacent packages and bytecode caches are not used.
Provisioning must drain helpers before replacing this root-owned source bundle.

The guardian requires only KILL/SETPCAP capabilities and supervises the job's
absolute BOOTTIME deadline independently of the native reader. Its fixed child
retains numeric root identity with all five capability sets empty and
NoNewPrivileges enabled. The native reader has a lease-only cache interface,
performs no account lookups, and accepts release only through the root channel.
It unwinds native/cache ownership before exposing failure metadata and does not
contradict a possibly visible release following an uncertain write.

The disposable process proof uses masked `/etc`, `/var/lib` and `/run`, with
explicit native-state/private-channel bindings. It checks actual child identity,
capabilities, masked policy/coordinator paths, release and whole-cgroup cleanup.
A trusted root reader is not a malicious-code isolation boundary against other
root processes. Full filesystem write-denial, stopped-reader deadline, durable
parent restart, actual key-location coverage and target repository/resource fit
remain separate gates. These source files install or enable no service, timer,
account or reporting capability.

### Atomic observation acceptance

Private journal schema 3 retains the latest accepted observation, release and
receipt together. `finish_observation` commits both successful terminals and the
detached strict receipt in one file-sync/rename/directory-sync transaction.
Individual observation/release success writes are rejected. Exact duplicates
cannot change the receipt; later failures preserve the accepted historical proof.
Unsupported older private state fails closed and is never reset by runtime.

Acceptance requires matching running nonce, boot, policy, counter identities and
actual held/release intervals. The caller must first prove exact root grant,
current job/policy/cache, owned-process termination and cleanup; the journal is
metadata validation, not physical execution authority. Uncertain persistence
blocks publication until the existing reconciliation barrier succeeds.

Public coordinator status derives historical receipt only from that fresh
accepted journal record. Optional explicit receipt input can assert equality but
cannot introduce, replace or suppress accepted proof. Policy/cache loss or reboot
may remove current availability while leaving the historical receipt unchanged.
The shared structural validator preserves honest expired/unconfirmed public
receipts; only a released, timely, unchanged-state receipt can be accepted as a
successful observation transaction.

### Fixed service adapter (source only)

`ObservationService` supplies the exact observation profile used by disposable
native CI. It admits both fixed entry scripts and the complete bounded project
source bundle before PID1 executes an entry. Root provisioning must drain running
helpers before replacing that bundle; this is not isolation from malicious root.

Launch consumes a process-local permit minted only after a new durable journal
start succeeds. Existing running metadata and a fresh adapter object cannot mint
permission. Journal mutations, reconciliation and lock release revoke pending
permits and consumed handles through the current launch epoch. Failed or unknown
launches are never automatically retried.

A spawned launcher alone proves no service ownership. The adapter requires its
strict root-job description marker, systemd InvocationID and a pinned actual
cgroup directory identity. Before stopping the fixed unit it checks that same
incarnation again. Missing/unconfirmed ownership or a replacement invocation
never authorizes stopping an encountered service; cleanup can reap only its own
launcher and retain uncertainty. Source-descriptor cleanup errors after launch
also trigger owned cleanup. Root administration racing the coordination lock is
outside the cooperating-controller boundary.

The adapter has no command/path/options CLI and enables no service. The parent
still owns actual OS readiness, policy/cache provenance, exact live-child checks,
whole-cgroup/UID exclusion and durable restart reconciliation. An exit code,
service disappearance or profile string alone is not completion authority.

### Owned live observation offers

`live_opened()` reads only the fixed root channel for its admitted job. Before
returning an active offer it checks the current service invocation/cgroup,
exact guardian/native process pair, direct parent, numeric identities, capability
sets and fixed command lines. Both tasks are pinned by pidfds, which are polled
for exit before and after process checks; numeric PID reuse cannot substitute a
new task. A changed pair or failed physical check cannot reattach to that job.

The opened bytes remain frozen. Matching durable release admission, a release
terminal or an existing root grant fences further offers. The adapter rereads the
exact result after physical checks, then rechecks pidfds and BOOTTIME/expiry so
an observed terminal change cannot return stale opened metadata. Partial pidfd
pinning unwinds and cleanup attempts every owned descriptor despite close errors.

This is point-in-time scope evidence, not continuous lock ownership or a promise
that a process cannot exit after checking. The parent must clear invalid offers
and require the matching final unchanged-state release receipt, current policy,
cache and actual cleanup before accepting a completed report. Full coordinator
readiness and target provisioning remain separate unactivated gates.

### Fixed private policy admission

`PolicyGuard.fixed()` admits the root policy directory by full no-follow
ancestry and reads only `policy.json` and `policy-commitment.key`. These
capability-owned input conventions require root UID/GID, exact 0400/0600 private
file modes, single-link regular objects, an 8 MiB policy bound and exactly 32 key
bytes. Both descriptors and both named references remain stable across the pair
read. Missing material is never initialized or regenerated by runtime.

The guard uses the existing strict parser, isolated renderer and HMAC commitment.
Its generation is the frozen admitted identity; authority boundaries require an
explicit fresh recheck. Rechecks require the same private key and canonical
commitment. Changed policy, key rotation/loss, uncertain I/O or cleanup poisons
the guard; retained bytes cannot silently authorize work afterwards. Equivalent
canonical policy replacement may retain the commitment. Administrator policy/key
updates must drain helpers; paired file admission is not an atomic multi-file
configuration deployment protocol.

Errors and representations are statically redacted, and closing drops private
references and owned descriptors. The parent must enter the inventory aggregate
before reading/parsing policy and must hold its current cache/lifecycle guards.
Policy admission alone proves no service readiness or target resource fit. The
native fixture uses synthetic inputs and verifies that neither the worker nor
reporter UID can read either private input.

### Current resource-profile admission

`RuntimeResources.fixed()` checks current membership in the fixed coordinator
service beneath the inventory aggregate. It pins full root-owned cache/cgroup
ancestry and binds kernel mount IDs and devices to those descriptors. The cache
must be a dedicated writable tmpfs with nodev/nosuid/noexec, exactly 128 MiB and
32,768 inodes; child mounts and whole/subtree aliases at other paths are unsupported. The
fixed systemd publisher may expose exactly two whole-root mounts stacked at the
same cache pathname. Both must retain nodev/nosuid/noexec on the same tmpfs
device; the actual cache descriptor must identify the writable top mount, whose
immediate parent is the lower mount. Forked, disconnected, cyclic or third-layer
stacks and lower-descriptor selection are rejected. The cgroup2 mount must expose its full root at the fixed mountpoint.

The aggregate must enforce the initial 256 MiB memory, zero swap and 64-task
profile. Stricter ancestor settings fail with `resource_limit`; this describes a
configured-profile mismatch, not observed free headroom. Rechecks validate mount
flags/identity, byte/inode totals, named references, current membership and limits.
Failed or closed contexts cannot return retained metrics. Checks perform no
mount, cgroup, sysctl or pressure-workload writes.

Current membership cannot prove that earlier allocations were charged there.
The trusted unit must enter the aggregate before Python, policy parsing and cache
activity. The new disposable probe does that before admitting synthetic policy;
other existing fixture work outside the aggregate remains explicitly excluded
from an all-allocators claim. Current/free metrics establish neither repository
fit nor available capacity. Full coordinator, UID/namespace writer exclusion,
sensitive-path coverage and real target headroom remain separate gates.

### Materialized APT input binding

A job/config hash alone cannot establish that APT consumed the current policy:
its sources, authentication, trust and pin files are separate inputs.
`MaterializedPolicy.fixed()` compares every actual rendered input with
`PolicyGuard.render(staging_token)` and checks the declared job config digest
against that expected configuration. Only a fixed-origin root PolicyGuard is
accepted by the production factory.

All consumed files remain single-link, root-owned, worker-group-readable objects
with exact private modes, lengths, bytes and frozen descriptor/named metadata.
Nested directory references are rechecked after all reads. The shared empty
configuration-parts directory must remain empty with unchanged metadata; checking
rejects after the first streamed entry rather than allocating an unbounded list.
Changed or closed guards cannot reuse retained evidence, and cleanup attempts all
owned descriptors without closing the borrowed PolicyGuard.

The native fixture holds this binding during acquisition and separately across
publication/observation, exposing only a bounded verification flag. It does not
publish raw auxiliary hashes or private bytes. Byte binding alone does not prove
worker traversal through every ancestor, namespace readiness or UID exclusion;
those remain fixed-service/provisioning gates before activation.

### Fixed refresh service adapter (source only)

`RefreshService` consumes the new durable refresh-start permission before
preparing a launch and binds that handle to the journal's current lock epoch.
It admits both fixed worker/guardian sources before executing any project source,
pins the strict root job file and verifies its nonce, times, boot and policy
against the held journal. Full rendered-input binding, fixed account identities,
source/job continuity and BOOTTIME are rechecked before PID1 starts the worker.

The adapter reuses the tested guardian privilege-drop profile. Its only writable
cache path comes from a strict root-job staging token; no caller command, UID,
path or option interface exists. Service ownership requires the exact root-job
marker, InvocationID and pinned cgroup identity. Unknown creation or replacement
never permits stopping an encountered unit; cleanup reaps only its own launcher
and attempts all owned binding/job/source descriptors. The borrowed PolicyGuard
remains caller-owned.

Disposable acquisition and stopped-unprivileged-child tests now use the actual
adapter after fsynced journal start admission. These fixture journals remain
separate from later publication fixtures, and the existing fixture parent still
runs outside the aggregate. This establishes neither a complete executable
coordinator nor all-allocator accounting. Whole-cgroup/UID exclusion, actual
worker ancestry traversal, filesystem key masks, namespace provenance and real
target readiness remain mandatory caller/provisioning gates before activation.

### Refresh guardian filesystem view

The fixed refresh profile masks `/etc`, `/var/lib` and `/run` with read-only
empty filesystems. It binds only the rendered APT subtree, exact root job/config
files and the listed OS account/resolver files. Private parent policy/key inputs,
host APT/dpkg state and service-control sockets are not bound. Optional generic
application-state roots are inaccessible; the strict staging-token path remains
the sole writable cache area. Privilege-drop and independent-deadline properties
remain unchanged.

The native acquisition tests use this same profile. During the already approved
stopped-unprivileged-child test, the owned guardian namespace must hide paths
known to exist on the host and expose required inputs as actual regular-file
binds, without following final symlinks or reading private bytes. In particular,
a resolver symlink into host `/run` must not require exposing its runtime parent.

Host `nsswitch.conf` can select nonlocal backends; these binds do not prove
local-only NSS. The signed fixture uses an IP URL and does not prove external
DNS or real repository fit. Unsupported layouts remain readiness failures;
no host APT, resolver-runtime directory or broader control-socket fallback is
allowed. Actual device secret-location coverage and initial namespace/unit
provenance remain separate provisioning gates before activation.

### Publisher permission profile (source only)

The fixed publisher profile retains only CHOWN and DAC_OVERRIDE in its capability
bounding set, with no ambient capabilities and NoNewPrivileges. Its writable
filesystem bindings are the capability's cache, private state, runtime and
rendered APT subtree. Private policy inputs and host native package state are
read-only. Empty `/etc`, `/var/lib` and `/run` views expose only explicit inputs.

Root access to PID1's private socket confers broad service-management authority.
The trusted fixed wrapper and data-only nonce protocol limit the operations;
these filesystem masks and capabilities do not sandbox malicious root code with
that socket. The profile itself supplies no launcher or activation entrypoint.
A private empty read-only tmpfs supplies systemd's existence-only boot marker,
bounded to 4 KiB and 16 inodes. Host runtime unit files remain hidden; the marker
is compatibility for the fixed client, not evidence of host/PID1 provenance.

The disposable publisher probe checks exact kernel capability sets, current
resource admission, read-only/writeable bindings, hidden synthetic host state,
a fixed PID1 query and sealing of worker-owned synthetic metadata. Its staging
fixture is prepared outside the aggregate; the probe cannot establish complete
allocator accounting, a complete coordinator or target repository fit. Those
remain separate gates before enabling the capability.

### Root refresh transaction composition (source only)

`RefreshMaterializer` prepares only a newly started operation under the held
journal. Its production factory admits fixed root-owned directory ancestry and
fixed numeric accounts. It creates fresh worker staging directories, sets their
private modes while root-owned, then transfers ownership to the worker. Rendered
policy/config/job files remain root-owned and worker-group-readable, with bounded
complete writes, pinned temporary identities and file/directory durability
barriers. Unsafe existing files, changed references and nonempty configuration
parts fail closed. Cleanup uncertainty revokes the admitted lifecycle's launch
permission through the same journal.

`WriterExclusion` checks the actual worker slice is empty and scans every thread's
real, effective, saved and filesystem UIDs through a full proc view. Hidden proc
subtrees, restricted mount options, empty visibility for a still-present group,
unreadable credentials and incomplete cleanup fail closed. Reserved refresh UID,
cooperating launchers and initial host namespaces remain trusted provisioning
prerequisites; a scan does not prevent a privileged actor starting a later writer.

`RefreshTransaction` composes admission, a brief nonblocking native/executor busy
probe, durable start, fixed materialization and service ownership, cleanup,
writer/resource/policy rechecks, actual cache sealing, durable success and fresh
public projection. Existing/stale/busy requests do not invent new no-work evidence
or relaunch started work. A manifest alone still cannot authorize success.

External persistence/cleanup failures call `Journal.fence_external`: revoke launch
permissions and durably retain global uncertainty without changing frozen success
or accepted receipts. Failed fence persistence keeps local readiness poisoned.
Successful completion cannot bypass this fence. Runtime does not clear durable
uncertainty, replay started work or infer that a failed publication rolled back.
Actual CAP3 transaction proof, full observation coordination, provisioning,
repository fit and activation remain separate gates. No production entrypoint or
enabled service is supplied by this source composition.

### Private-manager transport and retained exit bookkeeping

Production adapters launch through PID1's private socket without systemd-run's
`--wait` or stdio-forwarding modes: those modes require the system bus. The
publisher does not expose that bus. Adapters monitor the actual owned unit's
InvocationID and typed terminal properties instead of treating launcher exit as
worker completion.

Both guardian entrypoints translate a supervised child success (0) into the
internal exit sentinel 90. Workers/native readers and generic supervision still
use 0; an unexpected child 90 is rejected. `RemainAfterExit=no` ensures every
guardian exit triggers PID1's normal whole-cgroup stop path. Sentinel 90 is never
a systemd SuccessExitStatus. Default failed-unit retention preserves its exit
bookkeeping until the fixed owner acknowledges that exact failed incarnation.
This is expected transient bookkeeping, not an operational success claim.

Adapters return raw status 90/74/75/76 only from the same owned invocation's
strict failed terminal. A trimmed cgroup can identify that inert retained unit
for classification/acknowledgement, never establish kernel-empty state or permit
publication. The transaction independently requires whole-slice emptiness, every
thread's refresh-UID exclusion and current policy/resources/deadline before
sealing. Actual manifest, durable success and typed status remain later barriers.

Acknowledgement revalidates the same private job marker and InvocationID under
the held journal immediately before resetting the failed unit. Unknown creation
or replacement never grants reset/stop authority. Native tests require a failed
attempt followed by a new job under each fixed unit name. Legacy negative-policy
fixture wrappers may use the disposable host's system bus; production adapter
proofs use the private-manager path and retain all activation/fit limitations.

### Read-only metadata contention precheck

The refresh parent takes no native package or executor locks. Its advisory
prestart check pins the three fixed lock-file identities with O_PATH and reads
a bounded kernel lock table through the admitted full-host proc view. POSIX/OFD
write ranges on dpkg locks and FLOCK writes on the executor guard cause a frozen
no-start deferral. Partial, malformed, unsupported or unverifiable views never
mean clear; cleanup uncertainty still fences the process/lifecycle.

Exact device/inode matching is initially supported on ext4 and tmpfs. Other
filesystem layouts remain unavailable rather than assuming matching semantics.
The proc file must share its root mount identity; trusted initial PID/proc
namespace provenance remains a provisioning requirement. Descriptor rechecks
establish identity, not an atomic snapshot or a future absence guarantee.

A process-local mutex prevents descriptor closure from disturbing an existing
same-process POSIX owner. It takes no kernel lock and cannot block external
package operations if this parent stops. Coherent collection still acquires
actual native/executor shared locks in the independently supervised reader;
this precheck does not replace that receipt or grant installation authority.


### Root observation transaction composition (source only)

`ObservationTransaction` composes the existing fixed observation service, private
channel, cache pin, policy/resource guards and status publisher under one held,
reconciled journal. It accepts a strict nonce, requires the current cache to match
the durable refresh success, and persists receive/start before its one-use launch.
It never reconstructs process ownership from a running journal record.

A public offer requires the actual service's invocation/cgroup/process liveness
checks. Release withdraws that offer before writing one frozen grant. Acceptance
requires the exact opened lease, matching grant and equal installed fingerprints,
owned service termination, confirmed whole-slice/writer cleanup and unchanged
cache/policy context. The parent cache pin remains held through atomic durable
acceptance of both operations and their receipt. Failure or lost ownership fences
uncertainty and withdraws the offer; a poisoned policy guard publishes no admitted
policy or currently available cache. Prior accepted historical evidence remains
independent of the current operation. Invalid/unrelated/premature reporter inputs
cannot abort valid active work; duplicate requests never regenerate grants.

Focused tests use real journal/cache/channel/status components with test-only
process collaborators. The disposable Linux proof exercises the actual CAP3
publisher and fixed native observation service in that same context. Its new
`fixed_publisher_observation_transaction_verified` result is evidence of that
bounded composition only, not the complete executable coordinator. Initial host
namespace/unit provenance, all-allocator charging, target repository fit, client
integration, provisioning and rollout remain separate gates. No service is enabled
and no package install/upgrade authority is added by this source.

### Bounded root inbox dispatch (source only)

`RootDispatcher` connects the three fixed nonce inboxes to those transactions in
one bounded step under their shared journal, policy, resources, cache, publisher
and writer guards. It claims a fresh observation lifecycle once per process;
second owners and reattachment are rejected. Each step polls its owned scope,
reads each inbox at most once, and dispatches release before observation and
refresh. Only typed invalid-request input is ignored per inbox, allowing valid
requests in other inboxes to proceed. Trusted I/O or lifecycle uncertainty stops
and fences the dispatcher. Active observation suppresses refresh; the durable
journal remains the sole nonce/high-water authority. No request files are deleted,
rewritten or queued by production dispatch. Closing permanently disables dispatch
and cleans only its owned observation, preserving borrowed inputs.

Tests cover real nonce files, malformed-peer fairness, canonical tuples,
context/ownership rejection, duplicate requests, cleanup failure and idle close.
The native fixture uses synthetic reporter-owned nonce files to exercise the same
fixed Inbox readers and CAP3 transactions; this is distinct from the earlier
actual unprivileged reporter transport proof. A successful
`fixed_publisher_inbox_dispatch_verified` flag proves this bounded source
composition, not an enabled service, complete executable loop, initial namespace
provenance, startup allocator accounting or target resource fit.

### Fixed runtime ownership (source only)

`FixedRuntime.fixed()` assembles the actual guards and dispatcher without caller
paths, commands, account IDs or state initialization. Current resource admission
precedes private policy/cache contents and account lookup. The existing startup
durability barrier must return exactly true; unresolved started work refuses all
dispatch, with no automatic recovery or replay. Fixed worker/reporter identities
are retained and rechecked at every step.

The runtime keeps one journal lock throughout operation. Dispatcher, observation,
inboxes, channel, publisher, writer guard, policy and resources all close before
that lock is released. Every cleanup callback is attempted; failures fence the
journal while its original lock and state descriptor remain usable. Errors during
final lock/state descriptor release permanently close the runtime with local
shutdown uncertainty; no second lock is acquired to manufacture a durable fence.
Before the journal is acquired, admission failure closes only acquired resources.

Local tests retain real journal/cache/status fixtures while substituting factory
origins and lock acquisition. The native proof uses the actual fixed factory,
nonce dispatch and runtime close, then checks writer exclusion after shutdown.
`fixed_publisher_runtime_verified` therefore covers bounded assembly and ownership,
not a complete executable/bootstrap, trusted initial namespaces, all startup
allocations, actual target repository fit or device rollout.

### Fixed coordinator source bootstrap (inactive source)

`inventory_refresh_root_entry.py` is installed as the fixed `coordinator.py`
entry. Its launcher must admit the entry and trusted OS interpreter before either
executes. Current entry checks require Linux root, exact fixed argv, Python
`-I -B -S`, CAP3/empty inherited and ambient capabilities, NoNewPrivs and the exact
coordinator cgroup. Environment becomes a fixed PATH/locale. These checks cannot
prove initial host namespaces, prior startup allocations or already-executed entry
provenance.

Only stdlib loads before the fixed project source bundle. Every root-owned,
single-link bounded source and full library ancestry is pinned; all modules are
compiled before a final whole-batch FD/named-reference/ancestry fence and any
project execution. Entire-batch module collisions are rejected first. Failed
execution removes only exact module objects installed by this loader, and a
bundle cannot be retried. No project search path or bytecode import is used.

Main creates the fixed runtime and polls every 250ms. Admission, step, sleep or
cleanup failure exits with static code 74, without reopening or retrying work.
Physical guardians remain independent of this parent; interrupted started work
requires existing explicit reconciliation at the next startup. No service is
enabled by adding this source.

The native fixture pre-admits the actual entry, then exercises its actual bundle
loader and a finite actual-runtime proof under `-I -B -S`.
`fixed_publisher_root_bootstrap_verified` covers that loader path; it does not
claim that the fixture ran production main/profile admission or its infinite loop.
Those entry/provisioning and target/client rollout gates remain separate.

### Actual entry loop disposable proof

A separate GHA-only proof launches the pre-admitted exact coordinator entry under
its fixed CAP3 profile with `-I -B -S`. A real restricted reporter process validates
its numeric UID/GID, empty groups/capabilities and NoNewPrivs, then writes only
atomic bounded nonce files in the two existing observation/release inboxes. The
proof requires an actual opened lease, verified cache indexes and accepted receipt
before changing the disposable synthetic policy to invalid data. This exercises
ordinary policy refusal and exit 74, without new signals or pressure workloads.

Restoration is latched before any truncating policy write. Exact invocation,
retained inert unit, pinned empty cgroup, writer exclusion and journal lock release
must be confirmed before restoring/fsyncing the synthetic policy; a wrapper exit
alone is insufficient. The main must already have persisted uncertainty while
preserving successful refresh and accepted receipt. Only that same owned inert
unit may then be acknowledged. The proof's
`fixed_coordinator_entry_loop_and_controlled_policy_refusal_verified` flag covers
actual main, polling and controlled refusal; it is not a successful normal-shutdown
or complete provisioning/startup-allocation/target-fit readiness claim.

### Inactive helper source artifact

`scripts/package-inventory-helper.py OUTPUT_PARENT` builds a separate helper
archive without installing or enabling anything. It pins one full Git commit,
reads every regular source/doc/builder blob by that commit, rejects relevant dirty
files, and derives the exact known root module closure from a strict literal AST
without executing project code. Unrelated worktree changes are excluded.

The archive contains fixed relative readonly regular files: root modules, the
coordinator, worker, identical native/guardian observation entry copies and this
public contract. It contains no account, service, policy, key, runtime state or
installation hook. Sorted USTAR metadata and gzip filename/mtime are fixed;
`manifest.json` records source commit, builder digest, file hashes/sizes/modes and
literal install destinations. The Python 3.10 language floor is not proof of
systemd, kernel, python-apt, architecture or real-device repository compatibility.

Archive and SHA sidecar are fully staged before exclusive generation publication.
Final hardlinks never overwrite existing files. Failed publication removes only
matching owned inode references; foreign replacements are preserved. A generation
is consumable only after the build succeeds and both files/checksum validate.
Unknown descriptor cleanup is reported as failure. CI uploads this distinct source
artifact only after native checks and successful build, with no permission or
default reporter/executor package changes.

Digests establish integrity, not authenticity. PR artifacts are for review; actual
delivery must select a trusted main-pipeline source/artifact/digest and follow the
disabled provisioning workflow. Initial namespaces/unit provenance, reserved
identities, complete startup resource charging, real repository/headroom fit,
client/helper integration, enrollment/pilot and explicit source handoff remain
activation gates. Building this archive does not satisfy them.

### Generation-bound noncredential reader policy

A refreshed index alone is insufficient for trustworthy candidate comparison.
The reader must also use the admitted architectures, source definitions and pins,
rather than host APT defaults. The root policy guard renders an immutable
noncredential projection for exactly one chosen cache generation and opaque policy
commitment. Storage rejects cross-generation/policy substitution before sealing.
Worker-created `_inventory-reader` entries are rejected; only root adds the fixed
readonly reader files/empty directory, counted inside existing byte/inode limits
and hashed into the completed generation before pointer publication.

The fixed reader APT_CONFIG redirects both config parts and main before normal
loading, clears binary overrides, selects that generation's lists/source/pins and
actual native installed status, and disables binary cache/log writes. Source and
pin definitions are reporting operational metadata; auth, proxies, commitment key
and private credentials are omitted. No update/install command is added.

The internal framed policy-commitment schema now includes the static reader
template and reserved namespace (schema 2). Expanded random generation paths are
not part of policy identity. Template/namespace changes therefore invalidate prior
policy generations; old cache evidence cannot silently adopt new semantics. Public
status and private journal schemas remain unchanged. Projectionless legacy/test
generations are unsupported by the new reader, with Unknown candidate reliability.

Pure/descriptor tests cover exact bytes, credential exclusion, immutable bindings,
worker collision and resource bounds. Native candidate/pin and config-loading
behavior must pass under the restricted reader identity before any freshness claim.
The executable reporting client remains disconnected from this projection until
its native scan/receipt and durable lifecycle integration passes.

### Shared installed-state data fingerprint

`installed_fingerprint` exposes the unchanged bounded v1 dpkg status/arch/updates
hash for a borrowed admitted directory. It acquires no package/executor lock,
changes no mutex and never closes the borrowed directory. A standalone hash can be
computed without owning native locks; it is neither attestation nor coherence or
freshness authority. The root `NativeReadLocks` wrapper still verifies its actual
held descriptors before and after hashing and rechecks its deadline after final
verification. Existing native lock ownership and exact digest framing remain
unchanged.

A future unprivileged collector must bracket the entire scan and both hashes with
native boot-relative time, pin the exact generation, and require both hashes to
match both final root receipt hashes with the entire interval inside confirmed
lock coverage. No receipt, mismatch or uncertainty can become fresh evidence.
This data seam alone does not enable a reporting capability.

The native restricted-reader proof now admits the actual fixed shared hash module
from root-owned stable source descriptors without a project search path. It
brackets both fingerprint computations and the isolated candidate query with the
same kernel boot/BOOTTIME clock, retains its own generation lease, and returns
only a bounded internal hash/timing envelope. The parent requires exact context,
all four reporter/root hashes equal, and the entire interval within the final
root-held endpoint before recording success. This is a native proof prerequisite
for the still-disconnected production collector/adapter, not device activation.

### Inactive reporter reader-session library

`ReaderSession` pins and verifies the exact current generation, including all six
manifest-bound reader files and the same-filesystem, read-only empty config-parts
directory, **before** the caller requests a root observation. After an exact opened
lease is admitted, a one-use callback must durably record the actual scan start
before the first installed-state read. Both bounded data fingerprints bracket all
collector reads. Evidence is returned only after an exact released root receipt
matches the frozen context, all four hashes and the entire scan interval, and the
session has successfully closed its own generation pin. Receipt release cannot
be in the future relative to the current same-boot clock.

Invalid state, clock rewind/change, expiry, callback failure, changed data, missing
receipt or close failure consumes the session. None authorizes replay, reports
refresh success, or proves clean failure of possibly submitted root work. Cache
and dpkg directory descriptors remain borrowed; the session never accesses package
lock files, submits inbox requests, executes commands or publishes reports.

This library is not an executable adapter or part of the installed root source
closure. A fixed adapter must still authenticate root status/ancestry and the
native clock, persist observation intent, supervise the reader and use the existing
Rust collector inside the admitted interval. Request capabilities remain disabled
until that adapter and durable publication/recovery integration are verified.

The request journal also has a two-phase native collection admission seam. It
atomically persists `submitted=true`, `Running`, `scan=null` and a reserved root
observation nonce before returning a private, non-cloneable intent. Report ID,
sequence, source, request, boot and negotiation identity are frozen in that
same-run intent. Only consuming that intent on the original journal epoch can
persist the actual later scan start; the fixed adapter must first admit the
opened root lease. Every mutation/recovery attempt revokes outstanding intents,
and reopening an identical journal cannot recover them. A dropped intent or a
crash leaves submitted work unresolved, never permission to resubmit. Failed
persistence returns no authority and poisons the journal handle.

This seam uses the existing private journal schema: interrupted submission with
no scan is already an unresolved state. It has no native invocation and remains
behind the existing inactive request integration. Neither an admission token nor
an attached scan proof supplies native coherence or report-ready authority.

`StatusReader` supplies the inactive reporter's bounded protected-file input. It
holds its own duplicate of an admitted status-directory descriptor and checks the
root publication's exact owner, reader group, modes, single-link regular-file
shape and same-filesystem identity. It keeps the opened file through strict JSON
and schema parsing, then compares descriptor and named metadata. Concurrent root
replacement or in-place modification rejects that read; a fresh poll can observe
the new publication. Missing status returns no status after rechecking directory
protection. Previous content is never substituted, and absence proves neither
root termination nor clean native cleanup. Close failures prevent output.

The borrowed-directory constructor does not establish full named ancestry or
process provenance. Its fixed factory and source bootstrap remain deferred until
the restricted managed bridge is implemented and natively verified. It writes
no inbox, starts no process and changes no reporting capability or artifact.

Protected atomic replacement has a narrowly typed `publication_changed` result:
the old opened file retains its protected metadata/content shape (allowing only
unlink's link-count/ctime changes), while the final named file is a different,
independently protected root inode. No old status is returned. A bounded poll may
read a new file without re-pinning or replaying any native request. Malformed
bytes, unsafe metadata, in-place changes and cleanup errors remain fatal.

The additional disposable Linux roundtrip uses the actual status/session
libraries in one persistent restricted reader. Its pinned-context phase precedes
root observation submission; scan completion precedes root release. The final
phase follows receipt matching and every reader-owned close, with bounded phase
output, EOF and successful exit required by the parent. Its eight-module source
subset and admission callback are trusted test fixtures, not a production
bootstrap or durable reporting-journal proof. Native pipeline execution is
required before treating this roundtrip as verified; broader activation gates
remain unchanged.
