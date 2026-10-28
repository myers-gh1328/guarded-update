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
bounding masks exactly those four capabilities, inherited/ambient SETUID only,
and NNP=1. After setpriv, all five worker capability masks must be zero. The
namespace and device restrictions remain part of the service profile.
