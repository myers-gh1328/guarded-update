# Negotiated inventory request client foundation

The request journal, protocol parser, native clock and collection lifecycle are staged library code.
The executable does not advertise request capabilities or start requested work
until its runtime lifecycle and native observation integration are verified.
Installing this source does not enable a request capability or grant update
execution authority.

## Negotiation and identity

The existing signed inventory purpose remains independent of update execution.
Advanced check-ins add `capabilities` and `collection_result` to the existing six
fields. Supported protocol names are `inventory_refresh_v1` (manual metadata
refresh plus inventory) and `inventory_collection_v1` (inventory only). A local
session intersects advertised and controller-supported capabilities and also
requires `requests_enabled`. macOS never advertises the Linux metadata helper.

Parse the exact retained JSON response bytes, with required explicit nulls,
known fields and bounded safe integers. Unknown/duplicate fields, unsupported or
paused deliveries and collection/source mismatches cannot authorize starts.
Only an explicit typed JSON `invalid_check_in` rejection permits a new legacy
check-in. Authentication failures, redirects, HTML and arbitrary errors do not.
Legacy fallback never rewrites an existing package report.

## Durable metadata

A private, versioned `requests.json` is bounded at 64KiB. It retains active and
last-terminal metadata per capability, delivery high-water marks and independent
helper, collection and observation counters. It never stores package inventory.
The existing schedule format and single `latest.json` body remain separate.

Initialization is explicit provisioning for a new enrollment with trusted root
counter seeds and no unresolved old operation. Runtime opening never creates,
repairs or resets the journal. All access borrows the inventory process lock;
cached handles also compare exact persisted snapshots under an in-process mutex.
Stale/uncertain handles fail rather than overwrite counters or newer outcomes.

Admission burns the delivery high-water mark and operation counter before
returning. Persist the controller's matching received acknowledgement before
`begin` can return the one-use local operation nonce. Repeated delivery, reboot,
paused support or lost outcomes never allocate another start for that attempt.
A forgotten ID at/below the high-water mark requires explicit reconciliation.

## Proof and publication ordering

Proof parsing verifies schema and ordering under endpoint trust; it is not remote
attestation. The Linux adapter must verify actual root helper, reader and native
observation receipts before constructing manual evidence. Inventory-only proof
has its own boot, acceptance and scan sequence/start/finish and no metadata-helper
success requirement. Installed-state coherence remains a rollout prerequisite.

Reserve the report sequence and persist start identity before collection. Encode
the report once, compute its exact hash, and use `bind_ready_report` to merge
finished proof and its report ID/sequence/hash in one journal commit. Ordinary
collection `progress` cannot persist finished evidence without that binding, and
startup rejects such inconsistent state. `replace_encoded` publishes those same
bytes to the single latest file without reserialization. It requires the correct
enrollment and a reserved sequence, refuses head rewind and rejects changed bytes
at an existing sequence. Neither a retry nor an old acknowledgement replaces a
newer retained report.

If bound ready bytes are lost across publication, retain supersession metadata;
never regenerate a package snapshot. Supersession is absorbing across every local
mutator, including generic failure/uncertainty handling. Only matching canonical
terminal reconciliation can close that unchanged entry. A receipt alone is not
completion; canonical Complete must bind the report, nonce and accepted receipt.
An older canonical outcome never clears a newer active request or report.

A local failure before received acknowledgement has no submitted work and emits
Failed with its nonce but null attempt/report. The controller can close only that
never-acknowledged delivery, retaining a nonce/counter replay tombstone. Once any
start authority is acknowledged, labels alone cannot authorize a replacement.

## Runtime integration gates

One coordinator must own Schedule and RequestJournal writes under the same lock.
A request arriving during a scan waits for a fresh follow-up. An unfinished or
uncertain submitted attempt cannot be treated as stopped merely because the
process lock reopened. Disabling the feature or losing a native clock suppresses
new starts while retained metadata and immutable reports remain reconcilable.
Manual support remains unavailable until actual helper/observation integration is
verified. No arbitrary commands, paths, packages, policies or installation grants
are accepted from a request.

The Root journal can produce a locked, read-only internal projection of its
epoch and separate refresh, observation and release counters when no operation
is active or globally unconfirmed. The projection is not published to the agent,
does not reserve a nonce, and cannot initialize or authenticate an enrollment.
An unregistered Root journal operation can admit a proposed exact next nonce
against that locked snapshot. Its `received` record is durable but revocable;
it authenticates neither the supplied context nor the agent and does not grant
start authority. It has no runtime, client, CLI or provisioning entry point.

### Counter allocation integration boundary

The Root coordinator owns its durable counters and holds its journal lock for
the runtime lifetime. The inventory agent separately owns its request journal
under the inventory lock. A counter snapshot is immediately stale once other
Root operations can run, and an existing Root `received` record can be replaced
by a later higher nonce. Neither is an exclusive reservation for an agent.
Holding the service lock excludes other lock holders; it does not stop the same
dispatcher from processing a conflicting inbox while an exchange is in progress.

A future allocation exchange must authenticate the requesting agent and bind
its enrollment to the Root epoch. It must also define a single global lock order,
retain bounded service availability, and establish the shared nonce rules for
observation and release. A candidate flow is:

1. Root proposes a nonce under its journal's current counter state. The proposal
   does not authorize a process launch or establish a reservation.
2. The agent persists its exact intent under its own journal lock before sending
   an acknowledgement. It retains an uncertainty fence if the exchange fails.
3. Root durably admits the exact nonce before acknowledging admission. The agent
   cannot treat a missing acknowledgement as proof that admission failed.
4. Before a process effect, the agent durably persists its own submitted state;
   uncertain persistence authorizes no effect. Root revalidates the exact admitted
   record and persists its start under its journal lock. The two journal commits
   are not atomic. A later higher nonce may have superseded the earlier received
   record; an old acknowledgement is insufficient.

This flow is not implemented. A Root service waiting for an agent could starve
its dispatcher or deadlock against the agent lock. A viable implementation needs
fixed authenticated single-flight nonblocking transport, a separately supervised
bounded BOOTTIME deadline, and confirmed owned cleanup. Timeout alone proves no
cleanup or lock release. Transport ownership, epoch binding, lock order and
dispatcher fairness remain unresolved.
Crashes before or after either durable write, lost replies, reboot, duplicate
clients and supersession must retain uncertainty rather than retry a launch.
No journal seeding or runtime activation follows from this proposed flow.

The internal Root dispatcher has a one-way drain mode for an eventual
maintenance owner. It stops admitting new refresh and observation requests,
but can finish the matching release of an already owned observation. Its
`drained` result requires no active or unconfirmed journal entries, no owned
observation scope or pin, valid inbox reads, and revalidated policy and resource
context. It is not wired to a stop
request. The internal runtime rechecks its admitted context and retains its
Root journal lock while draining; neither result proves process-set emptiness,
lock release, or maintenance
ownership. Valid unstarted requests can still remain in the inboxes; a future
maintenance owner must fence producers and reconcile those files before
switching modes. Those remain separate requirements before publishing a binding.
Coordinator startup rejects any `maintenance.pending` entry, or an uncertain
read of that entry, before constructing action-capable components. This
sampled check does not stop reporter starts or prevent concurrent publication.
The marker has no automatic removal; startup requires explicit reconciliation
when it is present. Its absence does not resolve an uncertain prior write.

### Enrollment and Root epoch binding

The current Linux provisioning workflow generates the reporting key on the
device, hands its public half to the operator, and receives an enrollment UUID
after that key and device identity are registered with Command Center. The
Root-owned `initialized-enrollment` file is currently a historical recovery
marker: provisioning checks whether it exists, not that its contents match the
active server enrollment. It does not bind the reporting key to the helper epoch.

A proposed first-binding ceremony would use an authenticated operator and
trusted provisioning controller to compare one server observation of the active
device, fleet, boundary, enrollment, key ID and public-key fingerprint with the
device-generated public key and expected registration. It would run only in maintenance after preventing service and timer
restart, proving the owned process sets empty, and acquiring the Root and agent
journal locks in a separately reviewed order. Before publishing, it would
revalidate the protected Root journal epoch, enrollment marker, agent schedule
and reporting key. Agent-owned key bytes require an explicit ownership and lock
boundary; the private key must not be exported.

The proposed record is a separate, fixed Root-owned, read-only binding of the
device, enrollment, key ID, key fingerprint and Root epoch. Initial publication must use
exclusive nofollow creation, verified bytes and metadata, file and directory
durability barriers, and no-replace publication under protected ancestry. A
partial write, changed input, uncertain close or durability barrier is not
success. A lost reply after publication requires full current-state validation
and explicit recovery; merely finding identical bytes does not repair prior
uncertainty. Existing journal counters and reports must not be reset.

This ceremony is not implemented. Rotation and re-enrollment remain fail-closed
until their own two-phase procedure preserves counter history and proves old
work stopped. The server observation is only current at its observation point;
the policy for later revocation, key replacement and offline operation remains
to be defined. A Root-owned record alone does not authenticate a client or
grant request execution authority.

Linux sync inspects an existing request journal under its inventory lock before
starting a daily collection. A pending journal replacement, invalid or unreadable
journal, or retained manual or collection work defers that collection and
reports an error on check-in; retained uploads and check-ins continue. The fence
does not change the journal or initialize missing counters. A genuinely absent
journal and pending file retain the existing scheduling behavior. This is a
conservative transition: unacknowledged received deliveries and terminal failed
or expired deliveries with no work evidence no longer block collection; their
request metadata remains intact. Any completed, acknowledged or uncertain work still prevents a
daily collection until a later reconciliation implementation can safely clear it. The
fence does not prove processes have stopped or enable device requests.

## Collection lifecycle implementation

The staged coordinator opens the journal under the existing process lock. It
recovers matching retained bytes as ready, missing/different ready bytes as
absorbing supersession, and unfinished submitted work as unconfirmed. A logical
source cancellation does not prove native cleanup; the physical-work fence also
survives canonical terminal state and restart.

Collection starts require a fresh negotiated session, a matching persisted
controller acknowledgement, the admitted source revision and native boot identity.
One atomic journal commit freezes the scan identity and submitted marker before
returning an opaque, one-use start token. Check-in responses received during that
scan cannot replace its purpose. Authentication or malformed acknowledgement
failures invalidate cached start negotiation while retaining frozen metadata.

The finished token binds the exact encoded report before single-body publication.
Consuming that token ends the live execution exclusion even if publication fails.
Actual protected retained bytes determine ready versus superseded recovery;
unreadable state or uncertain persistence blocks starts while metadata remains
reconcilable. No missing inventory body is recreated.

Daily collection uses the same exclusive coordinator scope. It first persists a
supersession notice before replacing ready request evidence, refuses unresolved
native work and keeps new request intake outside the daily scan. The daily output
cannot be retroactively assigned to a request received during collection. Runtime
configuration, executable wiring and native observation verification remain gates;
this library slice alone does not enable device requests.

## Native observation and release staging

Private client journal version 2 retains a required nullable `native_attempt`.
Its observation nonce, boot identity and admission time correlate one Root scope;
its required nullable `release_requested_boottime_ms` freezes the first cleanup
intent. These are recovery metadata, not authority to restart an observation.
Runtime opening rejects earlier or incomplete journal formats without changing
their bytes. Root journal, public status and report schemas are unchanged.

Native collection admission first commits the submitted marker and observation
counter. A separate one-use publication gate checks the current negotiation,
boot, journal snapshot and process-lock ownership before the fixed bounded
nonce-publication callback. Only its successful return yields the token accepted
by native scan attachment. Generic progress and report binding cannot introduce
the first native scan. Scan attachment still requires the adapter to verify the
actual Root opening before any OS reads.

Release preparation persists the first cleanup-intent time before any release
publication. It revokes earlier work tokens and remains available for the exact
retained scope after logical source cancellation, canonical failure or reopening.
It never allocates a new observation nonce. A separate one-use release gate checks
the persisted scope, boot, monotonic time and snapshot before and after its fixed
callback. Repeated preparation preserves the first time. That time describes
local intent, including release of an observation still pending at Root; it does
not assert that Root opened or accepted anything.

Both callbacks run while the existing process lock and journal mutex protect the
snapshot. They must finish at bounded fsynced nonce publication and must not call
any journal operation, even through another handle, or wait for a lease, scan or
receipt. The trusted bridge must bind the release callback to the literal release
port. These staged APIs alone do not enforce that external binding.

Publication failure, missing status, elapsed time or a release file cannot clear
the physical-work fence. Even successful release publication leaves the attempt
unfinished until verified Root cleanup and all reporter-owned resources closing
can be bound to that exact scope. There is no cleanup-completion transition in
this slice, and no executable, capability advertisement or device activation.

The staged reporter session exposes a fixed APT policy query during its
admitted scan. It accepts at most 300 distinct canonical binary package IDs and
selects the immutable generation's `APT_CONFIG` internally. It accepts no caller
command, option, environment or path. Root-owned ancestry and the held generation
identity are checked around the query, alongside the reader projection and boot
clock. This does not read host APT lists or refresh metadata.

Output is streamed with a 16MiB per-query bound and cumulative 64MiB/67-query
session bounds. Each query has at most ten seconds and stays within the original
Root lease, reserving one second for later finishing/release. EOF and successful
direct-child exit are both required; failure consumes the session. Cleanup closes
owned resources and uses a bounded wait for the directly owned child. It cannot
prove descendant teardown or Root cleanup; the managed reporter's cgroup and
receipt gates remain required.

Four additional reads accept no arguments: installed packages, native package
architecture, holds and desktop package ownership. Each can run only once per
scan and shares the same aggregate output and original lease budgets. The dpkg
commands explicitly select the fingerprinted `/var/lib/dpkg` database. Fixed
per-operation output caps are 8MiB, 128 bytes, 1MiB and 1MiB respectively. A failed
optional desktop lookup consumes this strict session; the future Rust adapter
must explicitly skip unsupported enrichment and retain partial coverage.

Rust normalization integration and production source/bootstrap wiring remain
unfinished. Native verification exercises installed, architecture and hold reads
inside the same fingerprint window as policy. It compares real hold selections
without changing them; a positive nonempty hold or desktop lookup on every target
is not established by an empty runner hold set.

The Rust collector has a test-only selected-generation context that reuses its
existing package normalization. It skips host APT index-age reads and both
optional desktop traversal and ownership lookup. Index age stays null, graphical
coverage stays partial, and server application recognition remains available.
Candidates and holds retain Unknown update status; this context does not verify
a metadata refresh or authenticate native evidence. The default executable still
uses host-cached collection. A managed bridge must place every retained OS read
inside the verified observation interval before this context can be enabled.

The separate staged reporter resource sampler checks current non-root numeric
identity, zero capabilities, no new privileges and exact intended unit membership
before opening cache capabilities. It requires the existing bounded inventory
aggregate and a read-only cache view, including the held FD's read-only mount
flag. Mount geometry, aliases, capacity and ancestor limits remain strict; the
Root publisher's separate writable-view checks are unchanged. Failed checks
poison the sampler, and cleanup attempts every owned root once.

These observations do not prove dedicated NSS account mapping, parent identity,
initial namespace/unit provenance, allocation history, workload fit or native
cleanup. The current baseline reporting unit lacks the requested aggregate
placement and cannot pass this sampler. No unit, mount, account or capability is
changed by the library; full environment and source admission remain unfinished.

After the final fingerprint, the session exposes a copy of its frozen native
scan endpoints for the future coordinator handshake. Reading them does not
recompute the end time or assert Root cleanup; invalid phases, clock uncertainty
or a closed session return no endpoints. Final receipt evidence must preserve
those exact endpoints. The coordinator must still validate and durably bind the
same actual start and end around release before publishing a report.

The staged read-only parent owner first admits reporter resources, then checks
the fixed reporting/refresh NSS mappings, a live derived parent pidfd, consistent
numeric proc/PID-namespace views, and the parent's fixed Root-owned executable.
It deliberately reopens the current Kernel `exe` link around verification; an
old executable FD alone cannot establish current origin. The only proc boot-path
overmount exception is the canonical read-only `/proc/sys` protection. Native
clock reads use the held Kernel boot-ID FD and BOOTTIME, with parent liveness
checked before and after the read. Failures poison the owner and cleanup attempts
all owned capabilities once.

This owner exposes no inventory, source execution, request publication or
completion authority. Same UID remains a trusted-code boundary. It does not
establish initial host namespace, selected release/code-hash origin or fit.
Native verification uses an explicitly synthetic fixed-path C parent to check
these admission mechanics; it does not establish the Rust coordinator lifecycle.

The staged environment composes that parent owner with fixed Root-owned runtime,
status, cache, dpkg and library ancestry capabilities. It exposes protected status
reads and one read-only cache pin, with no caller path, UID, policy or generation
selection. Missing status or the narrowly typed atomic-publication race can
return no status only after parent/ancestry revalidation; every other unsafe
failure consumes the environment. A pin attempt is latched before reading status
or acquiring a lease. Even transient absence during that attempt closes the
environment; a caller can wait through separate status reads beforehand.

Pinned context is detached metadata for the original generation and native pin
time. A newer Root head does not replace that held pin or relabel its policy.
The metadata grants no freshness, observation or coherent-report authority.
Cleanup consumes the session, status reader, reverse ancestry owners and parent,
attempting every close once. The extra native fixture checks this read-only
composition under its synthetic C parent; source bootstrap, runtime wiring and
physical cleanup/publication gates remain separate.

The staged private framing codec accepts only fixed command field sets and
consecutive command IDs. It rejects duplicate keys, nonfinite numbers, numeric
aliases, unknown fields and frames over 256KiB before parsing. Data responses use
numbered chunks of at most 16K codepoints/64KiB UTF-8, with exact final byte and
chunk totals, per-operation limits and a shared 64MiB session budget. A maximum
16MiB ASCII policy response uses 1024 data chunks instead of one large escaped
JSON allocation.

Sender reservation occurs before returning an iterator. An abandoned response
cannot restart or refund its ID, operation or byte budget. Receivers expose no
partial text and retain ownership until a valid final frame is consumed once.
Any malformed, truncated, extra or reordered response poisons the session.
Generating a final frame is local encoding completion, not delivery
acknowledgement. This codec performs no I/O, phase execution, timing validation
or Root effect; the managed dispatcher and coordinator gates remain unfinished.

The staged pipe transport duplicates already nonblocking, directional FIFO
descriptors. It preserves borrowed descriptors and never changes their flags.
Callers must retain their identities and shared nonblocking flags and perform
no concurrent I/O: duplicates share open file descriptions. Checks before and
after I/O detect changes but do not isolate adversarial flag races. Linux pipe
inodes must differ between the incoming and outgoing channel.

Frames are bounded to 256KiB, with at most one overflow byte retained while
checking the first newline; coalesced tails are preserved. Partial writes and
full pipes use the same absolute native boot-time deadline, capped at 120 seconds
from admission and only eligible for tightening. Clock checks bracket polling,
I/O and returns, including buffered reads. Expiry, reboot, rewind, unsafe
descriptors, truncated EOF or uncertain close consume the channel. A write can
fail after bytes reached its peer; it is never an acknowledgement or permission
to replay.

The admitted clock/liveness owner must survive the final frame write. The current
environment closes its parent clock, so a future dispatcher must explicitly
retain or split that late-closing owner instead of using cached time. Transport
and clock still close before exit. EOF, exit status, producer quiescence and all
parent cleanup must be verified separately before any completion witness. Real
pipe tests establish I/O mechanics only; this layer is not wired into production
or the native Root proof source closure.

The staged fixed publication owner admits the environment before constructing
exactly two literal ports: observation and release. It exposes no capability,
path or identity selection. A pin is required before its one observation
publication, and its one release must carry exactly that original nonce.
Transferred fixture capabilities must have distinct correct roles and belong
to the same environment runtime ancestor and current numerical identity.

Each phase latches before effects, with parent and ancestry verification on
both sides. A failed write or postverification consumes every owner, even if
the request file is visible. Release, observation and environment closes are
all attempted once. Neither successful publication nor a logical failure
proves Root acceptance, physical cleanup, cancellation or readiness. The parent
must still hold its existing process lock and use its fsynced journal gate;
these ports supply no durable authorization themselves. Actual inbox write
access requires separately reviewed provisioning under the intended restricted
profile. The owner is not wired into an executable or admitted production
source bundle.

Its staged scan phases now wait for a fresh Root offer matching the bound nonce
and pass the exact proposed native start through a trusted acknowledgment
callback before the first installed-state fingerprint. The future parent must
fsync that exact start before acknowledging it. Missing or unrelated status may
poll within the original budget; a matching nonce with the wrong boot,
generation or policy consumes the owner. Fixed data reads run only inside this
scan. Freeze records the actual final fingerprint and endpoints before release.

The runtime's absolute120second admission budget also reaches every session
fingerprint and query supervisor, even if a later Root lease lasts longer. A
private capped clock latches failure without prematurely closing a running
query's cache pin: query pipes/child and hash descriptors unwind first, then the
session pin and remaining environment close. The public read-only environment's
default pin behavior is unchanged; this composition seam is not a wire clock
or caller deadline option.

Only a frozen scan followed by its exact release can prepare evidence. The
session verifies the own Root receipt, all hashes and actual interval and closes
its pin before returning bounded evidence. Prepared evidence is still an
uncommitted proposal. It permits no further tools or publication, while its
admitted clock stays alive for the eventual terminal pipe write. A cleanup-only
release without a scan cannot prepare evidence. These phase fixtures establish
neither production source bootstrap nor the parent journal handshake, native
Root composition, all-producer quiescence or a completion witness.

The staged managed dialogue now joins these owners over bounded pipes. Its
channel must use this runtime's exact bound clock. One command decoder spans
the nested admission handshake: an actual Root offer produces a proposed start,
and only the next exact `scan_admitted` command for that same start can permit
the first fingerprint. Publication acknowledgements are written before the
dialogue waits for Root. Fixed data responses exhaust their bounded chunk
iterator before accepting another command.

Its terminal `prepared` response carries receipt-checked evidence while the
clock owner remains alive. It then closes runtime and channel, attempting both
even after error. A close failure still fails the dialogue after visible final
bytes; no further command is processed. Caller-owned original descriptors,
child exit, process-set cleanup and durable journal/source gates remain
separate. This is a private capability composition library with real-pipe
fixtures, not an activated executable or native completion proof.

A build-only generator now composes a fixed reporter entry from the existing
Root source loader's exact helper/class segments and a reporter-specific
template. It preserves the Root coordinator and its 28-module closure. The
reporter closure has18 fixed dependency-ordered modules, admitted and compiled
as one batch before any project execution. Generation rejects unexpected AST
shapes, helper/closure shadowing and duplicate markers, and records input,
closure and generated-entry hashes. Artifact integration must still bind the
generator and all inputs to the selected commit; these hashes alone are not
trusted release provenance.

The template requires isolated Python, exact entry arguments, nonRoot saved
identity, zero capability sets, no-new-privileges and current intended unit
membership before project admission. Source owners close before runtime
construction. Both original pipe directions and identities are checked before
nonblocking flags change. Python stream wrappers and inherited raw descriptors
are tracked separately: borrowing wrappers close first, then their original
raw FD closes once after identity revalidation; owning wrappers never trigger
a raw-close retry. Replacement descriptors are preserved, distinct descriptors
sharing an inode remain distinct, and every close is attempted.

The outer entry exits only after explicit cleanup and bypasses later interpreter
flush/finalizer retries. Any admission or cleanup uncertainty yields74, including
after visible prepared evidence. Tests cover clean-process closure imports,
real owned pipe wrappers and silent profile rejection. This generator/template
is not yet packaged, installed or activated. Parent admission of the exact
entry bytes before execution, actual restricted entry/native Root roundtrip,
Rust durable ownership and complete process-set cleanup remain required.

The inactive helper artifact now includes that generated entry and the fixed
Root/reporter module union. It executes only the selected trusted build-time
generator after direct byte comparison of all tested sources against one pinned
Git commit, with replacement objects disabled. CLI isolation prevents local
standard-library shadows. The recipe independently binds generator/template/
loader/closure/output hashes and checks the generated closure itself. This
packages code only; actual entry execution, Parent pre-exec admission and every
activation/completion gate still require separate evidence.

The disposable native test harness now has a read-only artifact verifier. It
reads bounded nofollow archive/sidecar files, limits gzip expansion while
decompressing and rejects truncated, concatenated or trailing streams. It
independently reconstructs the exact complete USTAR bytes from fixed Git inputs,
including canonical manifest/recipe and generated entry. This detects hidden
members or nonzero padding after end markers, duplicate metadata and self-forged
hashes without executing generator/runtime or extracting untrusted paths. It
does not publish files or establish a running reporter/completion witness.

The hosted OBS9 mechanics test remains separate from the experimental process
sample. CI runs the latter in its own disposable job with an explicit opt-in;
a failure remains visible. Its current cgroup mount gate rejects the hosted
runner's writable nested mount. Until effective visibility and confinement are
proved, the process sample grants no completion witness or production authority.
