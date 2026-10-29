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
