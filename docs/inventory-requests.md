# Negotiated inventory request client foundation

The request journal, protocol parser and native clock are staged library code.
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
