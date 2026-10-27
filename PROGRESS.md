# Isolated inventory metadata helper — PB-0998

Approved scope: fixed low-privilege APT refresh worker, root coordinator/publisher,
read-only completed-generation collector. No endpoint activation, installs,
upgrades, reboots or host APT/executor metadata changes. Public PR23 is a draft on
`codex/inventory-metadata-helper`, based on released v0.1.9 source5c58550. Linux
reporter/provisioning PR22/infraPR208 already merged; six legacy recoveries closed
and fresh. No live reporter/helper is installed.

Current code: strict protocol, FD-only storage, structured trusted APT policy,
private durable root journal and fixed unprivileged worker. Local helper suite33
passes. Policy8/state12/storage4/protocol4/worker5. Worker only executes fixed
apt-get update as isolated ccrefresh, never accepts caller commands/paths/options,
reads admitted root job/config and discards native output. It requires reporter
and refresh UID/GID separation; no root group. Worker is not exercised natively
with APT yet. Root coordinator, request inbox consumption, native observation
locks/receipts, actual signed HTTPS/GPG acquisition and packaging/provisioning of
this new capability remain incomplete.

Independent reviews: contract/protocol/storage clear. Active reviewer
/root/review_reporting_security cleared policy/state after a changed-policy
replay finding was fixed test-first: start requires freshly admitted policy;
successful finish binds publication policy. Coordinator must recheck before
Store.publish. Worker review requested; never treat earlier review as full helper
approval. fsync actual-start authorization before spawning, entire worker cgroup
empty/no same-UID outside writers before sealing, one fixed root lock for every
publish/retire/head change, uncertain cleanup/persistence keeps guard. Observation
receipt must bind exact nonce/boot/gen/policy/expiry and lock-held interval through
final read/fingerprint; post-unlock release time cannot extend that interval.

Hosted native storage-only proof40591927544 passed all14 jobs at232e94f; receipt
/private/tmp/inventory-refresh-storage-proof/native-refresh-storage-proof.json.
Actual128MiB/32768-inode tmpfs,256MiB slice OOM, cross-UID immutable data,
current/staging/leased/open-unlinked byte+inode accounting, old-current retention
and kernel-empty cgroup before unmount all proved. memory_peak256MiB is deliberate
OOM stress, not normal-workload or target repository fit. apt_refresh_exercised=false.
Initial native failures were diagnosed/fixed fixture import permissions and
already-unloaded transient-unit cleanup. All checks through ci_monitor wrapper.

Next: implement native signed HTTPS synthetic repository proof that runs the fixed
worker with actual policy under containment, checks auth/TLS/GPG/expiry/all-repo
failure, host hook/config exclusion, binary Packages acquisition, policy-change
and old-generation preservation. Then fixed root coordinator/observation lifecycle
and native crash/cleanup proofs. No production fit/activation claim from mocks.

Ownership: provider agent handed off policy.py + tests (now ours); do not change
its unrelated work. Mac agent owns portable Rust request state/journal and
mod.rs/state.rs/transport.rs integration in separate worktree. Reserve Linux
collector linux.rs + new linux_refresh.rs and helperPython/native proof here.
Portable journal owns reporter nonce allocation (one helper counter daily/manual,
observation independent; release reuses observation nonce). Root journal only
receives/fences those counters. Never relax reporter-private state::read for root
receipts; Linux adapter needs separate root-owner no-follow reader. Preserve exact
v0.1.9 HTTP wire until explicit per-enrollment new capability negotiation.

Root is implementing PB1003 server request/outbox proof against the stable contract
in docs/inventory-refresh-contract.md. Frozen identity: request/delivery/enrollment/
source revision, local nonce/helper sequence/boot/local acceptance. Later proof
fills null fields only. localAccepted<=helperAccepted<=helperStart<=helperFinish
<=nativeLockOpen<=scanStart<=scanFinish<=confirmedLockHeldUntil<=leaseExpiry.
Final proof binds retained reportID/hash. Integration/deployment waits dependencies.
