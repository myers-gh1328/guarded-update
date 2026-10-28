# Reporting-only inventory agent

`command-center-inventory` is a separate opt-in executable built with the
`inventory-agent` feature. It links no updater, approval, root-executor or AI
modules. It does not replace `guarded-update`, its Homebrew link, its keys or its
schedule. No account, service or key is created by the archive or build.

## Collection and coverage

One `sync --config PATH` invocation signs a check-in, collects due inventory,
then attempts delivery. A managed five-minute launchd schedule keeps reporting
independent of the daily collection interval. Daily collection keeps replacing
the local latest report during controller outages after the first successful
check-in established source authority. Initial collection waits for that first
check-in. New authority revisions trigger a fresh report. The server determines
fleet and active source; the client cannot select either.

Daily collection includes up to 30 minutes of jitter. A long-running collector
runs separately from its heartbeat loop, which keeps sending collecting-state
check-ins every five minutes. Root execution of reporting commands is rejected.

The collector reads `system_profiler SPApplicationsDataType -json`, `sw_vers`,
and Homebrew installed/outdated state. It sets Homebrew no-auto-update and
no-analytics controls. It never invokes `brew update`, installation, upgrades,
restarts, SSH, sudo or macOS system-update installation. Metadata refresh is
explicitly `deferred/not_configured`; cached metadata may miss newer updates.
Only an explicit installed-version match in Homebrew outdated data establishes
an available update. Every other latest-version comparison remains unknown.
System Information failure preserves independently readable Homebrew inventory
as partial. Manual/portable applications and other users' inaccessible apps
remain coverage gaps. System updates, CVEs, service telemetry and logs are not
currently collected. macOS system updates remain report-only in the updater.

Application-identification evidence matches the existing macOS collector, so
third-party System Information apps, Homebrew casks and recognized service
formulae appear in Command Center's default Applications & services view.
Unreadable Homebrew inventory marks the report incomplete; it must not replace
the previous complete central inventory with an apparently empty provider.

## Identity and managed installation

Use the hosted `command-center-inventory-vVERSION-aarch64-apple-darwin.tar.gz`
artifact and verify its published SHA-256 before installation. Local builds are
for development, not deployment. The archive contains a reporting binary,
documentation and inactive examples; it never starts launchd.

Provision a dedicated unprivileged reporting account, separate from the
Homebrew owner and existing updater account. It must have no administrator
rights, sudo rules, updater private-key access or write access to Homebrew's
prefix. A Homebrew-owner LaunchAgent can install packages with that user's
existing authority: merely running read-only commands does not create a
restricted identity. Do not claim that arrangement is privilege-separated.

Administrative installation of the restricted account, root-owned executable
and LaunchDaemon is a provisioning prerequisite; this binary has no privileged
broker. Check access to the existing Homebrew executable/repositories and
System Information from that exact account. Never broaden ownership or add
general sudo to make collection work. Report unavailable user-context coverage.
Homebrew may require a writable account-specific cache; do not share the
updater's writable metadata/cache. Refresh helpers and exact update execution
need a separate reviewed mechanism; neither is supplied here.

Copy the synthetic TOML/plist examples into managed private configuration only
after replacing their identities. Generate a fresh P-256 reporting key on each
device, register only its public half with Command Center for inventory purpose
and a server-issued enrollment generation. Never copy an updater private key or
send a reporting private key to the server. The enrolled hostname must match
the collector's actual hostname. Provision owner-only (0700) state/config
directories and 0600 config/key files, owned by the reporting account. All
ancestors must be real directories, owned by root or that account, without
group/other writes (root-owned sticky temporary ancestors are accepted in tests).
Use canonical absolute paths; symlinked paths and parent traversal are rejected.

Run `initialize --config PATH` once as the reporting account for a newly issued
enrollment, then run one `sync` before enabling the managed LaunchDaemon. Never
initialize an existing enrollment after sequence loss; obtain a new enrollment
and revoke the old one. Initialize refuses existing state/report files. Source
switching, reporting registration and route authorization remain server-owned.

## Persistence and delivery

Only `latest.json` retains inventory. A completed collection atomically replaces
it even when its predecessor was unacknowledged; there is no historical backlog.
Private temporary replacement files are fsynced and renamed, then the directory
is fsynced. Allow space for the existing report plus its replacement (up to
16 MiB), a small schedule file and lock. The encoded JSON report limit is 8 MiB.
Sequences are durably reserved before collection; crashes may create gaps and
never reuse a sequence. Missing/corrupt schedule state fails closed and requires
operator reconciliation/re-enrollment. A corrupt latest report still permits
an error-state check-in without resetting the sequence. OS advisory locking
prevents overlap and releases automatically on process death.

Delivery uses a fixed HTTPS origin, verified TLS, no redirects, curl/OpenSSL,
P-256 and the purpose-bound `command-center-inventory-v1` signature domain.
Each request uses a new timestamp/128-bit nonce while retries preserve exact
report bytes, identity and digest. Reports are acknowledged only by receipts
matching enrollment, report ID, sequence and SHA-256; an old acknowledgment
cannot clear or mark a newer report delivered. Successful reports stay as the
single latest local snapshot. HTTP 408/429/network/server failures retry from
five minutes to one hour with jitter and numeric Retry-After (up to one day).
Other 4xx responses hold that report visibly until a new daily/source collection
or operator reconciliation; check-ins continue independently. A receipt from a
check-in recovers a lost successful upload response without resubmission.

The managed schedule staggers host activation. The current interval is five
minutes; per-host launch offsets should avoid simultaneous fleet checks. Tool
output/input are bounded, child environments omit inherited credentials, each
tool has a 120-second deadline and HTTPS uploads have a 90-second deadline.
Only static diagnostic categories reach the existing redacted output layer.

Disable the managed LaunchDaemon to stop collection/check-ins. Revoke the
reporting public key/enrollment server-side to invalidate requests. Neither
operation changes the existing updater or its pending transactions. Restore
only the latest report plus its matching sequence high-water mark; never roll
back a sequence counter alone.

## Homebrew preparation and drift verification

The reporting-only executable also exposes local read-only provider preparation:

```sh
command-center-inventory prepare --provider homebrew_formula --selection all
command-center-inventory prepare --provider homebrew_cask --selection app-one,app-two
command-center-inventory verify-preparation --provider homebrew_formula --selection all --snapshot /absolute/private/preparation.json
```

Preparation reads installed JSON and cached outdated metadata, applies local
pin/multiple-version exclusions and records observed installed/target versions,
recipe and bottle/cask artifact metadata, plus canonical state/metadata digests.
Versioned and tap-qualified names are supported. Selected missing/non-outdated
packages fail explicitly. Keep saved snapshots owner-only. Verification rejects
expired/future/overlong snapshots and any provider, selection, package, pin,
installed-state or metadata drift. Snapshots expire after 15 minutes.

`execution_supported:false` is mandatory. These are observed artifact candidates,
not verified downloaded archives or a frozen native dependency transaction.
Homebrew's current-recipe `upgrade` plus a post-install version check cannot
enforce an exact reviewed transaction. Exact dependency closure, immutable
recipe/artifact materialization, service impact and cask privilege constraints
must be proven before central execution can be advertised. This executable has
no install/execute operation and no central preparation polling capability.
Command Center must not advertise remote Brew actions from inventory alone.

## Linux reporting

The same separate executable supports Linux from version0.1.9. Static musl
archives cover ARM64, x86-64 and ARMv6 hard-float (also usable on ARMv7).
No host C-library upgrade is required. Verify the published SHA-256 and the
native executable version before provisioning. The hosted pipeline compares
native Linux reports with dpkg and starts cross-builds under QEMU, including
an ARM1176 CPU. Emulation is not a substitute for native device verification.

Linux collection reads dpkg installed package identities/versions/architectures,
APT cached repository-backed candidate observations and holds, and visible
.desktop launcher ownership plus recognized server applications. It never
refreshes APT, downloads packages, installs, restarts or reboots. APT cache-file
write destinations are disabled. Repository URLs and tool stderr are discarded.
The oldest readable cached binary-index timestamp is an observation only.
Until a separately reviewed metadata-refresh helper supplies trusted evidence,
all package currency remains Unknown even when a cached candidate is displayed.
Missing policy/desktop evidence does not erase a successfully collected dpkg
inventory; failed or malformed installed inventory is incomplete and preserves
the previous complete server snapshot. Other ecosystems and user/portable
installs remain explicit coverage gaps.

Install the root-owned executable at a separate path such as
`/usr/local/libexec/command-center-inventory`, never `/usr/bin/guarded-update`.
Provision a dedicated non-login unprivileged reporting identity with no sudo,
capabilities, updater-key access or package-manager write permissions. Use its
own 0600 reporting key/config and 0700 state directory. Generate the key on the
device; only its public half is registered centrally. The inactive Linux
service/timer examples contain hardening and five-minute check-in scheduling;
no archive or program enables them. First initialize the server-issued
enrollment once, then verify one signed read-only report and its durable
receipt before enabling the timer. Source comparison/review/switch remains a
separate server operation, never implicit in successful delivery.

Version0.1.9 sends x-device-body-sha256 for cryptographic admission before body
upload. That advertised exact-byte digest is already the final line of the
unchanged signed canonical message; the server verifies the header signature
first and the uploaded bytes afterward. Older clients without this header must
not activate against the reporting API that requires it.

## Staged request timing

Request journals and native timing remain disconnected from runtime capability
advertisement until lifecycle and native observation integration pass. No request
capability is enabled by installing this source.

macOS samples its boot-session UUID and
[CLOCK_MONOTONIC_RAW](https://github.com/apple-oss-distributions/Libc/blob/main/include/_time.h)
through the fixed native nanosecond API. Apple documents this as continuous timing
including sleep. Linux uses the approved helper profile's system Python3 in
isolated mode to sample the kernel boot ID and native CLOCK_BOOTTIME, avoiding
32-bit libc time_t/time64 ABI assumptions in static ARM builds. The fixed probe
has a five-second timeout and 256-byte output bound. Neither platform derives
proof timing from wall-clock subtraction or logs actual clock/boot values.
Linux-native clock execution must also pass hosted Linux CI before activation.
