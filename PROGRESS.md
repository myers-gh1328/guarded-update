# Pi executor rollout in progress

Owner authorized implementation, tests, packaging and deployment to the selected
business Pi. Exact package batch still requires dashboard approval.

Implemented remote-only signed claims, root ancestry/file checks, global lock,
durable consumed claim/nonce/attempt records, terminal results and manual
reconciliation. System Python APT preparation verifies sources, selects explicit
batch+dependencies, refreshes authenticated metadata, enforces signed Date ≤7days
and upstream expiry, and acquires archives as existing _apt. Controller transport
is unprivileged. Local/default builds exclude remote/executor components.

Current checks: 52 executor Rust tests pass (one Linux test ignored locally),
9 Python adapter tests pass; Clippy and formatting pass. Shared Node-generated
P256 fixture verified by Rust/OpenSSL. Disposable actual-upgrade tests and ARMv7
package contents/size checks are wired; First CI: all nine rejection cases held version1; valid authorization upgraded
fixture to version2. APT then reported missing isolated log directory; harness
now creates it. Production-hook cases pending rerun.

Next: run draft PR CI, fix integration evidence failures, then deploy verified
reporting package+keys/controller config. Keep root execution disabled until all
gates pass and exact batch is approved. No Pi package/config changes yet.
