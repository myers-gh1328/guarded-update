# Isolated inventory metadata helper

Approved next slice: fixed unprivileged refresh worker/root publisher under the device-agent reporting design. No endpoint activation, package upgrades or changes to host APT/executor metadata. Reporting-only v0.1.9 is already released; this branch begins from that released source.

Current step: `docs/inventory-refresh-contract.md` drafts bounded trigger/status/cache leases and observation-lock contract plus test-first implementation checklist. Parent can prepare server refresh reconciliation/outbox against the contract, but integration and deployment wait approved dependencies. Independent review required before privileged behavior is implemented.

Open review focus: fixed observation lease/native read-lock coordination, request deduplication across reboot, status persistence versus disposable cache, root FD publication/race resistance, strict host APT-config exclusion, cgroup+tmpfs accounting/fit. No helper executable or service exists on this branch yet. No live device changes.
