# Inventory metadata helper — source foundation

This pull request supplies an opt-in Linux inventory metadata refresh helper as
an isolated source foundation. It does not install or enable a service, create
accounts or credentials, change host APT configuration, install or upgrade
packages, reboot a device, or grant execution authority. Runtime deployment and
endpoint activation are separate work.

The branch contains the fixed low-privilege metadata worker; trusted policy,
resource and journal guards; generation publication; native observation and
lease handling; the fixed coordinator and reporter inbox dispatch; and a
reproducible, inactive source archive. The public contract describes the exact
boundaries and outstanding integration gates in
`docs/inventory-refresh-contract.md`.

The hosted ARM64 Linux job exercises synthetic signed TLS repository acquisition,
separate UIDs and cgroups, native lock observation, the fixed coordinator entry,
and inactive artifact packaging. These are disposable-runner checks, not evidence
of real-device resource headroom or repository compatibility. The native proof
explicitly does not claim guardian-death or OOM fault coverage. Independent review
of this foundation is required before merge.

Before activation, establish trusted initial namespaces and service/unit
provenance, reserved account identities, complete startup allocation accounting,
actual target repository and resource fit, reporter/client integration, and
reviewed provisioning and pilot rollout. Preserve the current service and prior
metadata on uncertainty; the helper must not replay interrupted work. A
successful source artifact build alone does not satisfy these gates.
