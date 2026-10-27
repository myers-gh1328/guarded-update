# WinGet native preparation snapshots

`scripts/winget_preparation.ps1` adds selected and all-eligible **read-only review
snapshots**. It does not download installers, freeze a dependency transaction,
install applications, request elevation, reboot, or grant installation authority.
Remote preparation enrollment and signed execution claims are not implemented for
this provider. Existing discovery-only behavior remains compatible.

## Prerequisites and context

Use already-installed PowerShell 7, `Microsoft.WinGet.Client`, its public
Microsoft.Management.Deployment/CsWinRT projection assemblies, and registered
production App Installer COM classes. Missing or incompatible prerequisites yield
an unavailable result; nothing installs or repairs them automatically. Run as the
intended unelevated Windows user. Built-in service identities and elevated tokens
are rejected. This does not enumerate other Windows profiles.

COM activation uses the production class identifiers published by Microsoft's
factory and public `WinRT.MarshalInterface<T>.FromAbi`; it never reflects private
PowerShell wrapper internals. Public `CatalogPackage.InstalledVersion` metadata
establishes installed scope. `DefaultInstallVersion` supplies WinGet's applicable
upgrade candidate under its native pin and installed-installer policy. A missing
candidate is labeled `pinned_or_no_applicable_upgrade`; the script does not invent
which pin caused it. Version comparison also uses the native API.

Only sources explicitly named by local package policy are consulted. Source
agreements are not accepted automatically, authentication is silent, and catalog
background refresh is disabled. Connecting a catalog/resolving its default
candidate can still consult native source manifests; this is not an offline
promise. Explicit-only sources are rejected in this first adapter. Store
preparation remains excluded. Installer downloads and OS updates stay separate.
The native worker has a 120-second deadline, bounded input/output, and no incoming
service or scheduled task. It strips ambient secret-looking environment variables
and SSH/askpass handles while preserving Windows account and module context.

## Local policy and requests

Create a local JSON policy for the intended Windows SID:

```json
{"schema_version":2,"context_id":"S-1-5-21-123456789-123456789-123456789-1001","allowed_packages":[{"id":"Example.Tool","source":"winget","scope":"user"}]}
```

Every allowed identity binds ID, source display name and installed scope (`user`
or `machine`). A machine-scope snapshot grants no machine installation privilege.
Policy is bounded to 5,000 unique identities; native results are bounded to
10,000 packages. Truncated/ambiguous discovery fails rather than becoming a
partial “all” operation. Exclusions remain visible for all-eligible review.
Selected identities that cannot be established exactly fail closed.

All-eligible request:

```json
{"schema_version":2,"provider":"winget","selection":{"mode":"all_eligible"}}
```

Selected request:

```json
{"schema_version":2,"provider":"winget","selection":{"mode":"selected","packages":[{"id":"Example.Tool","source":"winget","scope":"user"}]}}
```

Run through `pwsh -NoProfile -NonInteractive -File scripts/winget_preparation.ps1
-Mode prepare -PolicyPath <policy.json> -RequestPath <request.json>`.
Store the resulting JSON in a private local snapshot file. Use the same arguments
with `-Mode verify -SnapshotPath <snapshot.json>` for fresh native comparison.
Input shape, actual selection and SID policy are validated before catalog reads.
Do not pass unreviewed local files or interpret snapshots as signed authority.

Snapshots contain exact observed installed/target versions, source name, a hash
of the native source identifier, installed scope, explicit exclusions, account
context, policy hash and state hash. Raw source identifiers/URLs, credentials,
registry paths and native error diagnostics are not emitted. Snapshot lifetime is
15 minutes. Verification rejects changed targets, scope, policy, exclusions or
account context, as well as expired/future/oversized lifetimes.

`execution_supported` is always false. Dependency closure, installer bytes,
installer hashes, UAC/elevation and removal behavior remain unverified. A matching
snapshot says only that the same native preparation evidence was observed; it
never authorizes `winget upgrade --all` or any other installation command.

## Verification limits

```sh
python3 -B -m unittest discover -s tests -p 'test_winget*.py' -v
```

Tests execute PowerShell with synthetic public COM metadata and cover native
candidate exclusions, exact selections, policy/context binding, type validation,
expiry and drift. The Windows CI job includes these tests. Running them on macOS
is not native App Installer activation, enrolled Windows-user coverage or an
installer execution test. Those remain required evidence before advertising
native fleet capability.

Primary references:

- [Public COM contract](https://github.com/microsoft/winget-cli/blob/master/src/Microsoft.Management.Deployment/PackageManager.idl)
- [Native pin/applicability selection](https://github.com/microsoft/winget-cli/blob/master/src/AppInstallerRepositoryCore/PackageVersionSelection.cpp)
- [Production COM factory and projection activation](https://github.com/microsoft/winget-cli/blob/master/src/PowerShell/Microsoft.WinGet.Client.Engine/Helpers/ManagementDeploymentFactory.cs)
- [Native package enumeration](https://github.com/microsoft/winget-cli/blob/master/src/PowerShell/Microsoft.WinGet.Client.Engine/Commands/Common/FinderCommand.cs)
