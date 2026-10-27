# WinGet structured discovery boundary

`scripts/winget_provider.ps1` is a read-only Windows adapter. Run it as the
intended enrolled user with Windows PowerShell or PowerShell. It uses an
**already installed** `Microsoft.WinGet.Client` module; it does not install or
repair WinGet, App Installer, a module, or a source. No new bundled runtime or
dependency is introduced. It is not yet wired to remote reporting or packaging.

The schema-2 result names provider `winget`, the current Windows user SID as
`context_id`, and the package identity, source, installed version, available
versions and native update-availability observation. Available versions are
reported as returned by WinGet; their order is not interpreted as a safe target.
Missing prerequisites and provider failures return `status: unavailable` with a
safe reason. They never establish zero installed applications or zero updates.

Coverage is limited to packages visible to that account and accessible machine
registrations. SYSTEM, LocalService and NetworkService contexts are rejected.
Other users' profiles, portable software, manual packages and Windows OS updates
are not established by this report. A user-context scheduled task would require
separate provisioning; this script creates none.

## Preparation and execution remain unavailable

The documented installed-package PowerShell object exposes no installed scope
or native pin state. Consequently every discovered package currently has an
explicit exclusion, and `prepare` and `execute` capabilities are false. Both
selected and all-eligible preparation reject before any native change. Do not
hide these gaps behind a generic “all apps” or “current” claim.

Completing preparation requires structured native scope/pin evidence and a
complete frozen installer/dependency record. WinGet's download command can
select exact ID, version, source, architecture and scope, but downloading alone
does not prove the approved installer closure. Microsoft Store offline license
requirements are also distinct. Preparation may then download only after explicit
metadata/download authorization; it must hash and retain each actual installer,
dependency and exact native manifest and bind them to a versioned plan.

Completing execution also requires the separate reviewed-manifest and one-use
claim gate, exact-context checks, durable interrupted/unknown outcomes, and
native disposable Windows verification. `winget upgrade --all` must not execute
a reviewed plan: it resolves live targets. The absence of
`--uninstall-previous` does not prove no removals; installer manifests can select
that behavior themselves. No provider may request reboot, elevation, arbitrary
installer overrides, hash bypass, forced updates or unknown/pinned inclusion.

## Verification

`python3 -B -m unittest discover -s tests -p test_winget_provider.py -v`
executes the PowerShell normalization and rejection boundary using synthetic
module objects when `pwsh` is installed. Tests skip explicitly otherwise.
These tests exercise PowerShell on macOS; they are not native App Installer,
Windows-user coverage, signed transport, installer or Windows release evidence.

Primary references:

- [Microsoft installed-package object](https://github.com/microsoft/winget-cli/blob/master/src/PowerShell/Microsoft.WinGet.Client.Engine/PSObjects/PSInstalledCatalogPackage.cs)
- [Microsoft catalog-package object](https://github.com/microsoft/winget-cli/blob/master/src/PowerShell/Microsoft.WinGet.Client.Engine/PSObjects/PSCatalogPackage.cs)
- [WinGet upgrade behavior](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade)
- [WinGet download behavior](https://learn.microsoft.com/en-us/windows/package-manager/winget/download)
