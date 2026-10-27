# Structured WinGet discovery boundary. No install or privilege authority.
[CmdletBinding()]
param([ValidateSet('discover')][string]$Mode = 'discover')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-WinGetWindows { return $env:OS -eq 'Windows_NT' }

function New-WinGetResult {
    param([string]$Status, [AllowNull()][string]$Reason, [AllowNull()][string]$ContextId, [array]$Packages = @())
    return [ordered]@{
        schema_version = 2
        provider = 'winget'
        status = $Status
        reason = $Reason
        context_id = $ContextId
        coverage = 'current_user_and_accessible_machine_packages_only'
        capabilities = [ordered]@{ discover = ($Status -eq 'available'); prepare = $false; execute = $false }
        packages = @($Packages)
        gaps = @('other_user_profiles_not_enumerated', 'installed_scope_unavailable', 'native_pin_state_unavailable', 'windows_updates_separate')
    }
}

function ConvertTo-WinGetDiscovery {
    param([AllowEmptyCollection()][array]$Packages, [string]$ContextId)
    if ([string]::IsNullOrWhiteSpace($ContextId)) { throw 'context_required' }
    $rows = @()
    foreach ($package in $Packages) {
        # These are documented Microsoft.WinGet.Client properties, not parsed CLI tables.
        $id = [string]$package.Id
        $source = [string]$package.Source
        $installed = [string]$package.InstalledVersion
        $versions = @($package.AvailableVersions | ForEach-Object { [string]$_ })
        $exclusions = @('scope_unavailable', 'pin_state_unavailable', 'frozen_installer_evidence_unavailable')
        if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$') { $exclusions += 'unsupported_identity' }
        if ([string]::IsNullOrWhiteSpace($source)) { $exclusions += 'source_unavailable' }
        if ($source -eq 'msstore') { $exclusions += 'store_preparation_unavailable' }
        if ([string]::IsNullOrWhiteSpace($installed) -or $installed -eq 'Unknown') { $exclusions += 'installed_version_unknown' }
        if (-not $package.IsUpdateAvailable) { $exclusions += 'no_reported_upgrade' }
        if ($versions.Count -eq 0 -or @($versions | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -eq 'Unknown' }).Count -gt 0) {
            $exclusions += 'target_version_unknown'
        }
        $rows += [ordered]@{
            id = $id; source = $source; installed_version = $installed
            available_versions = @($versions); update_available = [bool]$package.IsUpdateAvailable
            scope = 'unknown'; pin_state = 'unknown'; eligible = $false
            exclusions = @($exclusions)
        }
    }
    return New-WinGetResult -Status 'available' -Reason $null -ContextId $ContextId -Packages $rows
}

function Invoke-WinGetDiscovery {
    if (-not (Test-WinGetWindows)) { return New-WinGetResult -Status 'unavailable' -Reason 'windows_required' -ContextId $null }
    if (-not (Get-Module -ListAvailable -Name Microsoft.WinGet.Client)) {
        return New-WinGetResult -Status 'unavailable' -Reason 'winget_client_module_unavailable' -ContextId $null
    }
    try {
        # Never install/repair the module or App Installer automatically.
        Import-Module Microsoft.WinGet.Client -ErrorAction Stop
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sid = $identity.User.Value
        if ($sid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')) {
            return New-WinGetResult -Status 'unavailable' -Reason 'interactive_user_context_required' -ContextId $sid
        }
        $packages = @(Get-WinGetPackage -ErrorAction Stop)
        return ConvertTo-WinGetDiscovery -Packages $packages -ContextId $sid
    } catch {
        # Raw provider/registry diagnostics can contain private paths or accounts.
        return New-WinGetResult -Status 'unavailable' -Reason 'winget_discovery_failed' -ContextId $null
    }
}

function Invoke-WinGetPreparation {
    param([object]$Request)
    # No request can bypass native pin/scope or installer-closure verification.
    throw 'winget_preparation_unavailable: native pin, installed scope and frozen installer evidence required'
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-WinGetDiscovery | ConvertTo-Json -Depth 12 -Compress
}
