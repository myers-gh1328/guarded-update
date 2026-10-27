# Native read-only preparation snapshot. No installer download or install authority.
[CmdletBinding()]
param([ValidateSet('prepare','verify')][string]$Mode='prepare', [string]$PolicyPath, [string]$RequestPath, [string]$SnapshotPath, [switch]$NativeWorker)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-WinGetSnapshotHash {
    param([object]$Value)
    $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 30 -Compress))
    $sha=[Security.Cryptography.SHA256]::Create()
    try {return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
}
function Get-WinGetIdentityKey {
    param([object]$Identity)
    if(@($Identity.Keys | Sort-Object) -join ',' -ne 'id,scope,source' -or
       $Identity.id -isnot [string] -or $Identity.id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$' -or
       $Identity.source -isnot [string] -or $Identity.source -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or
       $Identity.scope -notin @('user','machine')) {throw 'invalid_package_identity'}
    return ($Identity.id+'|'+$Identity.source+'|'+$Identity.scope).ToLowerInvariant()
}
function New-WinGetPreparation {
    param([AllowEmptyCollection()][array]$Packages,[System.Collections.IDictionary]$Policy,[System.Collections.IDictionary]$Request,[string]$ContextId,[long]$Now,[switch]$ValidateOnly)
    if($Now -lt 0 -or $Now -gt 9007199254739991) {throw 'invalid_snapshot_time'}
    if((@($Policy.Keys | Sort-Object) -join ',') -ne 'allowed_packages,context_id,schema_version' -or (($Policy.schema_version -isnot [int] -and $Policy.schema_version -isnot [long]) -or $Policy.schema_version -ne 2) -or
       $Policy.context_id -isnot [string] -or $Policy.context_id -cnotmatch '^S-1-[0-9-]{1,180}$' -or $Policy.context_id -ne $ContextId) {throw 'local_context_policy_mismatch'}
    if($ContextId -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {throw 'interactive_user_context_required'}
    if($Policy.allowed_packages -isnot [array] -or $Policy.allowed_packages.Count -gt 5000 -or $Packages.Count -gt 10000) {throw 'package_budget_exceeded'}
    if((@($Request.Keys | Sort-Object) -join ',') -ne 'provider,schema_version,selection' -or (($Request.schema_version -isnot [int] -and $Request.schema_version -isnot [long]) -or $Request.schema_version -ne 2) -or $Request.provider -ne 'winget' -or $Request.selection -isnot [System.Collections.IDictionary]) {throw 'invalid_provider_request'}
    $selection=$Request.selection
    $selected=$selection.mode -eq 'selected'
    if(($selected -and ((@($selection.Keys | Sort-Object) -join ',') -ne 'mode,packages' -or $selection.packages -isnot [array] -or $selection.packages.Count -eq 0 -or $selection.packages.Count -gt 5000)) -or
       (-not $selected -and ((@($selection.Keys) -join ',') -ne 'mode' -or $selection.mode -ne 'all_eligible'))) {throw 'invalid_provider_selection'}
    $allow=@{}; foreach($identity in $Policy.allowed_packages) {$key=Get-WinGetIdentityKey $identity; if($allow.ContainsKey($key)){throw 'duplicate_policy_identity'}; $allow[$key]=$true}
    $wanted=@{}; if($selected) {foreach($identity in $selection.packages) {$key=Get-WinGetIdentityKey $identity; if($wanted.ContainsKey($key)){throw 'duplicate_selected_identity'}; $wanted[$key]=$true}}
    if($ValidateOnly) {return}
    $observed=@{}; $rows=@(); $changes=@(); $excluded=@()
    foreach($package in $Packages) {
        $id=[string]$package.Id; $installed=$package.InstalledVersion; $target=$package.DefaultInstallVersion
        $scope='unknown'; $from=$null; $to=$null; $source=$null; $sourceId=$null; $reasons=@()
        if($id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$') {throw 'unsupported_native_identity'}
        if($null -eq $installed) {$reasons+='installed_version_unavailable'} else {
            $from=[string]$installed.Version
            $scope=([string]$installed.GetMetadata(1)).ToLowerInvariant() # Public InstalledScope enum value.
            if($scope -notin @('user','machine')) {$scope='unknown';$reasons+='scope_unavailable'}
            if([string]::IsNullOrWhiteSpace($from) -or $from -eq 'Unknown' -or $from.Length -gt 256) {$reasons+='installed_version_unknown';$from=$null}
        }
        if($null -eq $target) {$reasons+='pinned_or_no_applicable_upgrade'} else {
            $to=[string]$target.Version
            $source=[string]$target.PackageCatalog.Info.Name
            $sourceId=[string]$target.PackageCatalog.Info.Id
            if($source -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {$reasons+='source_unavailable';$source=$null}
            if([string]::IsNullOrWhiteSpace($sourceId) -or $sourceId.Length -gt 256) {$reasons+='source_unavailable';$sourceId=$null}
            if($source -eq 'msstore') {$reasons+='store_preparation_unavailable'}
            if([string]::IsNullOrWhiteSpace($to) -or $to -eq 'Unknown' -or $to.Length -gt 256) {$reasons+='target_version_unknown';$to=$null}
            if($null -ne $installed -and $null -ne $from -and $null -ne $to -and ([string]$installed.CompareToVersion($to)) -ne 'Lesser') {$reasons+='native_version_comparison_not_newer'}
            if(-not $package.IsUpdateAvailable) {$reasons+='no_reported_upgrade'}
        }
        $key=($id+'|'+$source+'|'+$scope).ToLowerInvariant()
        if($observed.ContainsKey($key)) {throw 'ambiguous_native_identity'}; $observed[$key]=$true
        # A pinned package may have no default candidate/source: retain its actual
        # native identity as an exclusion rather than guessing a source.
        if($selected -and -not $wanted.ContainsKey($key)) {continue}
        if(-not $allow.ContainsKey($key)) {$reasons+='local_policy_excluded'}
        $row=[ordered]@{id=$id;source=$source;source_sha256=$(if($sourceId){Get-WinGetSnapshotHash $sourceId}else{$null});scope=$scope;installed_version=$from;target_version=$to;reasons=@($reasons | Sort-Object)}
        $rows+=$row
        if($reasons.Count) {$excluded+=$row} else {$changes+=$row}
    }
    if($selected -and @($wanted.Keys | Where-Object {-not $observed.ContainsKey($_)}).Count) {throw 'selected_package_unavailable_or_ambiguous'}
    $rows=@($rows | Sort-Object id,source,scope);$changes=@($changes | Sort-Object id,source,scope);$excluded=@($excluded | Sort-Object id,source,scope)
    $normalizedPolicy=[ordered]@{context_id=$ContextId;allowed_packages=@($allow.Keys | Sort-Object)}
    $normalizedSelection=[ordered]@{mode=$selection.mode;packages=@($wanted.Keys | Sort-Object)}
    return [ordered]@{schema_version=2;kind='provider-preparation';provider='winget';selection=$normalizedSelection;context=[ordered]@{scope='user';user_id=$ContextId};
        changes=$changes;exclusions=$excluded;state_sha256=(Get-WinGetSnapshotHash $rows);policy_sha256=(Get-WinGetSnapshotHash $normalizedPolicy);
        generated_at_unix=$Now;expires_at_unix=($Now+900);execution_supported=$false;
        limitations=@('Native default candidate respects pins and applicable installed scope; absence does not identify an exact pin reason.',
        'Only the current Windows account and accessible machine registrations are covered; other profiles and Windows OS updates are separate.',
        'Catalog connection may consult native source manifests; no installer is downloaded or installed.',
        'Dependency closure, installer artifacts, elevation and removal behavior are unverified. This snapshot grants no install authority.')}
}
function Test-WinGetPreparation {
    param([System.Collections.IDictionary]$Original,[System.Collections.IDictionary]$Current,[long]$Now)
    if(($Original.schema_version -isnot [int] -and $Original.schema_version -isnot [long]) -or $Original.schema_version -ne 2 -or $Original.kind -ne 'provider-preparation' -or $Original.provider -ne 'winget' -or $Original.execution_supported -isnot [bool] -or $Original.execution_supported -ne $false) {throw 'invalid_preparation_snapshot'}
    if($Original.generated_at_unix -isnot [long] -and $Original.generated_at_unix -isnot [int]) {throw 'invalid_snapshot_time'}
    if($Original.expires_at_unix -isnot [long] -and $Original.expires_at_unix -isnot [int]) {throw 'invalid_snapshot_time'}
    if($Now -lt 0 -or $Original.generated_at_unix -lt 0 -or $Original.generated_at_unix -gt $Now -or $Original.expires_at_unix -le $Now -or $Original.expires_at_unix-$Original.generated_at_unix -notin 1..900) {throw 'preparation_expired_or_invalid'}
    foreach($field in @('provider','selection','context','changes','exclusions','state_sha256','policy_sha256')) {
        if((Get-WinGetSnapshotHash $Original[$field]) -ne (Get-WinGetSnapshotHash $Current[$field])) {throw 'preparation_drift_detected'}
    }
}

function New-WinGetPublicComObject {
    param([ValidateSet('PackageManager','CreateCompositePackageCatalogOptions','FindPackagesOptions','PackageMatchFilter')][string]$Class)
    $ids=@{PackageManager='C53A4F16-787E-42A4-B304-29EFFB4BF597';CreateCompositePackageCatalogOptions='526534B8-7E46-47C8-8416-B1685C327D37';FindPackagesOptions='572DED96-9C60-4526-8F92-EE7D91D38C1A';PackageMatchFilter='D02C9DAF-99DC-429C-B503-4E504E4AB000'}
    $projection=('Microsoft.Management.Deployment.'+$Class) -as [type]
    $marshaller='WinRT.MarshalInterface`1' -as [type]
    if($null -eq $projection -or $null -eq $marshaller) {throw 'native_projection_unavailable'}
    $instance=[Activator]::CreateInstance([type]::GetTypeFromCLSID([guid]$ids[$Class]))
    $pointer=[Runtime.InteropServices.Marshal]::GetIUnknownForObject($instance)
    try {
        $type=$marshaller.MakeGenericType(@($projection))
        $method=$type.GetMethod('FromAbi',[type[]]@([IntPtr]))
        if($null -eq $method) {throw 'native_projection_unavailable'}
        return $method.Invoke($null,@($pointer))
    } finally {[void][Runtime.InteropServices.Marshal]::Release($pointer)}
}
function Get-WinGetNativeContext {
    if($env:OS -ne 'Windows_NT') {throw 'windows_required'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)
    $sid=$identity.User.Value
    if($sid -in @('S-1-5-18','S-1-5-19','S-1-5-20') -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'unelevated_user_context_required'}
    return $sid
}
function Get-WinGetNativeCatalogPackages {
    param([System.Collections.IDictionary]$Policy)
    # Import only installed projection assemblies; do not inspect private cmdlet
    # wrapper internals, install modules, register sources or elevate activation.
    if(-not (Get-Module -ListAvailable -Name Microsoft.WinGet.Client)) {throw 'winget_client_module_unavailable'}
    Import-Module Microsoft.WinGet.Client -ErrorAction Stop
    $manager=New-WinGetPublicComObject PackageManager
    $composite=New-WinGetPublicComObject CreateCompositePackageCatalogOptions
    $composite.CompositeSearchBehavior=[Microsoft.Management.Deployment.CompositeSearchBehavior]::LocalCatalogs
    foreach($source in @($Policy.allowed_packages | ForEach-Object {$_.source} | Sort-Object -Unique)) {
        $catalog=$manager.GetPackageCatalogByName($source)
        if($null -eq $catalog -or $catalog.Info.Explicit) {throw 'configured_source_unavailable_or_explicit'}
        $catalog.PackageCatalogBackgroundUpdateInterval=[TimeSpan]::Zero
        $catalog.AcceptSourceAgreements=$false
        $authentication=[Microsoft.Management.Deployment.AuthenticationArguments]::new()
        $authentication.AuthenticationMode=[Microsoft.Management.Deployment.AuthenticationMode]::Silent
        $catalog.AuthenticationArguments=$authentication
        $composite.Catalogs.Add($catalog)
    }
    if($composite.Catalogs.Count -eq 0) {throw 'local_package_policy_empty'}
    $reference=$manager.CreateCompositePackageCatalog($composite)
    $connection=$reference.Connect()
    if([string]$connection.Status -ne 'Ok') {throw 'native_catalog_connection_unavailable'}
    $options=New-WinGetPublicComObject FindPackagesOptions
    $filter=New-WinGetPublicComObject PackageMatchFilter
    $filter.Field=[Microsoft.Management.Deployment.PackageMatchField]::CatalogDefault
    $filter.Option=[Microsoft.Management.Deployment.PackageFieldMatchOption]::EqualsCaseInsensitive
    $filter.Value=''
    $options.Selectors.Add($filter)
    $options.ResultLimit=10001
    $found=$connection.PackageCatalog.FindPackages($options)
    if([string]$found.Status -ne 'Ok' -or $found.WasLimitExceeded -or $found.Matches.Count -gt 10000) {throw 'native_catalog_results_incomplete'}
    return @($found.Matches | ForEach-Object {$_.CatalogPackage})
}
function Read-WinGetSnapshotInput {
    param([string]$Path)
    $item=Get-Item -LiteralPath $Path -ErrorAction Stop
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 8MB) {throw 'invalid_local_snapshot_file'}
    $file=[IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $memory=[IO.MemoryStream]::new()
    try {
        $buffer=[byte[]]::new(65536)
        $total=0
        while(($count=$file.Read($buffer,0,$buffer.Length)) -gt 0) {
            $total+=$count
            if($total -gt 8MB) {throw 'local_snapshot_file_exceeds_limit'}
            $memory.Write($buffer,0,$count)
        }
        $utf8=[Text.UTF8Encoding]::new($false,$true)
        return ($utf8.GetString($memory.ToArray()) | ConvertFrom-Json -AsHashtable -Depth 30)
    } finally {$file.Dispose();$memory.Dispose()}
}
function Invoke-WinGetBoundedWorker {
    param([string]$Script,[string]$Operation,[string]$Policy,[string]$Request,[string]$Snapshot,[ValidateRange(1,120000)][int]$TimeoutMs=120000)
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=Join-Path $PSHOME $(if($env:OS -eq 'Windows_NT'){'pwsh.exe'}else{'pwsh'})
    $start.UseShellExecute=$false
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    foreach($arg in @('-NoLogo','-NoProfile','-NonInteractive','-File',$Script,'-NativeWorker','-Mode',$Operation,'-PolicyPath',$Policy,'-RequestPath',$Request)) {[void]$start.ArgumentList.Add($arg)}
    if($Snapshot) {[void]$start.ArgumentList.Add('-SnapshotPath');[void]$start.ArgumentList.Add($Snapshot)}
    # Preserve Windows user/module/runtime context while removing ambient secrets.
    foreach($name in @($start.Environment.Keys)) {
        if($name -match 'TOKEN|SECRET|PASSWORD|KEY' -or $name -in @('SSH_AUTH_SOCK','GIT_ASKPASS')) {
            [void]$start.Environment.Remove($name)
        }
    }
    $child=[Diagnostics.Process]::Start($start)
    try {
        $output=$child.StandardOutput.ReadToEndAsync()
        $errors=$child.StandardError.ReadToEndAsync()
        if(-not $child.WaitForExit($TimeoutMs)) {
            $child.Kill($true)
            if(-not $child.WaitForExit(1000)) {throw 'native_worker_cleanup_unconfirmed'}
            $failure=[TimeoutException]::new('native_preparation_timeout')
            $failure.Data['child_id']=$child.Id
            throw $failure
        }
        if(-not $output.Wait(1000) -or -not $errors.Wait(1000)) {throw 'native_preparation_output_unavailable'}
        if($child.ExitCode -ne 0 -or [Text.Encoding]::UTF8.GetByteCount($output.Result) -gt 8MB) {throw 'native_preparation_unavailable'}
        return $output.Result.Trim()
    } finally {$child.Dispose()}
}
if($MyInvocation.InvocationName -ne '.') {
    try {
        if(-not $NativeWorker) {
            if($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -lt 7) {throw 'windows_powershell_projection_required'}
            Invoke-WinGetBoundedWorker -Script $PSCommandPath -Operation $Mode -Policy $PolicyPath -Request $RequestPath -Snapshot $SnapshotPath
            exit 0
        }
        if([string]::IsNullOrWhiteSpace($PolicyPath) -or [string]::IsNullOrWhiteSpace($RequestPath)) {throw 'policy_and_request_required'}
        $policy=Read-WinGetSnapshotInput $PolicyPath
        $request=Read-WinGetSnapshotInput $RequestPath
        $context=Get-WinGetNativeContext
        # Validate local authority and intent before consulting any source.
        [void](New-WinGetPreparation -Packages @() -Policy $policy -Request $request -ContextId $context -Now ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -ValidateOnly)
        $packages=@(Get-WinGetNativeCatalogPackages $policy)
        $current=New-WinGetPreparation -Packages $packages -Policy $policy -Request $request -ContextId $context -Now ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
        if($Mode -eq 'verify') {
            $original=Read-WinGetSnapshotInput $SnapshotPath
            Test-WinGetPreparation -Original $original -Current $current -Now ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
            [ordered]@{schema_version=2;provider='winget';status='snapshot_matches';execution_supported=$false} | ConvertTo-Json -Compress
        } else {
            $json=$current | ConvertTo-Json -Depth 30 -Compress
            if([Text.Encoding]::UTF8.GetByteCount($json) -gt 8MB) {throw 'snapshot_size_exceeded'}
            $json
        }
    } catch {
        # Raw COM diagnostics may contain private paths/source credentials.
        [ordered]@{schema_version=2;provider='winget';status='unavailable';reason='native_preparation_unavailable';execution_supported=$false} | ConvertTo-Json -Compress
        exit 1
    }
}
