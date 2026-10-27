"""Synthetic public COM contracts executed in PowerShell; no Windows operations."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

PWSH = shutil.which('pwsh')
SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'winget_preparation.ps1'
SETUP = r'''
function Package($id='Example.Tool',$target='2',$scope='user') {
 $installed=[pscustomobject]@{Version='1';Scope=$scope}
 $installed | Add-Member ScriptMethod GetMetadata {param($field) return $this.Scope}
 $installed | Add-Member ScriptMethod CompareToVersion {param($version) return 'Lesser'}
 $candidate=$null
 if($target) {$candidate=[pscustomobject]@{Version=$target;PackageCatalog=[pscustomobject]@{Info=[pscustomobject]@{Id='source-identity';Name='winget'}}}}
 return [pscustomobject]@{Id=$id;InstalledVersion=$installed;DefaultInstallVersion=$candidate;IsUpdateAvailable=[bool]$target}
}
$policy=@{schema_version=2;context_id='S-1-5-21-123';allowed_packages=@(@{id='Example.Tool';source='winget';scope='user'})}
$request=@{schema_version=2;provider='winget';selection=@{mode='all_eligible'}}
'''


@unittest.skipUnless(PWSH, 'PowerShell unavailable')
class WingetPreparationTests(unittest.TestCase):
    def ps(self, code):
        run = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-Command',
                              f". '{SCRIPT}'; {SETUP}; {code}"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_all_eligible_binds_native_scope_source_target_and_policy(self):
        result = self.ps("New-WinGetPreparation -Packages @((Package)) -Policy $policy -Request $request -ContextId $policy.context_id -Now 1000 | ConvertTo-Json -Depth 20 -Compress")
        self.assertEqual(result['changes'][0]['target_version'], '2')
        self.assertEqual(result['changes'][0]['scope'], 'user')
        self.assertEqual(len(result['changes'][0]['source_sha256']), 64)
        self.assertNotIn('source-identity', json.dumps(result))
        self.assertFalse(result['execution_supported'])
        self.assertEqual(result['expires_at_unix'], 1900)
        self.assertEqual(len(result['state_sha256']), 64)

    def test_native_pins_unknown_scope_and_local_exclusions_stay_visible(self):
        result = self.ps("New-WinGetPreparation -Packages @((Package -target ''),(Package -id 'Other.Tool'),(Package -id 'Unknown.Tool' -scope 'unknown')) -Policy $policy -Request $request -ContextId $policy.context_id -Now 1000 | ConvertTo-Json -Depth 20 -Compress")
        self.assertEqual(result['changes'], [])
        reasons = [x['reasons'] for x in result['exclusions']]
        self.assertIn('pinned_or_no_applicable_upgrade', reasons[0])
        self.assertTrue(any('local_policy_excluded' in x for x in reasons))
        self.assertTrue(any('scope_unavailable' in x for x in reasons))

    def test_selected_uses_same_native_resolution_without_expanding_other_roots(self):
        result = self.ps("$request.selection=@{mode='selected';packages=$policy.allowed_packages}; New-WinGetPreparation -Packages @((Package),(Package -id 'Other.Tool')) -Policy $policy -Request $request -ContextId $policy.context_id -Now 1000 | ConvertTo-Json -Depth 20 -Compress")
        self.assertEqual([p['id'] for p in result['changes']], ['Example.Tool'])
        self.assertEqual(result['selection']['mode'], 'selected')

    def test_snapshot_verification_rejects_drift_context_expiry_and_policy_change(self):
        result = self.ps(r'''
        $a=New-WinGetPreparation -Packages @((Package)) -Policy $policy -Request $request -ContextId $policy.context_id -Now 1000
        $answers=@()
        foreach($case in @('same','expired','target','context','policy')) {
          $b=New-WinGetPreparation -Packages @((Package)) -Policy $policy -Request $request -ContextId $policy.context_id -Now 1001
          if($case -eq 'target') {$b.changes[0].target_version='3'}
          if($case -eq 'context') {$b.context.user_id='other'}
          if($case -eq 'policy') {$b.policy_sha256='0'*64}
          try { Test-WinGetPreparation -Original $a -Current $b -Now $(if($case -eq 'expired'){1900}else{1100}); $answers += $true } catch {$answers += $false}
        }
        ConvertTo-Json -InputObject $answers -Compress
        ''')
        self.assertEqual(result, [True, False, False, False, False])

    def test_context_mismatch_and_duplicate_native_identity_fail_closed(self):
        result = self.ps(r'''
        $answers=@()
        try {New-WinGetPreparation -Packages @((Package)) -Policy $policy -Request $request -ContextId 'wrong' -Now 1000} catch {$answers+='context'}
        try {New-WinGetPreparation -Packages @((Package),(Package)) -Policy $policy -Request $request -ContextId $policy.context_id -Now 1000} catch {$answers+='duplicate'}
        ConvertTo-Json -InputObject $answers -Compress
        ''')
        self.assertEqual(result, ['context', 'duplicate'])

    def test_policy_types_and_extra_fields_are_rejected(self):
        result = self.ps(r"""
        $answers=@()
        foreach($version in @('2',2.0,$true)) {
          $bad=@{}+$policy; $bad.schema_version=$version
          try {New-WinGetPreparation -Packages @((Package)) -Policy $bad -Request $request -ContextId $policy.context_id -Now 1000; $answers+=$false} catch {$answers+=$true}
        }
        $bad=@{}+$policy; $bad.extra='not allowed'
        try {New-WinGetPreparation -Packages @((Package)) -Policy $bad -Request $request -ContextId $policy.context_id -Now 1000; $answers+=$false} catch {$answers+=$true}
        ConvertTo-Json -InputObject $answers -Compress
        """)
        self.assertEqual(result, [True]*4)

    def test_no_upgrade_or_unknown_target_never_becomes_an_update(self):
        result = self.ps(r"""
        $p=Package; $p.InstalledVersion | Add-Member ScriptMethod CompareToVersion {param($v) return 'Unknown'} -Force
        New-WinGetPreparation -Packages @($p) -Policy $policy -Request $request -ContextId $policy.context_id -Now 1000 | ConvertTo-Json -Depth 20 -Compress
        """)
        self.assertEqual(result['changes'], [])
        self.assertIn('native_version_comparison_not_newer', result['exclusions'][0]['reasons'])

    def test_verification_rejects_malformed_timestamps_and_schema(self):
        result = self.ps(r"""
        $answers=@()
        foreach($case in @('string-schema','negative','long-ttl','future')) {
          $a=New-WinGetPreparation -Packages @((Package)) -Policy $policy -Request $request -ContextId $policy.context_id -Now 1000
          $b=New-WinGetPreparation -Packages @((Package)) -Policy $policy -Request $request -ContextId $policy.context_id -Now 1000
          if($case -eq 'string-schema') {$a.schema_version='2'}
          if($case -eq 'negative') {$a.generated_at_unix=-100; $a.expires_at_unix=500}
          if($case -eq 'long-ttl') {$a.expires_at_unix=3000}
          if($case -eq 'future') {$a.generated_at_unix=1200; $a.expires_at_unix=1900}
          try {Test-WinGetPreparation -Original $a -Current $b -Now $(if($case -eq 'negative'){100}else{1100}); $answers+=$false} catch {$answers+=$true}
        }
        ConvertTo-Json -InputObject $answers -Compress
        """)
        self.assertEqual(result, [True]*4)

    def test_worker_deadline_kills_actual_synthetic_child(self):
        result = self.ps(r"""
        $script=Join-Path ([IO.Path]::GetTempPath()) ('winget-deadline-'+[guid]::NewGuid()+'.ps1')
        try {
          [IO.File]::WriteAllText($script, 'param([switch]$NativeWorker,[string]$Mode,[string]$PolicyPath,[string]$RequestPath); Start-Sleep -Seconds 10')
          $timer=[Diagnostics.Stopwatch]::StartNew()
          try {Invoke-WinGetBoundedWorker -Script $script -Operation prepare -Policy ignored -Request ignored -Snapshot '' -TimeoutMs 300; throw 'timeout not enforced'}
          catch {
            $alive=$true
            try {[void][Diagnostics.Process]::GetProcessById([int]$_.Exception.Data['child_id'])} catch {$alive=$false}
            @{message=$_.Exception.Message;alive=$alive;elapsed=$timer.Elapsed.TotalSeconds} | ConvertTo-Json -Compress
          }
        } finally {Remove-Item -LiteralPath $script -Force}
        """)
        self.assertEqual(result['message'], 'native_preparation_timeout')
        self.assertFalse(result['alive'])
        self.assertLess(result['elapsed'], 3)

    def test_input_reader_rejects_oversized_and_malformed_json(self):
        result = self.ps(r"""
        $file=Join-Path ([IO.Path]::GetTempPath()) ('winget-input-'+[guid]::NewGuid()+'.json')
        $answers=@()
        try {
          foreach($text in @('{invalid', (' '*8388609))) {
            [IO.File]::WriteAllText($file,$text)
            try {Read-WinGetSnapshotInput $file; $answers+=$false} catch {$answers+=$true}
          }
          ConvertTo-Json -InputObject $answers -Compress
        } finally {Remove-Item -LiteralPath $file -Force}
        """)
        self.assertEqual(result, [True, True])

    def test_successful_worker_drops_synthetic_secret_environment(self):
        result = self.ps(r"""
        $script=Join-Path ([IO.Path]::GetTempPath()) ('winget-environment-'+[guid]::NewGuid()+'.ps1')
        try {
          $env:GU_SYNTHETIC_API_TOKEN='synthetic-test-value'
          $env:GU_CONTEXT_TEST='preserve-user-context'
          [IO.File]::WriteAllText($script, 'param([switch]$NativeWorker,[string]$Mode,[string]$PolicyPath,[string]$RequestPath); @{secret_absent=($null -eq $env:GU_SYNTHETIC_API_TOKEN);context_retained=($env:GU_CONTEXT_TEST -eq "preserve-user-context")} | ConvertTo-Json -Compress')
          Invoke-WinGetBoundedWorker -Script $script -Operation prepare -Policy ignored -Request ignored -Snapshot '' -TimeoutMs 3000
        } finally {
          Remove-Item Env:GU_SYNTHETIC_API_TOKEN,Env:GU_CONTEXT_TEST
          Remove-Item -LiteralPath $script -Force
        }
        """)
        self.assertEqual(result, {'secret_absent': True, 'context_retained': True})

    def test_invalid_native_values_are_excluded_without_emitting_raw_values(self):
        result = self.ps(r"""
        $p=Package
        $p.DefaultInstallVersion.PackageCatalog.Info.Name='https://user:synthetic-secret@example.invalid'
        $p.InstalledVersion.Version='synthetic-oversized-'+('x'*300)
        $p.DefaultInstallVersion.Version='Unknown'
        $snapshot=New-WinGetPreparation -Packages @($p) -Policy $policy -Request $request -ContextId $policy.context_id -Now 1000
        $json=ConvertTo-Json -InputObject $snapshot -Depth 20 -Compress
        @{raw_value_absent=(-not $json.Contains('synthetic-secret') -and -not $json.Contains('synthetic-oversized'));snapshot=$snapshot} | ConvertTo-Json -Depth 25 -Compress
        """)
        self.assertTrue(result['raw_value_absent'])
        row = result['snapshot']['exclusions'][0]
        self.assertIsNone(row['source'])
        self.assertIsNone(row['installed_version'])
        self.assertIsNone(row['target_version'])
        self.assertIn('source_unavailable', row['reasons'])
        self.assertIn('installed_version_unknown', row['reasons'])
        self.assertIn('target_version_unknown', row['reasons'])


if __name__ == '__main__':
    unittest.main()
