"""Execute the PowerShell boundary with synthetic module objects; never call WinGet."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'winget_provider.ps1'
PWSH = shutil.which('pwsh')


@unittest.skipUnless(PWSH, 'PowerShell is not installed')
class WingetProviderTests(unittest.TestCase):
    def run_ps(self, body):
        result = subprocess.run([PWSH, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
                                 f". '{SCRIPT}'; {body}"], capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def test_native_objects_preserve_identity_and_exclude_unknown_scope_and_pins(self):
        result = self.run_ps("""
        $p = [pscustomobject]@{Id='Example.Tool';Source='winget';InstalledVersion='1.0';AvailableVersions=@('2.0');IsUpdateAvailable=$true}
        ConvertTo-WinGetDiscovery -Packages @($p) -ContextId 'test-user' | ConvertTo-Json -Depth 12 -Compress
        """)
        self.assertEqual(result['schema_version'], 2)
        self.assertEqual(result['provider'], 'winget')
        self.assertEqual(result['context_id'], 'test-user')
        self.assertFalse(result['capabilities']['execute'])
        self.assertFalse(result['capabilities']['prepare'])
        self.assertEqual(result['packages'][0]['id'], 'Example.Tool')
        self.assertEqual(result['packages'][0]['installed_version'], '1.0')
        self.assertEqual(result['packages'][0]['available_versions'], ['2.0'])
        self.assertIn('pin_state_unavailable', result['packages'][0]['exclusions'])
        self.assertIn('scope_unavailable', result['packages'][0]['exclusions'])

    def test_missing_source_and_unknown_version_are_not_eligible(self):
        result = self.run_ps("""
        $p = [pscustomobject]@{Id='Example.Tool';Source=$null;InstalledVersion='Unknown';AvailableVersions=@('2.0');IsUpdateAvailable=$true}
        ConvertTo-WinGetDiscovery -Packages @($p) -ContextId 'test-user' | ConvertTo-Json -Depth 12 -Compress
        """)
        row = result['packages'][0]
        self.assertFalse(row['eligible'])
        self.assertIn('source_unavailable', row['exclusions'])
        self.assertIn('installed_version_unknown', row['exclusions'])

    def test_prepare_rejects_all_and_selected_without_native_evidence(self):
        result = self.run_ps("""
        $answers = @()
        foreach($selection in @('all_eligible','selected')) {
          try { Invoke-WinGetPreparation -Request @{schema_version=2;provider='winget';selection=$selection;packages=@('Example.Tool')} }
          catch { $answers += $_.Exception.Message }
        }
        ConvertTo-Json -InputObject $answers -Compress
        """)
        self.assertEqual(result, ['winget_preparation_unavailable: native pin, installed scope and frozen installer evidence required'] * 2)

    def test_native_prerequisite_failure_is_structured_and_not_empty_success(self):
        result = self.run_ps("""
        function Test-WinGetWindows { return $false }
        Invoke-WinGetDiscovery | ConvertTo-Json -Depth 12 -Compress
        """)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['reason'], 'windows_required')
        self.assertEqual(result['packages'], [])

    def test_missing_module_is_not_installed_implicitly(self):
        result = self.run_ps("""
        function Test-WinGetWindows { return $true }
        function Get-Module { return $null }
        function Import-Module { throw 'must not import absent module' }
        Invoke-WinGetDiscovery | ConvertTo-Json -Depth 12 -Compress
        """)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['reason'], 'winget_client_module_unavailable')
        self.assertFalse(result['capabilities']['discover'])


if __name__ == '__main__':
    unittest.main()
