# Test-Startup.ps1 - startup classification and StartupApproved encoding.
# ASCII only, PowerShell 5.1 compatible.
#
# The enable/disable round trip is exercised against a throwaway registry key
# under HKCU, never against a real StartupApproved key, so a failing test can
# never leave a real startup item switched off.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'modules\Manage-StartupItems.ps1')

$pass = 0
$fail = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  PASS  " + $Name) -ForegroundColor Green; $script:pass++ }
    else { Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red; $script:fail++ }
}

Write-Host ''
Write-Host '  StartupApproved encoding' -ForegroundColor Cyan
Write-Host '  ------------------------' -ForegroundColor DarkGray

Assert-True 'Byte 0x02 reads as enabled'   (-not (Test-StartupApprovalDisabled -Bytes ([byte[]](2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))))
Assert-True 'Byte 0x03 reads as disabled'  (Test-StartupApprovalDisabled -Bytes ([byte[]](3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)))
Assert-True 'Byte 0x06 reads as enabled'   (-not (Test-StartupApprovalDisabled -Bytes ([byte[]](6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))))
Assert-True 'Byte 0x07 reads as disabled'  (Test-StartupApprovalDisabled -Bytes ([byte[]](7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)))
Assert-True 'Missing value means enabled'  (-not (Test-StartupApprovalDisabled -Bytes $null))
Assert-True 'Empty value means enabled'    (-not (Test-StartupApprovalDisabled -Bytes ([byte[]]@())))

$enabledBytes = New-StartupApprovalBytes -Enabled $true
$disabledBytes = New-StartupApprovalBytes -Enabled $false
Assert-True 'Generated enabled blob is 12 bytes'  ($enabledBytes.Count -eq 12)
Assert-True 'Generated disabled blob is 12 bytes' ($disabledBytes.Count -eq 12)
Assert-True 'Generated enabled blob round-trips'  (-not (Test-StartupApprovalDisabled -Bytes $enabledBytes))
Assert-True 'Generated disabled blob round-trips' (Test-StartupApprovalDisabled -Bytes $disabledBytes)

Write-Host ''
Write-Host '  Classification' -ForegroundColor Cyan
Write-Host '  --------------' -ForegroundColor DarkGray

$cases = @(
    # Disabling any of these hands back a broken machine
    @{ Name = 'SynTPEnh';                  Expect = 'Protected' },
    @{ Name = 'ETDCtrl';                   Expect = 'Protected' },
    @{ Name = 'RtkAudUService';            Expect = 'Protected' },
    @{ Name = 'RAVCpl64';                  Expect = 'Protected' },
    @{ Name = 'IgfxTray';                  Expect = 'Protected' },
    @{ Name = 'SecurityHealth';            Expect = 'Protected' },
    @{ Name = 'Windows Defender';          Expect = 'Protected' },
    @{ Name = 'McAfee Security';           Expect = 'Protected' },
    @{ Name = 'Lenovo Vantage Service';    Expect = 'Protected' },
    @{ Name = 'Dell Power Manager';        Expect = 'Protected' },
    @{ Name = 'TPHOTKEY';                  Expect = 'Protected' },
    @{ Name = 'NvBackend';                 Expect = 'Protected' },
    @{ Name = 'Ctfmon';                    Expect = 'Protected' },

    # Safe to switch off
    @{ Name = 'Adobe ARM';                 Expect = 'Optional' },
    @{ Name = 'SunJavaUpdateSched';        Expect = 'Optional' },
    @{ Name = 'iTunesHelper';              Expect = 'Optional' },
    @{ Name = 'Spotify';                   Expect = 'Optional' },
    @{ Name = 'Steam';                     Expect = 'Optional' },
    @{ Name = 'Discord';                   Expect = 'Optional' },
    @{ Name = 'Dropbox';                   Expect = 'Optional' },
    @{ Name = 'OneDrive';                  Expect = 'Optional' },
    @{ Name = 'CCleaner Monitoring';       Expect = 'Optional' },

    # Unknown must be left alone
    @{ Name = 'SomeLineOfBusinessAgent';   Expect = 'Unclassified' },
    @{ Name = 'AcmeCorpTimeTracker';       Expect = 'Unclassified' }
)

foreach ($c in $cases) {
    $got = (Get-StartupTier -Name $c.Name).Tier
    Assert-True ("{0,-14} {1}" -f $c.Expect, $c.Name) ($got -eq $c.Expect) "got=$got"
}

# Only Optional is ever eligible to be switched off.
$mustNotDisable = @('SynTPEnh', 'SecurityHealth', 'RtkAudUService', 'Lenovo Vantage Service',
    'SomeLineOfBusinessAgent', 'NvBackend')
$leak = @($mustNotDisable | Where-Object { (Get-StartupTier -Name $_).Tier -eq 'Optional' })
Assert-True 'No protected or unknown item is disable-eligible' ($leak.Count -eq 0) ("leaked=" + ($leak -join ','))

Write-Host ''
Write-Host '  Enable/disable round trip (throwaway key)' -ForegroundColor Cyan
Write-Host '  -----------------------------------------' -ForegroundColor DarkGray

$testKey = 'HKCU:\SOFTWARE\GSTuneUpTest\StartupApproved'
try {
    New-Item -Path $testKey -Force | Out-Null
    $fake = [pscustomobject]@{ Name = 'PretendApp'; ApprovalKey = $testKey }

    Set-StartupItemEnabled -Item $fake -Enabled $false
    $after = (Get-ItemProperty -LiteralPath $testKey -Name 'PretendApp').PretendApp
    Assert-True 'Disable writes a disabled blob' (Test-StartupApprovalDisabled -Bytes $after)

    Set-StartupItemEnabled -Item $fake -Enabled $true
    $after2 = (Get-ItemProperty -LiteralPath $testKey -Name 'PretendApp').PretendApp
    Assert-True 'Re-enable writes an enabled blob' (-not (Test-StartupApprovalDisabled -Bytes $after2))

    # The approval key is a separate store; the Run value itself is untouched.
    Assert-True 'Writes only to the approval key, not to Run' ($fake.ApprovalKey -like '*StartupApproved*')
}
finally {
    Remove-Item -LiteralPath 'HKCU:\SOFTWARE\GSTuneUpTest' -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host '  Live inventory (read-only)' -ForegroundColor Cyan
Write-Host '  --------------------------' -ForegroundColor DarkGray

$live = @(Get-StartupItems)
Assert-True 'Enumerates startup items without error' ($null -ne $live)
$badTier = @($live | Where-Object { @('Protected', 'Optional', 'Unclassified') -notcontains $_.Tier })
Assert-True 'Every live item has a valid tier' ($badTier.Count -eq 0)
$noName = @($live | Where-Object { [string]::IsNullOrWhiteSpace($_.Name) })
Assert-True 'Every live item has a name' ($noName.Count -eq 0)

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
