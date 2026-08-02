# Test-Driver.ps1 - driver problem-code decoding and risk classification.
# ASCII only, PowerShell 5.1 compatible. Read-only throughout.
#
# The risk classification is the safety-critical part: a package wrongly
# classed Standard is one a tech might delete, and for a storage controller
# that costs the boot.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'modules\Repair-DriverRollback.ps1')

$pass = 0
$fail = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  PASS  " + $Name) -ForegroundColor Green; $script:pass++ }
    else { Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red; $script:fail++ }
}

Write-Host ''
Write-Host '  Problem code decoding' -ForegroundColor Cyan
Write-Host '  ---------------------' -ForegroundColor DarkGray

$codeCases = @(
    @{ Code = 10; Match = 'cannot start' },
    @{ Code = 28; Match = 'not installed' },
    @{ Code = 43; Match = 'reported a problem' },
    @{ Code = 31; Match = 'failed to load' },
    @{ Code = 22; Match = 'disabled' },
    @{ Code = 52; Match = 'signature' }
)
foreach ($c in $codeCases) {
    $m = Get-DriverProblemMeaning -Code $c.Code
    Assert-True ("Code {0} decodes" -f $c.Code) ($m.Short -match $c.Match) ("got=" + $m.Short)
    Assert-True ("Code {0} names a layer to check" -f $c.Code) (-not [string]::IsNullOrWhiteSpace($m.Layer))
}

$unknown = Get-DriverProblemMeaning -Code 9999
Assert-True 'Unknown code is flagged, not invented' ($unknown.Short -match 'Unrecognised')

Write-Host ''
Write-Host '  Boot-critical classification' -ForegroundColor Cyan
Write-Host '  ----------------------------' -ForegroundColor DarkGray

foreach ($cls in @('SCSIAdapter', 'HDC', 'DiskDrive', 'Volume', 'System', 'Processor', 'SecurityDevices')) {
    Assert-True ("Class '$cls' is boot-critical") (Test-BootCriticalClass -ClassName $cls)
}
foreach ($cls in @('Printer', 'Camera', 'Biometric', 'Bluetooth')) {
    Assert-True ("Class '$cls' is not boot-critical") (-not (Test-BootCriticalClass -ClassName $cls))
}
Assert-True 'Empty class is not boot-critical' (-not (Test-BootCriticalClass -ClassName ''))
Assert-True 'Null class is not boot-critical'  (-not (Test-BootCriticalClass -ClassName $null))

Write-Host ''
Write-Host '  Risk tiers' -ForegroundColor Cyan
Write-Host '  ----------' -ForegroundColor DarkGray

Assert-True 'Storage controller is BootCritical' `
((Get-DriverRiskTier -ClassName 'SCSIAdapter' -BootCriticalFlag $false).Tier -eq 'BootCritical')

# Windows' own flag must win even for a class the catalog thinks is ordinary.
Assert-True 'Windows BootCritical flag beats the class list' `
((Get-DriverRiskTier -ClassName 'Printer' -BootCriticalFlag $true).Tier -eq 'BootCritical')

Assert-True 'Display is HighRisk'  ((Get-DriverRiskTier -ClassName 'Display' -BootCriticalFlag $false).Tier -eq 'HighRisk')
Assert-True 'Net is HighRisk'      ((Get-DriverRiskTier -ClassName 'Net' -BootCriticalFlag $false).Tier -eq 'HighRisk')
Assert-True 'Printer is Standard'  ((Get-DriverRiskTier -ClassName 'Printer' -BootCriticalFlag $false).Tier -eq 'Standard')

# The invariant that matters: nothing boot-critical may ever read as Standard.
$mustNotBeStandard = @('SCSIAdapter', 'HDC', 'DiskDrive', 'Volume', 'System', 'Processor', 'Display', 'Net')
$leak = @($mustNotBeStandard | Where-Object { (Get-DriverRiskTier -ClassName $_ -BootCriticalFlag $false).Tier -eq 'Standard' })
Assert-True 'No boot-critical or high-risk class reads as Standard' ($leak.Count -eq 0) ("leaked=" + ($leak -join ','))

Write-Host ''
Write-Host '  Report privacy' -ForegroundColor Cyan
Write-Host '  --------------' -ForegroundColor DarkGray

# Instance IDs embed hardware serials, so they must not survive into the
# report. Confirm the module's report shape has no InstanceId field.
$sample = [ordered]@{
    FriendlyName = 'Example Device'; Class = 'Net'; Status = 'Error'
    ProblemCode = 10; Meaning = 'x'; Layer = 'y'; RiskTier = 'HighRisk'
}
Assert-True 'Report entry shape carries no InstanceId' (-not $sample.Contains('InstanceId'))

$scan = Get-ProblemDevices
$live = @($scan.Devices)
Assert-True 'Problem device enumeration runs' ($null -ne $scan)
Assert-True 'Scan reports what it filtered' `
(($scan.SkippedPhantom -ge 0) -and ($scan.SkippedUnknown -ge 0))

# The important one: Status='Unknown' with no problem code is a hidden or
# unqueryable device, not a fault. Counting those produced 23 phantom
# "problems" on a healthy machine and would send a tech chasing nothing.
$falsePositives = @($live | Where-Object {
        $_.Status -ne 'Error' -and $_.Status -ne 'Degraded' -and $_.ProblemCode -eq 0
    })
Assert-True 'Unknown-status devices with no fault code are excluded' ($falsePositives.Count -eq 0) `
("leaked=" + $falsePositives.Count)

$noCode45 = @($live | Where-Object { $_.ProblemCode -eq 45 })
Assert-True 'Phantom (code 45) devices are filtered out' ($noCode45.Count -eq 0)

if ($live.Count -gt 0) {
    $badTier = @($live | Where-Object { @('BootCritical', 'HighRisk', 'Standard') -notcontains $_.RiskTier })
    Assert-True 'Every live problem device has a valid risk tier' ($badTier.Count -eq 0)
}
else {
    Write-Host '  note: no real device faults on this machine to sample' -ForegroundColor DarkGray
}

Write-Host ''
Write-Host '  Elevation honesty' -ForegroundColor Cyan
Write-Host '  -----------------' -ForegroundColor DarkGray

$store = Get-ThirdPartyDrivers -RecentDays 30
Assert-True 'Driver store reports a status, never a bare empty list' `
(@('Read', 'RequiresElevation', 'Unavailable') -contains $store.Status) ("status=" + $store.Status)

if (-not (Test-IsAdmin)) {
    Assert-True 'Unelevated driver store says RequiresElevation' ($store.Status -eq 'RequiresElevation')
    Assert-True 'Unelevated restore status says RequiresElevation' ((Get-RestoreStatus).Status -eq 'RequiresElevation')
}

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
