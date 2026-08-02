# Test-Stress.ps1 - stress module preflight, interlocks and unit conversions.
# ASCII only, PowerShell 5.1 compatible.
#
# Deliberately does NOT run a load test. A suite that pegs every core for
# minutes is a suite nobody runs. What is verified here is the arithmetic, the
# refusal logic and the coverage honesty - the parts that decide whether load
# is applied at all and what gets claimed afterwards.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'modules\Test-SystemStress.ps1')

$pass = 0
$fail = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  PASS  " + $Name) -ForegroundColor Green; $script:pass++ }
    else { Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red; $script:fail++ }
}

Write-Host ''
Write-Host '  Temperature conversion' -ForegroundColor Cyan
Write-Host '  ----------------------' -ForegroundColor DarkGray

Assert-True 'Freezing point (2731) = 0 C'   ((Convert-DeciKelvinToC -DeciKelvin 2731) -eq 0)
Assert-True 'Room temp (2981) = 25 C'       ((Convert-DeciKelvinToC -DeciKelvin 2981) -eq 25)
Assert-True 'Hot CPU (3731) = 100 C'        ((Convert-DeciKelvinToC -DeciKelvin 3731) -eq 100)
Assert-True 'Throttle range (3631) = 90 C'  ((Convert-DeciKelvinToC -DeciKelvin 3631) -eq 90)
Assert-True 'Conversion is not a raw divide' ((Convert-DeciKelvinToC -DeciKelvin 3731) -ne 373.1)

Write-Host ''
Write-Host '  Duration and thread guards' -ForegroundColor Cyan
Write-Host '  --------------------------' -ForegroundColor DarkGray

Assert-True 'Default duration is short'  ($script:StressDefaults.Minutes -le 5)
Assert-True 'Hard cap exists'            ($script:StressDefaults.MaxMinutes -gt 0 -and $script:StressDefaults.MaxMinutes -le 60)
Assert-True 'Default abort temp is sane' ($script:StressDefaults.MaxTempC -ge 80 -and $script:StressDefaults.MaxTempC -le 105)

Write-Host ''
Write-Host '  No in-process memory test exists' -ForegroundColor Cyan
Write-Host '  --------------------------------' -ForegroundColor DarkGray

# An earlier version verified memory patterns in-process. It was deleted on
# purpose: it could only touch pages this process owns, and a "partial pass"
# on RAM is exactly the false confidence this toolkit exists to prevent. If
# anyone reintroduces one, this fails and they have to argue the case.
foreach ($gone in @('New-MemoryTestBuffers', 'Test-MemoryChunk')) {
    Assert-True "Removed function '$gone' has not come back" `
    ($null -eq (Get-Command $gone -ErrorAction SilentlyContinue))
}

Write-Host ''
Write-Host '  External tool discovery' -ForegroundColor Cyan
Write-Host '  -----------------------' -ForegroundColor DarkGray

$inv = Get-ExternalToolInventory
foreach ($k in @('smartctl', 'LibreHardwareMonitor', 'CrystalDiskInfo')) {
    Assert-True "Inventory reports a slot for $k" ($inv.Contains($k))
}
Assert-True 'Missing tool resolves to null, not a guess' `
($null -eq (Find-ExternalTool -ExeName 'definitely-not-a-real-tool-xyz.exe'))

Write-Host ''
Write-Host '  Sensor and SMART honesty' -ForegroundColor Cyan
Write-Host '  ------------------------' -ForegroundColor DarkGray

$thermal = Get-ThermalReading
Assert-True 'Thermal reading always reports a status' `
(@('Read', 'Unsupported', 'RequiresElevation', 'Unknown') -contains $thermal.Status) ("status=" + $thermal.Status)
Assert-True 'Thermal reading names its source' (-not [string]::IsNullOrWhiteSpace($thermal.Source))
if ($thermal.Status -ne 'Read') {
    Assert-True 'Unreadable thermal yields no temperature' ($null -eq $thermal.TempC)
}

$smart = Get-SmartDetail -SmartctlPath $inv.smartctl
Assert-True 'SMART names which source it used' (@('smartctl', 'StorageReliabilityCounter', 'none') -contains $smart.Source)
Assert-True 'SMART reports a status' (@('Read', 'Failed', 'Unknown') -contains $smart.Status)

$fans = Get-FanReadings
Assert-True 'Fan reading always reports a status' `
(@('Read', 'NoFanSensors', 'Unavailable') -contains $fans.Status) ("status=" + $fans.Status)

Write-Host ''
Write-Host '  Battery health' -ForegroundColor Cyan
Write-Host '  --------------' -ForegroundColor DarkGray

$bat = Get-BatteryHealth
Assert-True 'Battery reports a status' `
(@('Read', 'NoBattery', 'NoData', 'ReportFailed', 'Unknown') -contains $bat.Status) ("status=" + $bat.Status)
if ($bat.Status -eq 'Read') {
    Assert-True 'Health percent is a plausible figure' ($bat.HealthPercent -gt 0 -and $bat.HealthPercent -le 200) ("pct=" + $bat.HealthPercent)
    Assert-True 'Design capacity is populated'         ($bat.DesignCapacity -gt 0)
}
else {
    Assert-True 'No battery data implies no health figure' ($null -eq $bat.HealthPercent)
}

Write-Host ''
Write-Host '  Preflight is read-only' -ForegroundColor Cyan
Write-Host '  ----------------------' -ForegroundColor DarkGray

$sw = [Diagnostics.Stopwatch]::StartNew()
$pre = Invoke-StressModule
$sw.Stop()

Assert-True 'Preflight returns a result'      ($null -ne $pre)
Assert-True 'Preflight mode is PreflightOnly' ($pre.Mode -eq 'PreflightOnly')
Assert-True 'Preflight applied no load'       (-not $pre.Completed)
Assert-True 'Preflight took no samples'       (@($pre.Samples).Count -eq 0)
Assert-True 'Preflight finished quickly'      ($sw.Elapsed.TotalSeconds -lt 120) ("secs=" + [math]::Round($sw.Elapsed.TotalSeconds, 1))
Assert-True 'Preflight never claims verified load' (-not $pre.LoadVerified)
Assert-True 'Duration is capped' ((Invoke-StressModule -Options @{ Minutes = 9999 }).Minutes -le $script:StressDefaults.MaxMinutes)

Write-Host ''
Write-Host '  Disk health interlock' -ForegroundColor Cyan
Write-Host '  ---------------------' -ForegroundColor DarkGray

$gate = Get-DiskHealthGate
Assert-True 'Disk gate reports a status' (@('Read', 'Unreadable', 'Unknown') -contains $gate.Status)
if ($gate.Status -eq 'Read' -and $gate.Healthy) {
    Assert-True 'Healthy disk does not block preflight' ($pre.AbortReason -ne 'DiskHealthInterlock')
}

Write-Host ''
Write-Host '  Coverage honesty' -ForegroundColor Cyan
Write-Host '  ----------------' -ForegroundColor DarkGray

# The coverage matrix is the promise that "entire device" means a stated
# position on every part, not silence about the ones that were skipped.
$cover = (Show-CoverageMatrix -Result $pre) 2>&1 | Out-String
if ([string]::IsNullOrWhiteSpace($cover)) {
    $cover = (& { Show-CoverageMatrix -Result $pre } 6>&1 | Out-String)
}
foreach ($part in @('CPU', 'Cooling', 'Fans', 'Storage', 'Battery', 'Memory', 'GPU', 'PSU', 'Display', 'Network')) {
    Assert-True "Coverage matrix states a position on $part" ($cover -match $part)
}
Assert-True 'Memory is declared untested, never passed' ($cover -match '(?s)Memory\s+NONE')

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
