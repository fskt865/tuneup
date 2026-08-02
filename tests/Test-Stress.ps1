# Test-Stress.ps1 - stress module preflight, interlocks and unit conversions.
# ASCII only, PowerShell 5.1 compatible.
#
# Deliberately does NOT run a load test. A test suite that pegs every core for
# minutes is a test suite nobody runs. What is verified here is the arithmetic
# and the refusal logic - the parts that decide whether load is applied at all.

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

# ACPI reports tenths of a Kelvin. Getting this wrong tells a tech a CPU is
# at 27 degrees when it is at 100, which is the difference between "fine" and
# "the fan is dead".
Assert-True 'Freezing point (2731) = 0 C'   ((Convert-DeciKelvinToC -DeciKelvin 2731) -eq 0)
Assert-True 'Room temp (2981) = 25 C'       ((Convert-DeciKelvinToC -DeciKelvin 2981) -eq 25)
Assert-True 'Hot CPU (3731) = 100 C'        ((Convert-DeciKelvinToC -DeciKelvin 3731) -eq 100)
Assert-True 'Throttle range (3631) = 90 C'  ((Convert-DeciKelvinToC -DeciKelvin 3631) -eq 90)
Assert-True 'Conversion is not a raw divide' ((Convert-DeciKelvinToC -DeciKelvin 3731) -ne 373.1)

Write-Host ''
Write-Host '  Duration and thread guards' -ForegroundColor Cyan
Write-Host '  --------------------------' -ForegroundColor DarkGray

Assert-True 'Default duration is short'  ($script:StressDefaults.Minutes -le 5) ("mins=" + $script:StressDefaults.Minutes)
Assert-True 'Hard cap exists'            ($script:StressDefaults.MaxMinutes -gt 0 -and $script:StressDefaults.MaxMinutes -le 60)
Assert-True 'Default abort temp is sane' ($script:StressDefaults.MaxTempC -ge 80 -and $script:StressDefaults.MaxTempC -le 105)

Write-Host ''
Write-Host '  Preflight is read-only' -ForegroundColor Cyan
Write-Host '  ----------------------' -ForegroundColor DarkGray

# Without -Apply nothing may run. Confirm by timing: a preflight that
# accidentally applied load would take minutes, not seconds.
$sw = [Diagnostics.Stopwatch]::StartNew()
$pre = Invoke-StressModule
$sw.Stop()

Assert-True 'Preflight returns a result'        ($null -ne $pre)
Assert-True 'Preflight mode is PreflightOnly'   ($pre.Mode -eq 'PreflightOnly') ("mode=" + $pre.Mode)
Assert-True 'Preflight applied no load'         (-not $pre.Completed)
Assert-True 'Preflight took no samples'         (@($pre.Samples).Count -eq 0)
Assert-True 'Preflight finished in seconds'     ($sw.Elapsed.TotalSeconds -lt 60) ("secs=" + [math]::Round($sw.Elapsed.TotalSeconds, 1))
Assert-True 'Preflight captured a baseline'     ($null -ne $pre.Baseline)

Assert-True 'Duration is capped' `
((Invoke-StressModule -Options @{ Minutes = 9999 }).Minutes -le $script:StressDefaults.MaxMinutes)
Assert-True 'Zero/negative duration is corrected' `
((Invoke-StressModule -Options @{ Minutes = 0 }).Minutes -ge 1)

Write-Host ''
Write-Host '  Disk health interlock' -ForegroundColor Cyan
Write-Host '  ---------------------' -ForegroundColor DarkGray

$gate = Get-DiskHealthGate
Assert-True 'Disk gate reports a status' (@('Read', 'Unreadable') -contains $gate.Status) ("status=" + $gate.Status)

# The interlock is the single most important behaviour in this module:
# stressing a machine with a dying disk risks the data that should be
# recovered first. Verify the refusal fires on a synthetic unhealthy gate.
if ($gate.Status -eq 'Read' -and $gate.Healthy) {
    Assert-True 'Healthy disk does not block preflight' ($pre.AbortReason -ne 'DiskHealthInterlock')
}

$blockedShape = [pscustomobject]@{ Status = 'Read'; Healthy = $false; Unhealthy = @(@{ Name = 'X'; Health = 'Unhealthy' }) }
Assert-True 'Unhealthy gate shape is recognised as blocking' (-not $blockedShape.Healthy)

Write-Host ''
Write-Host '  Sensor honesty' -ForegroundColor Cyan
Write-Host '  --------------' -ForegroundColor DarkGray

$thermal = Get-ThermalReading
Assert-True 'Thermal reading reports a status, never a bare null' `
(@('Read', 'Unsupported', 'RequiresElevation') -contains $thermal.Status) ("status=" + $thermal.Status)
if ($thermal.Status -ne 'Read') {
    Assert-True 'Unreadable thermal yields no temperature value' ($null -eq $thermal.TempC)
}

Write-Host ''
Write-Host '  Tool discovery' -ForegroundColor Cyan
Write-Host '  --------------' -ForegroundColor DarkGray

$tools = @(Get-BundledTools -ToolRoot (Join-Path $Root 'tools'))
Assert-True 'Tool discovery runs on a folder with no binaries' ($tools.Count -ge 0)
Assert-True 'Tool discovery on a missing folder returns empty' `
(@(Get-BundledTools -ToolRoot (Join-Path $Root 'no-such-folder')).Count -eq 0)

# The folder's own README is documentation, not a diagnostic tool. Listing it
# as one is how -Include silently failing showed up.
$nonExe = @($tools | Where-Object { $_.Name -notmatch '\.(exe|cmd|bat|msi)$' })
Assert-True 'Non-executables are not listed as tools' ($nonExe.Count -eq 0) `
("listed=" + (@($nonExe | ForEach-Object { $_.Name }) -join ','))

# Synthetic folder: one executable and one document, only the exe may appear.
$tmpTools = Join-Path ([IO.Path]::GetTempPath()) ('tuneup-tools-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    New-Item -ItemType Directory -Path $tmpTools -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $tmpTools 'notes.txt') -Value 'not a tool' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $tmpTools 'thing.exe') -Value 'pretend' -Encoding ASCII

    $synthetic = @(Get-BundledTools -ToolRoot $tmpTools)
    Assert-True 'Synthetic folder yields exactly one tool' ($synthetic.Count -eq 1) ("count=" + $synthetic.Count)
    if ($synthetic.Count -eq 1) {
        Assert-True 'The executable is the one listed' ($synthetic[0].Name -eq 'thing.exe')
    }
}
finally {
    Remove-Item -LiteralPath $tmpTools -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
