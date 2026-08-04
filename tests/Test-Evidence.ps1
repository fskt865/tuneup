# Test-Evidence.ps1 - hardware evidence module: snapshots, diffing, and the
# load-observation honesty checks.
# ASCII only, PowerShell 5.1 compatible.
#
# This module applies no load, so there is nothing here that pegs a core. What
# is verified is the arithmetic, the refusal logic, and above all the rule that
# an unobserved load can never be reported as a pass - which is the one new way
# this design can lie now that the load lives in an external tool.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'modules\Get-HardwareEvidence.ps1')

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
Write-Host '  Watch duration guards' -ForegroundColor Cyan
Write-Host '  ---------------------' -ForegroundColor DarkGray

Assert-True 'Default watch window is finite' ($script:EvidenceDefaults.WatchMinutes -gt 0 -and $script:EvidenceDefaults.WatchMinutes -le 60)
Assert-True 'Hard cap exists'                ($script:EvidenceDefaults.MaxWatchMins -gt 0 -and $script:EvidenceDefaults.MaxWatchMins -le 240)
Assert-True 'Hot threshold is sane'          ($script:EvidenceDefaults.HotTempC -ge 80 -and $script:EvidenceDefaults.HotTempC -le 105)
Assert-True 'Load threshold is a percentage' ($script:EvidenceDefaults.LoadCpuPct -gt 0 -and $script:EvidenceDefaults.LoadCpuPct -le 100)

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
Write-Host '  Load observation - the check that stops a false pass' -ForegroundColor Cyan
Write-Host '  ---------------------------------------------------' -ForegroundColor DarkGray

# The whole design rests on this. If the tech never started OCCT, the error
# diff is empty and everything downstream reads as healthy. Three states.
$noSamples = [pscustomobject]@{ Samples = @(); MeanCpuPercent = $null }
$obs = Get-LoadObservation -Result $noSamples
Assert-True 'No watch phase -> Undetermined, never a pass' ($obs.State -eq 'Undetermined') ("got=" + $obs.State)
Assert-True 'Undetermined explains itself'                 (-not [string]::IsNullOrWhiteSpace($obs.Note))

$unmeasurable = [pscustomobject]@{ Samples = @(1, 2, 3); MeanCpuPercent = $null }
Assert-True 'Samples but no CPU figure -> Undetermined' `
    ((Get-LoadObservation -Result $unmeasurable).State -eq 'Undetermined')

$idle = [pscustomobject]@{ Samples = @(1, 2, 3); MeanCpuPercent = 4 }
$idleObs = Get-LoadObservation -Result $idle
Assert-True 'Idle machine -> NotObserved, never a pass' ($idleObs.State -eq 'NotObserved') ("got=" + $idleObs.State)
Assert-True 'NotObserved says what was seen'            ($idleObs.Note -match '4')

$loaded = [pscustomobject]@{ Samples = @(1, 2, 3); MeanCpuPercent = 97 }
$loadedObs = Get-LoadObservation -Result $loaded
Assert-True 'Loaded machine -> Observed'      ($loadedObs.State -eq 'Observed')
Assert-True 'CPU-only load is labelled Cpu'   ($loadedObs.Kind -eq 'Cpu') ("got=" + $loadedObs.Kind)

# A GPU stress test leaves the CPU near idle BY DESIGN. Judging it on CPU
# percentage reported "nothing was tested" while the card was being cooked -
# which is the exact failure this module exists to prevent.
$gpuRun = [pscustomobject]@{
    MeanCpuPercent = 9
    Samples = @(
        [ordered]@{ GpuTempC = 44 }, [ordered]@{ GpuTempC = 61 }, [ordered]@{ GpuTempC = 78 })
}
$gpuObs = Get-LoadObservation -Result $gpuRun
Assert-True 'GPU test with idle CPU -> Observed' ($gpuObs.State -eq 'Observed') ("got=" + $gpuObs.State)
Assert-True 'GPU test is labelled Gpu'           ($gpuObs.Kind -eq 'Gpu') ("got=" + $gpuObs.Kind)
Assert-True 'GPU note says the CPU was idle'     ($gpuObs.Note -match '(?i)idle')

$both = [pscustomobject]@{
    MeanCpuPercent = 95
    Samples = @([ordered]@{ GpuTempC = 40 }, [ordered]@{ GpuTempC = 70 })
}
Assert-True 'CPU and GPU together -> CpuAndGpu' ((Get-LoadObservation -Result $both).Kind -eq 'CpuAndGpu')

# A GPU that barely moves is not a GPU under load - absolute temperature must
# never stand in for movement.
$gpuFlat = [pscustomobject]@{
    MeanCpuPercent = 5
    Samples = @([ordered]@{ GpuTempC = 71 }, [ordered]@{ GpuTempC = 72 }, [ordered]@{ GpuTempC = 71 })
}
$flatObs = Get-LoadObservation -Result $gpuFlat
Assert-True 'Hot but unmoving GPU is not load' ($flatObs.State -eq 'NotObserved') ("got=" + $flatObs.State)

# Nothing measurable at all is undetermined, not a negative finding.
$blind = [pscustomobject]@{ MeanCpuPercent = $null; Samples = @([ordered]@{ GpuTempC = $null }) }
Assert-True 'Nothing measurable -> Undetermined' ((Get-LoadObservation -Result $blind).State -eq 'Undetermined')

# The boundary itself, so a threshold edit cannot silently invert the meaning.
$atThreshold = [pscustomobject]@{ Samples = @(1); MeanCpuPercent = $script:EvidenceDefaults.LoadCpuPct }
Assert-True 'Exactly at the threshold counts as observed' `
    ((Get-LoadObservation -Result $atThreshold).State -eq 'Observed')
$belowThreshold = [pscustomobject]@{ Samples = @(1); MeanCpuPercent = ($script:EvidenceDefaults.LoadCpuPct - 1) }
Assert-True 'Just below the threshold is not observed' `
    ((Get-LoadObservation -Result $belowThreshold).State -eq 'NotObserved')

Write-Host ''
Write-Host '  The module generates no load' -ForegroundColor Cyan
Write-Host '  ----------------------------' -ForegroundColor DarkGray

# The load-generating machinery must stay gone. These names coming back means
# someone reintroduced a stress test into a module that promises it does not.
foreach ($gone in @('Invoke-StressModule', 'Invoke-DiskReadTest', 'Show-StressVerdict')) {
    Assert-True "Removed function '$gone' has not come back" `
    ($null -eq (Get-Command -Name $gone -ErrorAction SilentlyContinue))
}
$src = Get-Content -LiteralPath (Join-Path $Root 'modules\Get-HardwareEvidence.ps1') -Raw
Assert-True 'No background load workers are started' (-not ($src -match 'Start-Job'))

$sw = [Diagnostics.Stopwatch]::StartNew()
$base = Invoke-EvidenceModule
$sw.Stop()

Assert-True 'Baseline returns a result'        ($null -ne $base)
Assert-True 'Baseline is the default action'   ($base.Action -eq 'Baseline')
Assert-True 'Baseline declares it makes no load' (-not $base.GeneratesLoad)
Assert-True 'Baseline takes no samples'        (@($base.Samples).Count -eq 0)
Assert-True 'Baseline finished quickly'        ($sw.Elapsed.TotalSeconds -lt 180) ("secs=" + [math]::Round($sw.Elapsed.TotalSeconds, 1))
Assert-True 'Baseline recorded a snapshot'     ($null -ne $base.Baseline)
Assert-True 'Baseline snapshot is timestamped' (-not [string]::IsNullOrWhiteSpace($base.Baseline.TakenAt))

# An unknown action must fall back to the read-only default, not run something
# unexpected on a customer's machine.
$bogus = Invoke-EvidenceModule -Options @{ Action = 'DefinitelyNotAnAction' }
Assert-True 'Unknown action falls back to Baseline' ($bogus.Action -eq 'Baseline') ("got=" + $bogus.Action)

# The watch window must be capped however large a number is passed.
Assert-True 'Watch minutes are capped' ($script:EvidenceDefaults.MaxWatchMins -le 240)

Write-Host ''
Write-Host '  Baseline persistence' -ForegroundColor Cyan
Write-Host '  --------------------' -ForegroundColor DarkGray

# The baseline has to survive the tech closing the window while OCCT runs, so
# it lives on disk - on the LOCAL machine, never on the stick.
$bp = Get-BaselinePath
Assert-True 'Baseline path is under ProgramData, not the stick' ($bp -match '(?i)ProgramData')
Assert-True 'Baseline file was written'                         (Test-Path -LiteralPath $bp)
$loaded2 = Get-EvidenceBaseline
Assert-True 'Baseline reloads from disk'      ($null -ne $loaded2)
if ($loaded2) {
    Assert-True 'Reloaded baseline keeps its timestamp' (-not [string]::IsNullOrWhiteSpace($loaded2.TakenAt))
}

Write-Host ''
Write-Host '  Disk health interlock' -ForegroundColor Cyan
Write-Host '  ---------------------' -ForegroundColor DarkGray

$gate = Get-DiskHealthGate
Assert-True 'Disk gate reports a status' (@('Read', 'Unreadable', 'Unknown') -contains $gate.Status)
if ($gate.Status -eq 'Read' -and $gate.Healthy) {
    Assert-True 'Healthy disk does not trip the interlock' (-not $base.InterlockTripped)
}
# A failing disk must warn even though this module cannot stop an external tool.
$sick = [pscustomobject]@{ Status = 'Read'; Healthy = $false; Unhealthy = @([ordered]@{ Name = 'TestDisk'; Health = 'Warning' }) }
$warned = Show-DiskInterlock -Gate $sick 6>&1 | Out-Null
Assert-True 'Unhealthy disk trips the interlock' (Show-DiskInterlock -Gate $sick 6>$null)
$healthy = [pscustomobject]@{ Status = 'Read'; Healthy = $true; Unhealthy = @() }
Assert-True 'Healthy disk does not warn' (-not (Show-DiskInterlock -Gate $healthy 6>$null))

Write-Host ''
Write-Host '  Coverage honesty' -ForegroundColor Cyan
Write-Host '  ----------------' -ForegroundColor DarkGray

# The coverage matrix is the promise that "entire device" means a stated
# position on every part, not silence about the ones that were skipped.
$cover = (Show-CoverageMatrix -Result $base) 2>&1 | Out-String
if ([string]::IsNullOrWhiteSpace($cover)) {
    $cover = (& { Show-CoverageMatrix -Result $base } 6>&1 | Out-String)
}
foreach ($part in @('CPU', 'Cooling', 'Fans', 'Storage', 'Battery', 'Memory', 'GPU', 'PSU', 'Display', 'Network')) {
    Assert-True "Coverage matrix states a position on $part" ($cover -match $part)
}
Assert-True 'Memory is declared untested, never passed' ($cover -match '(?s)Memory\s+NONE')
# With no load observed the CPU must not be claimed as covered - that is the
# coverage-side half of the same false-pass guard.
Assert-True 'Unloaded CPU is not claimed as covered' ($cover -match '(?s)CPU\s+NONE')

Write-Host ''
Write-Host '  Verdict honesty with no load' -ForegroundColor Cyan
Write-Host '  ----------------------------' -ForegroundColor DarkGray

$idleResult = [pscustomobject]@{
    Samples = @(); MeanCpuPercent = $null; PeakTempC = $null; MinPerfPct = $null
    PeakFanRpm = $null; PeakGpuTempC = $null; SensorsUsable = $false
    Baseline = $null; After = $null; NewErrors = @(); SmartMoved = @()
    MemoryTest = $null
    LoadObservation = (Get-LoadObservation -Result ([pscustomobject]@{ Samples = @(); MeanCpuPercent = $null }))
}
$verdict = (& { Show-EvidenceVerdict -Result $idleResult } 6>&1 | Out-String)
Assert-True 'Verdict leads with the load warning' ($verdict -match 'LOAD NOT OBSERVED')
Assert-True 'Unloaded CPU is NOT TESTED, never PASS' ($verdict -match '(?s)CPU\s+NOT TESTED')
Assert-True 'Memory stays declared untested'         ($verdict -match '(?s)Memory\s+NOT TESTED')

# A GPU run must not be allowed to imply the CPU passed. This is the verdict
# side of the same mistake the observation logic had.
$gpuSamples = @([ordered]@{ GpuTempC = 40 }, [ordered]@{ GpuTempC = 75 })
$gpuObsForVerdict = Get-LoadObservation -Result ([pscustomobject]@{ Samples = $gpuSamples; MeanCpuPercent = 7 })
$gpuOnly = [pscustomobject]@{
    Samples = $gpuSamples
    MeanCpuPercent = 7; PeakTempC = $null; MinPerfPct = $null
    PeakFanRpm = $null; PeakGpuTempC = 75; SensorsUsable = $true
    Baseline = $null; After = $null; NewErrors = @(); SmartMoved = @()
    MemoryTest = $null
    LoadObservation = $gpuObsForVerdict
}
$gpuVerdict = (& { Show-EvidenceVerdict -Result $gpuOnly } 6>&1 | Out-String)
Assert-True 'GPU run reports load observed'        ($gpuVerdict -match 'Load observed')
Assert-True 'GPU run still says CPU NOT TESTED'    ($gpuVerdict -match '(?s)CPU\s+NOT TESTED')
Assert-True 'GPU run warns the CPU is unexercised' ($gpuVerdict -match '(?i)nothing below says anything about the CPU')
Assert-True 'GPU itself is passed on a GPU run'    ($gpuVerdict -match '(?s)GPU\s+PASS')

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
