<#MANIFEST
{
  "Key": "clocks",
  "Title": "Clock and power-state review",
  "Entry": "Invoke-ClockModule",
  "Order": 22,
  "RequiresAdmin": false,
  "Description": "Is anything running off spec - CPU capped by power policy, RAM below its rating, GPU or CPU overclocked"
}
MANIFEST#>

# Get-ClockStatus.ps1 - is anything running off its rated speed?
# ASCII only, PowerShell 5.1 compatible. READ ONLY - reports, never changes.
#
# Two different faults look identical to a customer ("it got slow"), and this
# tells them apart:
#
#   UNDERCLOCKED  something is holding the machine below spec. Most often the
#                 power plan's maximum processor state, which is a single
#                 registry-backed number that can make a healthy laptop feel
#                 broken. Also RAM running at JEDEC default because XMP/EXPO
#                 was never enabled, or a firmware thermal cap.
#   OVERCLOCKED   something is running above spec. On a machine that crashes
#                 under load this is the first thing to undo, before spending
#                 an hour on drivers or RAM.
#
# It changes nothing. Power plans and firmware settings are the owner's
# configuration, and an overclock may well be deliberate - so this prints what
# it found and the command to change it, and stops there.

# Documented power-setting GUIDs. Using the GUIDs rather than the friendly
# names keeps this working on non-English Windows, where powercfg's text output
# is localised and unparseable.
$script:PowerGuids = @{
    SubProcessor    = '54533251-82be-4824-96c1-47b60b740d00'
    ThrottleMax     = 'bc5038f7-23e0-4960-96da-33abaf5935ec'
    ThrottleMin     = '893dee8e-2bef-41e0-89c6-b55d0929964c'
    BoostMode       = 'be337238-0d82-4146-a960-4f3749d470c7'
}

function Get-PowerSettingIndex {
    param([string]$SettingGuid)

    $out = [pscustomobject]@{ Ac = $null; Dc = $null }
    try {
        $raw = & powercfg.exe '/q' 'SCHEME_CURRENT' $script:PowerGuids.SubProcessor $SettingGuid 2>$null | Out-String
        # "Current AC Power Setting Index: 0x00000064"
        if ($raw -match '(?im)^\s*Current AC Power Setting Index:\s*0x([0-9a-f]+)') { $out.Ac = [Convert]::ToInt32($Matches[1], 16) }
        if ($raw -match '(?im)^\s*Current DC Power Setting Index:\s*0x([0-9a-f]+)') { $out.Dc = [Convert]::ToInt32($Matches[1], 16) }
    }
    catch { }
    return $out
}

function Get-ActiveSchemeName {
    try {
        $raw = & powercfg.exe '/getactivescheme' 2>$null | Out-String
        if ($raw -match '\(([^)]+)\)') { return $Matches[1] }
        return $raw.Trim()
    }
    catch { return 'unknown' }
}

function Get-CpuClockStatus {
    $out = [pscustomobject]@{
        Name = ''; RatedMHz = $null; ReportedMHz = $null
        PerformancePct = $null; Cores = $null; Logical = $null
    }
    try {
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $out.Name = $cpu.Name
        $out.RatedMHz = [int]$cpu.MaxClockSpeed
        $out.ReportedMHz = [int]$cpu.CurrentClockSpeed
        $out.Cores = [int]$cpu.NumberOfCores
        $out.Logical = [int]$cpu.NumberOfLogicalProcessors
    }
    catch { }
    try { $out.PerformancePct = [math]::Round((Get-Counter '\Processor Information(_Total)\% Processor Performance' -ErrorAction Stop).CounterSamples[0].CookedValue, 1) }
    catch { }
    return $out
}

# RAM below its rating is the single most common "off spec" finding on a
# desktop: the modules are rated 3200 but the board booted them at the JEDEC
# default because XMP/EXPO was never switched on.
function Get-MemoryClockStatus {
    $out = @()
    try {
        foreach ($m in (Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop)) {
            $rated = [int]$m.Speed
            $running = [int]$m.ConfiguredClockSpeed
            $verdict = 'AT SPEC'
            if ($running -gt 0 -and $rated -gt 0) {
                if ($running -lt $rated) { $verdict = 'BELOW RATING' }
                elseif ($running -gt $rated) { $verdict = 'ABOVE RATING' }
            }
            else { $verdict = 'UNKNOWN' }

            $out += [pscustomobject]@{
                Slot = [string]$m.DeviceLocator
                CapacityGB = [math]::Round($m.Capacity / 1GB, 0)
                RatedMHz = $rated
                RunningMHz = $running
                Verdict = $verdict
            }
        }
    }
    catch { }
    return $out
}

# Live clocks from LibreHardwareMonitor if it happens to be running. Not
# started here - this module is read-only and a sensor provider loads a kernel
# driver. The stress module starts it when a run actually needs it.
function Get-LiveClocks {
    $out = @()
    try {
        $raw = Invoke-WebRequest -Uri 'http://localhost:8085/data.json' -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        $root = $raw.Content | ConvertFrom-Json
    }
    catch { return $out }

    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    $stack.Push([pscustomobject]@{ Node = $root; Group = '' })
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $n = $item.Node
        $kids = @()
        try { $kids = @($n.Children) } catch { }
        if ($kids.Count -gt 0) {
            $g = $item.Group
            if ($n.Text -match '^(Clocks)$') { $g = $n.Text }
            foreach ($k in $kids) { $stack.Push([pscustomobject]@{ Node = $k; Group = $g }) }
            continue
        }
        if ($item.Group -ne 'Clocks') { continue }
        $val = [string]$n.Value
        if ($val -match '(-?\d+(?:[.,]\d+)?)') {
            $num = $null
            try { $num = [double](($Matches[1]) -replace ',', '.') } catch { }
            if ($null -ne $num -and $num -gt 0) {
                $out += [pscustomobject]@{ Name = [string]$n.Text; MHz = [math]::Round($num, 0) }
            }
        }
    }
    return $out
}

function Invoke-ClockModule {
    [CmdletBinding()]
    param([switch]$Apply, [hashtable]$Options = @{})

    if ($Apply) {
        Write-Log -Message 'The clocks module is read-only. Power plans and firmware settings are the owner configuration - it prints what to change rather than changing it.' -Level WARN
    }

    Write-Banner 'Clock and power-state review'

    $result = [ordered]@{
        Cpu = $null; Memory = @(); LiveClocks = @()
        PowerScheme = ''; ThrottleMax = $null; ThrottleMin = $null; BoostMode = $null
        Findings = @()
    }

    $cpu = Get-CpuClockStatus
    $result.Cpu = $cpu
    $result.PowerScheme = Get-ActiveSchemeName
    $result.ThrottleMax = Get-PowerSettingIndex -SettingGuid $script:PowerGuids.ThrottleMax
    $result.ThrottleMin = Get-PowerSettingIndex -SettingGuid $script:PowerGuids.ThrottleMin
    $result.Memory = @(Get-MemoryClockStatus)
    $result.LiveClocks = @(Get-LiveClocks)

    $onBattery = $false
    try {
        $b = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($b) { $onBattery = ($b.BatteryStatus -eq 1) }
    }
    catch { }

    # --- CPU -----------------------------------------------------------
    Write-Host ''
    Write-Host '  CPU' -ForegroundColor White
    Write-Host ('    {0}' -f $cpu.Name) -ForegroundColor Gray
    Write-Host ('    Rated base clock : {0} MHz   ({1} cores / {2} threads)' -f $cpu.RatedMHz, $cpu.Cores, $cpu.Logical) -ForegroundColor Gray
    if ($null -ne $cpu.PerformancePct) {
        $pctColor = 'Green'
        $pctNote = 'at or near base clock'
        if ($cpu.PerformancePct -gt 105) { $pctColor = 'Cyan'; $pctNote = 'above base clock - turbo or an overclock' }
        if ($cpu.PerformancePct -lt 80) { $pctColor = 'Yellow'; $pctNote = 'BELOW base clock - being held back' }
        Write-Host ('    Running at       : {0}% of base clock - {1}' -f $cpu.PerformancePct, $pctNote) -ForegroundColor $pctColor
        Write-Host '    (sampled at idle - the stress module measures this under load)' -ForegroundColor DarkGray
    }

    # --- Power policy: the usual culprit --------------------------------
    Write-Host ''
    Write-Host '  POWER POLICY' -ForegroundColor White
    Write-Host ('    Active scheme    : {0}' -f $result.PowerScheme) -ForegroundColor Gray

    $maxAc = $result.ThrottleMax.Ac
    $maxDc = $result.ThrottleMax.Dc
    $minAc = $result.ThrottleMin.Ac
    $minDc = $result.ThrottleMin.Dc

    if ($null -ne $maxAc) {
        $acColor = $(if ($maxAc -lt 100) { 'Red' } else { 'Green' })
        $dcColor = $(if ($null -ne $maxDc -and $maxDc -lt 100) { 'Yellow' } else { 'Green' })
        Write-Host ('    Max processor    : {0}% on AC' -f $maxAc) -ForegroundColor $acColor
        Write-Host ('                       {0}% on battery' -f $maxDc) -ForegroundColor $dcColor
        Write-Host ('    Min processor    : {0}% AC / {1}% battery' -f $minAc, $minDc) -ForegroundColor Gray

        if ($maxAc -lt 100) {
            $result.Findings += 'CPU capped by power policy on AC'
            Write-Host ''
            Write-Host ('    CAPPED: the power plan limits this CPU to {0}% on mains.' -f $maxAc) -ForegroundColor Red
            Write-Host '    This is the most common reason a healthy machine feels slow, and it' -ForegroundColor Yellow
            Write-Host '    is a single setting - not a hardware fault. To lift it:' -ForegroundColor Yellow
            Write-Host '      powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100' -ForegroundColor DarkGray
            Write-Host '      powercfg /setactive SCHEME_CURRENT' -ForegroundColor DarkGray
            Write-Host '    Not done automatically - it is the owner configuration.' -ForegroundColor DarkGray
        }
        elseif ($null -ne $maxDc -and $maxDc -lt 100 -and $onBattery) {
            Write-Host ''
            Write-Host ('    On battery and capped at {0}% - expected, not a fault. Any clock' -f $maxDc) -ForegroundColor Yellow
            Write-Host '    measurement taken now understates the machine. Test on mains.' -ForegroundColor Yellow
        }
    }
    else {
        Write-Host '    Processor throttle settings could not be read.' -ForegroundColor Yellow
    }

    # --- Memory ---------------------------------------------------------
    Write-Host ''
    Write-Host '  MEMORY' -ForegroundColor White
    if ($result.Memory.Count -eq 0) {
        Write-Host '    could not read module details' -ForegroundColor Yellow
    }
    else {
        foreach ($m in $result.Memory) {
            $c = 'Green'
            if ($m.Verdict -eq 'BELOW RATING') { $c = 'Yellow' }
            if ($m.Verdict -eq 'ABOVE RATING') { $c = 'Cyan' }
            Write-Host ('    {0,-10} {1,3} GB   rated {2} MHz   running {3} MHz   {4}' -f `
                    $m.Slot, $m.CapacityGB, $m.RatedMHz, $m.RunningMHz, $m.Verdict) -ForegroundColor $c
        }
        $below = @($result.Memory | Where-Object { $_.Verdict -eq 'BELOW RATING' })
        if ($below.Count -gt 0) {
            $result.Findings += 'RAM running below its rated speed'
            Write-Host ''
            Write-Host '    BELOW RATING: the modules are rated faster than they are running.' -ForegroundColor Yellow
            Write-Host '    Usually XMP/EXPO was never enabled in firmware, so the board booted' -ForegroundColor Yellow
            Write-Host '    them at the JEDEC default. Real, but a configuration choice, and on' -ForegroundColor Yellow
            Write-Host '    a machine that is crashing it is the SAFE state - do not "fix" it' -ForegroundColor Yellow
            Write-Host '    until the instability is resolved.' -ForegroundColor Yellow
        }
        $above = @($result.Memory | Where-Object { $_.Verdict -eq 'ABOVE RATING' })
        if ($above.Count -gt 0) {
            $result.Findings += 'RAM running above its rated speed'
            Write-Host ''
            Write-Host '    ABOVE RATING: memory is overclocked. On a machine that crashes under' -ForegroundColor Red
            Write-Host '    load or fails MemTest86+, undo this FIRST - before drivers, before' -ForegroundColor Red
            Write-Host '    parts. An unstable memory overclock imitates failing RAM exactly.' -ForegroundColor Red
        }
    }

    # --- Live clocks -----------------------------------------------------
    if ($result.LiveClocks.Count -gt 0) {
        Write-Host ''
        Write-Host '  LIVE CLOCKS (LibreHardwareMonitor)' -ForegroundColor White
        foreach ($c in ($result.LiveClocks | Sort-Object MHz -Descending | Select-Object -First 10)) {
            Write-Host ('    {0,-28} {1,6} MHz' -f $c.Name, $c.MHz) -ForegroundColor Gray
        }
    }
    else {
        Write-Host ''
        Write-Host '  LIVE CLOCKS: not available - LibreHardwareMonitor is not running.' -ForegroundColor DarkGray
        Write-Host '  Per-core and GPU clocks need it up; the stress module starts it when' -ForegroundColor DarkGray
        Write-Host '  a load run needs sensors.' -ForegroundColor DarkGray
    }

    # --- Verdict ----------------------------------------------------------
    Write-Host ''
    if ($result.Findings.Count -eq 0) {
        Write-Host '  Nothing running off spec: CPU not capped, memory at its rated speed.' -ForegroundColor Green
    }
    else {
        Write-Host '  OFF-SPEC FINDINGS:' -ForegroundColor Yellow
        foreach ($f in $result.Findings) { Write-Host ('    - ' + $f) -ForegroundColor Yellow }
    }
    Write-Host ''
    Write-Host '  Read-only. Nothing was changed.' -ForegroundColor DarkGray
    Write-Host ''

    return [pscustomobject]$result
}
