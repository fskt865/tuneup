<#MANIFEST
{
  "Key": "stress",
  "Title": "Load and stability testing",
  "Entry": "Invoke-StressModule",
  "Order": 40,
  "RequiresAdmin": false,
  "Description": "Controlled CPU load with thermal and throttle telemetry; refuses to run on a failing disk"
}
MANIFEST#>

# Test-SystemStress.ps1 - reproduce load-dependent faults with telemetry.
# ASCII only, PowerShell 5.1 compatible.
#
# The point is NOT a benchmark score. It is reproducing "it shuts off when it
# gets warm" or "it crawls after ten minutes" on the bench, with the telemetry
# that tells you which layer failed - thermal, firmware throttle, or power.
#
# THE INTERLOCK THAT MATTERS: this refuses to run when the disk is not
# reporting healthy. Stressing a machine with a dying drive risks the data you
# should be recovering FIRST. Get the data off, then test the hardware.
# -Force overrides it; the tool says plainly what you are overriding.
#
# No disk WRITE tests, ever. A throughput benchmark that writes to a
# customer's volume is not worth the risk, and read-side telemetry plus SMART
# tells you what you need.
#
# No third-party binaries ship here. Drop them in tools\ on the stick (see
# tools\README.md) and this module will list what it finds.

$script:StressDefaults = @{
    Minutes    = 2
    MaxMinutes = 30
    MaxTempC   = 95
    SampleSecs = 5
}

# Kelvin tenths is what ACPI reports. Converting it wrong is an easy way to
# tell a tech a CPU is at 27 degrees when it is at 100.
function Convert-DeciKelvinToC {
    param([double]$DeciKelvin)
    return [math]::Round(($DeciKelvin / 10) - 273.15, 1)
}

function Get-ThermalReading {
    $out = [ordered]@{ Status = 'Unknown'; TempC = $null; ZoneCount = 0 }
    try {
        $zones = @(Get-CimInstance -Namespace 'root/wmi' -ClassName 'MSAcpi_ThermalZoneTemperature' -ErrorAction Stop)
        if ($zones.Count -eq 0) { $out.Status = 'Unsupported'; return [pscustomobject]$out }

        $temps = @($zones | ForEach-Object { Convert-DeciKelvinToC -DeciKelvin $_.CurrentTemperature })
        $out.ZoneCount = $zones.Count
        $out.TempC = ($temps | Measure-Object -Maximum).Maximum
        $out.Status = 'Read'
    }
    catch {
        # Plenty of laptops simply do not expose this. That is not a fault,
        # but it must not read as "temperature is fine" either.
        if (-not (Test-IsAdmin)) { $out.Status = 'RequiresElevation' }
        else { $out.Status = 'Unsupported' }
    }
    return [pscustomobject]$out
}

function Get-CpuPerformancePercent {
    # Above 100 means turbo. Below 100 means the chip is running under its own
    # base clock, which is the signature of thermal or firmware throttling.
    try {
        $s = Get-Counter '\Processor Information(_Total)\% Processor Performance' -ErrorAction Stop
        return [math]::Round($s.CounterSamples[0].CookedValue, 1)
    }
    catch { return $null }
}

function Get-DiskHealthGate {
    $gate = [ordered]@{ Status = 'Unknown'; Healthy = $false; Unhealthy = @() }
    try {
        $disks = @(Get-PhysicalDisk -ErrorAction Stop)
        $bad = @($disks | Where-Object { $_.HealthStatus -ne 'Healthy' })
        $gate.Unhealthy = @($bad | ForEach-Object { [ordered]@{ Name = $_.FriendlyName; Health = [string]$_.HealthStatus } })
        $gate.Healthy = ($bad.Count -eq 0)
        $gate.Status = 'Read'
    }
    catch { $gate.Status = 'Unreadable' }
    return [pscustomobject]$gate
}

function Get-ThrottleEventCount {
    param([datetime]$Since)
    # Kernel-Processor-Power ID 37: firmware is limiting processor speed.
    # That is the machine telling you it is throttling, in its own words.
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{
                LogName = 'System'; Id = 37; StartTime = $Since
                ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'
            } -ErrorAction Stop)
        return $ev.Count
    }
    catch { return 0 }
}

function Get-BundledTools {
    param([string]$ToolRoot)

    $found = @()
    if (-not (Test-Path -LiteralPath $ToolRoot)) { return $found }

    # Filter on the extension with Where-Object rather than -Include.
    # -Include is silently ignored alongside -LiteralPath, which listed the
    # folder's own README as though it were a diagnostic tool.
    $exeExtensions = @('.exe', '.cmd', '.bat', '.msi')

    $candidates = @(Get-ChildItem -LiteralPath $ToolRoot -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $exeExtensions -contains $_.Extension.ToLower() })

    foreach ($f in $candidates) {
        $found += [pscustomobject]@{
            Name = $f.Name
            RelativePath = $f.FullName.Substring($ToolRoot.Length).TrimStart('\')
            SizeMB = [math]::Round($f.Length / 1MB, 1)
        }
    }
    return $found
}

function Invoke-StressModule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$Apply,
        [hashtable]$Options = @{}
    )

    $minutes = $script:StressDefaults.Minutes
    if ($Options['Minutes']) { $minutes = [int]$Options['Minutes'] }
    if ($minutes -gt $script:StressDefaults.MaxMinutes) {
        Write-Log -Message ("Capping run at {0} minutes" -f $script:StressDefaults.MaxMinutes) -Level WARN
        $minutes = $script:StressDefaults.MaxMinutes
    }
    if ($minutes -lt 1) { $minutes = 1 }

    $maxTemp = $script:StressDefaults.MaxTempC
    if ($Options['MaxTempC']) { $maxTemp = [int]$Options['MaxTempC'] }
    $force = [bool]$Options['Force']

    $threads = 0
    try { $threads = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors } catch { }
    if ($Options['Threads']) { $threads = [int]$Options['Threads'] }
    if ($threads -lt 1) { $threads = 2 }

    Write-Banner 'Load and stability testing'

    $result = [ordered]@{
        Mode          = $(if ($Apply) { 'Apply' } else { 'PreflightOnly' })
        Minutes       = $minutes
        Threads       = $threads
        MaxTempC      = $maxTemp
        Baseline      = $null
        DiskGate      = $null
        OnBattery     = $null
        Samples       = @()
        PeakTempC     = $null
        MinPerfPct    = $null
        ThrottleEvents = 0
        AbortReason   = $null
        Completed     = $false
        BundledTools  = @()
    }

    # --- Preflight --------------------------------------------------------
    $thermal = Get-ThermalReading
    $perf = Get-CpuPerformancePercent
    $gate = Get-DiskHealthGate
    $result.DiskGate = $gate

    $cpuName = ''
    try { $cpuName = (Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).Name } catch { }

    $onBattery = $null
    try {
        $b = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($b) { $onBattery = ($b.BatteryStatus -eq 1) }
    }
    catch { }
    $result.OnBattery = $onBattery

    $result.Baseline = [ordered]@{
        Cpu           = $cpuName
        LogicalCores  = $threads
        ThermalStatus = $thermal.Status
        IdleTempC     = $thermal.TempC
        IdlePerfPct   = $perf
    }

    Write-Host ''
    Write-Host ('  CPU          : {0}' -f $cpuName) -ForegroundColor Gray
    Write-Host ('  Load threads : {0}' -f $threads) -ForegroundColor Gray
    Write-Host ('  Duration     : {0} minute(s), abort above {1} C' -f $minutes, $maxTemp) -ForegroundColor Gray

    switch ($thermal.Status) {
        'Read' { Write-Host ('  Idle temp    : {0} C across {1} zone(s)' -f $thermal.TempC, $thermal.ZoneCount) -ForegroundColor Gray }
        'RequiresElevation' { Write-Host '  Idle temp    : NOT READ - needs elevation. Thermal abort will not work.' -ForegroundColor Yellow }
        default { Write-Host '  Idle temp    : this machine does not expose ACPI thermal zones. No thermal abort.' -ForegroundColor Yellow }
    }
    if ($null -ne $perf) { Write-Host ('  Idle perf    : {0}% of base clock' -f $perf) -ForegroundColor Gray }

    # --- Safety interlocks -------------------------------------------------
    $blocked = @()

    if ($gate.Status -eq 'Read' -and -not $gate.Healthy) {
        $blocked += 'A disk is not reporting Healthy'
    }
    elseif ($gate.Status -ne 'Read') {
        Write-Host '  Disk health  : could not be read - cannot confirm it is safe to stress this machine.' -ForegroundColor Yellow
    }

    if ($thermal.Status -ne 'Read') {
        Write-Host '  WARNING: with no temperature source, this cannot abort on heat.' -ForegroundColor Yellow
        Write-Host '           Watch the machine, and stop it yourself if it gets hot.' -ForegroundColor Yellow
    }

    if ($onBattery -eq $true) {
        Write-Host '  WARNING: running on battery. Expect throttling and a fast drain -' -ForegroundColor Yellow
        Write-Host '           results will not represent behaviour on mains.' -ForegroundColor Yellow
    }

    if ($blocked.Count -gt 0) {
        Write-Host ''
        Write-Host '  REFUSING TO RUN A LOAD TEST:' -ForegroundColor Red
        foreach ($b in $blocked) { Write-Host ('    - ' + $b) -ForegroundColor Red }
        foreach ($u in $gate.Unhealthy) {
            Write-Host ('      {0}: {1}' -f $u.Name, $u.Health) -ForegroundColor Red
        }
        Write-Host ''
        Write-Host '  Stressing a machine with a failing drive risks the data you should be' -ForegroundColor Yellow
        Write-Host '  recovering first. Image the drive, get the data off, THEN test hardware.' -ForegroundColor Yellow
        Write-Host '  Override with -Force only when the data is already safe.' -ForegroundColor DarkGray
        Write-Host ''
        if (-not $force) {
            $result.AbortReason = 'DiskHealthInterlock'
            return [pscustomobject]$result
        }
        Write-Log -Message 'Disk health interlock OVERRIDDEN with -Force' -Level WARN
    }

    # --- Third-party tools on the stick ------------------------------------
    $toolRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools'
    $tools = @(Get-BundledTools -ToolRoot $toolRoot)
    foreach ($t in $tools) {
        $result.BundledTools += [ordered]@{ Name = $t.Name; SizeMB = $t.SizeMB }
    }
    if ($tools.Count -gt 0) {
        Write-Host ''
        Write-Host '  Third-party tools found in tools\ :' -ForegroundColor Cyan
        foreach ($t in $tools) {
            Write-Host ('    {0,-32} {1} MB' -f $t.Name, $t.SizeMB) -ForegroundColor Gray
        }
        Write-Host '    Launch these yourself - this module does not run them.' -ForegroundColor DarkGray
    }

    # --- Other stability tests worth knowing about -------------------------
    Write-Host ''
    Write-Host '  Not run here, because they need a reboot or are long-running:' -ForegroundColor Cyan
    Write-Host '    Memory test   : mdsched.exe        (schedules a test at next boot)' -ForegroundColor DarkGray
    Write-Host '    Surface scan  : chkdsk C: /scan    (online, read-only, safe to run live)' -ForegroundColor DarkGray
    Write-Host '    Full surface  : chkdsk C: /r       (offline, hours - only with the data backed up)' -ForegroundColor DarkGray

    if (-not $Apply) {
        Write-Host ''
        Write-Host '  Preflight only. No load was applied.' -ForegroundColor Cyan
        Write-Host '  -Apply runs the load test. Add -Minutes N to change the duration.' -ForegroundColor Cyan
        Write-Host ''
        return [pscustomobject]$result
    }

    if (-not $PSCmdlet.ShouldProcess(('CPU, {0} thread(s) for {1} minute(s)' -f $threads, $minutes), 'Apply sustained load')) {
        return [pscustomobject]$result
    }

    # --- Load test ---------------------------------------------------------
    Write-Banner ('Applying load: {0} thread(s), {1} minute(s)' -f $threads, $minutes)
    Write-Host '  Ctrl-C stops the test and shuts the workers down cleanly.' -ForegroundColor DarkGray
    Write-Host ''

    $started = Get-Date
    $deadline = $started.AddMinutes($minutes)
    $jobs = @()

    try {
        for ($i = 0; $i -lt $threads; $i++) {
            $jobs += Start-Job -ScriptBlock {
                param($EndTime)
                $x = 0.0
                $n = 0
                while ((Get-Date) -lt $EndTime) {
                    # Floating point plus integer work; enough to peg a core
                    # without allocating and dragging the GC into it.
                    $x = [math]::Sqrt($n) + [math]::Sin($n)
                    $n++
                    if ($n -gt 2147000000) { $n = 0 }
                }
                return $n
            } -ArgumentList $deadline
        }

        $peak = $null
        $minPerf = $null

        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $script:StressDefaults.SampleSecs

            $t = Get-ThermalReading
            $p = Get-CpuPerformancePercent
            $elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds, 0)

            $result.Samples += [ordered]@{ ElapsedSec = $elapsed; TempC = $t.TempC; PerfPct = $p }

            if ($null -ne $t.TempC) {
                if ($null -eq $peak -or $t.TempC -gt $peak) { $peak = $t.TempC }
            }
            if ($null -ne $p) {
                if ($null -eq $minPerf -or $p -lt $minPerf) { $minPerf = $p }
            }

            $line = '    {0,4}s  temp {1,6}  perf {2,6}%' -f $elapsed,
            $(if ($null -ne $t.TempC) { "$($t.TempC) C" } else { 'n/a' }),
            $(if ($null -ne $p) { $p } else { 'n/a' })

            $color = 'Gray'
            if ($null -ne $p -and $p -lt 70) { $color = 'Yellow' }
            if ($null -ne $t.TempC -and $t.TempC -ge ($maxTemp - 10)) { $color = 'Yellow' }
            Write-Host $line -ForegroundColor $color

            if ($null -ne $t.TempC -and $t.TempC -ge $maxTemp) {
                $result.AbortReason = ('ThermalLimit:{0}C' -f $t.TempC)
                Write-Log -Message ("ABORTING - {0} C reached the {1} C limit" -f $t.TempC, $maxTemp) -Level FAIL
                break
            }
        }

        $result.PeakTempC = $peak
        $result.MinPerfPct = $minPerf
        if (-not $result.AbortReason) { $result.Completed = $true }
    }
    finally {
        # Non-negotiable. Leaving CPU-pegging jobs behind on a customer's
        # machine because the test was interrupted is unforgivable, so this
        # runs on Ctrl-C, on abort and on error alike.
        foreach ($j in $jobs) {
            try { Stop-Job -Job $j -ErrorAction SilentlyContinue } catch { }
            try { Remove-Job -Job $j -Force -ErrorAction SilentlyContinue } catch { }
        }
        Write-Log -Message 'Load workers stopped' -Level OK
    }

    $result.ThrottleEvents = Get-ThrottleEventCount -Since $started

    # --- Verdict ------------------------------------------------------------
    Write-Host ''
    if ($result.AbortReason) {
        Write-Host ('  ABORTED: ' + $result.AbortReason) -ForegroundColor Red
        Write-Host '  The machine hit the thermal limit under sustained load. That is a' -ForegroundColor Yellow
        Write-Host '  cooling problem - paste, fan, or blocked intake - not a software one.' -ForegroundColor Yellow
    }
    elseif ($result.Completed) {
        Write-Host ('  Completed {0} minute(s) without hitting the limit.' -f $minutes) -ForegroundColor Green
    }

    if ($null -ne $result.PeakTempC) { Write-Host ('  Peak temperature : {0} C' -f $result.PeakTempC) -ForegroundColor Gray }
    if ($null -ne $result.MinPerfPct) {
        Write-Host ('  Lowest perf      : {0}% of base clock' -f $result.MinPerfPct) -ForegroundColor Gray
        if ($result.MinPerfPct -lt 70) {
            Write-Host '  Sustained running below base clock means it is throttling under load.' -ForegroundColor Yellow
        }
    }
    Write-Host ('  Firmware throttle events during the run: {0}' -f $result.ThrottleEvents) -ForegroundColor $(if ($result.ThrottleEvents -gt 0) { 'Yellow' } else { 'Gray' })
    if ($result.ThrottleEvents -gt 0) {
        Write-Host '  Kernel-Processor-Power ID 37 - firmware limited the CPU speed. Confirms' -ForegroundColor Yellow
        Write-Host '  throttling rather than a slow-software complaint.' -ForegroundColor Yellow
    }
    Write-Host ''

    return [pscustomobject]$result
}
