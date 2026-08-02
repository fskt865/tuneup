<#MANIFEST
{
  "Key": "stress",
  "Title": "Whole-system stress and fault isolation",
  "Entry": "Invoke-StressModule",
  "Order": 40,
  "RequiresAdmin": false,
  "Description": "Loads the CPU, reads real sensors and SMART via smartctl/LHM if present, attributes new hardware errors to a component"
}
MANIFEST#>

# Test-SystemStress.ps1 - load the machine, then work out which part is failing.
# ASCII only, PowerShell 5.1 compatible.
#
# THIS IS AN ORCHESTRATION AND EVIDENCE LAYER, NOT A MEASUREMENT LAYER.
#
# Established open-source tools measure hardware better than anything that can
# be written here, so this drives them where they exist and falls back to
# Windows' own APIs where they do not. It contributes three things they do not:
#
#   1. WHEA correlation. Snapshot the hardware error log, apply load, snapshot
#      again, and attribute anything NEW to a component. That is what actually
#      answers "which part is failing" - the load exists to provoke errors, and
#      the event diff names the culprit.
#   2. The disk-health interlock. Refusing to stress a machine whose drive is
#      failing, because the data comes off first.
#   3. The sanitized report, so findings can leave the customer's machine.
#
# THERE IS NO MEMORY TEST HERE, ON PURPOSE. An earlier version verified memory
# patterns in-process. It was deleted: it can only touch pages this process
# owns, the OS will not surrender the rest, and real faults need address-line
# walking that only a boot-time tester does. A "partial pass" on RAM is exactly
# the false confidence this toolkit exists to prevent. Use MemTest86+ from a
# boot device and give it several passes.
#
# Nothing here loads a GPU or a PSU either, and it says so rather than
# implying those parts are fine.

$script:StressDefaults = @{
    Minutes    = 2
    MaxMinutes = 30
    MaxTempC   = 95
    SampleSecs = 5
    DiskReadMB = 512
}

# ---------------------------------------------------------------------------
# External tool discovery.
#
# Search order: the stick's tools\ folder first so a tech can pin a known
# version, then PATH, then the usual install locations.
# ---------------------------------------------------------------------------
function Find-ExternalTool {
    param([Parameter(Mandatory = $true)][string]$ExeName, [string[]]$ExtraPaths = @())

    $toolRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools'
    if (Test-Path -LiteralPath $toolRoot) {
        $hit = Get-ChildItem -LiteralPath $toolRoot -Recurse -File -Filter $ExeName -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }

    $cmd = Get-Command $ExeName -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }

    foreach ($p in $ExtraPaths) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    return $null
}

function Get-ExternalToolInventory {
    $pf = ${env:ProgramFiles}
    $pf86 = ${env:ProgramFiles(x86)}

    return [ordered]@{
        smartctl = Find-ExternalTool -ExeName 'smartctl.exe' -ExtraPaths @(
            (Join-Path $pf 'smartmontools\bin\smartctl.exe'),
            (Join-Path $pf86 'smartmontools\bin\smartctl.exe')
        )
        LibreHardwareMonitor = Find-ExternalTool -ExeName 'LibreHardwareMonitor.exe' -ExtraPaths @(
            (Join-Path $pf 'LibreHardwareMonitor\LibreHardwareMonitor.exe')
        )
        CrystalDiskInfo = Find-ExternalTool -ExeName 'DiskInfo64.exe' -ExtraPaths @(
            (Join-Path $pf 'CrystalDiskInfo\DiskInfo64.exe')
        )
    }
}

# ---------------------------------------------------------------------------
# Temperature.
#
# LibreHardwareMonitor publishes a WMI namespace while it is RUNNING, and it
# reads sensors on the many laptops that expose no ACPI thermal zone - which
# is the gap that made the thermal abort useless on the first bench machine.
# Installed but not running is no use, so that case is reported distinctly.
# ---------------------------------------------------------------------------
# ACPI reports tenths of a Kelvin. Kept as its own function so it stays under
# test: getting it wrong tells a tech a CPU is at 27 degrees when it is at 100,
# which is the difference between "fine" and "the fan is dead".
function Convert-DeciKelvinToC {
    param([double]$DeciKelvin)
    return [math]::Round(($DeciKelvin / 10) - 273.15, 1)
}

function Get-ThermalReading {
    $out = [ordered]@{ Status = 'Unknown'; Source = 'none'; TempC = $null; ZoneCount = 0 }

    try {
        $sensors = @(Get-CimInstance -Namespace 'root/LibreHardwareMonitor' -ClassName 'Sensor' -ErrorAction Stop |
                Where-Object { $_.SensorType -eq 'Temperature' -and $_.Value -gt 0 })
        if ($sensors.Count -gt 0) {
            $out.Status = 'Read'
            $out.Source = 'LibreHardwareMonitor'
            $out.ZoneCount = $sensors.Count
            $out.TempC = [math]::Round((($sensors | Measure-Object -Property Value -Maximum).Maximum), 1)
            return [pscustomobject]$out
        }
    }
    catch { }

    try {
        $zones = @(Get-CimInstance -Namespace 'root/wmi' -ClassName 'MSAcpi_ThermalZoneTemperature' -ErrorAction Stop)
        if ($zones.Count -gt 0) {
            $temps = @($zones | ForEach-Object { Convert-DeciKelvinToC -DeciKelvin $_.CurrentTemperature })
            $out.Status = 'Read'
            $out.Source = 'ACPI'
            $out.ZoneCount = $zones.Count
            $out.TempC = ($temps | Measure-Object -Maximum).Maximum
            return [pscustomobject]$out
        }
        $out.Status = 'Unsupported'
    }
    catch {
        if (-not (Test-IsAdmin)) { $out.Status = 'RequiresElevation' }
        else { $out.Status = 'Unsupported' }
    }
    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------
# SMART. smartctl gives attribute-level data - reallocated sectors, pending
# sectors, media errors - which are the actual predictors of drive failure.
# Get-StorageReliabilityCounter returned blank PowerOnHours on the first bench
# machine and has no attribute detail at all, so it is the fallback, not the
# preference.
# ---------------------------------------------------------------------------
function Get-SmartDetail {
    param([string]$SmartctlPath)

    $out = [ordered]@{ Source = 'none'; Status = 'Unknown'; Disks = @() }

    if ($SmartctlPath) {
        $out.Source = 'smartctl'
        try {
            $disks = @(Get-Disk -ErrorAction Stop)
            foreach ($d in $disks) {
                $dev = '\\.\PhysicalDrive' + $d.Number
                $raw = & $SmartctlPath '-j' '-a' $dev 2>$null | Out-String
                if (-not $raw) { continue }
                $j = $null
                try { $j = $raw | ConvertFrom-Json } catch { continue }

                $entry = [ordered]@{
                    Model = $j.model_name
                    Passed = $null
                    PowerOnHours = $null
                    Temperature = $null
                    ReallocatedSectors = $null
                    PendingSectors = $null
                    MediaErrors = $null
                    PercentUsed = $null
                }
                try { $entry.Passed = $j.smart_status.passed } catch { }
                try { $entry.PowerOnHours = $j.power_on_time.hours } catch { }
                try { $entry.Temperature = $j.temperature.current } catch { }
                try { $entry.MediaErrors = $j.nvme_smart_health_information_log.media_errors } catch { }
                try { $entry.PercentUsed = $j.nvme_smart_health_information_log.percentage_used } catch { }
                try {
                    foreach ($a in $j.ata_smart_attributes.table) {
                        if ($a.id -eq 5) { $entry.ReallocatedSectors = $a.raw.value }
                        if ($a.id -eq 197) { $entry.PendingSectors = $a.raw.value }
                    }
                }
                catch { }
                $out.Disks += $entry
            }
            $out.Status = 'Read'
            return [pscustomobject]$out
        }
        catch { $out.Status = 'Failed' }
    }

    # Fallback: Windows' own counters. Thin, but better than nothing.
    $out.Source = 'StorageReliabilityCounter'
    try {
        foreach ($pd in (Get-PhysicalDisk -ErrorAction Stop)) {
            $rc = $null
            try { $rc = $pd | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }
            $out.Disks += [ordered]@{
                Model = $pd.FriendlyName
                Passed = ($pd.HealthStatus -eq 'Healthy')
                PowerOnHours = $rc.PowerOnHours
                Temperature = $(if ($rc.Temperature -and $rc.Temperature -gt 0) { $rc.Temperature } else { $null })
                ReadErrorsTotal = $rc.ReadErrorsTotal
                WriteErrorsTotal = $rc.WriteErrorsTotal
                Wear = $rc.Wear
            }
        }
        $out.Status = 'Read'
    }
    catch { $out.Status = 'Failed' }

    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------
# Fan speeds. A stuck or dead fan is one of the most common real faults on a
# machine that "gets hot and shuts down", and it is invisible to every other
# check here - the CPU just throttles and looks merely slow. Needs
# LibreHardwareMonitor; Windows exposes nothing usable.
# ---------------------------------------------------------------------------
function Get-FanReadings {
    $out = [ordered]@{ Status = 'Unavailable'; Fans = @() }
    try {
        $fans = @(Get-CimInstance -Namespace 'root/LibreHardwareMonitor' -ClassName 'Sensor' -ErrorAction Stop |
                Where-Object { $_.SensorType -eq 'Fan' })
        if ($fans.Count -eq 0) { $out.Status = 'NoFanSensors'; return [pscustomobject]$out }
        foreach ($f in $fans) {
            $out.Fans += [ordered]@{ Name = $f.Name; Rpm = [int]$f.Value }
        }
        $out.Status = 'Read'
    }
    catch { $out.Status = 'Unavailable' }
    return [pscustomobject]$out
}

function Get-GpuTemperature {
    try {
        $g = @(Get-CimInstance -Namespace 'root/LibreHardwareMonitor' -ClassName 'Sensor' -ErrorAction Stop |
                Where-Object { $_.SensorType -eq 'Temperature' -and $_.Identifier -like '*gpu*' -and $_.Value -gt 0 })
        if ($g.Count -gt 0) { return [math]::Round((($g | Measure-Object -Property Value -Maximum).Maximum), 1) }
    }
    catch { }
    return $null
}

# ---------------------------------------------------------------------------
# Battery health. Design capacity versus what it will actually hold now is a
# real, measurable component test - and on a laptop "it dies in 20 minutes" is
# a top-three complaint. powercfg is in the box and needs no third-party tool.
# ---------------------------------------------------------------------------
function Get-BatteryHealth {
    $out = [ordered]@{
        Status = 'Unknown'; Present = $false
        DesignCapacity = $null; FullChargeCapacity = $null
        HealthPercent = $null; CycleCount = $null
    }

    try {
        if (-not (Get-CimInstance Win32_Battery -ErrorAction Stop)) {
            $out.Status = 'NoBattery'
            return [pscustomobject]$out
        }
        $out.Present = $true
    }
    catch { $out.Status = 'NoBattery'; return [pscustomobject]$out }

    $xml = Join-Path $script:LocalRoot ('batteryreport-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.xml')
    try {
        $null = & powercfg.exe '/batteryreport' '/xml' '/output' $xml 2>$null
        if (-not (Test-Path -LiteralPath $xml)) { $out.Status = 'ReportFailed'; return [pscustomobject]$out }

        [xml]$doc = Get-Content -LiteralPath $xml -Raw
        $packs = @($doc.BatteryReport.Batteries.Battery)
        if ($packs.Count -eq 0) { $out.Status = 'NoData'; return [pscustomobject]$out }

        $design = 0; $full = 0; $cycles = $null
        foreach ($p in $packs) {
            $design += [int64]$p.DesignCapacity
            $full += [int64]$p.FullChargeCapacity
            if ($p.CycleCount) { $cycles = [int]$p.CycleCount }
        }

        $out.DesignCapacity = $design
        $out.FullChargeCapacity = $full
        $out.CycleCount = $cycles
        if ($design -gt 0) { $out.HealthPercent = [math]::Round(($full / $design) * 100, 1) }
        $out.Status = 'Read'
    }
    catch { $out.Status = 'ReportFailed' }
    finally { Remove-Item -LiteralPath $xml -Force -ErrorAction SilentlyContinue -WhatIf:$false }

    return [pscustomobject]$out
}

# Memory cannot be tested from in here, but the tester can be located and the
# exact next step named, rather than leaving the tech to work it out.
function Get-MemoryTestAvailability {
    $out = [ordered]@{ MemTest86Found = $null; Note = '' }
    $toolRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools'
    foreach ($pattern in @('memtest*.iso', 'memtest*.img', 'mt86*.iso')) {
        if (Test-Path -LiteralPath $toolRoot) {
            $hit = Get-ChildItem -LiteralPath $toolRoot -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($hit) { $out.MemTest86Found = $hit.Name; break }
        }
    }
    return [pscustomobject]$out
}

function Get-CpuUtilizationPercent {
    try { return [math]::Round((Get-Counter '\Processor Information(_Total)\% Processor Time' -ErrorAction Stop).CounterSamples[0].CookedValue, 1) }
    catch { return $null }
}

function Get-CpuPerformancePercent {
    try { return [math]::Round((Get-Counter '\Processor Information(_Total)\% Processor Performance' -ErrorAction Stop).CounterSamples[0].CookedValue, 1) }
    catch { return $null }
}

# ---------------------------------------------------------------------------
# Hardware error sources. Provider AND ids, never a provider alone -
# Kernel-Power emits hundreds of routine power-state events and only id 41 is
# an unexpected shutdown.
# ---------------------------------------------------------------------------
$script:ErrorSources = @(
    @{ Key = 'WheaFatal'; Log = 'System'; Provider = 'Microsoft-Windows-WHEA-Logger'; Ids = @(1, 18, 20, 23);
        Component = 'CPU / chipset'; Meaning = 'Uncorrected machine check - hardware reported a fatal error' },
    @{ Key = 'WheaCorrected'; Log = 'System'; Provider = 'Microsoft-Windows-WHEA-Logger'; Ids = @(19, 47);
        Component = 'CPU / memory'; Meaning = 'Corrected hardware error - fixed in flight, but the part is degrading' },
    @{ Key = 'WheaPcie'; Log = 'System'; Provider = 'Microsoft-Windows-WHEA-Logger'; Ids = @(17);
        Component = 'PCIe bus / GPU / NVMe'; Meaning = 'PCIe error - a device on the bus, its slot, or its power' },
    @{ Key = 'GpuTdr'; Log = 'System'; Provider = 'Microsoft-Windows-DxgKrnl'; Ids = @(4101);
        Component = 'GPU'; Meaning = 'Display driver stopped responding and recovered' },
    @{ Key = 'UnexpectedShutdown'; Log = 'System'; Provider = 'Microsoft-Windows-Kernel-Power'; Ids = @(41);
        Component = 'Power / thermal'; Meaning = 'Lost power without shutting down - PSU, battery or thermal cutout' },
    @{ Key = 'Bugcheck'; Log = 'System'; Provider = 'Microsoft-Windows-WER-SystemErrorReporting'; Ids = @(1001);
        Component = 'Varies - decode the stop code'; Meaning = 'Blue screen' },
    @{ Key = 'DiskError'; Log = 'System'; Provider = 'disk'; Ids = @(7, 11, 51, 153);
        Component = 'Storage'; Meaning = 'Bad block, controller error or I/O retry' },
    @{ Key = 'NtfsCorruption'; Log = 'System'; Provider = 'Ntfs'; Ids = @(55);
        Component = 'Storage / filesystem'; Meaning = 'Filesystem structure damage' }
)

function Get-HardwareErrorSnapshot {
    param([datetime]$Since)
    $snap = [ordered]@{}
    foreach ($src in $script:ErrorSources) {
        $count = 0
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $src.Log; ProviderName = $src.Provider; StartTime = $Since } `
                    -MaxEvents 500 -ErrorAction Stop)
            $count = @($ev | Where-Object { $src.Ids -contains $_.Id }).Count
        }
        catch { $count = 0 }
        $snap[$src.Key] = $count
    }
    return $snap
}

function Get-DiskHealthGate {
    $gate = [ordered]@{ Status = 'Unknown'; Healthy = $false; Unhealthy = @() }
    try {
        $bad = @(Get-PhysicalDisk -ErrorAction Stop | Where-Object { $_.HealthStatus -ne 'Healthy' })
        $gate.Unhealthy = @($bad | ForEach-Object { [ordered]@{ Name = $_.FriendlyName; Health = [string]$_.HealthStatus } })
        $gate.Healthy = ($bad.Count -eq 0)
        $gate.Status = 'Read'
    }
    catch { $gate.Status = 'Unreadable' }
    return [pscustomobject]$gate
}

# Read-only. Never writes.
function Invoke-DiskReadTest {
    param([int]$TotalMB)
    $out = [ordered]@{ Status = 'Unknown'; ReadMB = 0; ReadErrors = 0; ThroughputMBs = $null; Note = '' }

    if (-not (Test-IsAdmin)) { $out.Status = 'RequiresElevation'; return [pscustomobject]$out }

    $diskNumber = 0; $diskSize = 0
    try {
        $sys = Get-Disk -ErrorAction Stop | Where-Object { $_.IsSystem } | Select-Object -First 1
        if (-not $sys) { $sys = Get-Disk -ErrorAction Stop | Select-Object -First 1 }
        $diskNumber = $sys.Number; $diskSize = $sys.Size
    }
    catch { $out.Status = 'NoDisk'; return [pscustomobject]$out }

    $chunk = 4MB
    $chunks = [math]::Max(1, [int]($TotalMB * 1MB / $chunk))
    $fs = $null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $fs = New-Object IO.FileStream(('\\.\PhysicalDrive' + $diskNumber), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $buf = New-Object byte[] $chunk
        # Spread reads across the whole device; the first gigabyte is cached
        # and tells you nothing.
        $stride = [long]([math]::Floor([math]::Max($chunk, [long]($diskSize / $chunks)) / 4096) * 4096)
        for ($i = 0; $i -lt $chunks; $i++) {
            $offset = [long]$i * $stride
            if (($offset + $chunk) -ge $diskSize) { break }
            try {
                $fs.Seek($offset, [IO.SeekOrigin]::Begin) | Out-Null
                $out.ReadMB += [math]::Round($fs.Read($buf, 0, $chunk) / 1MB, 0)
            }
            catch { $out.ReadErrors++ }
        }
        $sw.Stop()
        if ($sw.Elapsed.TotalSeconds -gt 0) { $out.ThroughputMBs = [math]::Round($out.ReadMB / $sw.Elapsed.TotalSeconds, 1) }
        $out.Status = 'Read'
    }
    catch { $out.Status = 'Failed'; $out.Note = $_.Exception.Message }
    finally { if ($fs) { $fs.Dispose() } }
    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------
function Invoke-StressModule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch]$Apply, [hashtable]$Options = @{})

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
    $skipDisk = [bool]$Options['SkipDisk']

    $threads = 0
    try { $threads = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors } catch { }
    if ($Options['Threads']) { $threads = [int]$Options['Threads'] }
    if ($threads -lt 1) { $threads = 2 }

    Write-Banner 'Whole-system stress and fault isolation'

    $tools = Get-ExternalToolInventory
    $result = [ordered]@{
        Mode = $(if ($Apply) { 'Apply' } else { 'PreflightOnly' })
        Minutes = $minutes; Threads = $threads; MaxTempC = $maxTemp
        Tools = [ordered]@{
            smartctl = [bool]$tools.smartctl
            LibreHardwareMonitor = [bool]$tools.LibreHardwareMonitor
            CrystalDiskInfo = [bool]$tools.CrystalDiskInfo
        }
        Baseline = $null; DiskGate = $null; OnBattery = $null
        Samples = @(); PeakTempC = $null; MinPerfPct = $null
        MeanCpuPercent = $null; LoadVerified = $false
        Smart = $null; Disk = $null
        Battery = $null; MemoryTest = $null
        FanStatus = 'Unavailable'; IdleFanRpm = $null; PeakFanRpm = $null
        PeakGpuTempC = $null
        ErrorsBefore = $null; ErrorsDuring = $null
        Findings = @(); AbortReason = $null; Completed = $false
    }

    # --- Measurement sources ------------------------------------------------
    Write-Host ''
    Write-Host '  Measurement sources:' -ForegroundColor Cyan
    Write-Host ('    SMART    : {0}' -f $(if ($tools.smartctl) { 'smartctl (attribute-level)' } else { 'Windows counters only - install smartmontools for real attributes' })) -ForegroundColor $(if ($tools.smartctl) { 'Green' } else { 'Yellow' })
    Write-Host ('    Sensors  : {0}' -f $(if ($tools.LibreHardwareMonitor) { 'LibreHardwareMonitor present' } else { 'ACPI only - many laptops expose nothing' })) -ForegroundColor $(if ($tools.LibreHardwareMonitor) { 'Green' } else { 'Yellow' })
    if (-not $tools.smartctl -or -not $tools.LibreHardwareMonitor) {
        Write-Host '    Run Install-Tools.ps1 on the bench machine to provision these.' -ForegroundColor DarkGray
    }

    $thermal = Get-ThermalReading
    $gate = Get-DiskHealthGate
    $result.DiskGate = $gate
    $result.Smart = Get-SmartDetail -SmartctlPath $tools.smartctl

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
        Cpu = $cpuName; LogicalCores = $threads
        ThermalStatus = $thermal.Status; ThermalSource = $thermal.Source; IdleTempC = $thermal.TempC
        IdlePerfPct = (Get-CpuPerformancePercent)
    }

    Write-Host ''
    Write-Host ('  CPU          : {0}' -f $cpuName) -ForegroundColor Gray
    Write-Host ('  Load threads : {0}' -f $threads) -ForegroundColor Gray
    Write-Host ('  Duration     : {0} minute(s), abort above {1} C' -f $minutes, $maxTemp) -ForegroundColor Gray
    if ($thermal.Status -eq 'Read') {
        Write-Host ('  Idle temp    : {0} C via {1}' -f $thermal.TempC, $thermal.Source) -ForegroundColor Gray
    }
    else {
        Write-Host ('  Idle temp    : NOT AVAILABLE ({0}) - no thermal abort will happen.' -f $thermal.Status) -ForegroundColor Yellow
        Write-Host '                 Install LibreHardwareMonitor and leave it running.' -ForegroundColor Yellow
    }

    # --- SMART summary -------------------------------------------------------
    if ($result.Smart -and $result.Smart.Status -eq 'Read') {
        Write-Host ''
        Write-Host ('  SMART via {0}:' -f $result.Smart.Source) -ForegroundColor Cyan
        foreach ($d in $result.Smart.Disks) {
            Write-Host ('    {0}' -f $d.Model) -ForegroundColor Gray
            $bits = @()
            if ($null -ne $d.Passed) { $bits += ('overall=' + $(if ($d.Passed) { 'PASSED' } else { 'FAILED' })) }
            if ($null -ne $d.PowerOnHours) { $bits += ('poh=' + $d.PowerOnHours) }
            if ($null -ne $d.Temperature) { $bits += ('temp=' + $d.Temperature + 'C') }
            if ($null -ne $d.ReallocatedSectors) { $bits += ('realloc=' + $d.ReallocatedSectors) }
            if ($null -ne $d.PendingSectors) { $bits += ('pending=' + $d.PendingSectors) }
            if ($null -ne $d.MediaErrors) { $bits += ('media_err=' + $d.MediaErrors) }
            if ($null -ne $d.PercentUsed) { $bits += ('used=' + $d.PercentUsed + '%') }
            Write-Host ('      ' + ($bits -join '  ')) -ForegroundColor DarkGray
        }
    }

    # --- Battery ------------------------------------------------------------
    $result.Battery = Get-BatteryHealth
    if ($result.Battery.Status -eq 'Read') {
        Write-Host ''
        Write-Host ('  Battery: {0}% of design capacity ({1} of {2} mWh), {3} cycles' -f `
                $result.Battery.HealthPercent, $result.Battery.FullChargeCapacity,
            $result.Battery.DesignCapacity, $result.Battery.CycleCount) -ForegroundColor `
        $(if ($result.Battery.HealthPercent -lt 60) { 'Red' } elseif ($result.Battery.HealthPercent -lt 80) { 'Yellow' } else { 'Green' })
    }

    # --- Fans ----------------------------------------------------------------
    $fans = Get-FanReadings
    $result.FanStatus = $fans.Status
    if ($fans.Status -eq 'Read') {
        $result.IdleFanRpm = (@($fans.Fans | ForEach-Object { $_.Rpm }) | Measure-Object -Maximum).Maximum
        Write-Host ('  Fans   : {0} sensor(s), idle max {1} rpm' -f @($fans.Fans).Count, $result.IdleFanRpm) -ForegroundColor Gray
    }
    else {
        Write-Host '  Fans   : no fan sensor - a dead fan cannot be detected without LibreHardwareMonitor' -ForegroundColor Yellow
    }

    $result.MemoryTest = Get-MemoryTestAvailability

    # --- History -------------------------------------------------------------
    $history = Get-HardwareErrorSnapshot -Since (Get-Date).AddDays(-30)
    Write-Host ''
    Write-Host '  Hardware errors already logged in the last 30 days:' -ForegroundColor Cyan
    $anyHistory = $false
    foreach ($src in $script:ErrorSources) {
        if ($history[$src.Key] -gt 0) {
            $anyHistory = $true
            Write-Host ('    {0,-20} {1,4}   {2}' -f $src.Key, $history[$src.Key], $src.Component) -ForegroundColor Yellow
        }
    }
    if (-not $anyHistory) { Write-Host '    none' -ForegroundColor Green }

    # --- Interlock -----------------------------------------------------------
    if ($gate.Status -eq 'Read' -and -not $gate.Healthy) {
        Write-Host ''
        Write-Host '  REFUSING TO RUN: a disk is not reporting Healthy.' -ForegroundColor Red
        foreach ($u in $gate.Unhealthy) { Write-Host ('    {0}: {1}' -f $u.Name, $u.Health) -ForegroundColor Red }
        Write-Host '  Stressing a machine with a failing drive risks the data you should be' -ForegroundColor Yellow
        Write-Host '  recovering first. Image it, get the data off, THEN test hardware.' -ForegroundColor Yellow
        if (-not $force) { $result.AbortReason = 'DiskHealthInterlock'; return [pscustomobject]$result }
        Write-Log -Message 'Disk health interlock OVERRIDDEN with -Force' -Level WARN
    }

    if ($onBattery -eq $true) {
        Write-Host ''
        Write-Host '  WARNING: on battery. Expect throttling that is not a fault.' -ForegroundColor Yellow
    }

    if (-not $Apply) {
        Write-Host ''
        Write-Host '  PREFLIGHT ONLY - no load applied, nothing tested yet.' -ForegroundColor Yellow
        Write-Host ('    .\Invoke-TuneUp.ps1 -Module stress -Apply -Minutes {0}' -f $minutes) -ForegroundColor Gray
        Write-Host '  or pick "stress" from the RUN.cmd menu and answer YES.' -ForegroundColor Gray
        Write-Host ''
        Show-UntestableComponents -Result $result
        return [pscustomobject]$result
    }

    if (-not $PSCmdlet.ShouldProcess(('CPU, {0} thread(s) for {1} minute(s)' -f $threads, $minutes), 'Apply sustained load')) {
        return [pscustomobject]$result
    }

    # --- Load ----------------------------------------------------------------
    $runStart = Get-Date
    $result.ErrorsBefore = Get-HardwareErrorSnapshot -Since $runStart.AddMinutes(-1)

    Write-Banner ('Applying load: {0} thread(s), {1} minute(s)' -f $threads, $minutes)
    Write-Host '  Ctrl-C stops the test and shuts the workers down cleanly.' -ForegroundColor DarkGray
    Write-Host ''

    $deadline = $runStart.AddMinutes($minutes)
    $jobs = @()
    try {
        for ($i = 0; $i -lt $threads; $i++) {
            $jobs += Start-Job -ScriptBlock {
                param($EndTime)
                $x = 0.0; $n = 0
                while ((Get-Date) -lt $EndTime) { $x = [math]::Sqrt($n) + [math]::Sin($n); $n++; if ($n -gt 2147000000) { $n = 0 } }
                return $n
            } -ArgumentList $deadline
        }

        # Prove the workers started, or the loop below monitors an idle machine
        # for the full duration and reports a clean pass.
        Start-Sleep -Seconds 3
        $running = @($jobs | Where-Object { $_.State -eq 'Running' })
        if ($running.Count -eq 0) {
            $result.AbortReason = 'WorkersFailedToStart'
            throw 'Load workers did not start - no load was applied.'
        }
        Write-Log -Message ("{0} of {1} load worker(s) running" -f $running.Count, $jobs.Count) -Level OK

        $peak = $null; $minPerf = $null; $cpuSamples = @()
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $script:StressDefaults.SampleSecs
            # The sleep can carry us past the deadline, by which point the
            # workers have exited; sampling then records an idle reading.
            if ((Get-Date) -ge $deadline) { break }

            $t = Get-ThermalReading
            $p = Get-CpuPerformancePercent
            $cpu = Get-CpuUtilizationPercent
            $elapsed = [math]::Round(((Get-Date) - $runStart).TotalSeconds, 0)

            # Fan RPM under load is the check that catches a dead or stuck fan.
            # Without it a seized fan just looks like a CPU that throttles, and
            # you chase thermal paste instead of replacing a 12 dollar part.
            $rpm = $null
            $f = Get-FanReadings
            if ($f.Status -eq 'Read') {
                $rpm = (@($f.Fans | ForEach-Object { $_.Rpm }) | Measure-Object -Maximum).Maximum
                if ($null -eq $result.PeakFanRpm -or $rpm -gt $result.PeakFanRpm) { $result.PeakFanRpm = $rpm }
            }
            $gpuT = Get-GpuTemperature
            if ($null -ne $gpuT -and ($null -eq $result.PeakGpuTempC -or $gpuT -gt $result.PeakGpuTempC)) { $result.PeakGpuTempC = $gpuT }

            if ($null -ne $cpu) { $cpuSamples += $cpu }
            $result.Samples += [ordered]@{ ElapsedSec = $elapsed; TempC = $t.TempC; PerfPct = $p; CpuPct = $cpu; FanRpm = $rpm; GpuTempC = $gpuT }
            if ($null -ne $t.TempC -and ($null -eq $peak -or $t.TempC -gt $peak)) { $peak = $t.TempC }
            if ($null -ne $p -and ($null -eq $minPerf -or $p -lt $minPerf)) { $minPerf = $p }

            $line = '    {0,4}s   cpu {1,6}%   perf {2,6}%   temp {3,8}   fan {4,7}' -f $elapsed,
            $(if ($null -ne $cpu) { $cpu } else { 'n/a' }),
            $(if ($null -ne $p) { $p } else { 'n/a' }),
            $(if ($null -ne $t.TempC) { "$($t.TempC) C" } else { 'n/a' }),
            $(if ($null -ne $rpm) { "$rpm rpm" } else { 'n/a' })
            $color = 'Gray'
            if ($null -ne $p -and $p -lt 70) { $color = 'Yellow' }
            if ($null -ne $cpu -and $cpu -lt 70) { $color = 'Red' }
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
        if ($cpuSamples.Count -gt 0) { $result.MeanCpuPercent = [math]::Round((($cpuSamples | Measure-Object -Average).Average), 1) }
        if (-not $result.AbortReason) { $result.Completed = $true }
    }
    finally {
        # Runs on Ctrl-C, abort and error alike. Leaving CPU-pegging jobs on a
        # customer's machine is not an acceptable failure mode.
        foreach ($j in $jobs) {
            try { Stop-Job -Job $j -ErrorAction SilentlyContinue } catch { }
            try { Remove-Job -Job $j -Force -ErrorAction SilentlyContinue } catch { }
        }
        Write-Log -Message 'Load workers stopped' -Level OK
    }

    if (-not $skipDisk) {
        Write-Banner 'Read-only surface read'
        $result.Disk = Invoke-DiskReadTest -TotalMB $script:StressDefaults.DiskReadMB
        switch ($result.Disk.Status) {
            'Read' { Write-Host ('  Read {0} MB at {1} MB/s, {2} read error(s)' -f $result.Disk.ReadMB, $result.Disk.ThroughputMBs, $result.Disk.ReadErrors) -ForegroundColor $(if ($result.Disk.ReadErrors -gt 0) { 'Red' } else { 'Green' }) }
            'RequiresElevation' { Write-Host '  Surface read NOT RUN - needs elevation.' -ForegroundColor Yellow }
            default { Write-Host ('  Surface read unavailable: ' + $result.Disk.Status) -ForegroundColor Yellow }
        }
    }

    $result.ErrorsDuring = Get-HardwareErrorSnapshot -Since $runStart
    Show-StressVerdict -Result $result
    return [pscustomobject]$result
}

# Every component, and honestly how far this got with each. Printed whether
# the run passed or failed, so "entire device" means a stated position on each
# part rather than silence about the ones that were skipped.
function Show-CoverageMatrix {
    param($Result)

    Write-Host '  COVERAGE - what was and was not actually exercised' -ForegroundColor White
    Write-Host '  -------------------------------------------------' -ForegroundColor DarkGray

    $lhm = $false
    if ($Result -and $Result.Tools) { $lhm = [bool]$Result.Tools.LibreHardwareMonitor }
    $smart = $false
    if ($Result -and $Result.Tools) { $smart = [bool]$Result.Tools.smartctl }
    $memIso = $null
    if ($Result -and $Result.MemoryTest) { $memIso = $Result.MemoryTest.MemTest86Found }

    Write-Cover 'CPU'      'FULL'    'sustained all-core load, clocks sampled, WHEA diffed'
    Write-Cover 'Cooling'  $(if ($lhm) { 'FULL' } else { 'PARTIAL' }) $(if ($lhm) { 'temps and fan RPM under load' } else { 'ACPI only - install LibreHardwareMonitor for real sensors' })
    Write-Cover 'Fans'     $(if ($lhm) { 'FULL' } else { 'NONE' })    $(if ($lhm) { 'ramp checked under load' } else { 'no sensor source' })
    Write-Cover 'Storage'  $(if ($smart) { 'FULL' } else { 'PARTIAL' }) $(if ($smart) { 'SMART attributes + read-only surface read' } else { 'Windows counters + surface read; install smartmontools' })
    Write-Cover 'Battery'  'FULL'    'design vs full-charge capacity and cycle count'
    Write-Cover 'Memory'   'NONE'    $(if ($memIso) { "boot $memIso from the stick - several passes" } else { 'get MemTest86+ - nothing in Windows can test RAM the OS is using' })
    Write-Cover 'GPU'      'OBSERVED' 'temps and driver resets only - load it with FurMark/OCCT'
    Write-Cover 'PSU'      'INFERRED' 'cannot be loaded; suspect it on a drop with no thermal or WHEA cause'
    Write-Cover 'Display'  'NONE'    'panel, backlight and hinge are a physical inspection'
    Write-Cover 'Network'  'NONE'    'run the network module - it walks its own ladder'
    Write-Host ''
}

function Write-Cover {
    param([string]$Part, [string]$Level, [string]$Note)
    $color = 'DarkGray'
    if ($Level -eq 'FULL') { $color = 'Green' }
    if ($Level -eq 'PARTIAL' -or $Level -eq 'OBSERVED' -or $Level -eq 'INFERRED') { $color = 'Yellow' }
    Write-Host ('    {0,-9} {1,-9} {2}' -f $Part, $Level, $Note) -ForegroundColor $color
}

function Show-UntestableComponents {
    param($Result)
    Show-CoverageMatrix -Result $Result
}

function Show-StressVerdict {
    param($Result)

    Write-Banner 'Verdict'

    $Result.LoadVerified = ($null -ne $Result.MeanCpuPercent -and $Result.MeanCpuPercent -ge 70)
    if ($null -eq $Result.MeanCpuPercent) {
        Write-Host '  LOAD NOT VERIFIED - CPU utilisation could not be measured. Do not record' -ForegroundColor Red
        Write-Host '  this as a pass.' -ForegroundColor Red
    }
    elseif (-not $Result.LoadVerified) {
        Write-Host ('  LOAD NOT APPLIED - mean CPU only {0}%. Nothing was really tested.' -f $Result.MeanCpuPercent) -ForegroundColor Red
    }
    else {
        Write-Host ('  Load verified: mean CPU {0}% over {1} sample(s).' -f $Result.MeanCpuPercent, @($Result.Samples).Count) -ForegroundColor Green
    }

    $newErrors = @()
    foreach ($src in $script:ErrorSources) {
        $during = 0
        if ($Result.ErrorsDuring) { $during = [int]$Result.ErrorsDuring[$src.Key] }
        if ($during -gt 0) { $newErrors += [pscustomobject]@{ Source = $src; Count = $during } }
    }

    Write-Host ''
    Write-Host '  COMPONENT ASSESSMENT' -ForegroundColor White
    Write-Host '  --------------------' -ForegroundColor DarkGray

    $cpuVerdict = 'PASS'; $cpuNote = 'held full load, no machine-check errors'
    if (-not $Result.LoadVerified) { $cpuVerdict = 'NOT TESTED'; $cpuNote = 'load was not applied' }
    elseif (@($newErrors | Where-Object { $_.Source.Key -like 'Whea*' }).Count -gt 0) { $cpuVerdict = 'SUSPECT'; $cpuNote = 'WHEA errors appeared under load' }
    Write-StressLine 'CPU' $cpuVerdict $cpuNote

    if ($Result.AbortReason -like 'ThermalLimit*') {
        Write-StressLine 'Cooling' 'FAIL' ('hit ' + $Result.MaxTempC + ' C under load - paste, fan or blocked intake')
    }
    elseif ($null -ne $Result.PeakTempC) { Write-StressLine 'Cooling' 'PASS' ('peak ' + $Result.PeakTempC + ' C') }
    else { Write-StressLine 'Cooling' 'NOT MEASURED' 'no sensor available - install LibreHardwareMonitor' }

    # Fans. The signal is whether RPM ROSE under load, not its absolute value:
    # a fan sitting at idle speed while the CPU cooks is a seized fan, and that
    # is a part swap rather than a repaste.
    if ($Result.FanStatus -ne 'Read') {
        Write-StressLine 'Fans' 'NOT MEASURED' 'needs LibreHardwareMonitor running'
    }
    elseif ($null -eq $Result.PeakFanRpm -or $Result.PeakFanRpm -eq 0) {
        Write-StressLine 'Fans' 'FAIL' '0 rpm throughout a full load run - fan is dead, stuck or unplugged'
    }
    elseif ($null -ne $Result.IdleFanRpm -and $Result.PeakFanRpm -le $Result.IdleFanRpm) {
        Write-StressLine 'Fans' 'SUSPECT' ("never spun up under load (idle $($Result.IdleFanRpm), peak $($Result.PeakFanRpm) rpm)")
    }
    else {
        Write-StressLine 'Fans' 'PASS' ("ramped $($Result.IdleFanRpm) -> $($Result.PeakFanRpm) rpm under load")
    }

    # Battery
    $bat = $Result.Battery
    if (-not $bat -or $bat.Status -eq 'NoBattery') {
        Write-StressLine 'Battery' 'N/A' 'no battery present'
    }
    elseif ($bat.Status -ne 'Read') {
        Write-StressLine 'Battery' 'NOT MEASURED' ('powercfg report ' + $bat.Status)
    }
    elseif ($bat.HealthPercent -lt 60) {
        Write-StressLine 'Battery' 'FAIL' ("$($bat.HealthPercent)% of design capacity - worn out, replace")
    }
    elseif ($bat.HealthPercent -lt 80) {
        Write-StressLine 'Battery' 'DEGRADED' ("$($bat.HealthPercent)% of design capacity, $($bat.CycleCount) cycles")
    }
    else {
        Write-StressLine 'Battery' 'PASS' ("$($bat.HealthPercent)% of design capacity")
    }

    if ($null -ne $Result.MinPerfPct -and $Result.MinPerfPct -lt 70) {
        Write-StressLine 'Clocks' 'DEGRADED' ("dropped to $($Result.MinPerfPct)% of base clock under load")
    }
    elseif ($null -ne $Result.MinPerfPct) { Write-StressLine 'Clocks' 'PASS' ("held $($Result.MinPerfPct)% of base clock") }

    Write-StressLine 'Memory' 'NOT TESTED' 'by design - use MemTest86+ from a boot device'

    $d = $Result.Disk
    $smartBad = @()
    if ($Result.Smart -and $Result.Smart.Disks) {
        foreach ($sd in $Result.Smart.Disks) {
            if ($sd.Passed -eq $false) { $smartBad += ($sd.Model + ' SMART overall FAILED') }
            if ($sd.ReallocatedSectors -and [int]$sd.ReallocatedSectors -gt 0) { $smartBad += ($sd.Model + ' reallocated=' + $sd.ReallocatedSectors) }
            if ($sd.PendingSectors -and [int]$sd.PendingSectors -gt 0) { $smartBad += ($sd.Model + ' pending=' + $sd.PendingSectors) }
            if ($sd.MediaErrors -and [int]$sd.MediaErrors -gt 0) { $smartBad += ($sd.Model + ' media_errors=' + $sd.MediaErrors) }
        }
    }
    if (@($newErrors | Where-Object { $_.Source.Key -eq 'DiskError' -or $_.Source.Key -eq 'NtfsCorruption' }).Count -gt 0) {
        Write-StressLine 'Storage' 'FAIL' 'disk errors logged during the run'
    }
    elseif ($smartBad.Count -gt 0) {
        Write-StressLine 'Storage' 'FAIL' ($smartBad -join '; ')
    }
    elseif ($d -and $d.Status -eq 'Read') {
        Write-StressLine 'Storage' $(if ($d.ReadErrors -gt 0) { 'FAIL' } else { 'PASS' }) ("$($d.ReadMB) MB surface read, $($d.ReadErrors) error(s)")
    }
    else { Write-StressLine 'Storage' 'NOT TESTED' ('surface read ' + $(if ($d) { $d.Status } else { 'skipped' })) }

    if (@($newErrors | Where-Object { $_.Source.Key -eq 'GpuTdr' }).Count -gt 0) {
        Write-StressLine 'GPU' 'SUSPECT' 'display driver reset during the run'
    }
    elseif ($null -ne $Result.PeakGpuTempC) {
        Write-StressLine 'GPU' 'PARTIAL' ("peak $($Result.PeakGpuTempC) C observed, but NOT loaded - use FurMark/OCCT")
    }
    else { Write-StressLine 'GPU' 'NOT TESTED' 'nothing here loads a GPU - use FurMark or OCCT' }

    if (@($newErrors | Where-Object { $_.Source.Key -eq 'UnexpectedShutdown' }).Count -gt 0) {
        Write-StressLine 'Power' 'FAIL' 'machine lost power during the run'
    }
    else { Write-StressLine 'Power' 'NOT TESTED' 'cannot be loaded or measured from here' }

    if ($newErrors.Count -gt 0) {
        Write-Host ''
        Write-Host '  NEW HARDWARE ERRORS DURING THIS RUN:' -ForegroundColor Red
        foreach ($n in $newErrors) {
            Write-Host ('    {0} x{1}' -f $n.Source.Key, $n.Count) -ForegroundColor Red
            Write-Host ('      component: {0}' -f $n.Source.Component) -ForegroundColor Yellow
            Write-Host ('      meaning  : {0}' -f $n.Source.Meaning) -ForegroundColor Gray
            $Result.Findings += [ordered]@{ Source = $n.Source.Key; Count = $n.Count; Component = $n.Source.Component }
        }
        Write-Host ''
        Write-Host '  Errors that appear under load and not before is the strongest evidence' -ForegroundColor Yellow
        Write-Host '  available from inside Windows. Trust it over a subjective symptom.' -ForegroundColor Yellow
    }
    else {
        Write-Host ''
        Write-Host '  No new hardware errors were logged during the run.' -ForegroundColor Green
    }

    Write-Host ''
    Show-UntestableComponents -Result $Result
}

function Write-StressLine {
    param([string]$Component, [string]$Verdict, [string]$Note)
    $color = 'Gray'
    if ($Verdict -eq 'PASS') { $color = 'Green' }
    if ($Verdict -eq 'DEGRADED' -or $Verdict -eq 'SUSPECT') { $color = 'Yellow' }
    if ($Verdict -eq 'FAIL') { $color = 'Red' }
    if ($Verdict -like 'NOT *') { $color = 'DarkGray' }
    Write-Host ('    {0,-9} {1,-13} {2}' -f $Component, $Verdict, $Note) -ForegroundColor $color
}


