<#MANIFEST
{
  "Key": "evidence",
  "Title": "Hardware evidence around an external stress test",
  "Entry": "Invoke-EvidenceModule",
  "Order": 40,
  "RequiresAdmin": false,
  "Description": "Baseline before, watch during, compare after - reads sensors and SMART and attributes new hardware errors to a component. Generates no load itself"
}
MANIFEST#>

# Get-HardwareEvidence.ps1 - the evidence half of a stress test. READ ONLY.
# ASCII only, PowerShell 5.1 compatible.
#
# THIS GENERATES NO LOAD. That is deliberate: OCCT, Cinebench, FurMark and
# MemTest86+ apply load better than anything that can be written here, and they
# are on the stick already. What they do NOT do is tell you which component
# logged a hardware error while they ran. That is this module's job.
#
# The workflow is three steps around a tool this module does not run:
#
#   1. baseline  - snapshot SMART, sensors, battery and the hardware error log
#                  BEFORE anything is loaded, and refuse to advise stressing a
#                  machine whose drive is already failing.
#   2. watch     - sample temperature, clocks, fan RPM and CPU load WHILE the
#                  external tool runs, so peak thermals are actually observed
#                  rather than guessed at afterwards from a cooled-down machine.
#   3. compare   - re-read everything and diff it against the baseline. Errors
#                  that appear under load and not before are the strongest
#                  evidence available from inside Windows.
#
# The load being external creates one new way to be wrong, and it is the
# important one: if the tech never actually started the stress tool, the diff
# comes back empty and reads as a pass. So the watch step measures CPU
# utilisation and temperature movement and states plainly whether load was
# OBSERVED. No observation, no pass - same rule as everywhere else here.
#
# THERE IS NO MEMORY TEST HERE, ON PURPOSE. An earlier version verified memory
# patterns in-process. It was deleted: it can only touch pages this process
# owns, the OS will not surrender the rest, and real faults need address-line
# walking that only a boot-time tester does. A "partial pass" on RAM is exactly
# the false confidence this toolkit exists to prevent. Use MemTest86+ from a
# boot device and give it several passes.

$script:EvidenceDefaults = @{
    SampleSecs    = 5
    MaxWatchMins  = 120
    WatchMinutes  = 10
    HotTempC      = 95
    LoadCpuPct    = 60
    # Degrees C of GPU movement across the watch window that counts as a GPU
    # under load. Movement, not absolute temperature - see Get-LoadObservation.
    GpuRiseC      = 8
}

# The baseline lives on the LOCAL machine with the logs, never on the stick -
# same rule as the rest of the toolkit. It has to survive the tech closing this
# window while OCCT runs, so it is a file rather than a variable.
function Get-BaselinePath { return (Join-Path $script:LocalRoot 'hw-baseline.json') }

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

    # winget installs "portable" packages under LOCALAPPDATA, not Program
    # Files - LibreHardwareMonitor is one, and searching only Program Files
    # reported it missing immediately after winget said it installed fine.
    $wingetPkgs = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
    if (Test-Path -LiteralPath $wingetPkgs) {
        $hit = Get-ChildItem -LiteralPath $wingetPkgs -Recurse -File -Filter $ExeName -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
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

    # Exclude threshold sensors before taking a maximum.
    #
    # LHM reports a drive's "Critical Temperature" (82 C) and "Warning
    # Temperature" (79 C) alongside real readings, and those are CONSTANTS.
    # Taking the max across the group picked the 82 C limit and reported it as
    # the machine's temperature - flat from idle to full load, and high enough
    # to look alarming. The stuck-sensor check caught it, but the reading was
    # wrong at source.
    $web = @(Get-LhmWebSensors |
            Where-Object { $_.Group -eq 'Temperatures' -and $_.Value -gt 0 } |
            Where-Object { $_.Name -notmatch '(?i)critical|warning|limit|threshold|target|max\b|min\b' })

    if ($web.Count -gt 0) {
        $out.Status = 'Read'
        $out.Source = 'LibreHardwareMonitor'
        $out.ZoneCount = $web.Count
        $out.TempC = [math]::Round((($web | Measure-Object -Property Value -Maximum).Maximum), 1)
        return [pscustomobject]$out
    }

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

    $out = [ordered]@{ Source = 'none'; Status = 'Unknown'; Note = ''; Disks = @() }

    if ($SmartctlPath) {
        $out.Source = 'smartctl'
        $failures = @()
        try {
            # Let smartctl enumerate its own devices.
            #
            # On Windows it does NOT want \\.\PhysicalDriveN - passing that
            # returns "Unable to detect device type" even elevated, which is
            # easily mistaken for a permissions problem. --scan reports the
            # names it actually wants (/dev/sda) together with the right -d
            # type for each, so ask it rather than guessing.
            $scanLines = @(& $SmartctlPath '--scan' 2>$null)
            $targets = @()
            foreach ($line in $scanLines) {
                $text = [string]$line
                if ($text -match '^\s*(\S+)\s+-d\s+(\S+)') {
                    $targets += [pscustomobject]@{ Device = $Matches[1]; Type = $Matches[2] }
                }
                elseif ($text -match '^\s*(/dev/\S+)') {
                    $targets += [pscustomobject]@{ Device = $Matches[1]; Type = $null }
                }
            }

            if ($targets.Count -eq 0) {
                $out.Note = $(if (Test-IsAdmin) { 'smartctl --scan found no devices' }
                    else { 'smartctl needs elevation on Windows - re-run via RUN.cmd' })
                throw 'no smartctl targets'
            }

            foreach ($t in $targets) {
                $args = @('-j', '-a')
                if ($t.Type) { $args += @('-d', $t.Type) }
                $args += $t.Device

                $raw = & $SmartctlPath @args 2>$null | Out-String
                $j = $null
                if ($raw) { try { $j = $raw | ConvertFrom-Json } catch { } }

                # No model means the device was never actually read. Emitting a
                # blank row is how "could not read" becomes indistinguishable
                # from "nothing wrong".
                if (-not $j -or -not $j.model_name) {
                    $err = ''
                    try { $err = (@($j.smartctl.messages | ForEach-Object { $_.string }) -join '; ') } catch { }
                    $failures += ($t.Device + ': ' + $(if ($err) { $err } else { 'no data returned' }))
                    continue
                }

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

            if ($out.Disks.Count -gt 0) {
                $out.Status = 'Read'
                if ($failures.Count -gt 0) { $out.Note = ('some devices unreadable: ' + ($failures -join ' | ')) }
                return [pscustomobject]$out
            }

            # Nothing readable at all - fall through to the Windows counters
            # rather than returning an empty list that reads as a clean bill.
            $out.Note = $(if (Test-IsAdmin) { 'smartctl could not read any device' }
                else { 'smartctl needs elevation on Windows - re-run via RUN.cmd' })
        }
        catch { $out.Note = $_.Exception.Message }
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
# ---------------------------------------------------------------------------
# LibreHardwareMonitor only publishes its WMI namespace while it is RUNNING,
# so the toolkit starts it rather than relying on the tech to remember.
#
# This is done even though it is a change to the machine, because the thermal
# abort is a SAFETY mechanism: without a temperature source the stress test
# cannot stop when a machine overheats. Running a thermal load test blind is a
# worse thing to do to someone's hardware than loading a signed sensor driver.
#
# Be aware of what it does: LHM loads a kernel-mode driver to reach SuperIO and
# SMBus sensors. That is how every tool in this class works (HWiNFO, OCCT), but
# it is not nothing, and some AV products flag it. The module says so, and if
# it started LHM it also stops it afterwards so the machine is left as found.
# ---------------------------------------------------------------------------
$script:LhmPort = 8085

# LibreHardwareMonitor 0.9.6 does not publish the root\LibreHardwareMonitor WMI
# namespace - it runs for a minute and the namespace never appears at all
# ("Invalid namespace"). There is no user-facing WMI toggle in this build.
#
# Its web server IS available and documented, so that is what gets used:
# enable it in the config before launch, then read the sensor tree as JSON from
# localhost. WMI is still tried first in case a build or version does publish
# it, but nothing depends on it.
function Set-SensorProviderConfig {
    param([string]$ExePath)
    if (-not $ExePath) { return }
    $cfg = Join-Path (Split-Path -Parent $ExePath) 'LibreHardwareMonitor.config'
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="runWebServerMenuItem" value="true" />
    <add key="listenerPort" value="$($script:LhmPort)" />
    <add key="minTrayMenuItem" value="true" />
    <add key="startMinMenuItem" value="true" />
  </appSettings>
</configuration>
"@
    try { Set-Content -LiteralPath $cfg -Value $xml -Encoding UTF8 -WhatIf:$false } catch { }
}

# Flatten LHM's nested sensor tree. Nodes carry a formatted Value like
# "45.0 C" or "1200 RPM"; the numeric part is what matters, and the group name
# ("Temperatures", "Fans") is what identifies the kind.
function Get-LhmWebSensors {
    $out = @()
    try {
        $raw = Invoke-WebRequest -Uri ("http://localhost:{0}/data.json" -f $script:LhmPort) `
            -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
        $root = $raw.Content | ConvertFrom-Json
    }
    catch { return $out }

    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    $stack.Push([pscustomobject]@{ Node = $root; Group = '' })

    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $n = $item.Node
        $group = $item.Group

        $kids = @()
        try { $kids = @($n.Children) } catch { }

        if ($kids.Count -gt 0) {
            $nextGroup = $group
            if ($n.Text -match '^(Temperatures|Fans|Voltages|Powers|Clocks|Load|Controls)$') { $nextGroup = $n.Text }
            foreach ($k in $kids) { $stack.Push([pscustomobject]@{ Node = $k; Group = $nextGroup }) }
            continue
        }

        $val = [string]$n.Value
        if ([string]::IsNullOrWhiteSpace($val)) { continue }
        $num = $null
        if ($val -match '(-?\d+(?:[.,]\d+)?)') {
            try { $num = [double](($Matches[1]) -replace ',', '.') } catch { }
        }
        if ($null -eq $num) { continue }

        $out += [pscustomobject]@{ Name = [string]$n.Text; Group = $group; Value = $num; Raw = $val }
    }
    return $out
}

function Start-SensorProvider {
    param([string]$ExePath)

    $out = [ordered]@{ Started = $false; Process = $null; Status = 'NotAttempted' }

    if (-not $ExePath) { $out.Status = 'NotInstalled'; return [pscustomobject]$out }

    if (Get-Process -Name 'LibreHardwareMonitor' -ErrorAction SilentlyContinue) {
        # Already running - use it, but do NOT stop something we did not start.
        $out.Status = 'AlreadyRunning'
        return [pscustomobject]$out
    }

    if (-not (Test-IsAdmin)) {
        $out.Status = 'NeedsElevation'
        return [pscustomobject]$out
    }

    try {
        Set-SensorProviderConfig -ExePath $ExePath
        $p = Start-Process -FilePath $ExePath -WindowStyle Minimized -PassThru -ErrorAction Stop
        $out.Process = $p
        $out.Started = $true

        # Sensors take a few seconds to come up after launch.
        for ($i = 0; $i -lt 25; $i++) {
            Start-Sleep -Milliseconds 800
            if (@(Get-LhmWebSensors).Count -gt 0) { $out.Status = 'Running'; return [pscustomobject]$out }
            try {
                $probe = @(Get-CimInstance -Namespace 'root/LibreHardwareMonitor' -ClassName 'Sensor' -ErrorAction Stop)
                if ($probe.Count -gt 0) { $out.Status = 'Running'; return [pscustomobject]$out }
            }
            catch { }
        }
        $out.Status = 'StartedButNoSensors'
    }
    catch {
        $out.Status = 'LaunchFailed'
    }
    return [pscustomobject]$out
}

function Stop-SensorProvider {
    param($Handle)
    if (-not $Handle -or -not $Handle.Started -or -not $Handle.Process) { return }
    try { Stop-Process -Id $Handle.Process.Id -Force -ErrorAction SilentlyContinue } catch { }
}

function Get-FanReadings {
    $out = [ordered]@{ Status = 'Unavailable'; Fans = @() }

    $web = @(Get-LhmWebSensors | Where-Object { $_.Group -eq 'Fans' })
    if ($web.Count -gt 0) {
        foreach ($f in $web) { $out.Fans += [ordered]@{ Name = $f.Name; Rpm = [int]$f.Value } }
        $out.Status = 'Read'
        return [pscustomobject]$out
    }

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
    $web = @(Get-LhmWebSensors |
            Where-Object { $_.Group -eq 'Temperatures' -and $_.Name -match '(?i)gpu' -and $_.Value -gt 0 } |
            Where-Object { $_.Name -notmatch '(?i)critical|warning|limit|threshold|target|max\b|min\b' })
    if ($web.Count -gt 0) { return [math]::Round((($web | Measure-Object -Property Value -Maximum).Maximum), 1) }

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


# ---------------------------------------------------------------------------
# Shared collection. Everything read here is read the same way in every phase,
# so a baseline and a comparison are always measuring with the same ruler.
# ---------------------------------------------------------------------------
function Get-EvidenceSnapshot {
    param($Tools, [int]$HistoryDays = 30)

    $thermal = Get-ThermalReading
    $fans = Get-FanReadings
    $snap = [ordered]@{
        TakenAt       = (Get-Date).ToString('o')
        ThermalStatus = $thermal.Status
        ThermalSource = $thermal.Source
        TempC         = $thermal.TempC
        PerfPct       = (Get-CpuPerformancePercent)
        FanStatus     = $fans.Status
        FanRpm        = $null
        GpuTempC      = (Get-GpuTemperature)
        Smart         = (Get-SmartDetail -SmartctlPath $Tools.smartctl)
        Battery       = (Get-BatteryHealth)
        Errors        = (Get-HardwareErrorSnapshot -Since (Get-Date).AddDays(-$HistoryDays))
        ErrorWindowDays = $HistoryDays
    }
    if ($fans.Status -eq 'Read') {
        $snap.FanRpm = (@($fans.Fans | ForEach-Object { $_.Rpm }) | Measure-Object -Maximum).Maximum
    }
    return [pscustomobject]$snap
}

function Save-EvidenceBaseline {
    param($Snapshot)
    Initialize-LocalRoot
    $path = Get-BaselinePath
    try {
        # -WhatIf:$false deliberately: the baseline IS the deliverable of this
        # phase, and a dry run that saves nothing leaves the compare step with
        # nothing to compare against.
        $Snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8 -WhatIf:$false
        return $path
    }
    catch { return $null }
}

function Get-EvidenceBaseline {
    $path = Get-BaselinePath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) }
    catch { return $null }
}

# ---------------------------------------------------------------------------
# Printing helpers shared by the phases.
# ---------------------------------------------------------------------------
function Show-MeasurementSources {
    param($Tools)
    Write-Host ''
    Write-Host '  Measurement sources:' -ForegroundColor Cyan
    Write-Host ('    SMART    : {0}' -f $(if ($Tools.smartctl) { 'smartctl (attribute-level)' } else { 'Windows counters only - install smartmontools for real attributes' })) -ForegroundColor $(if ($Tools.smartctl) { 'Green' } else { 'Yellow' })
    Write-Host ('    Sensors  : {0}' -f $(if ($Tools.LibreHardwareMonitor) { 'LibreHardwareMonitor present' } else { 'ACPI only - many laptops expose nothing' })) -ForegroundColor $(if ($Tools.LibreHardwareMonitor) { 'Green' } else { 'Yellow' })
    if (-not $Tools.smartctl -or -not $Tools.LibreHardwareMonitor) {
        Write-Host '    Run Install-Tools.ps1 on the bench machine to provision these.' -ForegroundColor DarkGray
    }
}

function Show-SmartSummary {
    param($Smart)
    if (-not $Smart -or $Smart.Status -ne 'Read') { return }
    Write-Host ''
    Write-Host ('  SMART via {0}:' -f $Smart.Source) -ForegroundColor Cyan
    foreach ($d in $Smart.Disks) {
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

# The interlock. This module cannot stop OCCT, so the only thing it can do is
# say so before the tech starts it - which makes saying it clearly more
# important here than it was when the module owned the load itself.
function Show-DiskInterlock {
    param($Gate)
    if (-not $Gate -or $Gate.Status -ne 'Read' -or $Gate.Healthy) { return $false }
    Write-Host ''
    Write-Host '  DO NOT STRESS THIS MACHINE - a disk is not reporting Healthy.' -ForegroundColor Red
    foreach ($u in $Gate.Unhealthy) { Write-Host ('    {0}: {1}' -f $u.Name, $u.Health) -ForegroundColor Red }
    Write-Host '  Stressing a machine with a failing drive risks the data you should be' -ForegroundColor Yellow
    Write-Host '  recovering first. Image it, get the data off, THEN test hardware.' -ForegroundColor Yellow
    Write-Host '  Nothing here can stop an external tool - that is your call to make.' -ForegroundColor Yellow
    return $true
}

# ---------------------------------------------------------------------------
# Phase 1 - baseline.
# ---------------------------------------------------------------------------
function Invoke-EvidenceBaseline {
    param($Tools, $Result, $SensorHandle)

    Write-Banner 'Baseline - before any load is applied'

    $gate = Get-DiskHealthGate
    $Result.DiskGate = $gate
    $snap = Get-EvidenceSnapshot -Tools $Tools
    $Result.Baseline = $snap
    $Result.SensorsUsable = ($snap.ThermalStatus -eq 'Read')

    $cpuName = ''
    try { $cpuName = (Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).Name } catch { }
    $Result.Cpu = $cpuName

    Write-Host ''
    Write-Host ('  CPU        : {0}' -f $cpuName) -ForegroundColor Gray
    if ($snap.ThermalStatus -eq 'Read') {
        Write-Host ('  Idle temp  : {0} C via {1}' -f $snap.TempC, $snap.ThermalSource) -ForegroundColor Gray
    }
    else {
        Write-Host ('  Idle temp  : NOT AVAILABLE ({0})' -f $snap.ThermalStatus) -ForegroundColor Yellow
        Write-Host '               Without a temperature source the watch phase cannot tell you' -ForegroundColor Yellow
        Write-Host '               whether the machine got hot. Watch it yourself.' -ForegroundColor Yellow
    }
    if ($snap.FanStatus -eq 'Read') {
        Write-Host ('  Idle fans  : {0} rpm' -f $snap.FanRpm) -ForegroundColor Gray
    }
    else {
        Write-Host '  Idle fans  : no fan sensor - a dead fan cannot be detected from here' -ForegroundColor Yellow
    }

    Show-SmartSummary -Smart $snap.Smart

    if ($snap.Battery -and $snap.Battery.Status -eq 'Read') {
        Write-Host ''
        Write-Host ('  Battery: {0}% of design capacity ({1} of {2} mWh), {3} cycles' -f `
                $snap.Battery.HealthPercent, $snap.Battery.FullChargeCapacity,
            $snap.Battery.DesignCapacity, $snap.Battery.CycleCount) -ForegroundColor `
        $(if ($snap.Battery.HealthPercent -lt 60) { 'Red' } elseif ($snap.Battery.HealthPercent -lt 80) { 'Yellow' } else { 'Green' })
    }

    Write-Host ''
    Write-Host ('  Hardware errors already logged in the last {0} days:' -f $snap.ErrorWindowDays) -ForegroundColor Cyan
    $any = $false
    foreach ($src in $script:ErrorSources) {
        $n = 0
        if ($snap.Errors) { $n = [int]$snap.Errors[$src.Key] }
        if ($n -gt 0) {
            $any = $true
            Write-Host ('    {0,-20} {1,4}   {2}' -f $src.Key, $n, $src.Component) -ForegroundColor Yellow
        }
    }
    if (-not $any) { Write-Host '    none' -ForegroundColor Green }
    Write-Host '  These are the PRE-EXISTING counts. Only errors on top of these mean' -ForegroundColor DarkGray
    Write-Host '  anything about the test you are about to run.' -ForegroundColor DarkGray

    $Result.InterlockTripped = Show-DiskInterlock -Gate $gate

    $saved = Save-EvidenceBaseline -Snapshot $snap
    $Result.BaselinePath = $saved
    Write-Host ''
    if ($saved) {
        Write-Host '  Baseline saved on this machine (not on the stick).' -ForegroundColor Green
    }
    else {
        Write-Host '  BASELINE NOT SAVED - the compare step will have nothing to diff against.' -ForegroundColor Red
    }

    Write-Host ''
    Write-Host '  NEXT: start your stress tool, then come back.' -ForegroundColor White
    Write-Host '    OCCT / Cinebench are on the stick; MemTest86+ boots from it for RAM.' -ForegroundColor Gray
    Write-Host '    While it runs   :  -Module evidence -Phase Watch     (samples live)' -ForegroundColor Gray
    Write-Host '    After it stops  :  -Module evidence -Phase Compare   (diffs vs baseline)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  This module applies no load of its own - it only records what happens.' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Phase 2 - watch while an EXTERNAL tool applies the load.
#
# The point of sampling here rather than reading once afterwards is that a
# machine cools in seconds. Peak temperature and the fan ramp only exist while
# the load is on, and they are the readings that catch a seized fan or dried
# paste.
# ---------------------------------------------------------------------------
function Invoke-EvidenceWatch {
    param($Tools, $Result, [int]$Minutes)

    Write-Banner ('Watching for up to {0} minute(s) - start your stress tool now' -f $Minutes)
    Write-Host '  Ctrl-C stops watching. Nothing here is loading the machine.' -ForegroundColor DarkGray
    Write-Host ''

    $start = Get-Date
    $deadline = $start.AddMinutes($Minutes)
    $samples = @()
    $peakTemp = $null; $minPerf = $null; $peakFan = $null; $peakGpu = $null
    $cpuSamples = @()

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $script:EvidenceDefaults.SampleSecs
        $t = Get-ThermalReading
        $p = Get-CpuPerformancePercent
        $cpu = Get-CpuUtilizationPercent
        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 0)

        $rpm = $null
        $f = Get-FanReadings
        if ($f.Status -eq 'Read') {
            $rpm = (@($f.Fans | ForEach-Object { $_.Rpm }) | Measure-Object -Maximum).Maximum
            if ($null -eq $peakFan -or $rpm -gt $peakFan) { $peakFan = $rpm }
        }
        $gpuT = Get-GpuTemperature
        if ($null -ne $gpuT -and ($null -eq $peakGpu -or $gpuT -gt $peakGpu)) { $peakGpu = $gpuT }

        if ($null -ne $cpu) { $cpuSamples += $cpu }
        if ($null -ne $t.TempC -and ($null -eq $peakTemp -or $t.TempC -gt $peakTemp)) { $peakTemp = $t.TempC }
        if ($null -ne $p -and ($null -eq $minPerf -or $p -lt $minPerf)) { $minPerf = $p }

        $samples += [ordered]@{ ElapsedSec = $elapsed; TempC = $t.TempC; PerfPct = $p; CpuPct = $cpu; FanRpm = $rpm; GpuTempC = $gpuT }

        $line = '    {0,4}s   cpu {1,6}%   perf {2,6}%   temp {3,8}   fan {4,7}' -f $elapsed,
        $(if ($null -ne $cpu) { $cpu } else { 'n/a' }),
        $(if ($null -ne $p) { $p } else { 'n/a' }),
        $(if ($null -ne $t.TempC) { "$($t.TempC) C" } else { 'n/a' }),
        $(if ($null -ne $rpm) { "$rpm rpm" } else { 'n/a' })
        $color = 'Gray'
        if ($null -ne $cpu -and $cpu -ge $script:EvidenceDefaults.LoadCpuPct) { $color = 'Green' }
        if ($null -ne $p -and $p -lt 70) { $color = 'Yellow' }
        if ($null -ne $t.TempC -and $t.TempC -ge ($script:EvidenceDefaults.HotTempC - 10)) { $color = 'Yellow' }
        if ($null -ne $t.TempC -and $t.TempC -ge $script:EvidenceDefaults.HotTempC) { $color = 'Red' }
        Write-Host $line -ForegroundColor $color
    }

    $Result.Samples = $samples
    $Result.PeakTempC = $peakTemp
    $Result.MinPerfPct = $minPerf
    $Result.PeakFanRpm = $peakFan
    $Result.PeakGpuTempC = $peakGpu
    if ($cpuSamples.Count -gt 0) { $Result.MeanCpuPercent = [math]::Round((($cpuSamples | Measure-Object -Average).Average), 1) }
    $Result.WatchedSeconds = [math]::Round(((Get-Date) - $start).TotalSeconds, 0)
}

# Did the external tool actually run? Without this the whole module is a
# machine for producing false passes: no load, no new errors, looks clean.
#
# Three states, never two: OBSERVED / NOT OBSERVED / UNDETERMINED.
#
# CPU utilisation alone is NOT enough to answer this, and assuming it was is a
# bug this module had on its first real run. A GPU stress test - which is
# exactly what you reach for on a display fault - leaves the CPU near idle by
# design. Judging that run by CPU percentage reports "nothing was tested" while
# FurMark is cooking the card. So a rise in GPU temperature counts as load
# just as much, and the answer says WHICH kind was seen rather than implying
# the machine was fully exercised.
function Get-LoadObservation {
    param($Result)

    $out = [ordered]@{ State = 'Undetermined'; Kind = 'None'; Note = '' }
    $samples = @($Result.Samples)
    if ($samples.Count -eq 0) {
        $out.Note = 'no watch phase was run - nothing was sampled while the tool ran'
        return [pscustomobject]$out
    }

    # GPU temperature rise across the window. Absolute temperature says nothing
    # here - a card idling at 45 C and a card loaded to 45 C look identical -
    # so the signal is movement.
    $gpuRise = $null
    $gpuVals = @($samples | ForEach-Object { $_.GpuTempC } | Where-Object { $null -ne $_ })
    if ($gpuVals.Count -ge 2) {
        $gpuRise = ($gpuVals | Measure-Object -Maximum).Maximum - ($gpuVals | Measure-Object -Minimum).Minimum
    }

    $cpuKnown = ($null -ne $Result.MeanCpuPercent)
    $cpuLoaded = ($cpuKnown -and $Result.MeanCpuPercent -ge $script:EvidenceDefaults.LoadCpuPct)
    $gpuLoaded = ($null -ne $gpuRise -and $gpuRise -ge $script:EvidenceDefaults.GpuRiseC)

    if ($cpuLoaded -and $gpuLoaded) {
        $out.State = 'Observed'; $out.Kind = 'CpuAndGpu'
        $out.Note = ('mean CPU {0}%, GPU rose {1} C over {2} sample(s)' -f $Result.MeanCpuPercent, $gpuRise, $samples.Count)
        return [pscustomobject]$out
    }
    if ($cpuLoaded) {
        $out.State = 'Observed'; $out.Kind = 'Cpu'
        $out.Note = ('mean CPU {0}% over {1} sample(s)' -f $Result.MeanCpuPercent, $samples.Count)
        return [pscustomobject]$out
    }
    if ($gpuLoaded) {
        $out.State = 'Observed'; $out.Kind = 'Gpu'
        $out.Note = ('GPU temperature rose {0} C - a GPU test; the CPU was left near idle ({1})' -f `
                $gpuRise, $(if ($cpuKnown) { "mean $($Result.MeanCpuPercent)%" } else { 'CPU not measurable' }))
        return [pscustomobject]$out
    }

    # Nothing looked loaded. Whether that is a real finding depends on whether
    # anything was measurable in the first place.
    if (-not $cpuKnown -and $null -eq $gpuRise) {
        $out.Note = 'neither CPU load nor GPU temperature could be measured - cannot tell whether the tool ran'
        return [pscustomobject]$out
    }

    $out.State = 'NotObserved'
    $bits = @()
    if ($cpuKnown) { $bits += ('mean CPU only {0}%' -f $Result.MeanCpuPercent) }
    if ($null -ne $gpuRise) { $bits += ('GPU moved only {0} C' -f $gpuRise) }
    $out.Note = (($bits -join ', ') + ' - no sustained load was running, or it loaded neither CPU nor GPU')
    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------
# Phase 3 - compare against the baseline.
# ---------------------------------------------------------------------------
function Invoke-EvidenceCompare {
    param($Tools, $Result)

    Write-Banner 'Compare - what changed since the baseline'

    $base = Get-EvidenceBaseline
    if (-not $base) {
        Write-Host ''
        Write-Host '  NO BASELINE FOUND. Nothing can be diffed.' -ForegroundColor Red
        Write-Host '  Run -Phase Baseline BEFORE stressing, or every pre-existing error on' -ForegroundColor Yellow
        Write-Host '  this machine will look like something your test just caused.' -ForegroundColor Yellow
        $Result.CompareStatus = 'NoBaseline'
        return
    }

    $now = Get-EvidenceSnapshot -Tools $Tools
    $Result.After = $now
    $Result.CompareStatus = 'Read'
    $Result.BaselineTakenAt = $base.TakenAt
    # Keep the loaded baseline on the result - the verdict needs the idle fan
    # RPM from it to say whether the fan ever ramped.
    $Result.Baseline = $base

    Write-Host ''
    Write-Host ('  Baseline taken: {0}' -f $base.TakenAt) -ForegroundColor Gray

    # --- Hardware error diff ------------------------------------------------
    # The counts are over a rolling window ending now, so a count that went UP
    # means new events. Equal counts mean nothing new; a LOWER count means old
    # events aged out of the window and is not a finding.
    $newErrors = @()
    foreach ($src in $script:ErrorSources) {
        $before = 0; $after = 0
        if ($base.Errors -and $base.Errors.PSObject.Properties[$src.Key]) { $before = [int]$base.Errors.$($src.Key) }
        if ($now.Errors) { $after = [int]$now.Errors[$src.Key] }
        $delta = $after - $before
        if ($delta -gt 0) {
            $newErrors += [pscustomobject]@{ Source = $src; Count = $delta }
        }
    }
    $Result.NewErrors = @($newErrors | ForEach-Object { [ordered]@{ Source = $_.Source.Key; Count = $_.Count; Component = $_.Source.Component } })

    Write-Host ''
    if ($newErrors.Count -gt 0) {
        Write-Host '  NEW HARDWARE ERRORS SINCE THE BASELINE:' -ForegroundColor Red
        foreach ($n in $newErrors) {
            Write-Host ('    {0} x{1}' -f $n.Source.Key, $n.Count) -ForegroundColor Red
            Write-Host ('      component: {0}' -f $n.Source.Component) -ForegroundColor Yellow
            Write-Host ('      meaning  : {0}' -f $n.Source.Meaning) -ForegroundColor Gray
        }
        Write-Host ''
        Write-Host '  Errors that appear under load and not before is the strongest evidence' -ForegroundColor Yellow
        Write-Host '  available from inside Windows. Trust it over a subjective symptom.' -ForegroundColor Yellow
    }
    else {
        Write-Host '  No new hardware errors since the baseline.' -ForegroundColor Green
    }

    # --- SMART movement ------------------------------------------------------
    # A reallocated or pending count that moved during a stress run is a drive
    # actively failing, and it matters more than any temperature.
    $moved = @()
    if ($base.Smart -and $now.Smart -and $base.Smart.Status -eq 'Read' -and $now.Smart.Status -eq 'Read') {
        foreach ($nd in $now.Smart.Disks) {
            $bd = @($base.Smart.Disks | Where-Object { $_.Model -eq $nd.Model }) | Select-Object -First 1
            if (-not $bd) { continue }
            foreach ($attr in @('ReallocatedSectors', 'PendingSectors', 'MediaErrors')) {
                $b = $bd.$attr; $a = $nd.$attr
                if ($null -ne $b -and $null -ne $a -and [int]$a -gt [int]$b) {
                    $moved += ('{0}: {1} {2} -> {3}' -f $nd.Model, $attr, $b, $a)
                }
            }
            if ($bd.Passed -eq $true -and $nd.Passed -eq $false) {
                $moved += ('{0}: SMART overall PASSED -> FAILED' -f $nd.Model)
            }
        }
    }
    $Result.SmartMoved = $moved
    Write-Host ''
    if ($moved.Count -gt 0) {
        Write-Host '  SMART ATTRIBUTES MOVED DURING THE TEST:' -ForegroundColor Red
        foreach ($m in $moved) { Write-Host ('    ' + $m) -ForegroundColor Red }
        Write-Host '  Stop testing. This drive is failing now, not historically.' -ForegroundColor Yellow
    }
    elseif ($base.Smart -and $base.Smart.Status -eq 'Read' -and $now.Smart -and $now.Smart.Status -eq 'Read') {
        Write-Host '  No SMART attribute moved during the test.' -ForegroundColor Green
    }
    else {
        Write-Host '  SMART comparison COULD NOT BE MADE - attributes were not readable at' -ForegroundColor Magenta
        Write-Host '  both ends. That is not the same as nothing having changed.' -ForegroundColor Magenta
    }
}

# ---------------------------------------------------------------------------
function Invoke-EvidenceModule {
    [CmdletBinding()]
    param([switch]$Apply, [hashtable]$Options = @{})

    # Read-only throughout - there is nothing here to apply. The load comes
    # from a tool this module does not run.
    if ($Apply) {
        Write-Log -Message 'The evidence module is read-only - it observes, it does not load the machine. Run OCCT, Cinebench, FurMark or MemTest86+ yourself.' -Level WARN
    }

    $action = 'Baseline'
    if ($Options['Action']) { $action = [string]$Options['Action'] }
    if (@('Baseline', 'Watch', 'Compare') -notcontains $action) {
        Write-Log -Message ("Unknown action '{0}' - falling back to Baseline" -f $action) -Level WARN
        $action = 'Baseline'
    }

    $minutes = $script:EvidenceDefaults.WatchMinutes
    if ($Options['Minutes']) { $minutes = [int]$Options['Minutes'] }
    if ($minutes -gt $script:EvidenceDefaults.MaxWatchMins) { $minutes = $script:EvidenceDefaults.MaxWatchMins }
    if ($minutes -lt 1) { $minutes = 1 }

    $noLaunchSensors = [bool]$Options['NoLaunchSensors']

    Write-Banner 'Hardware evidence'

    $tools = Get-ExternalToolInventory
    $result = [ordered]@{
        Action = $action
        Tools = [ordered]@{
            smartctl = [bool]$tools.smartctl
            LibreHardwareMonitor = [bool]$tools.LibreHardwareMonitor
            CrystalDiskInfo = [bool]$tools.CrystalDiskInfo
        }
        SensorProvider = 'NotAttempted'
        SensorsUsable = $false
        Cpu = $null
        Baseline = $null; BaselinePath = $null; BaselineTakenAt = $null
        After = $null; CompareStatus = 'NotRun'
        DiskGate = $null; InterlockTripped = $false
        Samples = @(); WatchedSeconds = 0
        PeakTempC = $null; MinPerfPct = $null; MeanCpuPercent = $null
        PeakFanRpm = $null; PeakGpuTempC = $null
        LoadObservation = $null
        NewErrors = @(); SmartMoved = @()
        MemoryTest = $null
        GeneratesLoad = $false
    }

    Show-MeasurementSources -Tools $tools

    # Sensors come up before any reading so baseline and watch use the same
    # source, and go down again afterwards if this run started them.
    $sensorHandle = $null
    if (-not $noLaunchSensors) {
        $sensorHandle = Start-SensorProvider -ExePath $tools.LibreHardwareMonitor
        switch ($sensorHandle.Status) {
            'Running' {
                Write-Host ''
                Write-Host '  Started LibreHardwareMonitor for temperature and fan sensors.' -ForegroundColor Green
                Write-Host '  It loads a kernel driver to read them, and will be stopped again' -ForegroundColor DarkGray
                Write-Host '  when this run finishes. -NoLaunchSensors skips it.' -ForegroundColor DarkGray
            }
            'AlreadyRunning' { Write-Log -Message 'LibreHardwareMonitor already running - using it, will not stop it' -Level OK }
            'NeedsElevation' { Write-Log -Message 'Cannot start LibreHardwareMonitor unelevated - no temperature or fan readings. Re-run via RUN.cmd.' -Level WARN }
            'NotInstalled' { Write-Log -Message 'LibreHardwareMonitor not on this stick - run Install-Tools.ps1' -Level WARN }
            default { Write-Log -Message ('LibreHardwareMonitor did not come up: ' + $sensorHandle.Status) -Level WARN }
        }
    }
    $result.SensorProvider = $(if ($sensorHandle) { $sensorHandle.Status } else { 'Skipped' })
    $result.MemoryTest = Get-MemoryTestAvailability

    try {
        switch ($action) {
            'Baseline' {
                Invoke-EvidenceBaseline -Tools $tools -Result $result -SensorHandle $sensorHandle
            }
            'Watch' {
                $gate = Get-DiskHealthGate
                $result.DiskGate = $gate
                $result.InterlockTripped = Show-DiskInterlock -Gate $gate
                Invoke-EvidenceWatch -Tools $tools -Result $result -Minutes $minutes
                $result.LoadObservation = Get-LoadObservation -Result $result
                Invoke-EvidenceCompare -Tools $tools -Result $result
                Show-EvidenceVerdict -Result $result
            }
            'Compare' {
                $result.LoadObservation = Get-LoadObservation -Result $result
                Invoke-EvidenceCompare -Tools $tools -Result $result
                Show-EvidenceVerdict -Result $result
            }
        }
    }
    finally {
        # Leave the machine as it was found. Only stops what this run started -
        # if the tech already had it open, it stays open.
        Stop-SensorProvider -Handle $sensorHandle
        if ($sensorHandle -and $sensorHandle.Started) {
            Write-Log -Message 'LibreHardwareMonitor stopped (it was started by this run)' -Level OK
        }
    }

    return [pscustomobject]$result
}


# SMART can come from either end of the run. Prefer the AFTER reading, because
# a drive that degraded during the test is the finding.
function Get-ResultSmart {
    param($Result)
    if ($Result -and $Result.After -and $Result.After.Smart) { return $Result.After.Smart }
    if ($Result -and $Result.Baseline -and $Result.Baseline.Smart) { return $Result.Baseline.Smart }
    return $null
}

# Every component, and honestly how far this got with each. Printed whether the
# run found anything or not, so "entire device" means a stated position on each
# part rather than silence about the ones that were skipped.
#
# The coverage claims here are deliberately weaker than they used to be. This
# module no longer applies load, so it cannot claim a component was exercised -
# only that it was OBSERVED while something else exercised it. Claiming more
# would be the same false-confidence bug this toolkit keeps fixing.
function Show-CoverageMatrix {
    param($Result)

    Write-Host '  COVERAGE - what was and was not actually observed' -ForegroundColor White
    Write-Host '  ------------------------------------------------' -ForegroundColor DarkGray

    # Key off what was actually READ, not what is installed. Reporting coverage
    # from tool presence claimed FULL cooling coverage on a machine where the
    # provider was installed but not running - and contradicted the verdict
    # directly above it, which correctly said NOT MEASURED.
    $lhm = $false
    if ($Result) { $lhm = [bool]$Result.SensorsUsable }
    $rs = Get-ResultSmart -Result $Result
    $smart = $false
    if ($rs) { $smart = ($rs.Source -eq 'smartctl' -and $rs.Status -eq 'Read') }
    $memIso = $null
    if ($Result -and $Result.MemoryTest) { $memIso = $Result.MemoryTest.MemTest86Found }

    $loadState = 'Undetermined'
    if ($Result -and $Result.LoadObservation) { $loadState = [string]$Result.LoadObservation.State }

    # CPU coverage is now entirely a function of whether an EXTERNAL tool was
    # seen loading it. No observation, no claim.
    switch ($loadState) {
        'Observed' { Write-Cover 'CPU' 'OBSERVED' 'external load seen, clocks sampled, error log diffed' }
        'NotObserved' { Write-Cover 'CPU' 'NONE' 'no load was observed - nothing was exercised' }
        default { Write-Cover 'CPU' 'NONE' 'no watch phase, or CPU load could not be measured' }
    }

    # Cooling and fans are separate sources. ACPI gives a temperature and never
    # a fan speed, so deriving fan coverage from thermal availability claimed
    # FULL fan coverage on a machine with no fan sensor at all.
    $tempOk = $lhm
    $fanOk = $false
    if ($Result -and $Result.Baseline) { $fanOk = ($Result.Baseline.FanStatus -eq 'Read') }

    # A temperature that never moves while the machine goes from idle to loaded
    # is not a working sensor - it is a fixed ACPI trip point. Calling that a
    # pass is worse than reporting nothing.
    $tempStuck = $false
    if ($Result -and @($Result.Samples).Count -ge 3) {
        $temps = @($Result.Samples | ForEach-Object { $_.TempC } | Where-Object { $null -ne $_ })
        if ($temps.Count -ge 3) {
            $spread = ($temps | Measure-Object -Maximum).Maximum - ($temps | Measure-Object -Minimum).Minimum
            $tempStuck = ($spread -eq 0)
        }
    }

    if ($tempStuck) {
        Write-Cover 'Cooling' 'UNRELIABLE' 'temperature never moved while watching - sensor is not tracking'
    }
    elseif ($tempOk -and @($Result.Samples).Count -gt 0) {
        Write-Cover 'Cooling' 'OBSERVED' 'temps sampled while the external tool ran'
    }
    elseif ($tempOk) {
        Write-Cover 'Cooling' 'PARTIAL' 'idle temperature only - run -Phase Watch during the stress test'
    }
    else {
        Write-Cover 'Cooling' 'NONE' 'no temperature source available'
    }

    $fanNote = 'no sensor provider - a dead fan would not be detected'
    if ($fanOk -and @($Result.Samples).Count -gt 0) { $fanNote = 'ramp checked while loaded' }
    elseif ($fanOk) { $fanNote = 'idle reading only - watch during the test to see the ramp' }
    elseif ($tempOk) { $fanNote = 'machine exposes no fan RPM - a dead fan would not be detected here' }
    Write-Cover 'Fans' $(if ($fanOk -and @($Result.Samples).Count -gt 0) { 'OBSERVED' } elseif ($fanOk) { 'PARTIAL' } else { 'NONE' }) $fanNote

    Write-Cover 'Storage'  $(if ($smart) { 'OBSERVED' } else { 'PARTIAL' }) $(if ($smart) { 'SMART attributes diffed across the run' } else { 'Windows counters only; install smartmontools' })
    Write-Cover 'Battery'  'FULL'    'design vs full-charge capacity and cycle count'
    Write-Cover 'Memory'   'NONE'    $(if ($memIso) { "boot $memIso from the stick - several passes" } else { 'get MemTest86+ - nothing in Windows can test RAM the OS is using' })
    Write-Cover 'GPU'      'OBSERVED' 'temps and driver resets only - load it with OCCT or FurMark'
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
    if ($Level -eq 'UNRELIABLE') { $color = 'Magenta' }
    Write-Host ('    {0,-9} {1,-11} {2}' -f $Part, $Level, $Note) -ForegroundColor $color
}

function Show-UntestableComponents {
    param($Result)
    Show-CoverageMatrix -Result $Result
}

function Show-EvidenceVerdict {
    param($Result)

    Write-Banner 'Verdict'

    # --- Was anything actually tested? --------------------------------------
    # This has to come first. Every line below it is meaningless if the stress
    # tool was never running, and a clean result under no load is the single
    # easiest way for this module to lie.
    $obs = $Result.LoadObservation
    if (-not $obs -or $obs.State -eq 'Undetermined') {
        Write-Host '  LOAD NOT OBSERVED - this module applies no load of its own, and nothing' -ForegroundColor Magenta
        Write-Host '  was sampled while a tool did. Do not record any of this as a pass.' -ForegroundColor Magenta
        if ($obs -and $obs.Note) { Write-Host ('    ' + $obs.Note) -ForegroundColor Gray }
    }
    elseif ($obs.State -eq 'NotObserved') {
        Write-Host '  NO SUSTAINED LOAD OBSERVED while this was watching.' -ForegroundColor Red
        Write-Host ('    ' + $obs.Note) -ForegroundColor Gray
        Write-Host '    Start OCCT, Cinebench or FurMark FIRST, then run -Phase Watch.' -ForegroundColor Gray
    }
    else {
        Write-Host ('  Load observed: {0}.' -f $obs.Note) -ForegroundColor Green
        Write-Host '  The load came from an external tool - this module only watched.' -ForegroundColor DarkGray
        if ($obs.Kind -eq 'Gpu') {
            Write-Host '  This was a GPU test. Nothing below says anything about the CPU.' -ForegroundColor Yellow
        }
        elseif ($obs.Kind -eq 'Cpu') {
            Write-Host '  This was a CPU test. The GPU was not exercised.' -ForegroundColor Yellow
        }
    }

    $newErrors = @($Result.NewErrors)
    # Component-specific, not global. A GPU run proves nothing about the CPU and
    # vice versa, so each component checks the load KIND that would exercise it.
    $cpuLoadOk = ($obs -and $obs.State -eq 'Observed' -and @('Cpu', 'CpuAndGpu') -contains $obs.Kind)
    $gpuLoadOk = ($obs -and $obs.State -eq 'Observed' -and @('Gpu', 'CpuAndGpu') -contains $obs.Kind)
    $loadOk = ($obs -and $obs.State -eq 'Observed')

    Write-Host ''
    Write-Host '  COMPONENT ASSESSMENT' -ForegroundColor White
    Write-Host '  --------------------' -ForegroundColor DarkGray

    # CPU
    if (@($newErrors | Where-Object { $_.Source -like 'Whea*' }).Count -gt 0) {
        Write-StressLine 'CPU' 'SUSPECT' 'WHEA errors appeared during the run'
    }
    elseif ($cpuLoadOk) { Write-StressLine 'CPU' 'PASS' 'held observed load, no machine-check errors' }
    elseif ($gpuLoadOk) { Write-StressLine 'CPU' 'NOT TESTED' 'a GPU test was observed - the CPU was not loaded' }
    else { Write-StressLine 'CPU' 'NOT TESTED' 'no load observed' }

    # Cooling
    if ($null -ne $Result.PeakTempC) {
        $temps = @($Result.Samples | ForEach-Object { $_.TempC } | Where-Object { $null -ne $_ })
        $flat = ($temps.Count -ge 3 -and (($temps | Measure-Object -Maximum).Maximum - ($temps | Measure-Object -Minimum).Minimum) -eq 0)
        if ($flat) {
            Write-StressLine 'Cooling' 'UNRELIABLE' ("stuck at $($Result.PeakTempC) C throughout - not a real reading")
        }
        elseif ($Result.PeakTempC -ge $script:EvidenceDefaults.HotTempC) {
            Write-StressLine 'Cooling' 'FAIL' ("peaked at $($Result.PeakTempC) C - paste, fan or blocked intake")
        }
        elseif (-not $loadOk) {
            Write-StressLine 'Cooling' 'INCONCLUSIVE' ("peak $($Result.PeakTempC) C, but under no observed load")
        }
        else { Write-StressLine 'Cooling' 'PASS' ('peak ' + $Result.PeakTempC + ' C under observed load') }
    }
    else { Write-StressLine 'Cooling' 'NOT MEASURED' 'no sensor available - install LibreHardwareMonitor' }

    # Fans. The signal is whether RPM ROSE under load, not its absolute value:
    # a fan sitting at idle speed while the CPU cooks is a seized fan, and that
    # is a part swap rather than a repaste.
    $idleFan = $null
    if ($Result.Baseline) { $idleFan = $Result.Baseline.FanRpm }
    if (-not $Result.Baseline -or $Result.Baseline.FanStatus -ne 'Read') {
        # "No provider" and "provider running, machine has no fan sensor" are
        # different answers. Many laptops keep the fan on the EC where nothing
        # in userland can see it, and that is not a tooling failure.
        if ($Result.SensorsUsable) {
            Write-StressLine 'Fans' 'NOT MEASURED' 'sensors are up, but this machine exposes no fan RPM - check it by ear and by hand'
        }
        else { Write-StressLine 'Fans' 'NOT MEASURED' 'no sensor provider running' }
    }
    elseif (@($Result.Samples).Count -eq 0) {
        Write-StressLine 'Fans' 'NOT MEASURED' 'idle reading only - run -Phase Watch during the stress test'
    }
    elseif ($null -eq $Result.PeakFanRpm -or $Result.PeakFanRpm -eq 0) {
        Write-StressLine 'Fans' 'FAIL' '0 rpm throughout - fan is dead, stuck or unplugged'
    }
    elseif (-not $loadOk) {
        Write-StressLine 'Fans' 'INCONCLUSIVE' ("peak $($Result.PeakFanRpm) rpm, but under no observed load")
    }
    elseif ($null -ne $idleFan -and $Result.PeakFanRpm -le $idleFan) {
        Write-StressLine 'Fans' 'SUSPECT' ("never spun up under load (idle $idleFan, peak $($Result.PeakFanRpm) rpm)")
    }
    else {
        Write-StressLine 'Fans' 'PASS' ("ramped $idleFan -> $($Result.PeakFanRpm) rpm under load")
    }

    # Battery
    $bat = $null
    if ($Result.After) { $bat = $Result.After.Battery }
    elseif ($Result.Baseline) { $bat = $Result.Baseline.Battery }
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

    # Clocks
    if ($null -ne $Result.MinPerfPct -and $Result.MinPerfPct -lt 70) {
        Write-StressLine 'Clocks' 'DEGRADED' ("dropped to $($Result.MinPerfPct)% of base clock")
    }
    elseif ($null -ne $Result.MinPerfPct -and $loadOk) {
        Write-StressLine 'Clocks' 'PASS' ("held $($Result.MinPerfPct)% of base clock under load")
    }
    elseif ($null -ne $Result.MinPerfPct) {
        Write-StressLine 'Clocks' 'INCONCLUSIVE' ("held $($Result.MinPerfPct)%, but under no observed load")
    }

    Write-StressLine 'Memory' 'NOT TESTED' 'by design - use MemTest86+ from a boot device'

    # Storage. No surface read any more - the evidence is SMART movement and
    # disk errors logged during the window, which is better evidence anyway.
    $smartBad = @()
    $rs = Get-ResultSmart -Result $Result
    if ($rs -and $rs.Disks) {
        foreach ($sd in $rs.Disks) {
            if ($sd.Passed -eq $false) { $smartBad += ($sd.Model + ' SMART overall FAILED') }
            if ($sd.ReallocatedSectors -and [int]$sd.ReallocatedSectors -gt 0) { $smartBad += ($sd.Model + ' reallocated=' + $sd.ReallocatedSectors) }
            if ($sd.PendingSectors -and [int]$sd.PendingSectors -gt 0) { $smartBad += ($sd.Model + ' pending=' + $sd.PendingSectors) }
            if ($sd.MediaErrors -and [int]$sd.MediaErrors -gt 0) { $smartBad += ($sd.Model + ' media_errors=' + $sd.MediaErrors) }
        }
    }
    if (@($Result.SmartMoved).Count -gt 0) {
        Write-StressLine 'Storage' 'FAIL' ('SMART moved during the run: ' + (@($Result.SmartMoved) -join '; '))
    }
    elseif (@($newErrors | Where-Object { $_.Source -eq 'DiskError' -or $_.Source -eq 'NtfsCorruption' }).Count -gt 0) {
        Write-StressLine 'Storage' 'FAIL' 'disk errors logged during the run'
    }
    elseif ($smartBad.Count -gt 0) {
        Write-StressLine 'Storage' 'FAIL' ($smartBad -join '; ')
    }
    elseif ($rs -and $rs.Status -eq 'Read') {
        Write-StressLine 'Storage' 'PASS' 'no SMART movement and no disk errors during the run'
    }
    else { Write-StressLine 'Storage' 'NOT MEASURED' 'SMART not readable - install smartmontools' }

    # GPU
    if (@($newErrors | Where-Object { $_.Source -eq 'GpuTdr' }).Count -gt 0) {
        Write-StressLine 'GPU' 'SUSPECT' 'display driver reset during the run'
    }
    elseif ($gpuLoadOk) {
        Write-StressLine 'GPU' 'PASS' ("peak $($Result.PeakGpuTempC) C under observed GPU load, no driver resets")
    }
    elseif ($null -ne $Result.PeakGpuTempC) {
        Write-StressLine 'GPU' 'OBSERVED' ("peak $($Result.PeakGpuTempC) C, but not loaded - use OCCT or FurMark to test it")
    }
    else { Write-StressLine 'GPU' 'NOT MEASURED' 'no GPU temperature source' }

    # Power
    if (@($newErrors | Where-Object { $_.Source -eq 'UnexpectedShutdown' }).Count -gt 0) {
        Write-StressLine 'Power' 'FAIL' 'machine lost power or hung during the run'
    }
    else { Write-StressLine 'Power' 'NOT TESTED' 'cannot be loaded or measured from here' }

    Write-Host ''
    Show-UntestableComponents -Result $Result
}

function Write-StressLine {
    param([string]$Component, [string]$Verdict, [string]$Note)
    $color = 'Gray'
    if ($Verdict -eq 'PASS') { $color = 'Green' }
    if ($Verdict -eq 'DEGRADED' -or $Verdict -eq 'SUSPECT' -or $Verdict -eq 'OBSERVED') { $color = 'Yellow' }
    if ($Verdict -eq 'FAIL') { $color = 'Red' }
    if ($Verdict -eq 'UNRELIABLE' -or $Verdict -eq 'INCONCLUSIVE') { $color = 'Magenta' }
    if ($Verdict -like 'NOT *') { $color = 'DarkGray' }
    Write-Host ('    {0,-9} {1,-14} {2}' -f $Component, $Verdict, $Note) -ForegroundColor $color
}
