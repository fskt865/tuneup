<#MANIFEST
{
  "Key": "crashes",
  "Title": "Crash report review",
  "Entry": "Invoke-CrashModule",
  "Order": 35,
  "RequiresAdmin": false,
  "Description": "Windows bugchecks, WER app crashes and third-party crash dumps, attributed to a faulting module"
}
MANIFEST#>

# Get-CrashReports.ps1 - find and read crash artefacts. READ ONLY, ALWAYS.
# ASCII only, PowerShell 5.1 compatible.
#
# There is no -Apply here and there should never be one. Nothing about a crash
# report needs fixing; the artefacts are evidence, and deleting them destroys
# the only record of an intermittent fault.
#
# The point is the FAULTING MODULE. "It crashes sometimes" is not actionable;
# "eleven crashes, all in nvlddmkm.sys" names the display driver, and
# "bugcheck 0x7A twice" names the disk. That is what turns a vague complaint
# into a part or a driver.
#
# PRIVACY - this matters more here than anywhere else in the toolkit:
#
#   A kernel memory dump is a copy of RAM. It can contain documents, passwords
#   and keys. WER reports contain full paths and command lines. NONE of that
#   leaves the machine: this module records application names, module names,
#   stop codes, counts and dates, and never file contents, paths or dump
#   files. It will not copy a dump anywhere, and neither should you.

$script:CrashLookbackDays = 90

# Stop codes worth recognising, with the layer each one points at. The number
# is not the finding - the component is.
$script:BugcheckMap = @{
    0x0A  = @{ Name = 'IRQL_NOT_LESS_OR_EQUAL';        Component = 'Driver'; Note = 'A driver touched bad memory - usually third-party' }
    0x1A  = @{ Name = 'MEMORY_MANAGEMENT';             Component = 'RAM or driver'; Note = 'Run MemTest86+ before blaming software' }
    0x1E  = @{ Name = 'KMODE_EXCEPTION_NOT_HANDLED';   Component = 'Driver' }
    0x3B  = @{ Name = 'SYSTEM_SERVICE_EXCEPTION';      Component = 'Driver' }
    0x50  = @{ Name = 'PAGE_FAULT_IN_NONPAGED_AREA';   Component = 'RAM or driver'; Note = 'Classic bad-RAM signature' }
    0x7A  = @{ Name = 'KERNEL_DATA_INPAGE_ERROR';      Component = 'Storage'; Note = 'The disk failed to return a page - check SMART' }
    0x7B  = @{ Name = 'INACCESSIBLE_BOOT_DEVICE';      Component = 'Storage / boot config'; Note = 'Storage driver or controller mode' }
    0x9C  = @{ Name = 'MACHINE_CHECK_EXCEPTION';       Component = 'CPU / hardware'; Note = 'The CPU itself reported a fault' }
    0x9F  = @{ Name = 'DRIVER_POWER_STATE_FAILURE';    Component = 'Driver'; Note = 'Usually sleep/resume on a specific driver' }
    0xC2  = @{ Name = 'BAD_POOL_CALLER';               Component = 'Driver' }
    0xC4  = @{ Name = 'DRIVER_VERIFIER_DETECTED_VIOLATION'; Component = 'Driver' }
    0xD1  = @{ Name = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'; Component = 'Driver'; Note = 'The dump usually names the driver' }
    0xDE  = @{ Name = 'POOL_CORRUPTION_IN_FILE_AREA';  Component = 'Driver' }
    0xEF  = @{ Name = 'CRITICAL_PROCESS_DIED';         Component = 'OS / corruption'; Note = 'Run the component store repair' }
    0xF4  = @{ Name = 'CRITICAL_OBJECT_TERMINATION';   Component = 'OS / storage' }
    0x101 = @{ Name = 'CLOCK_WATCHDOG_TIMEOUT';        Component = 'CPU'; Note = 'A core stopped responding' }
    0x109 = @{ Name = 'CRITICAL_STRUCTURE_CORRUPTION'; Component = 'RAM or driver' }
    0x116 = @{ Name = 'VIDEO_TDR_ERROR';               Component = 'GPU'; Note = 'Display driver failed to reset' }
    0x117 = @{ Name = 'VIDEO_TDR_TIMEOUT_DETECTED';    Component = 'GPU' }
    0x124 = @{ Name = 'WHEA_UNCORRECTABLE_ERROR';      Component = 'Hardware'; Note = 'The machine reported a hardware fault - CPU, RAM or board' }
    0x133 = @{ Name = 'DPC_WATCHDOG_VIOLATION';        Component = 'Driver / storage'; Note = 'Often an old SSD firmware or storage driver' }
    0x139 = @{ Name = 'KERNEL_SECURITY_CHECK_FAILURE'; Component = 'Driver or RAM' }
}

function Get-BugcheckInfo {
    param([int]$Code)
    if ($script:BugcheckMap.ContainsKey($Code)) {
        $m = $script:BugcheckMap[$Code]
        return [pscustomobject]@{
            Code = ('0x{0:X}' -f $Code); Name = $m.Name; Component = $m.Component
            Note = $(if ($m.Note) { $m.Note } else { '' })
        }
    }
    return [pscustomobject]@{ Code = ('0x{0:X}' -f $Code); Name = 'Unrecognised stop code'; Component = 'Unknown'; Note = 'Look it up before acting' }
}

# ---------------------------------------------------------------------------
# Kernel dumps. The bugcheck code sits in the dump header at a fixed offset,
# so the stop code can be read without WinDbg or any symbol download.
# DUMP_HEADER64: 'PAGE' at 0, 'DU64' at 4, BugCheckCode at 0x38.
# ---------------------------------------------------------------------------
function Read-MinidumpBugcheck {
    param([string]$Path)
    $fs = $null
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        if ($fs.Length -lt 0x40) { return $null }
        $buf = New-Object byte[] 0x40
        [void]$fs.Read($buf, 0, 0x40)

        $sig = [Text.Encoding]::ASCII.GetString($buf, 0, 4)
        if ($sig -ne 'PAGE') { return $null }
        return [BitConverter]::ToUInt32($buf, 0x38)
    }
    catch { return $null }
    finally { if ($fs) { $fs.Dispose() } }
}

function Get-KernelDumps {
    $out = [ordered]@{ Status = 'Read'; Dumps = @(); Note = '' }
    $cutoff = (Get-Date).AddDays(-$script:CrashLookbackDays)

    $locations = @(
        @{ Path = (Join-Path $env:SystemRoot 'Minidump'); Kind = 'Minidump' },
        @{ Path = (Join-Path $env:SystemRoot 'LiveKernelReports'); Kind = 'LiveKernel' }
    )

    foreach ($loc in $locations) {
        if (-not (Test-Path -LiteralPath $loc.Path)) { continue }
        $files = @()
        try { $files = Get-ChildItem -LiteralPath $loc.Path -Recurse -File -Filter '*.dmp' -ErrorAction Stop }
        catch { $out.Note = 'some dump folders need elevation'; continue }

        foreach ($f in $files) {
            if ($f.LastWriteTime -lt $cutoff) { continue }
            $code = Read-MinidumpBugcheck -Path $f.FullName
            $info = $null
            if ($null -ne $code) { $info = Get-BugcheckInfo -Code ([int]$code) }
            $out.Dumps += [pscustomobject]@{
                Kind = $loc.Kind
                AgeDays = [math]::Round(((Get-Date) - $f.LastWriteTime).TotalDays, 1)
                SizeMB = [math]::Round($f.Length / 1MB, 1)
                StopCode = $(if ($info) { $info.Code } else { $null })
                StopName = $(if ($info) { $info.Name } else { 'unreadable header' })
                Component = $(if ($info) { $info.Component } else { 'Unknown' })
                Note = $(if ($info) { $info.Note } else { '' })
            }
        }
    }

    $full = Join-Path $env:SystemRoot 'MEMORY.DMP'
    if (Test-Path -LiteralPath $full) {
        try {
            $f = Get-Item -LiteralPath $full -ErrorAction Stop
            $code = Read-MinidumpBugcheck -Path $full
            $info = $null
            if ($null -ne $code) { $info = Get-BugcheckInfo -Code ([int]$code) }
            $out.Dumps += [pscustomobject]@{
                Kind = 'FullDump'
                AgeDays = [math]::Round(((Get-Date) - $f.LastWriteTime).TotalDays, 1)
                SizeMB = [math]::Round($f.Length / 1MB, 1)
                StopCode = $(if ($info) { $info.Code } else { $null })
                StopName = $(if ($info) { $info.Name } else { 'unreadable header' })
                Component = $(if ($info) { $info.Component } else { 'Unknown' })
                Note = 'Full memory dump - contains RAM contents, must not leave the machine'
            }
        }
        catch { }
    }
    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------
# Windows Error Reporting.
#
# The folder NAME carries the event type and the application, and is readable
# without elevation even when the files inside are not - so a useful answer is
# available either way, with faulting module detail added when elevated.
# Format: <EventType>_<AppName>_<hash>_<hash>_<guid>
# ---------------------------------------------------------------------------
# WER folder names are not one format. Real examples from a live machine:
#   AppHang_explorer.exe_<hash>_<hash>_<guid>
#   Critical_10.0.26100.2032__<hash>_00000000_<guid>   <- token 1 is a VERSION
#   NonCritical_80004004_<hash>_...                    <- token 1 is an HRESULT
#
# Token 1 is therefore only sometimes the application, and assuming it is
# produced a single nameless group containing every report. Prefer whichever
# token actually looks like an executable, and label the others honestly
# rather than presenting a build number as though it were an app.
function Split-WerFolderName {
    param([Parameter(Mandatory = $true)][string]$FolderName)

    $parts = $FolderName -split '_'
    $eventType = $parts[0]
    $app = ''

    foreach ($tok in $parts) {
        if ($tok -match '(?i)\.(exe|dll|sys)$') { $app = $tok; break }
    }
    if (-not $app -and $parts.Count -gt 1) {
        $app = $parts[1]
        if ($app -match '^\d+(\.\d+)+$') { $app = ('(Windows ' + $app + ')') }
        elseif ($app -match '^[0-9A-Fa-f]{8}$') { $app = ('(error ' + $app + ')') }
    }
    if (-not $app) { $app = '(unidentified)' }

    return [pscustomobject]@{ EventType = $eventType; App = $app }
}

function Get-WerReports {
    $out = [ordered]@{ Status = 'Read'; Reports = @(); Denied = 0 }
    $cutoff = (Get-Date).AddDays(-$script:CrashLookbackDays)

    $roots = @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportQueue'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportArchive')
    )

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $dirs = @()
        try { $dirs = Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop } catch { continue }

        foreach ($d in $dirs) {
            if ($d.LastWriteTime -lt $cutoff) { continue }

            $parsed = Split-WerFolderName -FolderName $d.Name
            $eventType = $parsed.EventType
            $app = $parsed.App

            $modName = $null
            $exception = $null
            try {
                $wer = Get-ChildItem -LiteralPath $d.FullName -Filter '*.wer' -File -ErrorAction Stop | Select-Object -First 1
                if ($wer) {
                    # Only three fields are taken. The rest of a .wer holds full
                    # paths and command lines and is deliberately not read out.
                    foreach ($line in (Get-Content -LiteralPath $wer.FullName -ErrorAction Stop)) {
                        if ($line -match '^Sig\[\d+\]\.Value=(.+)$' -and -not $modName -and $line -match '\.(dll|sys|exe|ocx)\s*$') { $modName = $Matches[1].Trim() }
                        if ($line -match '^ModName=(.+)$') { $modName = $Matches[1].Trim() }
                        if ($line -match '^ExceptionCode=(.+)$') { $exception = $Matches[1].Trim() }
                    }
                }
            }
            catch { $out.Denied++ }

            $out.Reports += [pscustomobject]@{
                EventType = $eventType
                App = $app
                Module = $modName
                Exception = $exception
                AgeDays = [math]::Round(((Get-Date) - $d.LastWriteTime).TotalDays, 1)
            }
        }
    }
    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------
# Third-party crash stores. Most modern apps use Crashpad or Breakpad and drop
# dumps in a predictable folder. Counts and dates only - never contents.
# ---------------------------------------------------------------------------
function Get-ThirdPartyCrashes {
    $cutoff = (Get-Date).AddDays(-$script:CrashLookbackDays)
    $found = @()

    $specs = @(
        @{ Name = 'Chrome';        Path = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Crashpad\reports'); Filter = '*.dmp' },
        @{ Name = 'Edge';          Path = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Crashpad\reports'); Filter = '*.dmp' },
        @{ Name = 'Brave';         Path = (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data\Crashpad\reports'); Filter = '*.dmp' },
        @{ Name = 'Firefox';       Path = (Join-Path $env:APPDATA 'Mozilla\Firefox\Crash Reports\pending'); Filter = '*.dmp' },
        @{ Name = 'Firefox (sent)'; Path = (Join-Path $env:APPDATA 'Mozilla\Firefox\Crash Reports\submitted'); Filter = '*.txt' },
        @{ Name = 'Thunderbird';   Path = (Join-Path $env:APPDATA 'Thunderbird\Crash Reports\pending'); Filter = '*.dmp' },
        @{ Name = 'Discord';       Path = (Join-Path $env:APPDATA 'discord\Crashpad\reports'); Filter = '*.dmp' },
        @{ Name = 'Slack';         Path = (Join-Path $env:APPDATA 'Slack\Crashpad\reports'); Filter = '*.dmp' },
        @{ Name = 'VS Code';       Path = (Join-Path $env:APPDATA 'Code\Crashpad\reports'); Filter = '*.dmp' },
        @{ Name = 'Steam';         Path = (Join-Path ${env:ProgramFiles(x86)} 'Steam\dumps'); Filter = '*.dmp' },
        @{ Name = 'NVIDIA';        Path = (Join-Path $env:ProgramData 'NVIDIA Corporation\CrashDumps'); Filter = '*.dmp' },
        @{ Name = 'Office';        Path = (Join-Path $env:LOCALAPPDATA 'Microsoft\Office\HangReports'); Filter = '*' }
    )

    foreach ($s in $specs) {
        if (-not $s.Path -or -not (Test-Path -LiteralPath $s.Path)) { continue }
        $files = @()
        try { $files = @(Get-ChildItem -LiteralPath $s.Path -File -Filter $s.Filter -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge $cutoff }) }
        catch { continue }
        if ($files.Count -eq 0) { continue }

        $newest = ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
        $found += [pscustomobject]@{
            App = $s.Name
            Count = $files.Count
            NewestAgeDays = [math]::Round(((Get-Date) - $newest).TotalDays, 1)
        }
    }

    # Java writes hs_err_pid*.log wherever the JVM was launched from, so only
    # the common locations are checked rather than scanning the whole disk.
    foreach ($jr in @($env:USERPROFILE, (Join-Path $env:USERPROFILE 'Desktop'), $env:TEMP)) {
        if (-not $jr -or -not (Test-Path -LiteralPath $jr)) { continue }
        try {
            $hs = @(Get-ChildItem -LiteralPath $jr -File -Filter 'hs_err_pid*.log' -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge $cutoff })
            if ($hs.Count -gt 0) {
                $found += [pscustomobject]@{ App = 'Java (JVM)'; Count = $hs.Count; NewestAgeDays = [math]::Round(((Get-Date) - ($hs | Sort-Object LastWriteTime -Desc | Select-Object -First 1).LastWriteTime).TotalDays, 1) }
            }
        }
        catch { }
    }

    return $found
}

# Reliability Monitor's own dataset - the tidiest chronological view Windows
# keeps of crashes, hangs and failed updates.
function Get-ReliabilitySummary {
    $out = [ordered]@{ Status = 'Read'; Total = 0; Buckets = @{} }
    try {
        $recs = @(Get-CimInstance Win32_ReliabilityRecords -ErrorAction Stop)
        $out.Total = $recs.Count
        foreach ($r in $recs) {
            $k = [string]$r.SourceName
            if (-not $out.Buckets.ContainsKey($k)) { $out.Buckets[$k] = 0 }
            $out.Buckets[$k]++
        }
    }
    catch { $out.Status = 'Unavailable' }
    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------
function Invoke-CrashModule {
    [CmdletBinding()]
    param([switch]$Apply, [hashtable]$Options = @{})

    if ($Apply) {
        Write-Log -Message 'The crashes module is read-only - there is nothing to apply. Crash artefacts are evidence; deleting them destroys the record of an intermittent fault.' -Level WARN
    }

    Write-Banner 'Crash report review'

    $result = [ordered]@{
        LookbackDays = $script:CrashLookbackDays
        Elevated = (Test-IsAdmin)
        Kernel = $null
        Wer = $null
        ThirdParty = @()
        Reliability = $null
        TopModules = @()
        TopApps = @()
    }

    $result.Kernel = Get-KernelDumps
    $result.Wer = Get-WerReports
    $result.ThirdParty = @(Get-ThirdPartyCrashes)
    $result.Reliability = Get-ReliabilitySummary

    # --- Kernel ------------------------------------------------------------
    Write-Host ''
    Write-Host ('  KERNEL CRASHES (blue screens), last {0} days' -f $script:CrashLookbackDays) -ForegroundColor White
    $dumps = @($result.Kernel.Dumps)
    if ($dumps.Count -eq 0) {
        Write-Host '    none - no kernel dump files on this machine' -ForegroundColor Green
    }
    else {
        foreach ($d in ($dumps | Sort-Object AgeDays)) {
            Write-Host ('    {0,-11} {1,5} days ago  {2} {3}' -f $d.Kind, $d.AgeDays, $d.StopCode, $d.StopName) -ForegroundColor Red
            Write-Host ('                component: {0}' -f $d.Component) -ForegroundColor Yellow
            if ($d.Note) { Write-Host ('                {0}' -f $d.Note) -ForegroundColor Gray }
        }
        Write-Host ''
        Write-Host '    Dumps stay on this machine. They are a copy of RAM and can contain' -ForegroundColor Yellow
        Write-Host '    documents, passwords and keys - do not copy them off.' -ForegroundColor Yellow
    }

    # --- WER ----------------------------------------------------------------
    Write-Host ''
    Write-Host ('  APPLICATION CRASHES AND HANGS, last {0} days' -f $script:CrashLookbackDays) -ForegroundColor White
    $reports = @($result.Wer.Reports)
    if ($reports.Count -eq 0) {
        Write-Host '    none recorded' -ForegroundColor Green
    }
    else {
        $byApp = $reports | Group-Object App | Sort-Object Count -Descending
        foreach ($g in ($byApp | Select-Object -First 12)) {
            $types = (@($g.Group | ForEach-Object { $_.EventType } | Sort-Object -Unique) -join ', ')
            $newest = ($g.Group | Sort-Object AgeDays | Select-Object -First 1).AgeDays
            Write-Host ('    {0,4} x  {1,-28} {2}  (newest {3} days ago)' -f $g.Count, $g.Name, $types, $newest) -ForegroundColor Yellow
            $result.TopApps += [ordered]@{ App = $g.Name; Count = $g.Count; Types = $types }
        }
        if ($byApp.Count -gt 12) { Write-Host ('    ... and {0} more application(s)' -f ($byApp.Count - 12)) -ForegroundColor DarkGray }

        # The faulting module is the finding. This is what turns "it crashes"
        # into a driver or a component.
        $mods = @($reports | Where-Object { $_.Module } | Group-Object Module | Sort-Object Count -Descending)
        if ($mods.Count -gt 0) {
            Write-Host ''
            Write-Host '    FAULTING MODULES - this is the part that names a culprit:' -ForegroundColor Cyan
            foreach ($m in ($mods | Select-Object -First 8)) {
                Write-Host ('      {0,4} x  {1}' -f $m.Count, $m.Name) -ForegroundColor Yellow
                $result.TopModules += [ordered]@{ Module = $m.Name; Count = $m.Count }
            }
            Write-Host '      Repeated crashes in one module point at that driver or component,' -ForegroundColor Gray
            Write-Host '      whichever application happened to be running at the time.' -ForegroundColor Gray
        }
        elseif (-not $result.Elevated) {
            Write-Host ''
            Write-Host '    Faulting module names need elevation - re-run via RUN.cmd.' -ForegroundColor Yellow
            Write-Host '    Without them you have which app died, but not what killed it.' -ForegroundColor Yellow
        }
    }

    # --- Third party ---------------------------------------------------------
    Write-Host ''
    Write-Host ('  THIRD-PARTY CRASH STORES, last {0} days' -f $script:CrashLookbackDays) -ForegroundColor White
    if ($result.ThirdParty.Count -eq 0) {
        Write-Host '    none found' -ForegroundColor Green
    }
    else {
        foreach ($t in $result.ThirdParty) {
            Write-Host ('    {0,4} x  {1,-16} newest {2} days ago' -f $t.Count, $t.App, $t.NewestAgeDays) -ForegroundColor Yellow
        }
    }

    # --- Reliability ---------------------------------------------------------
    Write-Host ''
    if ($result.Reliability.Status -eq 'Read') {
        Write-Host ('  RELIABILITY RECORD: {0} entries' -f $result.Reliability.Total) -ForegroundColor White
        $interesting = $result.Reliability.Buckets.Keys | Where-Object { $_ -match '(?i)hang|crash|error|bugcheck|fault' }
        foreach ($k in $interesting) {
            Write-Host ('    {0,4} x  {1}' -f $result.Reliability.Buckets[$k], $k) -ForegroundColor Yellow
        }
        if (-not $interesting) { Write-Host '    nothing crash-related - the rest is updates and installs' -ForegroundColor Green }
    }

    Write-Host ''
    Write-Host '  Read-only. Nothing was deleted or copied - crash artefacts are the only' -ForegroundColor DarkGray
    Write-Host '  record of an intermittent fault, and they belong to this machine.' -ForegroundColor DarkGray
    Write-Host ''

    return [pscustomobject]$result
}

