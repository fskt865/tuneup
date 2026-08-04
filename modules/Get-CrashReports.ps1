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
    0x113 = @{ Name = 'VIDEO_DXGKRNL_FATAL_ERROR';     Component = 'GPU' }
    0x116 = @{ Name = 'VIDEO_TDR_ERROR';               Component = 'GPU'; Note = 'Display driver failed to reset' }
    0x117 = @{ Name = 'VIDEO_TDR_TIMEOUT_DETECTED';    Component = 'GPU' }
    0x119 = @{ Name = 'VIDEO_SCHEDULER_INTERNAL_ERROR'; Component = 'GPU' }
    # 0x141 and 0x142 almost always arrive as LIVE kernel events rather than
    # blue screens - the machine kept running (or appeared to hang) and wrote a
    # dump to LiveKernelReports instead of bugchecking. Without them here a
    # display-engine timeout reads as 'Unrecognised stop code'.
    0x141 = @{ Name = 'VIDEO_ENGINE_TIMEOUT_DETECTED'; Component = 'GPU'; Note = 'A GPU engine stopped responding and did not recover - the classic freeze-with-looping-audio signature' }
    0x142 = @{ Name = 'VIDEO_TDR_APPLICATION_BLOCKED'; Component = 'GPU'; Note = 'Windows blocked an app after repeated display resets' }
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

# LiveKernelReports bucket folder -> subsystem. Only patterns specific enough
# to be sure are listed; an unknown bucket returns nothing rather than a guess,
# because a wrong component here sends a tech to the wrong part.
function Get-LiveKernelBucketComponent {
    param([string]$Bucket)
    if (-not $Bucket) { return $null }
    switch -Regex ($Bucket) {
        # Accept the bare and 0x-prefixed forms, but the trailing (?!\d) matters:
        # without it LiveKernelEvent_1410 would match 141 and be blamed on the GPU.
        '(?i)^LiveKernelEvent_?(0x)?0*141(?!\d)' { return 'GPU' }
        '(?i)^LiveKernelEvent_?(0x)?0*117(?!\d)' { return 'GPU' }
        '(?i)display|dxgkrnl|video'   { return 'GPU' }
        '(?i)^PoW32kWatchdog$'        { return 'Display / power transition' }
        '(?i)^WATCHDOG$'              { return 'Driver watchdog - a driver stopped responding' }
        '(?i)usbhub|^USB'             { return 'USB controller or device' }
        '(?i)^NDIS$|network'          { return 'Network adapter' }
        '(?i)storport|storage|^disk$' { return 'Storage' }
        default { return $null }
    }
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

            # LiveKernelReports files sit in a Windows-generated bucket folder
            # (WATCHDOG, PoW32kWatchdog, USBHUB3, LiveKernelEvent_141...). The
            # bucket names the failing subsystem on its own, so it is worth
            # having even when the header reads fine - and it is the ONLY
            # answer when the header does not. The names are Windows constants,
            # not customer data.
            $bucket = $null
            $component = $(if ($info) { $info.Component } else { 'Unknown' })
            if ($loc.Kind -eq 'LiveKernel') {
                $parent = Split-Path -Parent $f.FullName
                if ($parent -and $parent -ne $loc.Path) { $bucket = Split-Path -Leaf $parent }
                $guess = Get-LiveKernelBucketComponent -Bucket $bucket
                if ($guess -and $component -eq 'Unknown') { $component = $guess }
            }

            $out.Dumps += [pscustomobject]@{
                Kind = $loc.Kind
                Bucket = $bucket
                AgeDays = [math]::Round(((Get-Date) - $f.LastWriteTime).TotalDays, 1)
                SizeMB = [math]::Round($f.Length / 1MB, 1)
                StopCode = $(if ($info) { $info.Code } else { $null })
                StopName = $(if ($info) { $info.Name } else { 'unreadable header' })
                Component = $component
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
                    # WER labels its own signature fields, so read the labels
                    # rather than guessing by position or by file extension.
                    #
                    # An earlier version took any Sig value ending in .exe as
                    # the faulting module. In WER's APPCRASH schema Sig[0] is
                    # the APPLICATION, so that reported the crashing program as
                    # its own culprit - and for an AppHang there is no faulting
                    # module at all, because a hung thread never raised an
                    # exception. Inventing one there is worse than reporting
                    # none.
                    $sigNames = @{}
                    $sigValues = @{}
                    $werEventType = $null
                    foreach ($line in (Get-Content -LiteralPath $wer.FullName -ErrorAction Stop)) {
                        if ($line -match '^Sig\[(\d+)\]\.Name=(.*)$') { $sigNames[$Matches[1]] = $Matches[2].Trim(); continue }
                        if ($line -match '^Sig\[(\d+)\]\.Value=(.*)$') { $sigValues[$Matches[1]] = $Matches[2].Trim(); continue }
                        if ($line -match '^EventType=(.+)$') { $werEventType = $Matches[1].Trim(); continue }
                        if ($line -match '^ModName=(.+)$') { $modName = $Matches[1].Trim(); continue }
                        if ($line -match '^ExceptionCode=(.+)$') { $exception = $Matches[1].Trim(); continue }
                    }

                    foreach ($idx in $sigNames.Keys) {
                        switch -Regex ($sigNames[$idx]) {
                            '^Fault Module Name$' { if (-not $modName) { $modName = $sigValues[$idx] } }
                            '^Exception Code$' { if (-not $exception) { $exception = $sigValues[$idx] } }
                            # Windows servicing failures (WindowsWcp*) carry a
                            # Status rather than an exception, and their Sig[0]
                            # is an OS version - so without this they surface as
                            # a build number where an application should be.
                            '^Status$' { if (-not $exception) { $exception = $sigValues[$idx] } }
                        }
                    }

                    # The .wer states its own event type, which is more precise
                    # than the folder-name prefix: "Critical" on disk is really
                    # WindowsWcpOtherFailure3, a servicing fault and not a crash.
                    if ($werEventType) {
                        $eventType = $werEventType
                        if ($werEventType -match '^WindowsWcp' -and $app -match '^\(Windows ') {
                            $app = '(Windows servicing)'
                        }
                    }

                    # A module name that is just the application again carries
                    # no information and must not be presented as a culprit.
                    if ($modName -and $app -and $modName -eq $app) { $modName = $null }
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
# HARD HANGS - the crashes that leave no crash artefact.
#
# A machine that locks solid never bugchecks, so it writes no dump, no WER
# report and no reliability record. Every source above comes back empty and the
# module used to print "none", which reads as "no fault recorded" when the truth
# was "it hung so hard nothing could be written". Those are opposite findings.
#
# Kernel-Power 41 is the marker. It is logged on the NEXT boot whenever the
# previous shutdown was not clean, and its event data says which kind:
#
#   BugcheckCode != 0                     -> it blue-screened; the dump above
#                                            has the detail
#   BugcheckCode 0, power button pressed  -> IT HUNG and was power-cycled
#   BugcheckCode 0, no button press       -> power was lost outright: PSU,
#                                            battery, thermal cutout, or the
#                                            cable
#
# Read the event data BY NAME, never by index - same lesson as the WER Sig
# fields. The Kernel-Power 41 payload has grown across Windows versions and the
# field order is not stable, so position-based reads silently return the wrong
# number. Where a field is absent the answer is 'undetermined', not a guess.
# ---------------------------------------------------------------------------
# Get-WinEvent throws rather than returning nothing when a filter matches no
# events, and it throws for real failures too. Merging those would turn "could
# not read the log" into a clean bill of health, so they are separated here.
#
# Discriminate on FullyQualifiedErrorId, NOT on the message text: the messages
# are localized and matching them would silently misclassify every query on a
# non-English Windows. Two ids mean "nothing matched":
#   NoMatchingEventsFound      - the log has no such events
#   LogsAndProvidersDontOverlap- that provider writes nothing to that log,
#                                which is what a machine with no display reset
#                                in its history actually looks like
# Anything else is a genuine failure and must be reported as no information.
function Get-WinEventOrEmpty {
    param([Parameter(Mandatory = $true)][hashtable]$Filter, [int]$MaxEvents = 200)

    $out = [ordered]@{ Status = 'Read'; Events = @() }
    try {
        $out.Events = @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch {
        $id = [string]$_.FullyQualifiedErrorId
        if ($id -match '^(NoMatchingEventsFound|LogsAndProvidersDontOverlap)') {
            $out.Events = @()
        }
        else {
            $out.Status = 'Unavailable'
            $out.Events = @()
        }
    }
    return [pscustomobject]$out
}

function Get-EventDataByName {
    param($Event)
    $map = @{}
    try {
        $x = [xml]$Event.ToXml()
        foreach ($d in $x.Event.EventData.Data) {
            if ($d.Name) { $map[[string]$d.Name] = [string]$d.'#text' }
        }
    }
    catch { }
    return $map
}

# Classify one Kernel-Power 41 event from its named data fields. Separated from
# the log query so every branch can be tested without having to crash a machine
# to produce a sample.
#
# Returns: Bugcheck | HardHang | PowerLoss | Undetermined
function Get-UncleanShutdownKind {
    param([Parameter(Mandatory = $true)][hashtable]$Props)

    $bc = [int64]0
    $haveBc = $false
    if ($Props.ContainsKey('BugcheckCode')) {
        $haveBc = [int64]::TryParse([string]$Props['BugcheckCode'], [ref]$bc)
    }

    $btn = [int64]0
    $haveBtn = $false
    if ($Props.ContainsKey('PowerButtonTimestamp')) {
        $haveBtn = [int64]::TryParse([string]$Props['PowerButtonTimestamp'], [ref]$btn)
    }

    # Windows 10+ adds an explicit flag; when present it is the better signal
    # because a long press is unambiguous.
    $longPress = $false
    if ($Props.ContainsKey('LongPowerButtonPressDetected')) {
        $longPress = ([string]$Props['LongPowerButtonPressDetected'] -match '(?i)^\s*(true|1)\s*$')
    }

    if ($haveBc -and $bc -ne 0) { return 'Bugcheck' }
    if ($longPress) { return 'HardHang' }
    # Without the button field there is no way to tell a hang from a power cut,
    # and guessing sends a tech to the wrong part - PSU versus GPU.
    if (-not $haveBtn) { return 'Undetermined' }
    if ($btn -ne 0) { return 'HardHang' }
    return 'PowerLoss'
}

function Get-HangEvidence {
    $out = [ordered]@{
        Status        = 'Unknown'
        HardHangs     = 0
        PowerLosses   = 0
        Bugchecks     = 0
        Undetermined  = 0
        NewestHangAgeDays = $null
        DisplayResets = 0
        DisplayResetStatus = 'Unknown'
        NewestDisplayResetAgeDays = $null
        Note          = ''
    }
    $cutoff = (Get-Date).AddDays(-$script:CrashLookbackDays)

    # --- Kernel-Power 41 ---------------------------------------------------
    $q = Get-WinEventOrEmpty -Filter @{
        LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'
        Id = 41; StartTime = $cutoff
    } -MaxEvents 200
    $out.Status = $q.Status
    if ($q.Status -ne 'Read') {
        $out.Note = 'the System log could not be queried'
        return [pscustomobject]$out
    }

    foreach ($e in $q.Events) {
        $props = Get-EventDataByName -Event $e
        $kind = Get-UncleanShutdownKind -Props $props
        $age = [math]::Round(((Get-Date) - $e.TimeCreated).TotalDays, 1)

        switch ($kind) {
            'Bugcheck' { $out.Bugchecks++ }
            'PowerLoss' { $out.PowerLosses++ }
            'HardHang' {
                $out.HardHangs++
                if ($null -eq $out.NewestHangAgeDays -or $age -lt $out.NewestHangAgeDays) {
                    $out.NewestHangAgeDays = $age
                }
            }
            default { $out.Undetermined++ }
        }
    }

    # --- Display driver resets that recovered ------------------------------
    # A TDR the driver recovered from produces no dump at all, only this event.
    # It is the other half of the same story: repeated resets under load, then
    # one that does not recover, is the freeze.
    $tq = Get-WinEventOrEmpty -Filter @{
        LogName = 'System'; ProviderName = 'Microsoft-Windows-DxgKrnl'
        Id = 4101; StartTime = $cutoff
    } -MaxEvents 500
    $out.DisplayResetStatus = $tq.Status
    if ($tq.Status -eq 'Read') {
        $tdr = @($tq.Events)
        $out.DisplayResets = $tdr.Count
        if ($tdr.Count -gt 0) {
            $newest = ($tdr | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
            $out.NewestDisplayResetAgeDays = [math]::Round(((Get-Date) - $newest).TotalDays, 1)
        }
    }

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
        Hangs = $null
        Wer = $null
        ThirdParty = @()
        Reliability = $null
        TopModules = @()
        TopApps = @()
    }

    $result.Kernel = Get-KernelDumps
    $result.Hangs = Get-HangEvidence
    $result.Wer = Get-WerReports
    $result.ThirdParty = @(Get-ThirdPartyCrashes)
    $result.Reliability = Get-ReliabilitySummary

    # --- Kernel ------------------------------------------------------------
    Write-Host ''
    Write-Host ('  KERNEL CRASHES (blue screens), last {0} days' -f $script:CrashLookbackDays) -ForegroundColor White
    $dumps = @($result.Kernel.Dumps)
    $hangs = $result.Hangs
    if ($dumps.Count -eq 0) {
        # "No dumps" is only good news if nothing else says the machine died.
        # A hard hang writes no dump, so a green "none" here on a machine that
        # was power-cycled three times is the exact wrong impression.
        if ($hangs -and $hangs.Status -eq 'Read' -and ($hangs.HardHangs + $hangs.PowerLosses + $hangs.Undetermined) -gt 0) {
            Write-Host '    no kernel dump files - but see the section below, this machine went' -ForegroundColor Yellow
            Write-Host '    down without shutting down cleanly. A hang writes no dump.' -ForegroundColor Yellow
        }
        elseif ($null -eq $hangs -or $hangs.Status -ne 'Read') {
            # Green here would be a clean bill of health drawn from a check that
            # did not run. There are no dumps, but whether the machine went down
            # uncleanly is unknown - say only what was actually established.
            Write-Host '    no kernel dump files on this machine' -ForegroundColor Gray
            Write-Host '    (whether it went down uncleanly could not be established - see below)' -ForegroundColor Gray
        }
        else {
            Write-Host '    none - no kernel dump files on this machine' -ForegroundColor Green
        }
    }
    else {
        foreach ($d in ($dumps | Sort-Object AgeDays)) {
            Write-Host ('    {0,-11} {1,5} days ago  {2} {3}' -f $d.Kind, $d.AgeDays, $d.StopCode, $d.StopName) -ForegroundColor Red
            if ($d.Bucket) { Write-Host ('                bucket:    {0}' -f $d.Bucket) -ForegroundColor Gray }
            Write-Host ('                component: {0}' -f $d.Component) -ForegroundColor Yellow
            if ($d.Note) { Write-Host ('                {0}' -f $d.Note) -ForegroundColor Gray }
        }
        Write-Host ''
        Write-Host '    Dumps stay on this machine. They are a copy of RAM and can contain' -ForegroundColor Yellow
        Write-Host '    documents, passwords and keys - do not copy them off.' -ForegroundColor Yellow
    }

    # --- Hangs and unclean shutdowns ------------------------------------------
    Write-Host ''
    Write-Host ('  FREEZES AND UNEXPECTED SHUTDOWNS, last {0} days' -f $script:CrashLookbackDays) -ForegroundColor White
    if ($null -eq $hangs -or $hangs.Status -ne 'Read') {
        Write-Host '    COULD NOT ESTABLISH - the System event log could not be queried.' -ForegroundColor Magenta
        Write-Host '    This is not a clean bill of health; it is no information.' -ForegroundColor Magenta
    }
    elseif (($hangs.HardHangs + $hangs.PowerLosses + $hangs.Bugchecks + $hangs.Undetermined) -eq 0) {
        Write-Host '    none - every shutdown in this window was clean' -ForegroundColor Green
    }
    else {
        if ($hangs.HardHangs -gt 0) {
            Write-Host ('    {0,4} x  HARD HANG - locked up and was power-cycled (newest {1} days ago)' -f $hangs.HardHangs, $hangs.NewestHangAgeDays) -ForegroundColor Red
            Write-Host '            The machine stopped responding without blue-screening, so there' -ForegroundColor Gray
            Write-Host '            is no dump and no faulting module. Frozen picture with looping' -ForegroundColor Gray
            Write-Host '            or buzzing audio is this: the audio buffer repeats because' -ForegroundColor Gray
            Write-Host '            nothing is left running to refill it.' -ForegroundColor Gray
        }
        if ($hangs.PowerLosses -gt 0) {
            Write-Host ('    {0,4} x  POWER LOST - no button press recorded' -f $hangs.PowerLosses) -ForegroundColor Red
            Write-Host '            PSU, battery, thermal cutout or the cable - not a software fault.' -ForegroundColor Gray
        }
        if ($hangs.Bugchecks -gt 0) {
            Write-Host ('    {0,4} x  blue screen (already counted above - the dump has the detail)' -f $hangs.Bugchecks) -ForegroundColor Yellow
        }
        if ($hangs.Undetermined -gt 0) {
            Write-Host ('    {0,4} x  unclean shutdown, KIND UNDETERMINED' -f $hangs.Undetermined) -ForegroundColor Magenta
            Write-Host '            The event did not carry the fields that separate a hang from a' -ForegroundColor Gray
            Write-Host '            power loss. Do not assume either one.' -ForegroundColor Gray
        }
    }

    # Display resets are reported whatever the shutdown picture looks like -
    # they are the strongest single pointer to a GPU when the freeze left
    # nothing else behind.
    if ($null -ne $hangs -and $hangs.DisplayResetStatus -eq 'Read' -and $hangs.DisplayResets -gt 0) {
        Write-Host ''
        Write-Host ('    {0,4} x  DISPLAY DRIVER RESET and recovered (newest {1} days ago)' -f $hangs.DisplayResets, $hangs.NewestDisplayResetAgeDays) -ForegroundColor Red
        Write-Host '            The GPU stopped responding and Windows restarted its driver.' -ForegroundColor Gray
        Write-Host '            These leave no dump. Repeated resets under load, then one that' -ForegroundColor Gray
        Write-Host '            does not recover, is a freeze - and points at the GPU, its' -ForegroundColor Gray
        Write-Host '            driver, its power delivery or its temperature.' -ForegroundColor Gray
    }
    elseif ($null -ne $hangs -and $hangs.DisplayResetStatus -ne 'Read') {
        Write-Host '    Display reset count: COULD NOT ESTABLISH' -ForegroundColor Magenta
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
        else {
            # Elevated and still nothing: that is a real answer, not a failure.
            $hangs = @($reports | Where-Object { $_.EventType -match '(?i)hang' }).Count
            Write-Host ''
            Write-Host '    No faulting module recorded in any of these reports.' -ForegroundColor Gray
            if ($hangs -gt 0) {
                Write-Host ('    {0} of them are hangs, which never have one - a hung thread raised' -f $hangs) -ForegroundColor Gray
                Write-Host '    no exception, so there is no module to blame.' -ForegroundColor Gray
            }
            Write-Host '    The rest are non-critical reports (failed updates and installs), not' -ForegroundColor Gray
            Write-Host '    crashes. Nothing here points at a driver or a component.' -ForegroundColor Gray
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

