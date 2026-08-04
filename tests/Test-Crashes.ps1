# Test-Crashes.ps1 - crash report parsing and clock status.
# ASCII only, PowerShell 5.1 compatible. Both modules are read-only, so this
# suite changes nothing outside its own temp files.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'modules\Get-CrashReports.ps1')
. (Join-Path $Root 'modules\Get-ClockStatus.ps1')

$pass = 0
$fail = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  PASS  " + $Name) -ForegroundColor Green; $script:pass++ }
    else { Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red; $script:fail++ }
}

Write-Host ''
Write-Host '  Bugcheck decoding' -ForegroundColor Cyan
Write-Host '  -----------------' -ForegroundColor DarkGray

# The number is not the finding - the component is.
$cases = @(
    @{ Code = 0x7A;  Component = 'Storage' },
    @{ Code = 0x7B;  Component = 'Storage' },
    @{ Code = 0x116; Component = 'GPU' },
    @{ Code = 0x117; Component = 'GPU' },
    @{ Code = 0x124; Component = 'Hardware' },
    @{ Code = 0x101; Component = 'CPU' },
    @{ Code = 0x9C;  Component = 'CPU' },
    @{ Code = 0x1A;  Component = 'RAM' },
    @{ Code = 0x50;  Component = 'RAM' },
    @{ Code = 0xD1;  Component = 'Driver' },
    @{ Code = 0x141; Component = 'GPU' },
    @{ Code = 0x142; Component = 'GPU' },
    @{ Code = 0x113; Component = 'GPU' },
    @{ Code = 0x119; Component = 'GPU' }
)
foreach ($c in $cases) {
    $i = Get-BugcheckInfo -Code $c.Code
    Assert-True ("0x{0:X} attributes to {1}" -f $c.Code, $c.Component) ($i.Component -match $c.Component) ("got=" + $i.Component)
    Assert-True ("0x{0:X} has a name" -f $c.Code) ($i.Name -notmatch 'Unrecognised')
}

$unknown = Get-BugcheckInfo -Code 0xABCDEF
Assert-True 'Unknown stop code is flagged, not invented' ($unknown.Name -match 'Unrecognised')
Assert-True 'Unknown stop code says to look it up'       ($unknown.Note -match 'Look it up')

Write-Host ''
Write-Host '  Unclean shutdown classification' -ForegroundColor Cyan
Write-Host '  -------------------------------' -ForegroundColor DarkGray

# A hang leaves no dump, so this classification IS the finding. Every branch is
# exercised from synthetic field sets - waiting for a real machine to hang is
# not a test strategy, and the branches that matter most are the rare ones.
$shutdownCases = @(
    @{ Name = 'Bugcheck code set -> blue screen';
        Props = @{ BugcheckCode = '26'; PowerButtonTimestamp = '0' }; Expect = 'Bugcheck' },
    @{ Name = 'Button timestamp set -> hard hang';
        Props = @{ BugcheckCode = '0'; PowerButtonTimestamp = '132534000000000000' }; Expect = 'HardHang' },
    @{ Name = 'Long-press flag true -> hard hang';
        Props = @{ BugcheckCode = '0'; PowerButtonTimestamp = '0'; LongPowerButtonPressDetected = 'true' }; Expect = 'HardHang' },
    @{ Name = 'Long-press flag as 1 -> hard hang';
        Props = @{ BugcheckCode = '0'; PowerButtonTimestamp = '0'; LongPowerButtonPressDetected = '1' }; Expect = 'HardHang' },
    @{ Name = 'No bugcheck and no button -> power loss';
        Props = @{ BugcheckCode = '0'; PowerButtonTimestamp = '0'; LongPowerButtonPressDetected = 'false' }; Expect = 'PowerLoss' },
    # The honest third state. An older schema omits the button field entirely,
    # and PSU versus GPU is not a guess worth making.
    @{ Name = 'Button field absent -> undetermined, not a guess';
        Props = @{ BugcheckCode = '0' }; Expect = 'Undetermined' },
    @{ Name = 'Empty field set -> undetermined';
        Props = @{}; Expect = 'Undetermined' },
    @{ Name = 'Unparsable button value -> undetermined';
        Props = @{ BugcheckCode = '0'; PowerButtonTimestamp = 'not-a-number' }; Expect = 'Undetermined' },
    # Bugcheck wins over a button press: the machine blue-screened and someone
    # then held the button. The dump is the better evidence.
    @{ Name = 'Bugcheck outranks a button press';
        Props = @{ BugcheckCode = '154'; PowerButtonTimestamp = '132534000000000000' }; Expect = 'Bugcheck' }
)
foreach ($c in $shutdownCases) {
    $got = Get-UncleanShutdownKind -Props $c.Props
    Assert-True $c.Name ($got -eq $c.Expect) ("got=" + $got)
}

Write-Host ''
Write-Host '  Event query: empty vs unreadable' -ForegroundColor Cyan
Write-Host '  --------------------------------' -ForegroundColor DarkGray

# These must never be merged. "Nothing matched" is a clean bill of health;
# "could not read" is no information, and reporting the second as the first
# tells a tech the GPU is fine when nothing was actually checked.
$empty = Get-WinEventOrEmpty -Filter @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = (Get-Date).AddSeconds(-5) }
Assert-True 'No matching events still reports Read' ($empty.Status -eq 'Read') ("got=" + $empty.Status)
Assert-True 'No matching events returns no events'  (@($empty.Events).Count -eq 0)

# A provider that writes nothing to the named log throws a DIFFERENT error id
# than "no events found" - on a machine that has never had a display reset that
# is the normal case, and treating it as a failure would bury the real answer.
$noOverlap = Get-WinEventOrEmpty -Filter @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-DxgKrnl'; Id = 4101; StartTime = (Get-Date).AddDays(-3650) }
Assert-True 'Provider-with-no-events-in-log reports Read' ($noOverlap.Status -eq 'Read') ("got=" + $noOverlap.Status)

# A log that does not exist is a genuine failure and must say so.
$bogus = Get-WinEventOrEmpty -Filter @{ LogName = 'NoSuchLog-TuneUpTest'; Id = 1 }
Assert-True 'Unreadable log reports Unavailable, not Read' ($bogus.Status -eq 'Unavailable') ("got=" + $bogus.Status)

Write-Host ''
Write-Host '  LiveKernelReports bucket attribution' -ForegroundColor Cyan
Write-Host '  ------------------------------------' -ForegroundColor DarkGray

$bucketCases = @(
    @{ Bucket = 'LiveKernelEvent_141';  Expect = 'GPU' },
    @{ Bucket = 'LiveKernelEvent_0x141'; Expect = 'GPU' },
    @{ Bucket = 'PoW32kWatchdog';       Expect = 'Display' },
    @{ Bucket = 'WATCHDOG';             Expect = 'watchdog' },
    @{ Bucket = 'USBHUB3';              Expect = 'USB' },
    @{ Bucket = 'NDIS';                 Expect = 'Network' }
)
foreach ($b in $bucketCases) {
    $got = Get-LiveKernelBucketComponent -Bucket $b.Bucket
    Assert-True ("Bucket {0} -> {1}" -f $b.Bucket, $b.Expect) ($got -match $b.Expect) ("got=" + $got)
}
# An unrecognised bucket returns nothing rather than a wrong component.
Assert-True 'Unknown bucket returns null, not a guess' ($null -eq (Get-LiveKernelBucketComponent -Bucket 'SomeBucketNobodyMapped'))
Assert-True 'Empty bucket returns null'                ($null -eq (Get-LiveKernelBucketComponent -Bucket ''))
# A prefix match would blame the GPU for an unrelated event number.
Assert-True 'Event 1410 does not match event 141' ($null -eq (Get-LiveKernelBucketComponent -Bucket 'LiveKernelEvent_1410'))

Write-Host ''
Write-Host '  Hang evidence collection' -ForegroundColor Cyan
Write-Host '  ------------------------' -ForegroundColor DarkGray

$he = Get-HangEvidence
Assert-True 'Hang evidence returns a result' ($null -ne $he)
Assert-True 'Status is one of the three states' (@('Read', 'Unavailable', 'Unknown') -contains $he.Status) ("got=" + $he.Status)
Assert-True 'Display reset status is a known state' (@('Read', 'Unavailable', 'Unknown') -contains $he.DisplayResetStatus) ("got=" + $he.DisplayResetStatus)
# Counts must never be negative or null - a blank reads as zero and hides a fault.
foreach ($f in @('HardHangs', 'PowerLosses', 'Bugchecks', 'Undetermined', 'DisplayResets')) {
    Assert-True ("{0} is a real count" -f $f) ($null -ne $he.$f -and $he.$f -ge 0) ("got=" + $he.$f)
}
# An unreadable log must not report zero hangs - that is the false-clean-bill bug.
if ($he.Status -ne 'Read') {
    Assert-True 'Unavailable status carries a note' (-not [string]::IsNullOrWhiteSpace($he.Note))
}

Write-Host ''
Write-Host '  Minidump header parsing' -ForegroundColor Cyan
Write-Host '  -----------------------' -ForegroundColor DarkGray

# Synthesise a dump header rather than needing a real crash. DUMP_HEADER64:
# 'PAGE' at 0, BugCheckCode at 0x38.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('tuneup-dump-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.dmp')
try {
    $buf = New-Object byte[] 0x100
    [Text.Encoding]::ASCII.GetBytes('PAGE') | ForEach-Object -Begin { $i = 0 } -Process { $buf[$i] = $_; $i++ }
    [Text.Encoding]::ASCII.GetBytes('DU64') | ForEach-Object -Begin { $i = 4 } -Process { $buf[$i] = $_; $i++ }
    [BitConverter]::GetBytes([uint32]0x7A) | ForEach-Object -Begin { $i = 0x38 } -Process { $buf[$i] = $_; $i++ }
    [IO.File]::WriteAllBytes($tmp, $buf)

    $code = Read-MinidumpBugcheck -Path $tmp
    Assert-True 'Reads the bugcheck code from a dump header' ($code -eq 0x7A) ("got=" + $code)
    if ($code) {
        Assert-True 'Decoded dump attributes to storage' ((Get-BugcheckInfo -Code ([int]$code)).Component -match 'Storage')
    }

    # A file that is not a dump must return nothing rather than a wrong answer.
    $notDump = Join-Path ([IO.Path]::GetTempPath()) ('tuneup-notdump-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.dmp')
    [IO.File]::WriteAllBytes($notDump, (New-Object byte[] 0x100))
    Assert-True 'Non-dump file returns null, not a bogus code' ($null -eq (Read-MinidumpBugcheck -Path $notDump))
    Remove-Item -LiteralPath $notDump -Force -ErrorAction SilentlyContinue

    $tiny = Join-Path ([IO.Path]::GetTempPath()) ('tuneup-tiny-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.dmp')
    [IO.File]::WriteAllBytes($tiny, (New-Object byte[] 8))
    Assert-True 'Truncated file is handled safely' ($null -eq (Read-MinidumpBugcheck -Path $tiny))
    Remove-Item -LiteralPath $tiny -Force -ErrorAction SilentlyContinue
}
finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

Write-Host ''
Write-Host '  WER folder name parsing' -ForegroundColor Cyan
Write-Host '  -----------------------' -ForegroundColor DarkGray

# All four shapes are real, taken from a live machine. Assuming token 1 was
# always the application collapsed every report into one nameless group.
$werCases = @(
    @{ Folder = 'AppHang_explorer.exe_2f4a8e1ff8467f759bd_7808a6e2_0bc4e620-974e'; Type = 'AppHang'; App = 'explorer.exe' },
    @{ Folder = 'NonCritical_setup.exe_394af94a6aa793d85eb_00000000_3813edf8-5b02'; Type = 'NonCritical'; App = 'setup.exe' },
    @{ Folder = 'Critical_10.0.26100.2032__55e1694dee6c4b09f_00000000_4e25fd93-b67f'; Type = 'Critical'; App = '(Windows 10.0.26100.2032)' },
    @{ Folder = 'NonCritical_80004004_367f5c4b6f21b018f2c_00000000_0d81aabf-836d'; Type = 'NonCritical'; App = '(error 80004004)' }
)
foreach ($w in $werCases) {
    $r = Split-WerFolderName -FolderName $w.Folder
    Assert-True ("Event type: " + $w.Type) ($r.EventType -eq $w.Type) ("got=" + $r.EventType)
    Assert-True ("App: " + $w.App)        ($r.App -eq $w.App)        ("got=" + $r.App)
}

# A version or an error code must never be presented as an application name.
$v = Split-WerFolderName -FolderName 'Critical_10.0.99999.1__abc_0_def'
Assert-True 'A build number is labelled, not passed off as an app' ($v.App -match '^\(Windows ')

Write-Host ''
Write-Host '  Crash module is read-only' -ForegroundColor Cyan
Write-Host '  -------------------------' -ForegroundColor DarkGray

$before = @(Get-ChildItem "$env:ProgramData\Microsoft\Windows\WER\ReportArchive" -Directory -ErrorAction SilentlyContinue).Count
$cr = Invoke-CrashModule
$after = @(Get-ChildItem "$env:ProgramData\Microsoft\Windows\WER\ReportArchive" -Directory -ErrorAction SilentlyContinue).Count

Assert-True 'Crash module returns a result'        ($null -ne $cr)
Assert-True 'Crash module deletes nothing'         ($before -eq $after) ("before=$before after=$after")
Assert-True 'Crash module reports its lookback'    ($cr.LookbackDays -gt 0)
Assert-True 'Crash module has no Apply behaviour'  ($null -eq (Get-Member -InputObject $cr -Name 'Removed' -ErrorAction SilentlyContinue))

Write-Host ''
Write-Host '  Clock status' -ForegroundColor Cyan
Write-Host '  ------------' -ForegroundColor DarkGray

$ck = Invoke-ClockModule
Assert-True 'Clock module returns a result'   ($null -ne $ck)
Assert-True 'Reports the active power scheme' (-not [string]::IsNullOrWhiteSpace($ck.PowerScheme))
Assert-True 'Reads a rated CPU clock'         ($ck.Cpu.RatedMHz -gt 0) ("got=" + $ck.Cpu.RatedMHz)

if (@($ck.Memory).Count -gt 0) {
    $badVerdict = @($ck.Memory | Where-Object { @('AT SPEC', 'BELOW RATING', 'ABOVE RATING', 'UNKNOWN') -notcontains $_.Verdict })
    Assert-True 'Every memory module gets a valid verdict' ($badVerdict.Count -eq 0)
    $mismatch = @($ck.Memory | Where-Object { $_.RatedMHz -gt 0 -and $_.RunningMHz -gt 0 -and $_.RunningMHz -lt $_.RatedMHz -and $_.Verdict -ne 'BELOW RATING' })
    Assert-True 'Running below rated is reported as BELOW RATING' ($mismatch.Count -eq 0)
}

# Throttle values are percentages; anything outside 0-100 means the hex parse
# went wrong and the cap warning would fire on nonsense.
if ($null -ne $ck.ThrottleMax.Ac) {
    Assert-True 'Max processor state parses to a percentage' ($ck.ThrottleMax.Ac -ge 0 -and $ck.ThrottleMax.Ac -le 100) ("got=" + $ck.ThrottleMax.Ac)
}
if ($null -ne $ck.ThrottleMin.Ac) {
    Assert-True 'Min processor state parses to a percentage' ($ck.ThrottleMin.Ac -ge 0 -and $ck.ThrottleMin.Ac -le 100) ("got=" + $ck.ThrottleMin.Ac)
}

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
