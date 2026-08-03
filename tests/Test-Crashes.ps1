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
    @{ Code = 0xD1;  Component = 'Driver' }
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
