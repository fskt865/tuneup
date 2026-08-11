# Common.ps1 - shared helpers for the tune-up toolkit.
# Dot-sourced by Invoke-TuneUp.ps1. ASCII only, PowerShell 5.1 compatible.

# Verbose logs and resume state live on the LOCAL machine by default, never on
# the stick. The stick only ever receives the sanitized report. See README.md.
#
# -LogToStick moves THE LOG AND ONLY THE LOG onto the stick, redacted line by
# line and verified before the stick leaves. It exists for jobs where writing
# to the machine is itself undesirable - a suspect drive you may end up
# imaging, or a unit that must be left byte-identical.
#
# Resume state and the undo backups modules write (hw-baseline.json,
# startup-backup.json, browser-backup, the ipconfig capture) stay local no
# matter what. They exist to put a machine back the way it was found, and a
# backup that leaves in someone's pocket cannot do that. Splitting the two is
# the whole point: the log is the part that is unsanitized and disposable, the
# backups are the part that is sanitized-irrelevant and load-bearing.
$script:LocalRoot   = Join-Path $env:ProgramData 'GSTuneUp'
$script:LogRoot     = $null      # falls back to LocalRoot
$script:LogPath     = $null
$script:LogSanitize = $false
$script:StatePath   = Join-Path $script:LocalRoot 'state.json'

# Call once, early, before anything logs. Re-pointing the root clears LogPath
# so the stamped filename is recreated under the new root rather than the old
# name being reused in a new place.
function Set-LogDestination {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Sanitize
    )
    $script:LogRoot     = $Path
    $script:LogPath     = $null
    $script:LogSanitize = [bool]$Sanitize
}

function Get-LogDestination {
    if (-not $script:LogRoot) { return $script:LocalRoot }
    return $script:LogRoot
}

function Test-LogIsSanitized { return $script:LogSanitize }

function Initialize-LogRoot {
    if (-not $script:LogRoot) { $script:LogRoot = $script:LocalRoot }
    if (-not (Test-Path -LiteralPath $script:LogRoot)) {
        # -WhatIf:$false to match the Add-Content below. Without it a dry run
        # skips the mkdir and then every log line fails against a directory
        # that was never created.
        New-Item -ItemType Directory -Path $script:LogRoot -Force -WhatIf:$false | Out-Null
    }
    if (-not $script:LogPath) {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $script:LogPath = Join-Path $script:LogRoot ("run-$stamp.log")
    }
}

# The local state/backup directory, created ON DEMAND by the things that
# genuinely need it. Deliberately no longer called at startup: with the log on
# the stick, a read-only run must be able to finish without creating anything
# on the machine at all.
function Initialize-LocalRoot {
    if (-not (Test-Path -LiteralPath $script:LocalRoot)) {
        New-Item -ItemType Directory -Path $script:LocalRoot -Force -WhatIf:$false | Out-Null
    }
    if (-not $script:LogPath) { Initialize-LogRoot }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'FAIL', 'OK', 'STEP')][string]$Level = 'INFO',
        [switch]$Quiet
    )
    Initialize-LogRoot

    # One timestamp for both renderings. Formatting twice can straddle a second
    # boundary and print a console line that does not match its own log entry.
    $stamp = (Get-Date).ToString('HH:mm:ss')

    # The console belongs to the tech standing at the machine and always shows
    # the real text - account names and paths are exactly what they need to
    # read. The FILE is the thing that can leave, so only the file is redacted.
    # Same split the elevation module already makes for group member names.
    $forFile = $Message
    if ($script:LogSanitize) {
        if (Get-Command -Name Protect-String -CommandType Function -ErrorAction SilentlyContinue) {
            $forFile = Protect-String -Text $Message
        }
        else {
            # Refuse rather than leak. If the sanitizer is not loaded we cannot
            # redact, and an unredacted line does not go onto removable media.
            $forFile = '[line suppressed - sanitizer not loaded]'
        }
    }

    $line = '{0} [{1}] {2}' -f $stamp, $Level, $forFile
    # -WhatIf:$false deliberately. Logging is bookkeeping, not an effect the
    # user is deciding about - and a dry run that produces no log is useless
    # for working out what the real run would have done.
    Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 -WhatIf:$false

    if (-not $Quiet) {
        $color = 'Gray'
        if ($Level -eq 'WARN') { $color = 'Yellow' }
        if ($Level -eq 'FAIL') { $color = 'Red' }
        if ($Level -eq 'OK')   { $color = 'Green' }
        if ($Level -eq 'STEP') { $color = 'Cyan' }
        Write-Host ('{0} [{1}] {2}' -f $stamp, $Level, $Message) -ForegroundColor $color
    }
}

# End-of-run check on a log that is about to leave on the stick.
#
# Per-line redaction has no equivalent of the report writer's "verify, then
# refuse to write" moment - by the time a bad line is written it is already on
# disk. So the equivalent happens here: scan the finished file and delete it if
# anything identifying survived. A log that cannot be PROVEN clean does not
# travel. Returns three states, never two: not checked / clean / dirty.
function Test-LogFileClean {
    param([switch]$RemoveIfDirty)

    $result = [pscustomobject]@{
        Checked = $false
        Clean   = $false
        Hits    = @()
        Path    = $script:LogPath
        Removed = $false
        Reason  = ''
    }

    if (-not $script:LogSanitize) { $result.Reason = 'log is local and unsanitized by design'; return $result }
    if (-not $script:LogPath -or -not (Test-Path -LiteralPath $script:LogPath)) {
        $result.Reason = 'no log file'
        return $result
    }
    if (-not (Get-Command -Name Test-SanitizedText -CommandType Function -ErrorAction SilentlyContinue)) {
        $result.Reason = 'verifier not loaded - CANNOT confirm this log is clean'
        return $result
    }

    $text = Get-Content -LiteralPath $script:LogPath -Raw -ErrorAction SilentlyContinue
    if ($null -eq $text) { $result.Reason = 'log unreadable'; return $result }

    $v = Test-SanitizedText -Text $text
    $result.Checked = $true
    $result.Clean   = $v.Clean
    $result.Hits    = @($v.Hits)

    if (-not $v.Clean -and $RemoveIfDirty) {
        Remove-Item -LiteralPath $script:LogPath -Force -ErrorAction SilentlyContinue -WhatIf:$false
        $result.Removed = -not (Test-Path -LiteralPath $script:LogPath)
    }
    return $result
}

function Write-Banner {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host ''
    Write-Host ('=' * 68) -ForegroundColor DarkCyan
    Write-Host ("  $Text") -ForegroundColor Cyan
    Write-Host ('=' * 68) -ForegroundColor DarkCyan
    Write-Log -Message "=== $Text ===" -Level STEP -Quiet
}

# Whether a report gets written. Pure, and it lives here rather than in
# Invoke-TuneUp.ps1 so the test suite can reach it - that file executes on
# dot-source and cannot be loaded for testing.
#
#   -NoReport always wins.
#   A scripted run keeps the old behaviour and writes one, so nothing that
#   already depends on a report appearing changes.
#   The menu ASKS, and defaults to NO. Every action used to write a report
#   whether or not anyone wanted it, which piled files onto the stick for
#   read-only runs that existed only to be read off the screen.
function Test-ShouldWriteReport {
    param(
        [bool]$NoReport,
        [bool]$Interactive,
        [string]$Answer = ''
    )
    if ($NoReport) { return $false }
    if (-not $Interactive) { return $true }
    return ($Answer -match '^\s*(y|yes)\s*$')
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (Test-IsAdmin) { return }

    # A dry run writes nothing, so it is allowed to print its plan from an
    # unelevated session. Refusing here would make -WhatIf useless for the
    # exact case it is for: deciding whether to run this at all.
    if ($WhatIfPreference) {
        Write-Log -Message 'Not elevated - printing plan only. The real run will need RUN.cmd.' -Level WARN
        return
    }

    throw 'This action needs an elevated session. Re-launch with RUN.cmd.'
}

# ---------------------------------------------------------------------------
# Native process invocation.
#
# sfc.exe writes UTF-16LE to stdout, which arrives full of NUL bytes when
# redirected in PowerShell 5.1. Strip them here so callers can pattern-match
# the text. Do not "simplify" this away.
# ---------------------------------------------------------------------------
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutMinutes = 90
    )

    $outFile = [IO.Path]::GetTempFileName()
    $errFile = [IO.Path]::GetTempFileName()

    try {
        $p = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile

        # Touching .Handle caches the process handle. Without this,
        # Start-Process -PassThru hands back an object whose ExitCode reads
        # back empty once the process is gone. Long-standing PowerShell quirk;
        # do not remove this line.
        $null = $p.Handle

        $timedOut = $false
        if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) {
            $timedOut = $true
            try { $p.Kill() } catch { }
        }

        $stdout = ''
        $stderr = ''
        if (Test-Path -LiteralPath $outFile) { $stdout = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $errFile) { $stderr = Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue }
        if ($null -eq $stdout) { $stdout = '' }
        if ($null -eq $stderr) { $stderr = '' }

        $nul = [string][char]0
        $stdout = $stdout.Replace($nul, '')
        $stderr = $stderr.Replace($nul, '')

        return [pscustomobject]@{
            ExitCode = $p.ExitCode
            StdOut   = $stdout
            StdErr   = $stderr
            TimedOut = $timedOut
            Command  = ('{0} {1}' -f $FilePath, ($ArgumentList -join ' '))
        }
    }
    finally {
        Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue -WhatIf:$false
    }
}

# ---------------------------------------------------------------------------
# Resume state. Kept local because a tune-up spans reboots and the stick may
# come back on a different letter, or not at all.
# ---------------------------------------------------------------------------
function Get-RunState {
    Initialize-LocalRoot
    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        return [pscustomobject]@{ Completed = @(); Started = (Get-Date).ToString('o') }
    }
    try {
        return Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json
    }
    catch {
        Write-Log -Message "State file unreadable, starting fresh: $($_.Exception.Message)" -Level WARN
        return [pscustomobject]@{ Completed = @(); Started = (Get-Date).ToString('o') }
    }
}

function Set-RunStateCompleted {
    param([Parameter(Mandatory = $true)][string]$TaskName)
    $state = Get-RunState
    $done = @($state.Completed)
    if ($done -notcontains $TaskName) { $done += $TaskName }
    $state.Completed = $done
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:StatePath -Encoding UTF8
}

function Clear-RunState {
    if (Test-Path -LiteralPath $script:StatePath) {
        Remove-Item -LiteralPath $script:StatePath -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
function Get-PendingReboot {
    $reasons = @()
    $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    if (Test-Path -LiteralPath $cbs) { $reasons += 'ComponentBasedServicing' }

    $wu = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    if (Test-Path -LiteralPath $wu) { $reasons += 'WindowsUpdate' }

    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    try {
        $pfro = Get-ItemProperty -LiteralPath $sm -Name PendingFileRenameOperations -ErrorAction Stop
        if ($pfro.PendingFileRenameOperations) { $reasons += 'PendingFileRename' }
    }
    catch { }

    return [pscustomobject]@{
        Pending = ($reasons.Count -gt 0)
        Reasons = $reasons
    }
}

# The Windows Update agent reports MaxDownloadSize for a bundle as a rolled-up
# worst case, which for some cumulative packages comes back as tens of GB and
# is plainly not the download size. Report an implausible figure as unknown
# rather than printing a number that will make a tech think the link is dead.
function Get-PlausibleSizeMB {
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    $mb = [math]::Round($Bytes / 1MB, 1)
    if ($mb -le 0 -or $mb -gt 32768) { return $null }
    return $mb
}

function Format-SizeMB {
    param($SizeMB)
    if ($null -eq $SizeMB) { return 'size n/a' }
    return ('{0} MB' -f $SizeMB)
}

function Get-FreeSpacePercent {
    param([string]$DriveLetter = $env:SystemDrive.TrimEnd(':'))
    try {
        $v = Get-Volume -DriveLetter $DriveLetter -ErrorAction Stop
        if ($v.Size -gt 0) { return [math]::Round(($v.SizeRemaining / $v.Size) * 100, 1) }
    }
    catch { }
    return $null
}
