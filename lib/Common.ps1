# Common.ps1 - shared helpers for the tune-up toolkit.
# Dot-sourced by Invoke-TuneUp.ps1. ASCII only, PowerShell 5.1 compatible.

# Verbose logs and resume state live on the LOCAL machine, never on the stick.
# The stick only ever receives the sanitized report. See README.md.
$script:LocalRoot  = Join-Path $env:ProgramData 'GSTuneUp'
$script:LogPath    = $null
$script:StatePath  = Join-Path $script:LocalRoot 'state.json'

function Initialize-LocalRoot {
    if (-not (Test-Path -LiteralPath $script:LocalRoot)) {
        New-Item -ItemType Directory -Path $script:LocalRoot -Force | Out-Null
    }
    if (-not $script:LogPath) {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $script:LogPath = Join-Path $script:LocalRoot ("run-$stamp.log")
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'FAIL', 'OK', 'STEP')][string]$Level = 'INFO',
        [switch]$Quiet
    )
    Initialize-LocalRoot
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('HH:mm:ss'), $Level, $Message
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
        Write-Host $line -ForegroundColor $color
    }
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
