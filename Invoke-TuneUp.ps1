# Invoke-TuneUp.ps1 - entry point for the tune-up stick.
# ASCII only, PowerShell 5.1 compatible. Launch via RUN.cmd.
#
# Default action is Report: read-only, changes nothing. That is what you get
# when you forget an argument, on purpose.
#
# Verbose logs and resume state stay in C:\ProgramData\GSTuneUp on the machine
# being worked on. The ONLY thing written to this stick is a sanitized report.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Report', 'Repair', 'Update', 'Clean', 'Full', 'Purge', 'Triage')]
    [string]$Action,

    # Run a drop-in capability module from modules\ by its key.
    [string]$Module,

    # Modules are read-only without this. Nothing in modules\ changes the
    # machine unless -Apply is passed explicitly.
    [switch]$Apply,
    [switch]$IncludeOptional,
    [switch]$Provisioned,

    # Undo: re-enable everything the startup module disabled on this machine.
    [switch]$Restore,

    # Hardware evidence module. It applies no load itself - Phase selects which
    # side of an external stress test to record. NOT called Action: that name
    # is already the top-level Report/Repair/Clean selector above.
    [ValidateSet('Baseline', 'Watch', 'Compare')]
    [string]$Phase,
    [int]$Minutes,
    [switch]$NoLaunchSensors,
    [switch]$Force,

    # Network: opt in to winsock / TCP-IP stack resets. Both need a reboot,
    # and the stack reset wipes static IP configuration.
    [switch]$Disruptive,

    [switch]$IncludeDrivers,
    [switch]$IncludeComponentCleanup,
    [string]$SourcePath,
    [switch]$SkipEventLogs,

    # Suppress the sanitized report entirely. Every action used to write one
    # whether or not anyone wanted it, which piles reports onto the stick for
    # read-only runs that were never going to be read.
    [switch]$NoReport,

    # Triage only: walk the fix prompts after the scan. TRIAGE.cmd passes
    # this so a double-click gets the ask-before-every-fix flow without the
    # menu. Without it a scripted -Action Triage stays scan-and-plan only,
    # because a run with no console must never be asked a question.
    [switch]$Walk,

    # Write the run log to the toolkit's own logs\ directory instead of to
    # ProgramData on the machine being worked on. The log is redacted line by
    # line and the finished file is verified before the stick leaves.
    #
    # For jobs where writing to the unit is itself the problem: a suspect drive
    # you may end up imaging, or a machine that has to be left untouched.
    #
    # It does NOT relocate resume state or the modules' undo backups - those
    # stay local on purpose. See lib\Common.ps1.
    [switch]$LogToStick
)

# Deliberately NOT 'Stop'. This tool runs on machines where WMI classes are
# missing, services are dead and providers throw. Every call that must succeed
# is wrapped in try/catch with -ErrorAction Stop locally; a global Stop just
# means the tool dies on the machines it exists to diagnose.
$ErrorActionPreference = 'Continue'

# Resolve everything off $PSScriptRoot. The stick will not be the same drive
# letter twice and hardcoding one will burn you inside a week.
$Root = $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.Path }

# $PSBoundParameters is scoped to the function that reads it. Invoke-Action is
# a function, so asking it there returns ITS parameters (just -Name) and every
# "was this switch actually supplied?" test came back false - which silently
# dropped -Minutes and friends on the floor and left modules on their defaults
# no matter what was typed. Capture the SCRIPT's bound parameters here, at
# script scope, and test against this instead.
$script:ScriptBound = $PSBoundParameters

. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'lib\Modules.ps1')
. (Join-Path $Root 'lib\Triage.ps1')
. (Join-Path $Root 'tasks\Collect-Report.ps1')
. (Join-Path $Root 'tasks\Repair-ComponentStore.ps1')
. (Join-Path $Root 'tasks\Invoke-WindowsUpdate.ps1')
. (Join-Path $Root 'tasks\Clear-TempFiles.ps1')
. (Join-Path $Root 'tasks\Invoke-Triage.ps1')

$ReportDir = Join-Path $Root 'reports'
$ModuleRoot = Join-Path $Root 'modules'

# -LogToStick has to be wired before ANYTHING logs, or the first few lines land
# in ProgramData and the whole point is lost.
#
# Refusing when the toolkit is running from the system drive is not pedantry:
# "log to the stick" while running from C:\Users\...\Desktop\tuneup would write
# the log to the very machine it was meant to keep clean, and the switch would
# read as satisfied. Better to fail loudly than to quietly do the opposite.
$LogDir = $null
if ($LogToStick) {
    $rootQualifier = ''
    if ($Root -match '^([A-Za-z]:)') { $rootQualifier = $Matches[1] }

    if ($rootQualifier -and $rootQualifier -ieq $env:SystemDrive) {
        # Built as a variable first: 'throw (expr) -f args' is ambiguous enough
        # that it is not worth relying on how it binds.
        $msg = "-LogToStick was passed but the toolkit is running from '{0}', which is on the system drive ({1}). " +
               "The log would land on the machine you are trying to keep clean. Run the toolkit from the stick instead."
        throw ($msg -f $Root, $env:SystemDrive)
    }

    $LogDir = Join-Path $Root 'logs'
    Set-LogDestination -Path $LogDir -Sanitize
}

$ToolkitVersion = 'unknown'
$versionFile = Join-Path $Root 'VERSION'
if (Test-Path -LiteralPath $versionFile) {
    $ToolkitVersion = (Get-Content -LiteralPath $versionFile -Raw).Trim()
}

# Set only on the menu path. A run driven by -Action or -Module has no stdin
# and must never be asked a question - see the Read-Host note at the bottom.
$script:Interactive = $false

function Show-LogFooter {
    Write-Host ''
    Write-Host ('  Verbose log: ' + $script:LogPath) -ForegroundColor DarkGray
    if ($LogToStick) {
        Write-Host '  That log is on the STICK, redacted line by line. Baselines and' -ForegroundColor DarkGray
        Write-Host '  undo backups still stay on this machine - option 7 removes those.' -ForegroundColor DarkGray
    }
    else {
        Write-Host '  Logs and baselines stay on THIS machine, never on the stick -' -ForegroundColor DarkGray
        Write-Host '  they are unsanitized. Option 7 removes them when the job is done.' -ForegroundColor DarkGray
    }
    Write-Host ''
}

# Verify a log that is about to leave on the stick, and destroy it if it cannot
# be proven clean.
#
# A function rather than inline code because there are TWO exit paths - the
# interactive menu and a scripted -Module/-Action run - and the scripted one is
# exactly how this gets used for a quick read-only collection. Verifying on
# only one path would leave unverified logs on the stick in the common case.
function Invoke-StickLogVerification {
    if (-not $LogToStick) { return }

    $logCheck = Test-LogFileClean -RemoveIfDirty
    Write-Host ''
    if ($logCheck.Checked -and $logCheck.Clean) {
        Write-Host '  Stick log verified clean:' -ForegroundColor Green
        Write-Host ('    ' + $logCheck.Path) -ForegroundColor Green
    }
    elseif ($logCheck.Checked) {
        Write-Host '  STICK LOG FAILED VERIFICATION - identifiers survived redaction:' -ForegroundColor Red
        Write-Host ('    ' + ($logCheck.Hits -join ', ')) -ForegroundColor Red
        if ($logCheck.Removed) {
            Write-Host '  It has been DELETED from the stick. Nothing left the machine.' -ForegroundColor Red
            Write-Host '  Re-run without -LogToStick if you need the detail locally.' -ForegroundColor DarkGray
        }
        else {
            Write-Host '  DELETE FAILED. Remove it by hand before the stick leaves:' -ForegroundColor Red
            Write-Host ('    ' + $logCheck.Path) -ForegroundColor Red
        }
    }
    else {
        Write-Host ('  Stick log NOT verified: ' + $logCheck.Reason) -ForegroundColor Yellow
        Write-Host '  Treat it as unsanitized until you have checked it yourself.' -ForegroundColor Yellow
    }
    Write-Host ''
}

function Show-Header {
    Clear-Host
    Write-Host ''
    Write-Host ('  TUNE-UP STICK  v' + $ToolkitVersion) -ForegroundColor White
    Write-Host '  ------------------------------------------------------------' -ForegroundColor DarkGray
    $adminText = 'NOT ELEVATED - repair actions unavailable'
    $adminColor = 'Yellow'
    if (Test-IsAdmin) { $adminText = 'Elevated'; $adminColor = 'Green' }
    Write-Host ('  Session:  ' + $adminText) -ForegroundColor $adminColor
    Write-Host ('  Toolkit:  ' + $Root) -ForegroundColor DarkGray
    # The header is where a tech checks what this run is going to do to the
    # machine, so it must never describe a destination the run is not using.
    if ($LogToStick) {
        Write-Host ('  Logs:     ' + $LogDir + '  (on the stick, redacted)') -ForegroundColor Cyan
        Write-Host '            Undo backups and resume state still go local.' -ForegroundColor DarkGray
    }
    else {
        Write-Host ('  Logs:     ' + $script:LocalRoot + '  (stays on this machine)') -ForegroundColor DarkGray
    }
    Write-Host ''
}

function Show-Menu {
    Show-Header
    Write-Host '   1  Collect diagnostic report        (read-only, safe on anything)' -ForegroundColor Gray
    Write-Host '   2  Repair component store           (DISM ladder, then SFC)' -ForegroundColor Gray
    Write-Host '   3  Windows Update                   (software only, no drivers)' -ForegroundColor Gray
    Write-Host '   4  Reclaim cache space              (temp, WU cache, WER)' -ForegroundColor Gray
    Write-Host '   5  Full tune-up                     (2 then 3 then 4, then report)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   6  Dry run of the full tune-up      (prints the plan, writes nothing)' -ForegroundColor DarkGray
    Write-Host '   7  Purge logs and state from THIS machine' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '   8  TRIAGE - scan everything, then ask before each fix' -ForegroundColor White
    Write-Host '      (read-only scan of report + every module, ranked findings,' -ForegroundColor DarkGray
    Write-Host '       one typed YES per fix - nothing applies in bulk)' -ForegroundColor DarkGray
    Write-Host ''

    $mods = Get-TuneUpModules -ModuleRoot $ModuleRoot
    if (@($mods).Count -gt 0) {
        Write-Host '   Modules (type the key - all run read-only first):' -ForegroundColor Gray
        Show-ModuleList -Modules $mods
        Write-Host ''
    }

    Write-Host '   Q  Quit' -ForegroundColor DarkGray
    Write-Host ''
    return (Read-Host '  Select')
}

# ---------------------------------------------------------------------------
# Report writing. This is the only path that puts anything on the stick, so
# the sanitizer runs here and refuses to write if verification fails.
# ---------------------------------------------------------------------------
function Write-SanitizedReport {
    param([Parameter(Mandatory = $true)]$Report)

    Write-Banner 'Sanitizing and writing report'

    New-RedactionMap | Out-Null
    Write-Log ("Redaction map built: {0} machine-specific literal(s)" -f @($script:RedactionMap).Count)

    $clean = Protect-Object -InputObject $Report
    $json = $clean | ConvertTo-Json -Depth 14

    # PowerShell 5.1 escapes < and > as < / >, which turns every
    # redaction token into <SID> in the file a tech actually opens.
    # Both forms are valid JSON; restore the readable one. Done BEFORE
    # verification so the check runs on exactly the bytes that get written.
    # The backslash is built from its char code rather than written literally,
    # so no editor or transport can quietly decode the sequence and turn these
    # into no-op replaces.
    $bs = [string][char]0x5C
    $json = $json.Replace(($bs + 'u003c'), '<').Replace(($bs + 'u003e'), '>').Replace(($bs + 'u0027'), "'")

    $verify = Test-SanitizedText -Text $json
    if (-not $verify.Clean) {
        # Say what actually happened. The old wording here claimed the full
        # report "stayed in the local log directory" - it does not, and never
        # did. This path writes nothing anywhere, so that sent a tech hunting
        # for a file that was never created, and implied an unsanitized copy
        # was sitting on the customer's disk when none was.
        Write-Log -Message 'SANITIZER VERIFICATION FAILED - nothing written, on the stick or anywhere else.' -Level FAIL
        Write-Log -Message ('Surviving identifiers: ' + ($verify.Hits -join ', ')) -Level FAIL
        Write-Log -Message 'The collected data was discarded. Nothing leaked, and there is no partial file to salvage.' -Level FAIL
        Write-Log -Message 'Fix the redaction gap, then re-run the collection.' -Level FAIL
        return $null
    }

    # Timestamp only. Never name a report after the machine or its owner.
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $jsonPath = Join-Path $ReportDir ("report-$stamp.json")
    $txtPath  = Join-Path $ReportDir ("report-$stamp.txt")

    # Bail before writing rather than after, so a dry run cannot print
    # "Report written" about a file that does not exist.
    if ($WhatIfPreference) {
        Write-Log -Message "Dry run - report NOT written. It would have gone to: $jsonPath" -Level WARN
        return $null
    }

    if (-not (Test-Path -LiteralPath $ReportDir)) {
        New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
    }

    Set-Content -LiteralPath $jsonPath -Value $json -Encoding UTF8
    Set-Content -LiteralPath $txtPath -Value (Format-ReportText -Report $clean) -Encoding UTF8

    if (-not (Test-Path -LiteralPath $jsonPath)) {
        Write-Log -Message "Report write FAILED - $jsonPath does not exist after the write." -Level FAIL
        return $null
    }

    Write-Log -Message "Report written: $jsonPath" -Level OK
    Write-Log -Message 'Verified clean: no hostname, account, serial, MAC, IP, email or profile path survived.' -Level OK
    return $jsonPath
}

function Format-ReportText {
    param($Report)

    $sb = New-Object System.Text.StringBuilder
    function Add-Line { param($t) [void]$sb.AppendLine($t) }

    Add-Line 'TUNE-UP DIAGNOSTIC REPORT (sanitized)'
    Add-Line ('Collected: ' + $Report.CollectedAt)
    if (-not $Report.Elevated) {
        Add-Line 'NOTE: collected WITHOUT elevation. SMART counters and component'
        Add-Line '      store were not readable - blanks below mean "not checked",'
        Add-Line '      not "healthy". Re-run via RUN.cmd for the full picture.'
    }
    Add-Line ''

    if ($Report.OS) {
        Add-Line '-- OS --'
        Add-Line ('  {0} {1} build {2}.{3}' -f $Report.OS.Caption, $Report.OS.DisplayVersion, $Report.OS.Build, $Report.OS.UBR)
        Add-Line ('  Install age {0} days, uptime {1} h' -f $Report.OS.InstallAgeDays, $Report.OS.UptimeHours)
        Add-Line ''
    }

    if ($Report.Hardware) {
        Add-Line '-- Hardware --'
        Add-Line ('  {0} {1}' -f $Report.Hardware.Manufacturer, $Report.Hardware.Model)
        Add-Line ('  {0}, {1} GB RAM, {2}, SecureBoot={3}' -f $Report.Hardware.CpuName, $Report.Hardware.RamGB, $Report.Hardware.FirmwareType, $Report.Hardware.SecureBoot)
        Add-Line ''
    }

    if ($Report.Disks) {
        Add-Line '-- Disks --'
        foreach ($d in $Report.Disks) {
            Add-Line ('  {0} | {1} {2} | {3} GB | health {4}' -f `
                    $d.FriendlyName, $d.BusType, $d.MediaType, $d.SizeGB, $d.HealthStatus)
            if ($d.SmartStatus -eq 'Read') {
                Add-Line ('      SMART: wear {0} | {1} C | POH {2} | read err {3} | write err {4}' -f `
                        $d.Wear, $d.TemperatureC, $d.PowerOnHours, $d.ReadErrorsTotal, $d.WriteErrorsTotal)
            }
            else {
                Add-Line ('      SMART: ' + $d.SmartStatus)
            }
        }
        Add-Line ''
    }

    if ($Report.Volumes) {
        Add-Line '-- Volumes --'
        foreach ($v in $Report.Volumes) {
            Add-Line ('  {0}: {1} {2} GB, {3}% free, {4}' -f $v.DriveLetter, $v.FileSystem, $v.SizeGB, $v.FreePercent, $v.HealthStatus)
        }
        Add-Line ''
    }

    if ($Report.ComponentStore) {
        Add-Line '-- Component store --'
        Add-Line ('  ' + $Report.ComponentStore.Verdict)
        Add-Line ''
    }

    if ($Report.WindowsUpdate) {
        Add-Line '-- Windows Update --'
        Add-Line ('  Pending: ' + $Report.WindowsUpdate.PendingCount)
        if ($Report.WindowsUpdate.RecentFailures) {
            Add-Line ('  Recent failures: ' + @($Report.WindowsUpdate.RecentFailures).Count)
            foreach ($f in $Report.WindowsUpdate.RecentFailures) {
                Add-Line ('    hresult ' + $f.HResult + ' op ' + $f.Operation)
            }
        }
        Add-Line ''
    }

    if ($Report.EventSignatures) {
        Add-Line '-- Event signatures (30 days) --'
        foreach ($k in $Report.EventSignatures.Counts.Keys) {
            Add-Line ('  {0,-22} {1}' -f $k, $Report.EventSignatures.Counts[$k])
        }
        foreach ($b in $Report.EventSignatures.Bugchecks) {
            Add-Line ('  BUGCHECK ' + $b.StopCode)
        }
        Add-Line ''
    }

    if ($Report.PendingReboot) {
        Add-Line '-- Pending reboot --'
        Add-Line ('  {0} {1}' -f $Report.PendingReboot.Pending, ($Report.PendingReboot.Reasons -join ', '))
        Add-Line ''
    }

    if ($Report.TriageFindings) {
        Add-Line '-- Triage findings --'
        Add-Line '  (UNKNOWN = check could not run, not a pass)'
        if ($Report.TriageDataFirst) {
            Add-Line '  DATA-FIRST MODE: a disk finding was critical. Heavy-I/O fixes were gated.'
        }
        foreach ($f in $Report.TriageFindings) {
            Add-Line ('  [{0,-8}] {1,-12} {2}' -f $f.Severity, $f.Area, $f.Finding)
            if ($f.Evidence) { Add-Line ('              ' + $f.Evidence) }
            if ($f.Recommend) { Add-Line ('              -> ' + $f.Recommend) }
        }
        Add-Line ''
    }

    if ($Report.TriageOutcomes -and @($Report.TriageOutcomes).Count -gt 0) {
        Add-Line '-- Triage fixes --'
        foreach ($o in $Report.TriageOutcomes) {
            $detail = ''
            if ($o.Detail) { $detail = ' (' + $o.Detail + ')' }
            Add-Line ('  {0,-20} {1}{2}' -f $o.Outcome, $o.Title, $detail)
        }
        Add-Line ''
    }

    return $sb.ToString()
}

# ---------------------------------------------------------------------------
function Invoke-Action {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Name)

    $results = [ordered]@{}
    $rebootNeeded = $false

    switch ($Name) {
        'Report' {
            $results.Report = Get-TuneUpReport -SkipEventLogs:$SkipEventLogs
        }
        'Repair' {
            $results.Repair = Repair-ComponentStore -SourcePath $SourcePath
            if ($results.Repair.RebootNeeded) { $rebootNeeded = $true }
            $results.Report = Get-TuneUpReport -SkipEventLogs:$SkipEventLogs
        }
        'Update' {
            $results.Update = Invoke-WindowsUpdateRun -IncludeDrivers:$IncludeDrivers
            if ($results.Update.RebootNeeded) { $rebootNeeded = $true }
            $results.Report = Get-TuneUpReport -SkipEventLogs:$SkipEventLogs
        }
        'Clean' {
            $results.Clean = Clear-TuneUpTempFiles -IncludeComponentCleanup:$IncludeComponentCleanup
            $results.Report = Get-TuneUpReport -SkipEventLogs:$SkipEventLogs
        }
        'Full' {
            $state = Get-RunState
            $done = @($state.Completed)

            if ($done -notcontains 'Repair') {
                $results.Repair = Repair-ComponentStore -SourcePath $SourcePath
                if ($results.Repair.RebootNeeded) { $rebootNeeded = $true }
                Set-RunStateCompleted -TaskName 'Repair'
            }
            else { Write-Log 'Repair already completed this run - skipping (resume)' }

            if ($done -notcontains 'Update') {
                $results.Update = Invoke-WindowsUpdateRun -IncludeDrivers:$IncludeDrivers
                if ($results.Update.RebootNeeded) { $rebootNeeded = $true }
                Set-RunStateCompleted -TaskName 'Update'
            }
            else { Write-Log 'Update already completed this run - skipping (resume)' }

            if ($done -notcontains 'Clean') {
                $results.Clean = Clear-TuneUpTempFiles -IncludeComponentCleanup:$IncludeComponentCleanup
                Set-RunStateCompleted -TaskName 'Clean'
            }
            else { Write-Log 'Clean already completed this run - skipping (resume)' }

            $results.Report = Get-TuneUpReport -SkipEventLogs:$SkipEventLogs
        }
        'Triage' {
            $t = Invoke-TuneUpTriage -ModuleRoot $ModuleRoot -Interactive:($script:Interactive -or $Walk)
            if ($t.RebootNeeded) { $rebootNeeded = $true }
            # Findings and outcomes are already folded into the report object,
            # so the sanitized file carries the whole story with no extra merge.
            $results.Report = $t.Report
        }
        'Module' {
            $mods = Get-TuneUpModules -ModuleRoot $ModuleRoot
            $info = @($mods | Where-Object { $_.Key -eq $Module }) | Select-Object -First 1
            if (-not $info) {
                $known = (@($mods | ForEach-Object { $_.Key }) -join ', ')
                if (-not $known) { $known = '(none installed)' }
                throw ("No module with key '{0}'. Installed: {1}" -f $Module, $known)
            }

            $opts = @{
                IncludeOptional = [bool]$IncludeOptional
                Provisioned     = [bool]$Provisioned
                Restore         = [bool]$Restore
                Force           = [bool]$Force
                Disruptive      = [bool]$Disruptive
            }
            # Only pass numeric options through when actually supplied, so a
            # module keeps its own default instead of receiving 0. Note this
            # reads $script:ScriptBound, not $PSBoundParameters - see the note
            # where it is captured.
            if ($script:ScriptBound.ContainsKey('Minutes')) { $opts['Minutes'] = $Minutes }
            if ($script:ScriptBound.ContainsKey('Phase'))   { $opts['Action'] = $Phase }
            if ($NoLaunchSensors) { $opts['NoLaunchSensors'] = $true }
            $results.ModuleResult = Invoke-TuneUpModuleByInfo -ModuleInfo $info -Apply:$Apply -Options $opts
            $results.Report = Get-TuneUpReport -SkipEventLogs:$SkipEventLogs
        }
        'Purge' {
            Write-Banner 'Purging tune-up traces from this machine'
            Clear-RunState
            if (Test-Path -LiteralPath $script:LocalRoot) {
                if ($PSCmdlet.ShouldProcess($script:LocalRoot, 'Delete logs and state')) {
                    Remove-Item -LiteralPath $script:LocalRoot -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host '  Local logs and state removed.' -ForegroundColor Green
                }
            }
            else { Write-Host '  Nothing to purge.' -ForegroundColor Gray }
            return
        }
    }

    if ($results.Contains('Report') -and $results.Report) {
        # Fold the action outcomes into the report so the sanitized file that
        # comes back off the stick shows what was done, not just what was found.
        $merged = $results.Report
        $merged | Add-Member -NotePropertyName 'ActionsRun' -NotePropertyValue @($results.Keys) -Force
        if ($results.Contains('Repair')) { $merged | Add-Member -NotePropertyName 'RepairOutcome' -NotePropertyValue $results.Repair -Force }
        if ($results.Contains('Update')) { $merged | Add-Member -NotePropertyName 'UpdateOutcome' -NotePropertyValue $results.Update -Force }
        if ($results.Contains('Clean'))  { $merged | Add-Member -NotePropertyName 'CleanOutcome'  -NotePropertyValue $results.Clean  -Force }
        if ($results.Contains('ModuleResult')) {
            $merged | Add-Member -NotePropertyName 'ModuleKey' -NotePropertyValue $Module -Force
            $merged | Add-Member -NotePropertyName 'ModuleOutcome' -NotePropertyValue $results.ModuleResult -Force
        }

        $answer = ''
        if (-not $NoReport -and $script:Interactive) {
            Write-Host ''
            $answer = Read-Host '  Write a sanitized report to the stick? (y/N)'
        }
        if (Test-ShouldWriteReport -NoReport ([bool]$NoReport) -Interactive $script:Interactive -Answer $answer) {
            Write-SanitizedReport -Report $merged | Out-Null
        }
        else {
            Write-Host '  No report written.' -ForegroundColor DarkGray
        }
    }

    if ($rebootNeeded) {
        Write-Host ''
        Write-Host '  REBOOT REQUIRED. Re-run option 5 after the reboot -' -ForegroundColor Yellow
        Write-Host '  completed steps are recorded and will be skipped.' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Log root only. The local state/backup directory is created on demand by the
# things that actually need it, so a read-only run with -LogToStick can finish
# without creating anything at all on the machine being worked on.
Initialize-LogRoot
Write-Log -Message ("Session start. Elevated={0} Root={1}" -f (Test-IsAdmin), $Root) -Level STEP -Quiet

function Invoke-ActionSafely {
    param([string]$Name)
    try {
        Invoke-Action -Name $Name
    }
    catch {
        # A missing-elevation refusal is an expected outcome, not a crash.
        # Show it as a sentence; keep the stack trace in the log.
        Write-Host ''
        Write-Host ('  STOPPED: ' + $_.Exception.Message) -ForegroundColor Yellow
        Write-Log -Message ("Action '$Name' stopped: " + $_.Exception.Message) -Level FAIL -Quiet
        Write-Log -Message $_.ScriptStackTrace -Level FAIL -Quiet
    }
}

# Menu path for modules: always run read-only first, show what was found,
# then ask. A module never changes anything from the menu without the tech
# reading the findings and typing yes.
function Invoke-ModuleFromMenu {
    param([string]$Key)

    $script:Module = $Key
    $script:Apply = $false
    Invoke-ActionSafely -Name 'Module'

    # Read-only modules have nothing to apply. Asking "apply fixes?" after one
    # implies there is a second half that changes something, and there is not.
    if (@('crashes', 'evidence', 'elevation', 'codeintegrity') -contains $Key) {
        Write-Host ''
        Write-Host '  This module is read-only - nothing to apply.' -ForegroundColor DarkGray
        if ($Key -eq 'evidence') {
            Write-Host '  Run your stress tool, then:  -Module evidence -Phase Watch' -ForegroundColor Gray
            Write-Host '  or afterwards:               -Module evidence -Phase Compare' -ForegroundColor Gray
        }
        if ($Key -eq 'elevation') {
            Write-Host '  If the complaint is that a fix does not stick, a single reading' -ForegroundColor Gray
            Write-Host '  cannot see that. Watch it, or bracket a reboot:' -ForegroundColor Gray
            Write-Host '    -Module elevation -Phase Watch -Minutes 5' -ForegroundColor Gray
            Write-Host '    -Module elevation -Phase Baseline   (then reboot, then)' -ForegroundColor Gray
            Write-Host '    -Module elevation -Phase Compare' -ForegroundColor Gray
        }
        return
    }

    # Wording matters: "apply fixes" is meaningless for a module that only
    # creates a restore point, and reads as though there is nothing to do.
    $prompt = '  Apply fixes for this module?'
    if ($Key -eq 'driver') { $prompt = '  Create a System Restore point? (this module never rolls drivers back)' }

    Write-Host ''
    Write-Host $prompt -ForegroundColor Cyan
    $answer = Read-Host '  Type YES to proceed, anything else to skip'

    # Case-INsensitive. The earlier -cne meant typing "yes" silently skipped,
    # which looked exactly like the module refusing to do anything.
    if ($answer -ne 'YES') {
        Write-Host '  Skipped. Nothing was changed.' -ForegroundColor Gray
        return
    }

    if (-not (Test-IsAdmin)) {
        Write-Host '  Cannot apply without elevation. Re-launch with RUN.cmd.' -ForegroundColor Yellow
        return
    }

    $script:Apply = $true
    Invoke-ActionSafely -Name 'Module'
}

if ($Module) {
    Show-Header
    Invoke-ActionSafely -Name 'Module'
}
elseif ($Action) {
    Show-Header
    Invoke-ActionSafely -Name $Action
}
else {
    # The menu is a LOOP. It used to run exactly one command and then close,
    # so every second thing a tech wanted to do meant relaunching the toolkit
    # from the stick and re-elevating. Q was listed but had no case and fell
    # through to "Nothing selected", so the only documented way out did not
    # work either.
    $script:Interactive = $true
    $running = $true
    $emptyChoices = 0

    while ($running) {
        $choice = Show-Menu
        $quit = $false

        # Guard against a menu loop with no stdin. Read-Host returns empty
        # forever if input is closed, which would spin this at full tilt.
        if ([string]::IsNullOrWhiteSpace($choice)) {
            $emptyChoices++
            if ($emptyChoices -ge 3) {
                Write-Host '  No input - closing.' -ForegroundColor Yellow
                break
            }
            continue
        }
        $emptyChoices = 0

        switch ($choice.Trim()) {
            '1' { Invoke-ActionSafely -Name 'Report' }
            '2' { Invoke-ActionSafely -Name 'Repair' }
            '3' { Invoke-ActionSafely -Name 'Update' }
            '4' { Invoke-ActionSafely -Name 'Clean' }
            '5' { Invoke-ActionSafely -Name 'Full' }
            '6' { $WhatIfPreference = $true; Invoke-ActionSafely -Name 'Full'; $WhatIfPreference = $false }
            '7' { Invoke-ActionSafely -Name 'Purge' }
            '8' { Invoke-ActionSafely -Name 'Triage' }
            'Q' { $quit = $true }
            default {
                $mods = Get-TuneUpModules -ModuleRoot $ModuleRoot
                $hit = @($mods | Where-Object { $_.Key -eq $choice.Trim() }) | Select-Object -First 1
                if ($hit) { Invoke-ModuleFromMenu -Key $hit.Key }
                else { Write-Host '  Nothing selected.' -ForegroundColor Gray }
            }
        }

        if ($quit) { break }

        Show-LogFooter
        Read-Host '  Press Enter to return to the menu' | Out-Null
    }

    # Last chance to leave the machine as it was found. A tech who is done
    # should not have to remember option 7 from a menu they have just left.
    if (Test-Path -LiteralPath $script:LocalRoot) {
        # Do not claim logs are here when -LogToStick sent them elsewhere. The
        # directory still exists in that case for baselines and undo backups,
        # and describing those as "logs" would send someone hunting for a file
        # that is on the stick.
        $leftBehind = 'logs and baselines'
        if ($LogToStick) { $leftBehind = 'baselines and undo backups - the log went to the stick' }

        Write-Host ''
        Write-Host ('  This run left ' + $leftBehind + ' in:') -ForegroundColor Yellow
        Write-Host ('    ' + $script:LocalRoot) -ForegroundColor Yellow
        Write-Host '  They are unsanitized, which is exactly why they never went to the' -ForegroundColor DarkGray
        Write-Host '  stick. Remove them if the job is finished.' -ForegroundColor DarkGray
        $purge = Read-Host '  Remove them now? (y/N)'
        if ($purge -match '^\s*(y|yes)\s*$') {
            Invoke-ActionSafely -Name 'Purge'
        }
        else {
            Write-Host '  Left in place. Option 7 removes them later.' -ForegroundColor DarkGray
        }
    }

    # LAST, deliberately. This has to run after the purge prompt above, because
    # Purge logs as it works: verifying first would check a file and then append
    # unverified lines to it, and the green "verified clean" would be about a
    # file that no longer exists in the state it was checked in.
    Invoke-StickLogVerification
}

if (-not $script:Interactive) {
    Show-LogFooter
    # A scripted run is the common way to do a quick read-only collection, so
    # it needs the same verification the menu path gets. Without this, exactly
    # the runs most likely to use -LogToStick would leave the stick unchecked.
    Invoke-StickLogVerification
}
