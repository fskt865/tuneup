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
    [ValidateSet('Report', 'Repair', 'Update', 'Clean', 'Full', 'Purge')]
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
    [switch]$SkipEventLogs
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
. (Join-Path $Root 'tasks\Collect-Report.ps1')
. (Join-Path $Root 'tasks\Repair-ComponentStore.ps1')
. (Join-Path $Root 'tasks\Invoke-WindowsUpdate.ps1')
. (Join-Path $Root 'tasks\Clear-TempFiles.ps1')

$ReportDir = Join-Path $Root 'reports'
$ModuleRoot = Join-Path $Root 'modules'

$ToolkitVersion = 'unknown'
$versionFile = Join-Path $Root 'VERSION'
if (Test-Path -LiteralPath $versionFile) {
    $ToolkitVersion = (Get-Content -LiteralPath $versionFile -Raw).Trim()
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
    Write-Host ('  Logs:     ' + $script:LocalRoot + '  (stays on this machine)') -ForegroundColor DarkGray
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
        Write-Log -Message 'SANITIZER VERIFICATION FAILED - nothing written to the stick.' -Level FAIL
        Write-Log -Message ('Surviving identifiers: ' + ($verify.Hits -join ', ')) -Level FAIL
        Write-Log -Message 'The full report stayed in the local log directory. Do not copy it off by hand.' -Level FAIL
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

        Write-SanitizedReport -Report $merged | Out-Null
    }

    if ($rebootNeeded) {
        Write-Host ''
        Write-Host '  REBOOT REQUIRED. Re-run option 5 after the reboot -' -ForegroundColor Yellow
        Write-Host '  completed steps are recorded and will be skipped.' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
Initialize-LocalRoot
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
    if (@('crashes', 'evidence') -contains $Key) {
        Write-Host ''
        Write-Host '  This module is read-only - nothing to apply.' -ForegroundColor DarkGray
        if ($Key -eq 'evidence') {
            Write-Host '  Run your stress tool, then:  -Module evidence -Phase Watch' -ForegroundColor Gray
            Write-Host '  or afterwards:               -Module evidence -Phase Compare' -ForegroundColor Gray
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
    $choice = Show-Menu
    switch ($choice) {
        '1' { Invoke-ActionSafely -Name 'Report' }
        '2' { Invoke-ActionSafely -Name 'Repair' }
        '3' { Invoke-ActionSafely -Name 'Update' }
        '4' { Invoke-ActionSafely -Name 'Clean' }
        '5' { Invoke-ActionSafely -Name 'Full' }
        '6' { $WhatIfPreference = $true; Invoke-ActionSafely -Name 'Full'; $WhatIfPreference = $false }
        '7' { Invoke-ActionSafely -Name 'Purge' }
        default {
            $mods = Get-TuneUpModules -ModuleRoot $ModuleRoot
            $hit = @($mods | Where-Object { $_.Key -eq $choice }) | Select-Object -First 1
            if ($hit) { Invoke-ModuleFromMenu -Key $hit.Key }
            else { Write-Host '  Nothing selected.' -ForegroundColor Gray }
        }
    }
}

Write-Host ''
Write-Host ('  Verbose log: ' + $script:LogPath) -ForegroundColor DarkGray
Write-Host '  That log stays on this machine. Option 7 purges it when the job is done.' -ForegroundColor DarkGray
Write-Host ''
# Only pause when we actually came through the menu. A non-interactive run
# (-Action or -Module) has no stdin, and Read-Host there fails the whole script.
if (-not $Action -and -not $Module) { Read-Host '  Press Enter to close' | Out-Null }
