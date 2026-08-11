# Invoke-Triage.ps1 - the full-scan worker: scan everything read-only,
# aggregate findings, then ask before EVERY fix, one at a time.
# ASCII only, PowerShell 5.1 compatible.
#
# The judgment lives in lib\Triage.ps1 and is pure; this file is the part
# that touches the machine. Scan first, show everything, then apply nothing
# without a typed YES per fix. A scripted run (-Action Triage) never applies
# anything at all - it prints the plan as commands instead, because a run
# with no stdin must never be asked a question.

function Invoke-TuneUpTriage {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$ModuleRoot,
        [switch]$Interactive
    )

    Write-Banner 'Triage: scan everything, then decide'
    Write-Host '  Phase 1 is read-only - the core report plus every module inventory.' -ForegroundColor DarkGray
    Write-Host '  Nothing changes until you approve a specific fix by typing YES.' -ForegroundColor DarkGray

    # --- Phase 1: scan --------------------------------------------------
    $report = Get-TuneUpReport

    $moduleResults = @{}
    $moduleErrors = @{}
    foreach ($m in @(Get-TuneUpModules -ModuleRoot $ModuleRoot)) {
        if ($m.Key -eq 'evidence') {
            # It exists to bracket an EXTERNAL stress run - baseline, watch,
            # compare. An automatic scan has no stress tool running, so a pass
            # from it here would be exactly the empty-diff false pass it was
            # built to refuse.
            Write-Log -Message "Skipping module 'evidence': it brackets an external stress test and has nothing to measure in a plain scan." -Quiet
            continue
        }
        Write-Banner ('Scanning: ' + $m.Title)
        try {
            $moduleResults[$m.Key] = Invoke-TuneUpModuleByInfo -ModuleInfo $m -Apply:$false -Options @{}
        }
        catch {
            $moduleErrors[$m.Key] = $_.Exception.Message
            Write-Log -Message ("Module '{0}' failed to scan: {1}" -f $m.Key, $_.Exception.Message) -Level FAIL
        }
    }

    # --- Phase 2: findings ----------------------------------------------
    $findings = @(Get-TriageFindings -Report $report -ModuleResults $moduleResults -ModuleErrors $moduleErrors)
    $plan = @(Get-TriageFixPlan -Findings $findings)
    $dataFirst = Test-TriageDataFirst -Findings $findings

    Show-TriageFindings -Findings $findings
    if ($dataFirst) { Show-TriageDataFirstWarning }

    # --- Phase 3: fixes, one YES at a time ------------------------------
    $outcomes = @()
    if ($plan.Count -eq 0) {
        Write-Host '  No automated fixes to offer. Findings above that carry a' -ForegroundColor Gray
        Write-Host '  recommendation are judgment calls, deliberately not scripted.' -ForegroundColor Gray
    }
    elseif (-not $Interactive) {
        Show-TriageFixPlanScripted -Plan $plan
    }
    else {
        $outcomes = @(Invoke-TriageFixWalk -Plan $plan -ModuleRoot $ModuleRoot)
    }

    $rebootNeeded = $false
    foreach ($o in $outcomes) {
        if ($o.RebootNeeded) { $rebootNeeded = $true }
    }

    Show-TriageToolbox -ToolkitRoot (Split-Path -Parent $ModuleRoot) -Findings $findings

    # --- Fold into the report -------------------------------------------
    # Strings only: the report is the thing that leaves on the stick, and
    # every one of these lines is built from fields the sanitizer already
    # handles in the sections they came from.
    $foldFindings = @()
    foreach ($f in $findings) {
        $foldFindings += [ordered]@{
            Severity = $f.Severity; Area = $f.Area; Finding = $f.Finding
            Evidence = $f.Evidence; Recommend = $f.Recommend; FixKey = $f.FixKey
        }
    }
    $foldOutcomes = @()
    foreach ($o in $outcomes) {
        $foldOutcomes += [ordered]@{
            FixKey = $o.FixKey; Title = $o.Title; Outcome = $o.Outcome; Detail = $o.Detail
        }
    }
    $report | Add-Member -NotePropertyName 'TriageFindings' -NotePropertyValue $foldFindings -Force
    $report | Add-Member -NotePropertyName 'TriageDataFirst' -NotePropertyValue $dataFirst -Force
    $report | Add-Member -NotePropertyName 'TriageOutcomes' -NotePropertyValue $foldOutcomes -Force

    return [pscustomobject]@{
        Report       = $report
        Findings     = $findings
        Plan         = $plan
        Outcomes     = $outcomes
        RebootNeeded = $rebootNeeded
    }
}

function Show-TriageFindings {
    param($Findings)

    Write-Banner 'Findings'

    $all = @($Findings)
    if ($all.Count -eq 0) {
        Write-Host '  Nothing found. On an elevated run that is a real verdict:' -ForegroundColor Green
        Write-Host '  every check either passed or said so when it could not run.' -ForegroundColor Green
        return
    }

    $tally = @{}
    foreach ($f in $all) {
        if (-not $tally.Contains($f.Severity)) { $tally[$f.Severity] = 0 }
        $tally[$f.Severity] = $tally[$f.Severity] + 1
    }
    $parts = @()
    foreach ($s in @('CRITICAL', 'WARNING', 'UNKNOWN', 'INFO')) {
        if ($tally.Contains($s)) { $parts += ('{0} {1}' -f $tally[$s], $s.ToLower()) }
    }
    Write-Host ('  ' + ($parts -join ', ')) -ForegroundColor White
    Write-Host '  UNKNOWN means a check could not run - not that it passed.' -ForegroundColor DarkGray
    Write-Host ''

    foreach ($f in $all) {
        $color = 'Gray'
        if ($f.Severity -eq 'CRITICAL') { $color = 'Red' }
        if ($f.Severity -eq 'WARNING') { $color = 'Yellow' }
        if ($f.Severity -eq 'UNKNOWN') { $color = 'Magenta' }
        Write-Host ('  [{0,-8}] {1,-12} {2}' -f $f.Severity, $f.Area, $f.Finding) -ForegroundColor $color
        if ($f.Evidence) { Write-Host ('              {0}' -f $f.Evidence) -ForegroundColor DarkGray }
        if ($f.Recommend) { Write-Host ('              -> {0}' -f $f.Recommend) -ForegroundColor DarkCyan }
    }
    Write-Host ''
}

function Show-TriageDataFirstWarning {
    Write-Host ('  ' + ('!' * 64)) -ForegroundColor Red
    Write-Host '  A DISK ON THIS MACHINE IS NOT HEALTHY. DATA COMES FIRST.' -ForegroundColor Red
    Write-Host '  Image or copy the user data off before any repair, update or' -ForegroundColor Red
    Write-Host '  load. Heavy-I/O fixes below are gated for exactly that reason:' -ForegroundColor Red
    Write-Host '  sustained load is how a drive that reads today stops reading.' -ForegroundColor Red
    Write-Host ('  ' + ('!' * 64)) -ForegroundColor Red
    Write-Host ''
}

function Show-TriageFixPlanScripted {
    param($Plan)

    Write-Banner 'Fix plan (nothing was applied)'
    Write-Host '  Scripted runs never apply fixes - there is no one at the keyboard' -ForegroundColor DarkGray
    Write-Host '  to say yes. Run these individually, or option 8 from the menu.' -ForegroundColor DarkGray
    Write-Host ''
    foreach ($p in @($Plan)) {
        Write-Host ('  ' + $p.Title) -ForegroundColor Cyan
        foreach ($why in @($p.Reasons)) {
            Write-Host ('    because: ' + $why) -ForegroundColor Gray
        }
        if ($p.Gated) {
            Write-Host '    GATED: heavy I/O with a critical disk finding. Data first.' -ForegroundColor Red
        }
        Write-Host ('    ' + $p.Command) -ForegroundColor White
        Write-Host ''
    }
}

# What else is on this stick, said at the moment it is useful: right after
# the findings, when the tech is deciding what to do next. Everything listed
# is checked for on disk first - a tool that is not there is not offered.
function Show-TriageToolbox {
    param(
        [Parameter(Mandatory = $true)][string]$ToolkitRoot,
        $Findings = @()
    )

    $toolsDir = Join-Path $ToolkitRoot 'tools'
    $isoDir = Join-Path (Split-Path -Parent $ToolkitRoot) 'iso'

    $toolNotes = @(
        @{ Dir = 'smartmontools'; Note = 'smartctl --scan first, then -d <type> it reports; reads SMART through most USB bridges' },
        @{ Dir = 'CrystalDiskInfo'; Note = 'second opinion on drive health, GUI' },
        @{ Dir = 'LibreHardwareMonitor'; Note = 'temperatures, fans and clocks; the evidence module drives it' },
        @{ Dir = 'Everything'; Note = 'launch via SEARCH.cmd, never the exe - the launcher keeps the index off this stick' }
    )

    $haveTools = @()
    foreach ($t in $toolNotes) {
        if (Test-Path -LiteralPath (Join-Path $toolsDir $t.Dir)) { $haveTools += $t }
    }

    $isos = @()
    if (Test-Path -LiteralPath $isoDir) {
        $isos = @(Get-ChildItem -LiteralPath $isoDir -Filter '*.iso' -ErrorAction SilentlyContinue)
    }

    if ($haveTools.Count -eq 0 -and $isos.Count -eq 0) { return }

    Write-Banner 'Also on this stick'

    if ($haveTools.Count -gt 0) {
        Write-Host '  Hands-on tools (tools\):' -ForegroundColor White
        foreach ($t in $haveTools) {
            Write-Host ('    {0,-22} {1}' -f $t.Dir, $t.Note) -ForegroundColor Gray
        }
        Write-Host ''
    }

    if ($isos.Count -gt 0) {
        Write-Host '  Bootable (reboot, pick this stick in the boot menu, Ventoy lists these):' -ForegroundColor White
        foreach ($i in $isos) {
            $note = ''
            if ($i.Name -match 'systemrescue') { $note = 'Linux rescue: ddrescue, testdisk/photorec, GParted - the data-first toolbox' }
            if ($i.Name -match 'mt86|memtest') { $note = 'memory test - the answer to crashes no module can attribute' }
            if ($i.Name -match 'HBCD|hiren') { $note = 'Windows PE bench environment - repairs when the installed OS will not boot' }
            Write-Host ('    {0,-34} {1}' -f $i.Name, $note) -ForegroundColor Gray
        }
        $diskCritical = $false
        foreach ($f in @($Findings)) {
            if ($f.Severity -eq 'CRITICAL' -and $f.Area -eq 'Disk') { $diskCritical = $true }
        }
        if ($diskCritical) {
            Write-Host ''
            Write-Host '  With the disk finding above: boot SystemRescue and get the data off' -ForegroundColor Yellow
            Write-Host '  with ddrescue BEFORE any repair here. The booted OS does not touch' -ForegroundColor Yellow
            Write-Host '  the patient disk unless told to.' -ForegroundColor Yellow
        }
        Write-Host ''
    }
}

function Invoke-TriageFixWalk {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][string]$ModuleRoot
    )

    Write-Banner 'Fixes - one decision at a time'
    Write-Host '  Enter skips. Skipping is always safe.' -ForegroundColor DarkGray

    $outcomes = @()
    $n = 0
    foreach ($entry in @($Plan)) {
        $n++
        Write-Host ''
        Write-Host ('  [{0}/{1}] {2}' -f $n, @($Plan).Count, $entry.Title) -ForegroundColor Cyan
        foreach ($why in @($entry.Reasons)) {
            Write-Host ('        because: ' + $why) -ForegroundColor Gray
        }

        $outcome = [pscustomobject]@{
            FixKey = $entry.FixKey; Title = $entry.Title
            Outcome = 'Skipped'; Detail = ''; RebootNeeded = $false
        }

        if ($entry.RequiresAdmin -and -not (Test-IsAdmin)) {
            Write-Host '        Needs elevation - re-launch with RUN.cmd to offer this one.' -ForegroundColor Yellow
            $outcome.Outcome = 'SkippedNoElevation'
            $outcomes += $outcome
            continue
        }

        if ($entry.Gated) {
            # High friction on purpose. YES is the ordinary consent word; this
            # one requires stating the thing that makes it safe to proceed.
            Write-Host '        GATED: heavy I/O while a disk finding is CRITICAL.' -ForegroundColor Red
            $answer = Read-Host '        Type DATA IS SAFE if the data is already recovered, anything else skips'
            if ($answer -ne 'DATA IS SAFE') {
                Write-Host '        Skipped. Right call until the data is off.' -ForegroundColor Gray
                $outcomes += $outcome
                continue
            }
        }
        else {
            $answer = Read-Host '        Type YES to apply, anything else skips'
            if ($answer -ne 'YES') {
                Write-Host '        Skipped. Nothing was changed.' -ForegroundColor Gray
                $outcomes += $outcome
                continue
            }
        }

        try {
            $res = Invoke-TriageFix -Entry $entry -ModuleRoot $ModuleRoot
            $outcome.Outcome = 'Applied'
            if ($res -and (Get-TriageProp $res 'RebootNeeded')) {
                $outcome.RebootNeeded = $true
                $outcome.Detail = 'reboot needed'
            }
        }
        catch {
            $outcome.Outcome = 'Failed'
            $outcome.Detail = $_.Exception.Message
            Write-Log -Message ("Fix '{0}' failed: {1}" -f $entry.FixKey, $_.Exception.Message) -Level FAIL
        }
        $outcomes += $outcome
    }

    Write-Host ''
    $applied = @($outcomes | Where-Object { $_.Outcome -eq 'Applied' }).Count
    $failed = @($outcomes | Where-Object { $_.Outcome -eq 'Failed' }).Count
    $skipped = @($outcomes).Count - $applied - $failed
    Write-Host ('  Fixes: {0} applied, {1} skipped, {2} failed.' -f $applied, $skipped, $failed) -ForegroundColor White

    return @($outcomes)
}

function Invoke-TriageFix {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Entry,
        [Parameter(Mandatory = $true)][string]$ModuleRoot
    )

    if ($Entry.Kind -eq 'Task') {
        switch ($Entry.TaskName) {
            'RepairStore' { return Repair-ComponentStore }
            'WindowsUpdate' { return Invoke-WindowsUpdateRun }
            'CleanTemp' { return Clear-TuneUpTempFiles }
        }
        throw ("Fix '{0}' names unknown task '{1}'" -f $Entry.FixKey, $Entry.TaskName)
    }

    if ($Entry.Kind -eq 'Module') {
        $mods = Get-TuneUpModules -ModuleRoot $ModuleRoot
        $info = @($mods | Where-Object { $_.Key -eq $Entry.ModuleKey }) | Select-Object -First 1
        if (-not $info) {
            throw ("Fix '{0}' wants module '{1}', which is not on this stick" -f $Entry.FixKey, $Entry.ModuleKey)
        }
        return Invoke-TuneUpModuleByInfo -ModuleInfo $info -Apply -Options @{}
    }

    throw ("Fix '{0}' has unknown kind '{1}'" -f $Entry.FixKey, $Entry.Kind)
}
