# Triage.ps1 - findings and fix-plan logic for the full-scan triage action.
# ASCII only, PowerShell 5.1 compatible.
#
# Everything in this file is PURE: facts in, findings out, nothing read from
# the machine and nothing written to it. That is what lets the test suite pin
# the judgment calls - which severity a fact earns, and when a fix is gated -
# without a live machine to provoke.
#
# The three-state rule applies to every finding here: a check that did not
# return a verdict produces an UNKNOWN finding, never silence. Silence reads
# as "scanned and healthy", and half of these checks need elevation the
# session may not have.

# Severity vocabulary, in display order. UNKNOWN sits above INFO on purpose:
# "could not establish" is a fact the tech must act on (usually by
# re-running elevated), not a footnote.
$script:TriageSeverities = @('CRITICAL', 'WARNING', 'UNKNOWN', 'INFO')

function Get-TriageSeverityRank {
    param([string]$Severity)
    $i = [array]::IndexOf($script:TriageSeverities, $Severity)
    if ($i -lt 0) { return 99 }
    return $i
}

# Report objects arrive as a mix of PSCustomObject and nested [ordered]
# hashtables depending on whether they came straight from the collector or
# through a JSON round trip. These two helpers make the rules below agnostic
# to that, and make a MISSING property read as $null rather than throwing.
function Test-TriageProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return [bool]$Object.PSObject.Properties[$Name]
}

function Get-TriageProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function New-TriageFinding {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('CRITICAL', 'WARNING', 'UNKNOWN', 'INFO')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Area,
        [Parameter(Mandatory = $true)][string]$Finding,
        [string]$Evidence = '',
        [string]$FixKey = '',
        [string]$Recommend = ''
    )
    return [pscustomobject]@{
        Severity  = $Severity
        Area      = $Area
        Finding   = $Finding
        Evidence  = $Evidence
        FixKey    = $FixKey
        Recommend = $Recommend
    }
}

# ---------------------------------------------------------------------------
# Fix registry. Every automated fix triage can offer maps to machinery that
# already exists - a core task or a module's -Apply half - so triage adds no
# new way to change a machine, only a front door to the existing ones.
#
# HeavyIO marks fixes that hammer the disk for a sustained stretch. Those get
# GATED when any disk-class finding is critical: sustained load on a drive
# that is already logging errors is how recoverable data becomes
# unrecoverable, and at Level 1 the data is the job.
# ---------------------------------------------------------------------------
function Get-TriageFixSpec {
    param([Parameter(Mandatory = $true)][string]$Key)

    switch ($Key) {
        'repair-store' {
            return [pscustomobject]@{
                FixKey = $Key; Kind = 'Task'; TaskName = 'RepairStore'
                Title = 'Repair the component store (DISM ladder, then SFC)'
                RequiresAdmin = $true; HeavyIO = $true
                Command = '.\Invoke-TuneUp.ps1 -Action Repair'
            }
        }
        'windows-update' {
            return [pscustomobject]@{
                FixKey = $Key; Kind = 'Task'; TaskName = 'WindowsUpdate'
                Title = 'Install pending Windows updates (software only, no drivers)'
                RequiresAdmin = $true; HeavyIO = $true
                Command = '.\Invoke-TuneUp.ps1 -Action Update'
            }
        }
        'clean-temp' {
            return [pscustomobject]@{
                FixKey = $Key; Kind = 'Task'; TaskName = 'CleanTemp'
                Title = 'Reclaim cache space (temp, WU cache, WER)'
                RequiresAdmin = $true; HeavyIO = $false
                Command = '.\Invoke-TuneUp.ps1 -Action Clean'
            }
        }
        'fix-startup' {
            return [pscustomobject]@{
                FixKey = $Key; Kind = 'Module'; ModuleKey = 'startup'
                Title = 'Disable optional startup items (reversible: -Restore or Task Manager)'
                RequiresAdmin = $true; HeavyIO = $false
                Command = '.\Invoke-TuneUp.ps1 -Module startup -Apply'
            }
        }
        'fix-bloatware' {
            return [pscustomobject]@{
                FixKey = $Key; Kind = 'Module'; ModuleKey = 'bloatware'
                Title = 'Remove consumer junk apps (never OEM utilities or antivirus)'
                RequiresAdmin = $true; HeavyIO = $false
                Command = '.\Invoke-TuneUp.ps1 -Module bloatware -Apply'
            }
        }
        'fix-browser' {
            return [pscustomobject]@{
                FixKey = $Key; Kind = 'Module'; ModuleKey = 'browser'
                Title = 'Repair browser hijacks (shortcuts and proxy only, backed up first)'
                RequiresAdmin = $true; HeavyIO = $false
                Command = '.\Invoke-TuneUp.ps1 -Module browser -Apply'
            }
        }
        'fix-network' {
            return [pscustomobject]@{
                FixKey = $Key; Kind = 'Module'; ModuleKey = 'network'
                Title = 'Apply safe network repairs (stack resets need -Disruptive, not offered here)'
                RequiresAdmin = $true; HeavyIO = $false
                Command = '.\Invoke-TuneUp.ps1 -Module network -Apply'
            }
        }
    }
    return $null
}

# Any critical disk-class finding puts the whole machine in data-first mode.
function Test-TriageDataFirst {
    param($Findings)
    foreach ($f in @($Findings)) {
        if ($f.Severity -eq 'CRITICAL' -and $f.Area -eq 'Disk') { return $true }
    }
    return $false
}

# Dedupe findings into an ordered fix plan. Several findings can point at the
# same fix (pending updates AND update failures both want windows-update);
# the tech gets asked once, with every reason listed.
function Get-TriageFixPlan {
    param($Findings)

    $dataFirst = Test-TriageDataFirst -Findings $Findings

    $plan = @()
    $seen = @{}
    foreach ($f in @($Findings)) {
        if (-not $f.FixKey) { continue }
        if ($seen.Contains($f.FixKey)) {
            $seen[$f.FixKey].Reasons += $f.Finding
            continue
        }
        $spec = Get-TriageFixSpec -Key $f.FixKey
        if ($null -eq $spec) { continue }

        $entry = [pscustomobject]@{
            FixKey        = $spec.FixKey
            Kind          = $spec.Kind
            TaskName      = (Get-TriageProp $spec 'TaskName')
            ModuleKey     = (Get-TriageProp $spec 'ModuleKey')
            Title         = $spec.Title
            RequiresAdmin = $spec.RequiresAdmin
            Command       = $spec.Command
            Gated         = ($dataFirst -and $spec.HeavyIO)
            Reasons       = @($f.Finding)
        }
        $seen[$f.FixKey] = $entry
        $plan += $entry
    }
    return @($plan)
}

# ---------------------------------------------------------------------------
# The findings engine. One rule per fact; a fact that cannot be read becomes
# an UNKNOWN finding that says why.
# ---------------------------------------------------------------------------
function Get-TriageFindings {
    param(
        [Parameter(Mandatory = $true)]$Report,
        [hashtable]$ModuleResults = @{},
        [hashtable]$ModuleErrors = @{},
        [string]$SystemDriveLetter = $env:SystemDrive.TrimEnd(':')
    )

    $found = @()

    # --- Session --------------------------------------------------------
    if (-not (Get-TriageProp $Report 'Elevated')) {
        $found += New-TriageFinding -Severity UNKNOWN -Area 'Session' `
            -Finding 'Scan ran WITHOUT elevation - every blank below means not-checked, not healthy' `
            -Recommend 'Re-launch with RUN.cmd and run the triage again for the full picture.'
    }

    # --- Disks ----------------------------------------------------------
    foreach ($d in @(Get-TriageProp $Report 'Disks')) {
        if ($null -eq $d) { continue }
        if (Test-TriageProp $d 'Error') {
            $found += New-TriageFinding -Severity UNKNOWN -Area 'Disk' `
                -Finding 'Disk inventory failed - drive health was NOT checked' `
                -Evidence ([string](Get-TriageProp $d 'Error'))
            continue
        }
        $name = [string](Get-TriageProp $d 'FriendlyName')
        $bus = [string](Get-TriageProp $d 'BusType')

        $health = [string](Get-TriageProp $d 'HealthStatus')
        if ($health -and $health -ne 'Healthy') {
            $found += New-TriageFinding -Severity CRITICAL -Area 'Disk' `
                -Finding ("Disk '{0}' reports health '{1}'" -f $name, $health) `
                -Evidence ("Bus {0}, operational status '{1}'" -f $bus, [string](Get-TriageProp $d 'OperationalStatus')) `
                -Recommend 'DATA FIRST: image or copy the user data off before any repair, update or load. A drive that still reads today is not guaranteed to tomorrow.'
        }

        $smart = [string](Get-TriageProp $d 'SmartStatus')
        if ($smart -eq 'Read') {
            $readErr = Get-TriageProp $d 'ReadErrorsTotal'
            $writeErr = Get-TriageProp $d 'WriteErrorsTotal'
            if (($readErr -gt 0) -or ($writeErr -gt 0)) {
                $found += New-TriageFinding -Severity CRITICAL -Area 'Disk' `
                    -Finding ("Disk '{0}' has logged media errors" -f $name) `
                    -Evidence ("SMART totals: {0} read error(s), {1} write error(s)" -f [int]$readErr, [int]$writeErr) `
                    -Recommend 'DATA FIRST: recover the data before anything stresses this drive. Do not run chkdsk /f or a stress test against it.'
            }
            $wear = Get-TriageProp $d 'Wear'
            if ($wear -ge 80) {
                $found += New-TriageFinding -Severity WARNING -Area 'Disk' `
                    -Finding ("Disk '{0}' SSD wear is at {1} percent" -f $name, [int]$wear) `
                    -Recommend 'Plan replacement. Back up now, not at 100.'
            }
            $temp = Get-TriageProp $d 'TemperatureC'
            if ($temp -ge 60) {
                $found += New-TriageFinding -Severity WARNING -Area 'Disk' `
                    -Finding ("Disk '{0}' is at {1} C at idle" -f $name, [int]$temp) `
                    -Recommend 'Check airflow and the drive bay before blaming the drive.'
            }
        }
        elseif ($smart -eq 'RequiresElevation') {
            $found += New-TriageFinding -Severity UNKNOWN -Area 'Disk' `
                -Finding ("Disk '{0}': SMART counters NOT read - needs elevation" -f $name) `
                -Recommend 'Re-launch with RUN.cmd. A blank wear figure is not a healthy one.'
        }
        elseif ($smart) {
            # USB bridges routinely refuse SMART passthrough. On a small stick
            # that is expected and barely worth a line; on a real disk it means
            # the health verdict above is the only one we have.
            $sev = 'UNKNOWN'
            if ($bus -eq 'USB' -and ((Get-TriageProp $d 'SizeGB') -lt 128)) { $sev = 'INFO' }
            $found += New-TriageFinding -Severity $sev -Area 'Disk' `
                -Finding ("Disk '{0}': SMART counters unavailable ({1}) over bus {2}" -f $name, $smart, $bus) `
                -Recommend 'If this disk is the patient: tools\smartmontools, smartctl --scan then -d <type> from the scan output, reads SMART through most USB bridges.'
        }
    }

    # --- Volumes --------------------------------------------------------
    foreach ($v in @(Get-TriageProp $Report 'Volumes')) {
        if ($null -eq $v) { continue }
        $letter = [string](Get-TriageProp $v 'DriveLetter')
        $vHealth = [string](Get-TriageProp $v 'HealthStatus')
        if ($vHealth -and $vHealth -ne 'Healthy') {
            $found += New-TriageFinding -Severity WARNING -Area 'Volume' `
                -Finding ("Volume {0}: reports '{1}'" -f $letter, $vHealth) `
                -Recommend ("chkdsk {0}: /scan checks it online without a reboot. Do NOT run /f while any disk finding above is critical - data first." -f $letter)
        }
        $free = Get-TriageProp $v 'FreePercent'
        if ($null -ne $free) {
            $isSystem = ($letter -eq $SystemDriveLetter)
            $fixKey = ''
            if ($isSystem) { $fixKey = 'clean-temp' }
            if ($free -lt 5) {
                $found += New-TriageFinding -Severity WARNING -Area 'Volume' `
                    -Finding ("Volume {0}: down to {1} percent free" -f $letter, $free) `
                    -FixKey $fixKey `
                    -Recommend 'Below 5 percent Windows starts failing in strange ways - updates abort, profiles refuse to load.'
            }
            elseif ($free -lt 12) {
                $found += New-TriageFinding -Severity INFO -Area 'Volume' `
                    -Finding ("Volume {0}: {1} percent free" -f $letter, $free) `
                    -FixKey $fixKey
            }
        }
    }

    # --- Component store ------------------------------------------------
    $cs = Get-TriageProp $Report 'ComponentStore'
    if ($cs) {
        $verdict = [string](Get-TriageProp $cs 'Verdict')
        switch ($verdict) {
            'Repairable' {
                $found += New-TriageFinding -Severity WARNING -Area 'OS servicing' `
                    -Finding 'Component store corruption flagged (repairable)' `
                    -FixKey 'repair-store' `
                    -Recommend 'Repair this BEFORE Windows Update - installing onto a corrupt store is how updates fail halfway.'
            }
            'NotRepairable' {
                $found += New-TriageFinding -Severity CRITICAL -Area 'OS servicing' `
                    -Finding 'Component store corruption flagged as NOT repairable from this image' `
                    -FixKey 'repair-store' `
                    -Recommend 'The repair task can try against a mounted install source (-SourcePath). Failing that, this is an in-place upgrade conversation.'
            }
            'RequiresElevation' {
                $found += New-TriageFinding -Severity UNKNOWN -Area 'OS servicing' `
                    -Finding 'Component store NOT checked - needs elevation' `
                    -Recommend 'Re-launch with RUN.cmd.'
            }
            'Healthy' { }
            default {
                if (Test-TriageProp $cs 'Error') {
                    $found += New-TriageFinding -Severity UNKNOWN -Area 'OS servicing' `
                        -Finding 'Component store check failed to run' `
                        -Evidence ([string](Get-TriageProp $cs 'Error'))
                }
                else {
                    $found += New-TriageFinding -Severity UNKNOWN -Area 'OS servicing' `
                        -Finding ('Component store check returned no verdict ({0})' -f $verdict)
                }
            }
        }
    }

    # --- Windows Update -------------------------------------------------
    $wu = Get-TriageProp $Report 'WindowsUpdate'
    if ($wu) {
        if (Test-TriageProp $wu 'Error') {
            $found += New-TriageFinding -Severity UNKNOWN -Area 'Windows Update' `
                -Finding 'Windows Update agent could not be queried' `
                -Evidence ([string](Get-TriageProp $wu 'Error')) `
                -Recommend 'Often the service, sometimes the network. The network ladder below will say which end is dead.'
        }
        else {
            $pendCount = [int](Get-TriageProp $wu 'PendingCount')
            if ($pendCount -gt 0) {
                $sev = 'INFO'
                if ($pendCount -ge 10) { $sev = 'WARNING' }
                $kbs = @()
                foreach ($p in @(Get-TriageProp $wu 'Pending')) {
                    $kb = [string](Get-TriageProp $p 'KB')
                    if ($kb) { $kbs += $kb }
                }
                $ev = ''
                if ($kbs.Count -gt 0) { $ev = 'Includes ' + (($kbs | Select-Object -First 5) -join ', ') }
                $found += New-TriageFinding -Severity $sev -Area 'Windows Update' `
                    -Finding ("{0} update(s) pending" -f $pendCount) `
                    -Evidence $ev -FixKey 'windows-update'
            }
            $failures = @(Get-TriageProp $wu 'RecentFailures')
            if ($failures.Count -gt 0) {
                $codes = @()
                foreach ($f in $failures) {
                    $h = [string](Get-TriageProp $f 'HResult')
                    if ($h -and $codes -notcontains $h) { $codes += $h }
                }
                $found += New-TriageFinding -Severity WARNING -Area 'Windows Update' `
                    -Finding ("{0} recent update failure(s) in history" -f $failures.Count) `
                    -Evidence (($codes | Select-Object -First 4) -join ', ') `
                    -FixKey 'windows-update' `
                    -Recommend 'If the component store finding above fired, repair that first - same root cause more often than not.'
            }
        }
    }

    # --- Event signatures -----------------------------------------------
    $es = Get-TriageProp $Report 'EventSignatures'
    if ($es) {
        $counts = Get-TriageProp $es 'Counts'
        $windowDays = Get-TriageProp $es 'WindowDays'

        # Storage-layer events back a disk verdict with independent evidence -
        # these fire from the driver stack, not from SMART.
        $stormNames = @('BadBlock', 'PagingIoError', 'DiskIoRetry', 'DiskResetTimeout', 'DiskControllerError')
        $stormHits = @()
        foreach ($n in $stormNames) {
            $c = [int](Get-TriageProp $counts $n)
            if ($c -gt 0) { $stormHits += ('{0}={1}' -f $n, $c) }
        }
        if ($stormHits.Count -gt 0) {
            $found += New-TriageFinding -Severity CRITICAL -Area 'Disk' `
                -Finding ("Storage errors in the event log over {0} days" -f $windowDays) `
                -Evidence ($stormHits -join ', ') `
                -Recommend 'DATA FIRST. These are the driver stack reporting real I/O failures, independent of SMART.'
        }

        $ntfs = [int](Get-TriageProp $counts 'NtfsCorruption')
        if ($ntfs -gt 0) {
            $found += New-TriageFinding -Severity WARNING -Area 'Volume' `
                -Finding ("NTFS logged {0} corruption event(s) (provider-matched, not just ID 55)" -f $ntfs) `
                -Recommend 'chkdsk /scan once any critical disk finding is resolved or the data is off.'
        }

        $shutdown = [int](Get-TriageProp $counts 'UnexpectedShutdown')
        if ($shutdown -gt 0) {
            $found += New-TriageFinding -Severity WARNING -Area 'Crashes' `
                -Finding ("{0} unexpected shutdown(s) (Kernel-Power 41) in {1} days" -f $shutdown, $windowDays) `
                -Recommend 'Hard hangs and power losses leave no dump - the crash section below is the detail.'
        }

        $bugchecks = @(Get-TriageProp $es 'Bugchecks')
        if ($bugchecks.Count -gt 0) {
            $codes = @()
            foreach ($b in $bugchecks) {
                $c = [string](Get-TriageProp $b 'StopCode')
                if ($c -and $codes -notcontains $c) { $codes += $c }
            }
            $found += New-TriageFinding -Severity WARNING -Area 'Crashes' `
                -Finding ("{0} bugcheck(s) (blue screens) in {1} days" -f $bugchecks.Count, $windowDays) `
                -Evidence ($codes -join ', ')
        }

        $svc = [int](Get-TriageProp $counts 'ServiceCrash')
        $app = [int](Get-TriageProp $counts 'AppCrash')
        if (($svc + $app) -gt 5) {
            $found += New-TriageFinding -Severity INFO -Area 'Crashes' `
                -Finding ("{0} service crash(es), {1} app crash(es) in {2} days" -f $svc, $app, $windowDays)
        }
    }

    # --- Defender -------------------------------------------------------
    $def = Get-TriageProp $Report 'Defender'
    if ($def) {
        if (Test-TriageProp $def 'Error') {
            $found += New-TriageFinding -Severity INFO -Area 'Security' `
                -Finding 'Defender status unavailable - usually a third-party AV holding the role'
        }
        else {
            if ((Test-TriageProp $def 'RealTimeProtection') -and -not (Get-TriageProp $def 'RealTimeProtection')) {
                $found += New-TriageFinding -Severity WARNING -Area 'Security' `
                    -Finding 'Defender real-time protection is OFF' `
                    -Recommend 'Never auto-enabled by this tool: find out WHY it is off first - a third-party AV, a policy, or malware are three different jobs.'
            }
            $sigAge = Get-TriageProp $def 'SignatureAgeDays'
            if ($sigAge -gt 7) {
                $found += New-TriageFinding -Severity INFO -Area 'Security' `
                    -Finding ("Defender signatures are {0} days old" -f [int]$sigAge) `
                    -Recommend 'Updates once the machine is online - see the network finding if there is one.'
            }
        }
    }

    # --- Pending reboot -------------------------------------------------
    $pr = Get-TriageProp $Report 'PendingReboot'
    if ($pr -and (Get-TriageProp $pr 'Pending')) {
        $found += New-TriageFinding -Severity INFO -Area 'Reboot' `
            -Finding ('Reboot pending: ' + ((@(Get-TriageProp $pr 'Reasons')) -join ', ')) `
            -Recommend 'Reboot before judging anything servicing-related - half of these findings can be a reboot away from resolved.'
    }

    # --- Module results -------------------------------------------------
    $found += @(Get-TriageModuleFindings -ModuleResults $ModuleResults)

    foreach ($key in @($ModuleErrors.Keys | Sort-Object)) {
        $found += New-TriageFinding -Severity UNKNOWN -Area 'Scan' `
            -Finding ("Module '{0}' failed to run - its territory was NOT scanned" -f $key) `
            -Evidence ([string]$ModuleErrors[$key])
    }

    return @($found | Sort-Object -Property @{ Expression = { Get-TriageSeverityRank -Severity $_.Severity } }, Area)
}

# Adapters for the module results triage collects. Each adapter only reads
# properties it positively recognizes from that module's contract; a module
# this file does not know produces no findings here rather than invented ones
# (its own console output and report section still carry whatever it said).
function Get-TriageModuleFindings {
    param([hashtable]$ModuleResults = @{})

    $found = @()

    # bloatware: Counts.Consumer is the only tier it will auto-remove.
    $r = $ModuleResults['bloatware']
    if ($r) {
        $consumer = [int](Get-TriageProp (Get-TriageProp $r 'Counts') 'Consumer')
        if ($consumer -gt 0) {
            $found += New-TriageFinding -Severity INFO -Area 'Apps' `
                -Finding ("{0} consumer junk app(s) installed" -f $consumer) `
                -FixKey 'fix-bloatware'
        }
    }

    # startup: only enabled Optional-tier items are actionable.
    $r = $ModuleResults['startup']
    if ($r) {
        $optOn = 0
        foreach ($i in @(Get-TriageProp $r 'Items')) {
            if (((Get-TriageProp $i 'Tier') -eq 'Optional') -and (Get-TriageProp $i 'Enabled')) { $optOn++ }
        }
        if ($optOn -gt 0) {
            $found += New-TriageFinding -Severity INFO -Area 'Startup' `
                -Finding ("{0} optional startup item(s) enabled" -f $optOn) `
                -FixKey 'fix-startup' `
                -Recommend 'Disable, never delete - the customer can re-enable any of them from Task Manager.'
        }
    }

    # browser: the four repairable/flaggable classes count as a hijack signal;
    # hosts and DNS entries are report-only by that module's design.
    $r = $ModuleResults['browser']
    if ($r) {
        $hijacks = @(Get-TriageProp $r 'ShortcutHijacks').Count +
        @(Get-TriageProp $r 'ProxyFindings').Count +
        @(Get-TriageProp $r 'PolicyFindings').Count +
        @(Get-TriageProp $r 'ScheduledTasks').Count
        if ($hijacks -gt 0) {
            $found += New-TriageFinding -Severity WARNING -Area 'Browser' `
                -Finding ("{0} browser hijack indicator(s) found" -f $hijacks) `
                -FixKey 'fix-browser' `
                -Recommend 'The fix only touches the unambiguous ones (shortcut arguments, proxy) and backs up first. Extensions are never auto-removed.'
        }
        $hostsCount = @(Get-TriageProp $r 'HostsFindings').Count
        if ($hostsCount -gt 0) {
            $found += New-TriageFinding -Severity INFO -Area 'Browser' `
                -Finding ("hosts file has {0} non-default entr(ies) - reported, never auto-edited" -f $hostsCount)
        }
    }

    # network: FailedLayer is 'none' (the module's sentinel) or null when the
    # ladder passed end to end.
    $r = $ModuleResults['network']
    if ($r) {
        $layer = [string](Get-TriageProp $r 'FailedLayer')
        if ($layer -and $layer -ne 'none') {
            $detail = ''
            foreach ($rung in @(Get-TriageProp $r 'Rungs')) {
                if ((Get-TriageProp $rung 'Name') -eq $layer) { $detail = [string](Get-TriageProp $rung 'Detail') }
            }
            $found += New-TriageFinding -Severity WARNING -Area 'Network' `
                -Finding ("Connectivity fails at the '{0}' layer" -f $layer) `
                -Evidence $detail `
                -FixKey 'fix-network'
        }
    }

    # driver: report only - that module never rolls a driver back, so triage
    # never offers to.
    $r = $ModuleResults['driver']
    if ($r) {
        $devices = @(Get-TriageProp $r 'Devices')
        if ($devices.Count -gt 0) {
            $ev = @()
            foreach ($d in ($devices | Select-Object -First 3)) {
                $ev += ('{0}: {1}' -f [string](Get-TriageProp $d 'FriendlyName'), [string](Get-TriageProp $d 'Meaning'))
            }
            $found += New-TriageFinding -Severity WARNING -Area 'Drivers' `
                -Finding ("{0} device(s) reporting a driver or hardware problem" -f $devices.Count) `
                -Evidence ($ev -join '; ') `
                -Recommend 'The driver module printed which layer to check and the rollback commands. Nothing here runs them - the wrong storage rollback costs the boot.'
        }
    }

    # crashes: dumps are one signal; unclean shutdowns are a separate one
    # because a hard hang writes no dump at all.
    $r = $ModuleResults['crashes']
    if ($r) {
        $dumps = @(Get-TriageProp (Get-TriageProp $r 'Kernel') 'Dumps')
        if ($dumps.Count -gt 0) {
            $codes = @()
            foreach ($d in ($dumps | Select-Object -First 4)) {
                $c = [string](Get-TriageProp $d 'StopCode')
                if ($c -and $codes -notcontains $c) { $codes += $c }
            }
            $found += New-TriageFinding -Severity WARNING -Area 'Crashes' `
                -Finding ("{0} kernel crash dump(s) on this machine" -f $dumps.Count) `
                -Evidence ($codes -join ', ')
        }
        $hangs = Get-TriageProp $r 'Hangs'
        if ($hangs) {
            $hangStatus = [string](Get-TriageProp $hangs 'Status')
            if ($hangStatus -eq 'Read') {
                $unclean = [int](Get-TriageProp $hangs 'HardHangs') + [int](Get-TriageProp $hangs 'PowerLosses') + [int](Get-TriageProp $hangs 'Undetermined')
                if ($unclean -gt 0) {
                    $found += New-TriageFinding -Severity WARNING -Area 'Crashes' `
                        -Finding ("{0} unclean shutdown(s) - hangs and power losses write no dump" -f $unclean) `
                        -Evidence ('hard hangs {0}, power losses {1}, undetermined {2}' -f [int](Get-TriageProp $hangs 'HardHangs'), [int](Get-TriageProp $hangs 'PowerLosses'), [int](Get-TriageProp $hangs 'Undetermined'))
                }
            }
            else {
                $found += New-TriageFinding -Severity UNKNOWN -Area 'Crashes' `
                    -Finding 'Unclean-shutdown history could NOT be established' `
                    -Evidence ('shutdown event query status: ' + $hangStatus)
            }
        }
    }

    # clocks: the module curates its own findings list; anything in it is a
    # thing running off spec right now.
    $r = $ModuleResults['clocks']
    if ($r) {
        foreach ($f in @(Get-TriageProp $r 'Findings')) {
            if ($f) {
                $found += New-TriageFinding -Severity WARNING -Area 'Power' `
                    -Finding ([string]$f) `
                    -Recommend 'The clocks module output above has the specifics. Power plan changes stay a judgment call.'
            }
        }
    }

    # elevation: three verdict states, matched exactly.
    $r = $ModuleResults['elevation']
    if ($r) {
        $verdict = [string](Get-TriageProp $r 'Verdict')
        if ($verdict -eq 'CAUSE FOUND') {
            $found += New-TriageFinding -Severity WARNING -Area 'Elevation' `
                -Finding 'Something on this machine is blocking elevation' `
                -Evidence ([string](Get-TriageProp $r 'VerdictDetail')) `
                -Recommend 'The elevation module output names the rung. If the fix does not stick, bracket a reboot with -Phase Baseline / Compare.'
        }
        elseif ($verdict -eq 'COULD NOT ESTABLISH') {
            $found += New-TriageFinding -Severity UNKNOWN -Area 'Elevation' `
                -Finding 'Elevation health could NOT be established' `
                -Evidence ([string](Get-TriageProp $r 'VerdictDetail'))
        }
    }

    # codeintegrity: verdict states matched exactly; NOTHING LOGGED and
    # OTHER EVENTS ONLY are quiet machines.
    $r = $ModuleResults['codeintegrity']
    if ($r) {
        $verdict = [string](Get-TriageProp $r 'Verdict')
        $detail = [string](Get-TriageProp $r 'VerdictDetail')
        if ($verdict -eq 'POLICY IS BLOCKING' -or $verdict -eq 'SIGNING-LEVEL FAILURES, POLICY PRESENT') {
            $found += New-TriageFinding -Severity WARNING -Area 'Policy' `
                -Finding ('Code Integrity: ' + $verdict) -Evidence $detail
        }
        elseif ($verdict -eq 'COULD NOT ESTABLISH') {
            $found += New-TriageFinding -Severity UNKNOWN -Area 'Policy' `
                -Finding 'Code Integrity state could NOT be established' -Evidence $detail
        }
        elseif ($verdict -eq 'SIGNING-LEVEL NOISE') {
            $found += New-TriageFinding -Severity INFO -Area 'Policy' `
                -Finding 'Code Integrity: signing-level noise only - usually one Winsock provider, not a blocked program' -Evidence $detail
        }
    }

    return @($found)
}
