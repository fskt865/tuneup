# Test-Triage.ps1 - pins the triage judgment rules in lib\Triage.ps1.
# Pure-function tests: no machine access, no elevation, changes nothing.
# ASCII only, PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path (Split-Path -Parent $here) 'lib\Triage.ps1')

$script:Pass = 0
$script:Fail = 0

function Assert {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:Pass++
        Write-Host ('  ok   ' + $Name) -ForegroundColor Green
    }
    else {
        $script:Fail++
        Write-Host ('  FAIL ' + $Name) -ForegroundColor Red
    }
}

function Find-Where {
    param($Findings, [scriptblock]$Filter)
    # PS 5.1 unrolls the returned array: one hit arrives as the bare finding,
    # whose .Count is $null. Every caller therefore wraps this in @( ) - a
    # comma-wrap here instead would break the multi-hit case the same way.
    return @(@($Findings) | Where-Object $Filter)
}

# --- Fixture builders ------------------------------------------------------
# Reports are built the way the collector builds them: PSCustomObject on top,
# [ordered] hashtables nested. The engine must not care which it gets.
function New-HealthyReport {
    return [pscustomobject]@{
        Elevated = $true
        Disks    = @([ordered]@{
                FriendlyName = 'TESTDISK M.2'; MediaType = 'SSD'; BusType = 'NVMe'
                SizeGB = 512; HealthStatus = 'Healthy'; OperationalStatus = 'OK'
                SmartStatus = 'Read'; Wear = 3; TemperatureC = 38
                ReadErrorsTotal = 0; WriteErrorsTotal = 0; PowerOnHours = 900
            })
        Volumes  = @([ordered]@{
                DriveLetter = 'C'; FileSystem = 'NTFS'; DriveType = 'Fixed'
                SizeGB = 512; FreePercent = 40; HealthStatus = 'Healthy'
            })
        ComponentStore  = [ordered]@{ ExitCode = 0; Verdict = 'Healthy' }
        WindowsUpdate   = [ordered]@{ PendingCount = 0; Pending = @(); RecentFailures = @() }
        EventSignatures = [ordered]@{ WindowDays = 30; Bugchecks = @(); Counts = @{
                UnexpectedShutdown = 0; DiskControllerError = 0; BadBlock = 0; PagingIoError = 0
                DiskIoRetry = 0; DiskResetTimeout = 0; NtfsCorruption = 0; ServiceCrash = 0; AppCrash = 0
            }
        }
        Defender      = [ordered]@{ RealTimeProtection = $true; AntivirusEnabled = $true; SignatureAgeDays = 1; TamperProtection = $true }
        PendingReboot = [ordered]@{ Pending = $false; Reasons = @() }
    }
}

Write-Host ''
Write-Host 'Triage: healthy elevated machine' -ForegroundColor White

$f = @(Get-TriageFindings -Report (New-HealthyReport) -SystemDriveLetter 'C')
Assert (@(Find-Where $f { $_.Severity -eq 'CRITICAL' }).Count -eq 0) 'healthy machine: no criticals'
Assert (@(Find-Where $f { $_.Severity -eq 'WARNING' }).Count -eq 0) 'healthy machine: no warnings'
Assert (@(Find-Where $f { $_.Severity -eq 'UNKNOWN' }).Count -eq 0) 'healthy machine: no unknowns'
Assert ((@(Get-TriageFixPlan -Findings $f)).Count -eq 0) 'healthy machine: empty fix plan'

Write-Host ''
Write-Host 'Triage: three states, never two' -ForegroundColor White

# Unelevated: SMART and the component store were NOT read. That must surface
# as UNKNOWN findings - silence here would read as a clean bill of health.
$r = New-HealthyReport
$r.Elevated = $false
$r.Disks[0].SmartStatus = 'RequiresElevation'
$r.Disks[0].Wear = $null; $r.Disks[0].TemperatureC = $null
$r.Disks[0].ReadErrorsTotal = $null; $r.Disks[0].WriteErrorsTotal = $null
$r.ComponentStore = [ordered]@{ ExitCode = $null; Verdict = 'RequiresElevation' }
$f = @(Get-TriageFindings -Report $r -SystemDriveLetter 'C')
Assert (@(Find-Where $f { $_.Severity -eq 'UNKNOWN' -and $_.Area -eq 'Session' }).Count -eq 1) 'unelevated: session finding fires'
Assert (@(Find-Where $f { $_.Severity -eq 'UNKNOWN' -and $_.Area -eq 'Disk' }).Count -eq 1) 'unelevated: SMART not-read is UNKNOWN, not silence'
Assert (@(Find-Where $f { $_.Severity -eq 'UNKNOWN' -and $_.Area -eq 'OS servicing' }).Count -eq 1) 'unelevated: component store not-checked is UNKNOWN'
Assert (@(Find-Where $f { $_.Severity -eq 'CRITICAL' }).Count -eq 0) 'unelevated: no invented criticals'

# A small USB stick that cannot pass SMART through is expected, INFO only.
$r = New-HealthyReport
$r.Disks += [ordered]@{
    FriendlyName = 'PNY USB 2.0 FD'; MediaType = 'Unspecified'; BusType = 'USB'
    SizeGB = 14.4; HealthStatus = 'Healthy'; OperationalStatus = 'OK'
    SmartStatus = 'Unsupported'
}
$f = @(Get-TriageFindings -Report $r -SystemDriveLetter 'C')
Assert (@(Find-Where $f { $_.Area -eq 'Disk' -and $_.Severity -eq 'INFO' }).Count -eq 1) 'small USB stick without SMART: INFO, not UNKNOWN'

# The same Unsupported on a big USB disk is a real gap in the verdict.
$r = New-HealthyReport
$r.Disks[0].BusType = 'USB'; $r.Disks[0].SizeGB = 2000; $r.Disks[0].SmartStatus = 'Unsupported'
$f = @(Get-TriageFindings -Report $r -SystemDriveLetter 'C')
Assert (@(Find-Where $f { $_.Area -eq 'Disk' -and $_.Severity -eq 'UNKNOWN' }).Count -eq 1) 'large USB disk without SMART: UNKNOWN'

Write-Host ''
Write-Host 'Triage: failing disk and the data-first gate' -ForegroundColor White

$r = New-HealthyReport
$r.Disks[0].HealthStatus = 'Warning'
$r.Disks[0].ReadErrorsTotal = 12
$r.EventSignatures.Counts['BadBlock'] = 4
$r.ComponentStore = [ordered]@{ ExitCode = 0; Verdict = 'Repairable' }
$r.WindowsUpdate = [ordered]@{ PendingCount = 3; Pending = @([ordered]@{ KB = 'KB5031234'; Severity = ''; SizeMB = 100 }); RecentFailures = @() }
$f = @(Get-TriageFindings -Report $r -SystemDriveLetter 'C')
Assert (@(Find-Where $f { $_.Severity -eq 'CRITICAL' -and $_.Area -eq 'Disk' }).Count -eq 3) 'failing disk: health, media errors and event storm are three separate criticals'
Assert (Test-TriageDataFirst -Findings $f) 'failing disk: data-first mode set'

$plan = @(Get-TriageFixPlan -Findings $f)
$repair = @($plan | Where-Object { $_.FixKey -eq 'repair-store' })
$update = @($plan | Where-Object { $_.FixKey -eq 'windows-update' })
Assert ($repair.Count -eq 1) 'repairable store: repair-store fix offered'
Assert ($repair[0].Gated) 'data-first: repair-store (heavy I/O) is GATED'
Assert ($update.Count -eq 1) 'pending updates: windows-update fix offered'
Assert ($update[0].Gated) 'data-first: windows-update (heavy I/O) is GATED'

# Same store verdict on a healthy disk: nothing gated.
$r = New-HealthyReport
$r.ComponentStore = [ordered]@{ ExitCode = 0; Verdict = 'Repairable' }
$f = @(Get-TriageFindings -Report $r -SystemDriveLetter 'C')
$plan = @(Get-TriageFixPlan -Findings $f)
Assert (-not (Test-TriageDataFirst -Findings $f)) 'healthy disk: no data-first mode'
Assert ((@($plan | Where-Object { $_.Gated })).Count -eq 0) 'healthy disk: nothing gated'

Write-Host ''
Write-Host 'Triage: fix plan dedupe' -ForegroundColor White

$r = New-HealthyReport
$r.WindowsUpdate = [ordered]@{
    PendingCount = 12
    Pending = @([ordered]@{ KB = 'KB5031234'; Severity = ''; SizeMB = 100 })
    RecentFailures = @([ordered]@{ ResultCode = 4; HResult = '0x80070002'; Operation = 1 })
}
$f = @(Get-TriageFindings -Report $r -SystemDriveLetter 'C')
$wuFindings = @(Find-Where $f { $_.FixKey -eq 'windows-update' })
$plan = @(Get-TriageFixPlan -Findings $f)
$wuPlan = @($plan | Where-Object { $_.FixKey -eq 'windows-update' })
Assert ($wuFindings.Count -eq 2) 'pending + failures: two findings'
Assert ($wuPlan.Count -eq 1) 'pending + failures: ONE deduped plan entry'
Assert (@($wuPlan[0].Reasons).Count -eq 2) 'deduped entry carries both reasons'

Write-Host ''
Write-Host 'Triage: volume rules' -ForegroundColor White

$r = New-HealthyReport
$r.Volumes = @(
    [ordered]@{ DriveLetter = 'C'; FileSystem = 'NTFS'; DriveType = 'Fixed'; SizeGB = 500; FreePercent = 3; HealthStatus = 'Healthy' },
    [ordered]@{ DriveLetter = 'D'; FileSystem = 'NTFS'; DriveType = 'Fixed'; SizeGB = 500; FreePercent = 4; HealthStatus = 'Healthy' }
)
$f = @(Get-TriageFindings -Report $r -SystemDriveLetter 'C')
$sysLow = @(Find-Where $f { $_.Area -eq 'Volume' -and $_.Finding -like 'Volume C*' })
$dataLow = @(Find-Where $f { $_.Area -eq 'Volume' -and $_.Finding -like 'Volume D*' })
Assert ($sysLow.Count -eq 1 -and $sysLow[0].FixKey -eq 'clean-temp') 'low system volume: clean-temp offered'
Assert ($dataLow.Count -eq 1 -and -not $dataLow[0].FixKey) 'low data volume: reported, no automated fix'

Write-Host ''
Write-Host 'Triage: module adapters' -ForegroundColor White

$mods = @{
    'clocks'  = [pscustomobject]@{ Findings = @('CPU capped by power policy on AC') }
    'network' = [pscustomobject]@{ FailedLayer = 'DNS'; Rungs = @([ordered]@{ Name = 'DNS'; Ok = $false; Detail = 'resolution failed for all probes' }) }
    'browser' = [pscustomobject]@{ ShortcutHijacks = @(1); ProxyFindings = @(); PolicyFindings = @(); ScheduledTasks = @(); HostsFindings = @(); DnsFindings = @() }
    'codeintegrity' = [pscustomobject]@{ Verdict = 'NOTHING LOGGED'; VerdictDetail = '' }
    'elevation' = [pscustomobject]@{ Verdict = 'NO BLOCKING CONDITION FOUND' }
    'crashes' = [pscustomobject]@{
        Kernel = [ordered]@{ Status = 'Read'; Dumps = @() }
        Hangs  = [ordered]@{ Status = 'NoLog'; HardHangs = 0; PowerLosses = 0; Undetermined = 0 }
    }
    'startup' = [pscustomobject]@{ Items = @(
            [ordered]@{ Name = 'Vendor Updater'; Tier = 'Optional'; Enabled = $true },
            [ordered]@{ Name = 'Audio Service'; Tier = 'Protected'; Enabled = $true }
        )
    }
    'bloatware' = [pscustomobject]@{ Counts = @{ Consumer = 5; Optional = 2; Protected = 8; SystemComponent = 40; Unclassified = 3 } }
}
$f = @(Get-TriageFindings -Report (New-HealthyReport) -ModuleResults $mods -SystemDriveLetter 'C')

Assert (@(Find-Where $f { $_.Area -eq 'Power' -and $_.Severity -eq 'WARNING' }).Count -eq 1) 'clocks findings surface as warnings'
$net = @(Find-Where $f { $_.Area -eq 'Network' })
Assert ($net.Count -eq 1 -and $net[0].FixKey -eq 'fix-network' -and $net[0].Evidence -like '*resolution failed*') 'network failed layer: warning with rung detail'

# 'none' is the module's all-rungs-passed sentinel, not a layer name. Caught
# on the first live run: a healthy machine was told its network failed.
$fNone = @(Get-TriageFindings -Report (New-HealthyReport) -SystemDriveLetter 'C' -ModuleResults @{
        'network' = [pscustomobject]@{ FailedLayer = 'none'; Rungs = @() }
    })
Assert ((@(Find-Where $fNone { $_.Area -eq 'Network' })).Count -eq 0) 'network sentinel none: silent, ladder passed'
$br = @(Find-Where $f { $_.Area -eq 'Browser' })
Assert ($br.Count -eq 1 -and $br[0].FixKey -eq 'fix-browser') 'one hijack indicator: browser fix offered'
Assert (@(Find-Where $f { $_.Area -eq 'Policy' }).Count -eq 0) 'codeintegrity NOTHING LOGGED: silent'
Assert (@(Find-Where $f { $_.Area -eq 'Elevation' }).Count -eq 0) 'elevation NO BLOCKING CONDITION: silent'
$hang = @(Find-Where $f { $_.Area -eq 'Crashes' -and $_.Severity -eq 'UNKNOWN' })
Assert ($hang.Count -eq 1) 'hang history unreadable: UNKNOWN, never a pass'
$su = @(Find-Where $f { $_.Area -eq 'Startup' })
Assert ($su.Count -eq 1 -and $su[0].Finding -like '1 optional*') 'startup: only enabled Optional items counted'
$bw = @(Find-Where $f { $_.Area -eq 'Apps' })
Assert ($bw.Count -eq 1 -and $bw[0].FixKey -eq 'fix-bloatware') 'bloatware: consumer count surfaces with fix'

# A module that died must leave a hole the tech can see.
$f = @(Get-TriageFindings -Report (New-HealthyReport) -ModuleErrors @{ 'network' = 'boom' } -SystemDriveLetter 'C')
$dead = @(Find-Where $f { $_.Area -eq 'Scan' -and $_.Severity -eq 'UNKNOWN' })
Assert ($dead.Count -eq 1 -and $dead[0].Finding -like "*'network'*") 'failed module: UNKNOWN finding names it'

Write-Host ''
Write-Host 'Triage: severity ordering' -ForegroundColor White

$r = New-HealthyReport
$r.Elevated = $false
$r.Disks[0].HealthStatus = 'Warning'
$r.ComponentStore = [ordered]@{ ExitCode = 0; Verdict = 'Repairable' }
$f = @(Get-TriageFindings -Report $r -SystemDriveLetter 'C')
Assert ($f[0].Severity -eq 'CRITICAL') 'criticals sort first'
$ranks = @($f | ForEach-Object { Get-TriageSeverityRank -Severity $_.Severity })
$sorted = $true
for ($i = 1; $i -lt $ranks.Count; $i++) { if ($ranks[$i] -lt $ranks[$i - 1]) { $sorted = $false } }
Assert $sorted 'findings arrive sorted by severity'

# --- Summary ---------------------------------------------------------------
Write-Host ''
Write-Host ('  {0} passed, {1} failed' -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { 'Green' } else { 'Red' })
if ($script:Fail -gt 0) { exit 1 }
exit 0
