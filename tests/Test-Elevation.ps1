# Test-Elevation.ps1 - decoders, verdict logic and the no-names invariant.
# ASCII only, PowerShell 5.1 compatible. Changes nothing.
#
# The verdict tests are the ones that matter. Every branch below decides which
# layer a tech spends the next hour on, and three of them encode asymmetries
# that are easy to get backwards:
#
#   - ConsentPromptBehaviorUser=0 is a fault for a standard user and NOT a
#     fault for an administrator. Same value, opposite meaning.
#   - A filtered admin token (member, in token, not elevated) is the HEALTHY
#     state. Reporting it as broken sends the tech after UAC on a working
#     machine.
#   - Membership is tri-state. Unreadable must not be scored as "not a member".

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'lib\Modules.ps1')

$ModulePath = Join-Path $Root 'modules\Get-ElevationStatus.ps1'
. $ModulePath

$pass = 0
$fail = 0

function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  PASS  " + $Name) -ForegroundColor Green; $script:pass++ }
    else { Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red; $script:fail++ }
}

# A facts object with nothing wrong. Every verdict test starts from this and
# breaks exactly one thing, so a failure names its own cause.
function New-HealthyFacts {
    return [pscustomobject]@{
        TokenReadable       = $true
        PolicyReadable      = $true
        MembershipReadable  = $true
        IsElevated          = $false
        AdminSidInToken     = $true
        ElevationType       = 3
        UserIsAdminMember   = $true
        AppInfoStatus       = 'Running'
        AppInfoStartType    = 'Manual'
        ServiceFailureEvents = 0
        IfeoOnCriticalExe   = @()
        VerbProblems        = @()
        EnableLua           = 1
        ConsentUser         = 3
        ValidateAdminCodeSignatures = 0
        RemovableDenyExecute = $false
        SrpDefaultLevel     = $null
        CodeIntegrityBlocks = 0
        AppLockerBlocks     = 0
        RunningStateMismatch = $false
        MismatchDetail      = ''
        UnsignedBinaryCount = 0
    }
}

Write-Host ''
Write-Host '  Manifest' -ForegroundColor Cyan
Write-Host '  --------' -ForegroundColor DarkGray

$mods = Get-TuneUpModules -ModuleRoot (Join-Path $Root 'modules')
$me = @($mods | Where-Object { $_.Key -eq 'elevation' }) | Select-Object -First 1
Assert-True 'The elevation module is discovered' ($null -ne $me)

# Load-bearing: this module exists for a machine that cannot elevate. If it
# ever gets marked RequiresAdmin the menu will warn that results are partial
# on precisely the machine where it is the only thing that works.
if ($me) {
    Assert-True 'It does NOT require admin (it runs on the broken machine)' (-not $me.RequiresAdmin)
    Assert-True 'It defines its entry point' ($null -ne (Get-Command -Name $me.Entry -ErrorAction SilentlyContinue))
}

Write-Host ''
Write-Host '  Decoders' -ForegroundColor Cyan
Write-Host '  --------' -ForegroundColor DarkGray

Assert-True 'Elevation type 3 is described as the healthy filtered state' `
((Get-ElevationTypeMeaning -Type 3) -match 'Limited')
Assert-True 'Elevation type 2 reads as already elevated' `
((Get-ElevationTypeMeaning -Type 2) -match 'Full')
Assert-True 'Elevation type 1 does not claim the account is fine' `
((Get-ElevationTypeMeaning -Type 1) -match 'no split token')
Assert-True 'An unreadable elevation type says so rather than guessing' `
((Get-ElevationTypeMeaning -Type $null) -match 'could not be read')

Assert-True 'ConsentPromptBehaviorUser 0 is called out as a silent denial' `
((Get-ConsentUserMeaning -Value 0) -match 'AUTOMATICALLY DENY')
Assert-True 'ConsentPromptBehaviorUser unset reports the Windows default' `
((Get-ConsentUserMeaning -Value $null) -match 'default')
Assert-True 'ConsentPromptBehaviorAdmin 0 is described as never prompting' `
((Get-ConsentAdminMeaning -Value 0) -match 'without prompting')
Assert-True 'ConsentPromptBehaviorAdmin 5 is named the Windows default' `
((Get-ConsentAdminMeaning -Value 5) -match 'default')

Assert-True 'High integrity SID decodes' ((Get-IntegrityLevelName -Sid 'S-1-16-12288') -eq 'High')
Assert-True 'Medium integrity SID decodes' ((Get-IntegrityLevelName -Sid 'S-1-16-8192') -eq 'Medium')
Assert-True 'An unknown integrity SID is not guessed at' ((Get-IntegrityLevelName -Sid 'S-1-16-999') -eq 'unknown')

Write-Host ''
Write-Host '  Run-as verb' -ForegroundColor Cyan
Write-Host '  -----------' -ForegroundColor DarkGray

Assert-True 'Stock exefile runas command passes' (Test-RunAsCommandSane -Actual '"%1" %*' -Expected '"%1" %*')
Assert-True 'Trailing whitespace still passes' (Test-RunAsCommandSane -Actual '  "%1" %*  ' -Expected '"%1" %*')
Assert-True 'A hijacked command fails' (-not (Test-RunAsCommandSane -Actual 'C:\bad\thing.exe "%1"' -Expected '"%1" %*'))
Assert-True 'A missing command fails rather than passing by default' (-not (Test-RunAsCommandSane -Actual $null -Expected '"%1" %*'))
Assert-True 'An empty command fails too' (-not (Test-RunAsCommandSane -Actual '' -Expected '"%1" %*'))

# REGRESSION. This fired on a healthy machine on the first real run.
# batfile and cmdfile store an ALREADY-EXPANDED absolute path, not the
# %SystemRoot% form, and the casing of that path varies between installs.
# Exact-matching them reported a verb hijack on a clean machine.
$realBat = 'C:\WINDOWS\System32\cmd.exe /C "%1" %*'
Assert-True 'The real-world batfile runas value passes the structural check' `
(Test-RunAsCommandSane -Actual $realBat -MustContain @('cmd.exe', '"%1"'))
Assert-True 'A differently-cased system path still passes' `
(Test-RunAsCommandSane -Actual 'C:\Windows\system32\CMD.EXE /C "%1" %*' -MustContain @('cmd.exe', '"%1"'))
Assert-True 'A batfile verb redirected away from cmd.exe fails' `
(-not (Test-RunAsCommandSane -Actual 'C:\bad\thing.exe /C "%1" %*' -MustContain @('cmd.exe', '"%1"')))
Assert-True 'A batfile verb that no longer passes the file fails' `
(-not (Test-RunAsCommandSane -Actual 'C:\WINDOWS\System32\cmd.exe /C badthing' -MustContain @('cmd.exe', '"%1"')))

# Live: whatever this machine actually has must not read as a hijack.
$liveHijack = Get-HijackFindings
Assert-True 'Live: this machine reports no verb hijack' (@($liveHijack.VerbProblems).Count -eq 0) `
("problems=" + (@($liveHijack.VerbProblems) -join '; '))

Write-Host ''
Write-Host '  Verdict' -ForegroundColor Cyan
Write-Host '  -------' -ForegroundColor DarkGray

$v = Get-ElevationVerdict -Facts (New-HealthyFacts)
Assert-True 'A healthy machine reports no blocking condition' ($v.State -eq 'NO BLOCKING CONDITION FOUND') ("got=" + $v.State)

# The healthy baseline is a filtered admin. If this ever starts producing a
# cause, the module is calling working UAC broken.
Assert-True 'A filtered admin token is not reported as a fault' ($v.Causes.Count -eq 0) ("causes=" + ($v.Causes -join ' | '))

$f = New-HealthyFacts; $f.TokenReadable = $false
$v = Get-ElevationVerdict -Facts $f
Assert-True 'An unreadable token gives COULD NOT ESTABLISH, not a pass' ($v.State -eq 'COULD NOT ESTABLISH') ("got=" + $v.State)

$f = New-HealthyFacts; $f.MembershipReadable = $false
$v = Get-ElevationVerdict -Facts $f
Assert-True 'Unreadable group membership gives COULD NOT ESTABLISH' ($v.State -eq 'COULD NOT ESTABLISH')

# A real cause outranks an unknown: something IS wrong, say what.
$f = New-HealthyFacts; $f.PolicyReadable = $false; $f.AppInfoStartType = 'DISABLED'
$v = Get-ElevationVerdict -Facts $f
Assert-True 'A found cause outranks an unknown rung' ($v.State -eq 'CAUSE FOUND')
Assert-True 'The unknown is still reported alongside it' ($v.Unknowns.Count -gt 0)

$f = New-HealthyFacts; $f.AppInfoStartType = 'DISABLED'
$v = Get-ElevationVerdict -Facts $f
Assert-True 'Disabled AppInfo is a cause' (($v.Causes -join ' ') -match 'Application Information')

# Manual + Stopped is AppInfo's normal resting state - it starts on demand.
# Reporting it as a fault would flag almost every healthy Windows machine.
$f = New-HealthyFacts; $f.AppInfoStatus = 'Stopped'; $f.AppInfoStartType = 'Manual'
$v = Get-ElevationVerdict -Facts $f
Assert-True 'Stopped+Manual AppInfo alone is NOT a cause' ($v.Causes.Count -eq 0) ("causes=" + ($v.Causes -join ' | '))

$f = New-HealthyFacts; $f.AppInfoStatus = 'Stopped'; $f.AppInfoStartType = 'Manual'; $f.ServiceFailureEvents = 4
$v = Get-ElevationVerdict -Facts $f
Assert-True 'Stopped AppInfo WITH service failures is a cause' ($v.Causes.Count -eq 1)

$f = New-HealthyFacts; $f.EnableLua = 0
$v = Get-ElevationVerdict -Facts $f
Assert-True 'EnableLUA=0 is a cause' (($v.Causes -join ' ') -match 'EnableLUA')

# The asymmetry. Same registry value, opposite meaning by account type.
$f = New-HealthyFacts; $f.ConsentUser = 0; $f.UserIsAdminMember = $false; $f.AdminSidInToken = $false
$v = Get-ElevationVerdict -Facts $f
Assert-True 'ConsentUser=0 is a cause for a standard user' (($v.Causes -join ' ') -match 'denied automatically')

$f = New-HealthyFacts; $f.ConsentUser = 0
$v = Get-ElevationVerdict -Facts $f
Assert-True 'ConsentUser=0 is NOT a cause for an administrator' (($v.Causes -join ' ') -notmatch 'denied automatically')

$f = New-HealthyFacts; $f.ConsentUser = 0; $f.UserIsAdminMember = $null; $f.MembershipReadable = $false
$v = Get-ElevationVerdict -Facts $f
Assert-True 'ConsentUser=0 with UNKNOWN membership is not scored as a denial' `
(($v.Causes -join ' ') -notmatch 'denied automatically')

# The stale-token case. No UAC repair fixes it and it is routinely misread.
# Type 1 is the real thing: in the group, but no split token in the session.
$f = New-HealthyFacts; $f.UserIsAdminMember = $true; $f.AdminSidInToken = $false
$f.IsElevated = $false; $f.ElevationType = 1
$v = Get-ElevationVerdict -Facts $f
Assert-True 'Group membership absent from the token is reported as stale' (($v.Causes -join ' ') -match 'granted after sign-in')

$f = New-HealthyFacts; $f.IsElevated = $true; $f.AdminSidInToken = $true; $f.ElevationType = 2
$v = Get-ElevationVerdict -Facts $f
Assert-True 'An already-elevated session is not reported as stale' (($v.Causes -join ' ') -notmatch 'granted after sign-in')

# REGRESSION. This fired on a healthy machine on the first real run.
# .NET WindowsIdentity.Groups omits deny-only groups, so a filtered
# administrator looks exactly like an account whose membership never reached
# the token. TokenElevationType 3 proves a split token exists and therefore
# that the membership DID reach it - so type 3 must veto the stale verdict
# even when the admin SID appears to be missing.
$f = New-HealthyFacts; $f.AdminSidInToken = $false; $f.ElevationType = 3
$v = Get-ElevationVerdict -Facts $f
Assert-True 'A filtered admin with unreadable group SIDs is NOT called stale' `
(($v.Causes -join ' ') -notmatch 'granted after sign-in') ("causes=" + ($v.Causes -join ' | '))

$f = New-HealthyFacts; $f.IfeoOnCriticalExe = @('consent.exe')
$v = Get-ElevationVerdict -Facts $f
Assert-True 'An IFEO debugger on consent.exe is a cause' (($v.Causes -join ' ') -match 'IFEO Debugger')

$f = New-HealthyFacts; $f.ValidateAdminCodeSignatures = 1
$v = Get-ElevationVerdict -Facts $f
Assert-True 'ValidateAdminCodeSignatures=1 is a cause' (($v.Causes -join ' ') -match 'validly signed')

$f = New-HealthyFacts; $f.RemovableDenyExecute = $true
$v = Get-ElevationVerdict -Facts $f
Assert-True 'Removable-media execute denial is a cause' (($v.Causes -join ' ') -match 'removable disks')

$f = New-HealthyFacts; $f.SrpDefaultLevel = 0
$v = Get-ElevationVerdict -Facts $f
Assert-True 'SRP default Disallowed is a cause' (($v.Causes -join ' ') -match 'Software Restriction')

# 262144 is Basic User and 40960 is Unrestricted. Neither blocks everything,
# and treating "SRP is configured" as "SRP is blocking" would fire on any
# managed fleet.
$f = New-HealthyFacts; $f.SrpDefaultLevel = 262144
$v = Get-ElevationVerdict -Facts $f
Assert-True 'A non-zero SRP default level is not a cause' (($v.Causes -join ' ') -notmatch 'Software Restriction')

$f = New-HealthyFacts; $f.RunningStateMismatch = $true; $f.MismatchDetail = 'test detail'
$v = Get-ElevationVerdict -Facts $f
Assert-True 'A running-versus-registry mismatch is a cause' (($v.Causes -join ' ') -match 'does not match its registry state')

$f = New-HealthyFacts; $f.UnsignedBinaryCount = 1
$v = Get-ElevationVerdict -Facts $f
Assert-True 'An unsigned elevation binary is a cause' (($v.Causes -join ' ') -match 'signature check')

Write-Host ''
Write-Host '  Snapshot comparison' -ForegroundColor Cyan
Write-Host '  -------------------' -ForegroundColor DarkGray

function New-Snapshot {
    param([int]$EnableLua = 1, [string]$AppInfo = 'Running/Manual', [string[]]$Ifeo = @())
    return [pscustomobject]@{
        TakenAt       = (Get-Date).ToString('o')
        Values        = [pscustomobject]@{ EnableLUA = $EnableLua; ConsentPromptBehaviorAdmin = 5 }
        Services      = [pscustomobject]@{ Appinfo = $AppInfo }
        IfeoDebuggers = $Ifeo
        PolicyWrite   = $null
    }
}

$a = New-Snapshot
$b = New-Snapshot
Assert-True 'Identical snapshots produce no changes' ((Compare-UacSnapshot -Before $a -After $b).Count -eq 0)

$b = New-Snapshot -EnableLua 0
$changes = Compare-UacSnapshot -Before $a -After $b
Assert-True 'A UAC value change is detected' (($changes -join ' ') -match 'EnableLUA: 1 -> 0')

$b = New-Snapshot -AppInfo 'Stopped/DISABLED'
$changes = Compare-UacSnapshot -Before $a -After $b
Assert-True 'A service state change is detected' (($changes -join ' ') -match 'service Appinfo')

$b = New-Snapshot -Ifeo @('consent.exe')
$changes = Compare-UacSnapshot -Before $a -After $b
Assert-True 'A newly appearing IFEO debugger is detected' (($changes -join ' ') -match 'appeared on consent.exe')

$a2 = New-Snapshot -Ifeo @('consent.exe')
$changes = Compare-UacSnapshot -Before $a2 -After (New-Snapshot)
Assert-True 'A removed IFEO debugger is detected' (($changes -join ' ') -match 'removed from consent.exe')

# The bug this pins: Get-UacSnapshot used to hand back [ordered] hashtables,
# whose .PSObject.Properties are Keys/Values/Count rather than the entries.
# Comparison then found nothing to compare and Watch reported "nothing moved"
# no matter what happened - a check that cannot fail is not a check.
$live = Get-UacSnapshot
Assert-True 'Get-UacSnapshot returns comparable property bags, not dictionaries' `
(@($live.Values.PSObject.Properties.Name) -contains 'EnableLUA') `
("names=" + (@($live.Values.PSObject.Properties.Name) -join ','))
Assert-True 'A live snapshot compares clean against itself' `
((Compare-UacSnapshot -Before $live -After (Get-UacSnapshot)).Count -eq 0)

Write-Host ''
Write-Host '  Event queries' -ForegroundColor Cyan
Write-Host '  -------------' -ForegroundColor DarkGray

# A query that legitimately matches nothing must come back READABLE with zero,
# not unreadable. Get-WinEvent raises "No events were found" as a terminating
# error for an empty result, so the naive catch turns every clean check into
# an unknown - and the report then cannot tell "checked, nothing there" from
# "never checked".
$e = Get-ProviderEventCount -LogName 'System' -ProviderName 'Service Control Manager' -Ids @(31337) -Days 1
Assert-True 'An empty result is readable with a count of zero' ($e.Readable -and $e.Count -eq 0) `
("readable=" + $e.Readable + " count=" + $e.Count + " reason=" + $e.Reason)

# And a provider that does not exist must not be reported as a clean zero.
$e = Get-ProviderEventCount -LogName 'System' -ProviderName 'No-Such-Provider-Exists' -Ids @(1) -Days 1
Assert-True 'A bad provider is reported as unreadable, not as zero' (-not $e.Readable) ("reason=" + $e.Reason)

Write-Host ''
Write-Host '  Customer-data invariant' -ForegroundColor Cyan
Write-Host '  -----------------------' -ForegroundColor DarkGray

# The hard rule for this tree. Administrators group members are account names;
# they go to the console and the local log, both of which stay on the
# customer's machine, but they must never reach the object that gets folded
# into the report written to the stick. Account SIDs are fine - the sanitizer
# turns S-1-5-21-... into <SID> and leaves well-known SIDs alone.
$src = Get-Content -LiteralPath $ModulePath -Raw
$idx = $src.LastIndexOf('return [pscustomobject]@{')
Assert-True 'The module ends with a returned result object' ($idx -gt 0)
if ($idx -gt 0) {
    $returned = $src.Substring($idx)
    Assert-True 'Account NAMES are not in the returned report object' ($returned -notmatch 'DisplayNames')
    Assert-True 'Member SIDs are (they redact to <SID> downstream)' ($returned -match 'AdminMemberSids')
    Assert-True 'Defender exclusion PATHS are not returned, only the count' `
    ($returned -notmatch 'ExclusionPath')
}

# Live check: whatever this machine actually reports must survive the
# sanitizer. Runs against the tech's own machine, changes nothing.
$membership = Get-AdminMembership
if ($membership.Readable) {
    Assert-True 'Live: group enumeration returned at least one SID' (@($membership.MemberSids).Count -ge 1)
    $probe = [pscustomobject]@{ AdminMemberSids = $membership.MemberSids }
    $json = Protect-Object -InputObject $probe | ConvertTo-Json -Depth 5
    $verify = Test-SanitizedText -Text $json
    Assert-True 'Live: returned member SIDs pass the sanitizer' $verify.Clean ("hits=" + ($verify.Hits -join ','))
}
else {
    Write-Host '  SKIP  live group enumeration (unreadable on this machine)' -ForegroundColor Yellow
}

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
