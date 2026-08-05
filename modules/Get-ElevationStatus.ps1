<#MANIFEST
{
  "Key": "elevation",
  "Title": "Elevation and UAC failure diagnosis",
  "Entry": "Invoke-ElevationModule",
  "Order": 12,
  "RequiresAdmin": false,
  "Description": "Nothing will run as administrator - which layer is refusing, and is something rewriting UAC behind you"
}
MANIFEST#>

# Get-ElevationStatus.ps1 - why will nothing run as administrator?
# ASCII only, PowerShell 5.1 compatible. READ ONLY - reports, never changes.
#
# RequiresAdmin is false and that is load-bearing, not laziness. This module
# exists for a machine that cannot elevate, so every rung has to produce an
# answer from a standard-user session. The rungs that genuinely need elevation
# (some event logs) are marked RequiresElevation rather than reported as clean.
# A blank must never read as a pass - same rule as the rest of the toolkit.
#
# THE LADDER. Elevation is not one thing, and "run as administrator does
# nothing" is produced by at least eight different faults that look identical
# from the customer's chair. Walk them in this order, because a failure at a
# low rung makes every rung above it untestable:
#
#   1  TOKEN      what this session actually is. Standard user, filtered admin,
#                 or already elevated. Everything else is read in this light.
#   2  MEMBERSHIP is the account in Administrators at all, and does the running
#                 token know it. Those are different questions - see below.
#   3  SERVICE    AppInfo performs elevation. Stopped or disabled, every
#                 request fails, usually with no prompt and no error.
#   4  POLICY     the UAC values under Policies\System. One of them
#                 (ConsentPromptBehaviorUser=0) silently denies every request.
#   5  HIJACK     IFEO debuggers, SilentProcessExit, and the runas verb. This
#                 is the rung where "I click Yes and nothing happens" lives.
#   6  RESTRICTION SRP, AppLocker, WDAC/Smart App Control, DisallowRun, and
#                 removable-media execute denial. These block the launch, not
#                 the elevation - a distinction that changes the whole repair.
#   7  TAMPER     is the current state stable, or is something rewriting it.
#                 Registry write times versus last boot, and running state
#                 versus registry state.
#   8  EVIDENCE   provider-filtered event counts that corroborate 1-7.
#
# WHAT IT WILL NOT DO. It changes nothing. UAC, SRP, AppLocker and WDAC are
# security configuration; on a managed machine they are also somebody's policy,
# and on an infected one turning UAC back on before the infection is dealt with
# just gets reverted. It prints the exact command for each fix and stops there.
#
# ON "A VIRUS IS TURNING UAC OFF". That is a hypothesis this module TESTS, it
# is not an assumption it starts from. UAC settings reverting has an innocent
# twin - a domain or MDM policy refresh putting them back every 90 minutes -
# and a single look at the registry cannot tell the two apart. Rung 7 is what
# separates them: who owns the value, when it was last written relative to
# boot, and whether it moves while you watch it.

$script:UacPolicyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$script:UacPolicySub = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$script:BaselinePath = Join-Path $env:ProgramData 'GSTuneUp\uac-baseline.json'

# ---------------------------------------------------------------------------
# Native helpers.
#
# Both of these degrade to $null rather than throwing. Add-Type compiles C# at
# runtime, which is one of the things a locked-down or damaged machine may not
# be able to do - and this module has to keep working on exactly those.
# ---------------------------------------------------------------------------
$script:NativeState = 'unknown'

function Initialize-ElevationNative {
    if ($script:NativeState -eq 'ready') { return $true }
    if ($script:NativeState -eq 'failed') { return $false }

    try {
        Add-Type -Namespace GSElev -Name Native -ErrorAction Stop -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
    out int TokenInformation, int TokenInformationLength, out int ReturnLength);

[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int RegQueryInfoKey(IntPtr hKey, System.Text.StringBuilder lpClass,
    ref int lpcbClass, IntPtr lpReserved, out int lpcSubKeys, out int lpcbMaxSubKeyLen,
    out int lpcbMaxClassLen, out int lpcValues, out int lpcbMaxValueNameLen,
    out int lpcbMaxValueLen, out int lpcbSecurityDescriptor, out long lpftLastWriteTime);
'@
        $script:NativeState = 'ready'
        return $true
    }
    catch {
        Write-Log -Message ('Native helpers unavailable (token type and key write times will be blank): ' + $_.Exception.Message) -Level WARN -Quiet
        $script:NativeState = 'failed'
        return $false
    }
}

# TokenElevationType, class 18. This is the single most informative value in
# the whole module: it says what UAC is doing to THIS session right now,
# independently of what the registry claims it should be doing.
function Get-TokenElevationType {
    if (-not (Initialize-ElevationNative)) { return $null }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $val = 0
        $len = 0
        if ([GSElev.Native]::GetTokenInformation($id.Token, 18, [ref]$val, 4, [ref]$len)) { return $val }
    }
    catch { }
    return $null
}

# When a registry key was last written. Compared against last boot in rung 7:
# a UAC policy value written after the machine came up was written by
# something that is running on it.
function Get-KeyLastWriteTime {
    param(
        [ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [Parameter(Mandatory = $true)][string]$SubKey
    )
    if (-not (Initialize-ElevationNative)) { return $null }

    $key = $null
    try {
        $root = [Microsoft.Win32.Registry]::LocalMachine
        if ($Hive -eq 'HKCU') { $root = [Microsoft.Win32.Registry]::CurrentUser }
        $key = $root.OpenSubKey($SubKey, $false)
        if (-not $key) { return $null }

        $cls = New-Object System.Text.StringBuilder 256
        $clsLen = 256
        $subKeys = 0; $maxSub = 0; $maxCls = 0; $values = 0
        $maxName = 0; $maxVal = 0; $sd = 0
        $ft = [long]0

        $rc = [GSElev.Native]::RegQueryInfoKey($key.Handle.DangerousGetHandle(), $cls, [ref]$clsLen,
            [IntPtr]::Zero, [ref]$subKeys, [ref]$maxSub, [ref]$maxCls, [ref]$values,
            [ref]$maxName, [ref]$maxVal, [ref]$sd, [ref]$ft)
        if ($rc -ne 0) { return $null }
        return [DateTime]::FromFileTime($ft)
    }
    catch { return $null }
    finally { if ($key) { try { $key.Close() } catch { } } }
}

# ---------------------------------------------------------------------------
# Registry reading with three states, not two.
#
# "Value absent" and "could not read the key" are different findings and the
# difference matters here more than anywhere: an unreadable Policies\System is
# itself suspicious, and reporting it as "not set" would hand a tech a clean
# bill of health from a check that never ran.
# ---------------------------------------------------------------------------
function Read-RegValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $out = [pscustomobject]@{
        Name     = $Name
        Value    = $null
        Present  = $false
        Readable = $false
        Error    = ''
    }

    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $out.Readable = $true
        $v = $key.GetValue($Name, $null)
        if ($null -ne $v) {
            $out.Present = $true
            $out.Value = $v
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        # The key itself is absent. That is a readable answer: nothing is set.
        $out.Readable = $true
    }
    catch {
        $out.Error = $_.Exception.Message
    }

    return $out
}

function Get-RegDefault {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        return [string]$key.GetValue('', '')
    }
    catch { return $null }
}

# ---------------------------------------------------------------------------
# Pure decoders. No machine access, so the test suite can pin every branch -
# these are where a wrong answer sends a tech to the wrong layer.
# ---------------------------------------------------------------------------
function Get-ElevationTypeMeaning {
    param($Type)
    switch ([string]$Type) {
        '1' { return 'Default - this session has no split token. UAC is off, or the account has no administrator token at all.' }
        '2' { return 'Full - this session is already elevated.' }
        '3' { return 'Limited - filtered administrator. This is the healthy state: elevation is available and has to be asked for.' }
        default { return 'could not be read' }
    }
}

function Get-ConsentAdminMeaning {
    param($Value)
    switch ([string]$Value) {
        '0' { return 'Elevate without prompting - no prompt ever appears for an administrator. Reported as "it never asks", not as "it never works".' }
        '1' { return 'Prompt for credentials on the secure desktop' }
        '2' { return 'Prompt for consent on the secure desktop' }
        '3' { return 'Prompt for credentials' }
        '4' { return 'Prompt for consent' }
        '5' { return 'Prompt for consent for non-Windows binaries (Windows default)' }
        default { return 'not set - Windows default (5) applies' }
    }
}

function Get-ConsentUserMeaning {
    param($Value)
    switch ([string]$Value) {
        '0' { return 'AUTOMATICALLY DENY elevation requests - a standard user gets no prompt and nothing runs.' }
        '1' { return 'Prompt for credentials on the secure desktop' }
        '3' { return 'Prompt for credentials (Windows default)' }
        default { return 'not set - Windows default (3) applies' }
    }
}

function Get-IntegrityLevelName {
    param([string]$Sid)
    switch ($Sid) {
        'S-1-16-0'     { return 'Untrusted' }
        'S-1-16-4096'  { return 'Low' }
        'S-1-16-8192'  { return 'Medium' }
        'S-1-16-8448'  { return 'Medium Plus' }
        'S-1-16-12288' { return 'High' }
        'S-1-16-16384' { return 'System' }
        default        { return 'unknown' }
    }
}

# The runas verb. A hijack here is why right-click "Run as administrator" can
# do nothing at all while the machine is otherwise healthy.
#
# Only exefile gets an exact-match test. Its stock value really is the literal
# string "%1" %* on every build. batfile and cmdfile do NOT: Windows stores an
# already-expanded absolute path there, so a real machine holds
#   C:\WINDOWS\System32\cmd.exe /C "%1" %*
# and not the %SystemRoot% form the documentation implies. Exact-matching
# those reported a verb hijack on a perfectly healthy machine - and a
# diagnostic that cries hijack on a clean machine is worse than no diagnostic,
# because it sends a tech hunting malware that is not there. Check structure
# (does it still invoke cmd.exe with the file) rather than an exact string.
$script:ExpectedVerbs = @(
    @{ Class = 'exefile'; Verb = 'runas'; Expected = '"%1" %*'; MustContain = @() },
    @{ Class = 'exefile'; Verb = 'open';  Expected = '"%1" %*'; MustContain = @() },
    @{ Class = 'batfile'; Verb = 'runas'; Expected = '';        MustContain = @('cmd.exe', '"%1"') },
    @{ Class = 'cmdfile'; Verb = 'runas'; Expected = '';        MustContain = @('cmd.exe', '"%1"') }
)

function Test-RunAsCommandSane {
    param(
        [AllowNull()][string]$Actual,
        [string]$Expected = '',
        [string[]]$MustContain = @()
    )
    if ([string]::IsNullOrEmpty($Actual)) { return $false }
    $a = $Actual.Trim()
    if ($Expected) { return ($a -eq $Expected.Trim()) }
    foreach ($needle in $MustContain) {
        # IndexOf with an explicit comparison, not -like: these needles carry
        # % and " and the path casing varies (C:\WINDOWS vs C:\Windows).
        if ($a.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    }
    return $true
}

# ---------------------------------------------------------------------------
# RUNG 1 + 2. Token facts and Administrators membership.
#
# These are two questions and conflating them is the classic mistake:
#
#   in the group + in the token, filtered   normal, elevation should work
#   in the group + NOT in the token         membership added since sign-in.
#                                           The token is stale; sign out and
#                                           back in. No amount of UAC repair
#                                           fixes this and it is common after
#                                           somebody "made them an admin".
#   NOT in the group                        elevation will ask for someone
#                                           else's credentials, and if
#                                           ConsentPromptBehaviorUser is 0 it
#                                           will not even do that.
# ---------------------------------------------------------------------------
# Every SID in this token, including the two kinds .NET will not give you.
#
# [WindowsIdentity]::GetCurrent().Groups omits BOTH of the things this module
# needs most: groups marked SE_GROUP_USE_FOR_DENY_ONLY, and the mandatory
# integrity label. On a filtered administrator that is precisely the
# interesting state - S-1-5-32-544 is in the token as deny-only, and .NET
# reports it as simply absent. Trusting .NET here reported a healthy filtered
# admin as having a stale token, which is a wrong answer that sends the tech
# to sign the customer out for no reason.
#
# whoami /groups lists the raw token. Parsed by SID with a regex rather than
# by column, because the CSV headers and the attribute text are localised and
# the SIDs are not.
function Get-TokenGroupSids {
    $sids = @()
    try {
        $raw = & whoami.exe '/groups' 2>$null | Out-String
        foreach ($m in [regex]::Matches($raw, '\bS-1-\d+(?:-\d+)+\b')) { $sids += $m.Value }
    }
    catch { }
    return @($sids | Sort-Object -Unique)
}

function Get-TokenFacts {
    $WhatIfPreference = $false

    $out = [pscustomobject]@{
        IsElevated        = $false
        ElevationType     = $null
        ElevationMeaning  = ''
        IntegritySid      = ''
        IntegrityLevel    = 'unknown'
        UserSid           = ''
        IsBuiltInAdmin    = $false
        AdminSidInToken   = $false
        GroupSids         = @()
        Readable          = $true
    }

    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        $out.IsElevated = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $out.UserSid = [string]$id.User.Value
        # RID 500 is the built-in Administrator on every Windows install. It
        # legitimately runs unfiltered when FilterAdministratorToken is 0, so
        # it must not be reported as a UAC fault.
        $out.IsBuiltInAdmin = ($out.UserSid -match '-500$')

        $sids = @()
        foreach ($g in $id.Groups) {
            try { $sids += [string]$g.Value } catch { }
        }
        # Union with the raw token. .NET is the fast path; whoami is the one
        # that actually sees deny-only groups and the integrity label.
        foreach ($s in (Get-TokenGroupSids)) {
            if ($sids -notcontains $s) { $sids += $s }
        }
        $out.GroupSids = $sids
        $out.AdminSidInToken = ($sids -contains 'S-1-5-32-544')

        $label = @($sids | Where-Object { $_ -like 'S-1-16-*' }) | Select-Object -First 1
        if ($label) {
            $out.IntegritySid = $label
            $out.IntegrityLevel = Get-IntegrityLevelName -Sid $label
        }
    }
    catch {
        $out.Readable = $false
    }

    $out.ElevationType = Get-TokenElevationType
    $out.ElevationMeaning = Get-ElevationTypeMeaning -Type $out.ElevationType
    return $out
}

# Membership via ADSI, deliberately not Get-LocalGroupMember.
#
# Get-LocalGroupMember throws "Failed to compare two elements in the array" on
# any machine whose Administrators group holds an orphaned SID - an account
# deleted from a domain, or an Azure AD principal the machine can no longer
# resolve. That is not rare, and the failure reads like a permissions problem
# while actually telling you nothing. ADSI returns the orphans as SIDs.
#
# Member NAMES never leave this function. They go to the console, which stays
# on the customer's machine; only SIDs and counts go into the returned object,
# and the sanitizer turns account SIDs into <SID> on the way out.
function Get-AdminMembership {
    $WhatIfPreference = $false

    $out = [pscustomobject]@{
        Readable       = $false
        Error          = ''
        MemberCount    = 0
        MemberSids     = @()
        DisplayNames   = @()
        CurrentUserIsMember = $false
        BuiltInAdminEnabled = $null
    }

    try {
        $grp = [ADSI]('WinNT://./Administrators,group')
        $members = @($grp.psbase.Invoke('Members'))
        foreach ($m in $members) {
            $name = ''
            $sid = ''
            try { $name = [string]$m.GetType().InvokeMember('Name', 'GetProperty', $null, $m, $null) } catch { }
            try {
                $bytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
                if ($bytes) { $sid = (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value }
            }
            catch { }
            if ($name) { $out.DisplayNames += $name }
            if ($sid) { $out.MemberSids += $sid }
        }
        $out.MemberCount = @($members).Count
        $out.Readable = $true
    }
    catch {
        $out.Error = $_.Exception.Message
    }

    # Is the built-in Administrator account usable? Relevant only as a fallback
    # route when the customer's own account cannot elevate.
    try {
        $acct = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop |
            Where-Object { $_.SID -match '-500$' } | Select-Object -First 1
        if ($acct) { $out.BuiltInAdminEnabled = (-not $acct.Disabled) }
    }
    catch { }

    return $out
}

function Test-CurrentUserInAdmins {
    param($Token, $Membership)
    if (-not $Membership.Readable) { return $null }
    if ($Membership.MemberSids -contains $Token.UserSid) { return $true }
    foreach ($g in $Token.GroupSids) {
        if ($g -eq 'S-1-5-32-544') { continue }
        if ($Membership.MemberSids -contains $g) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# RUNG 3. The service that actually performs elevation.
#
# AppInfo (Application Information) is what launches an elevated process after
# consent. Stopped or disabled, every elevation request fails - commonly with
# no prompt at all, sometimes with error 740, and on some builds with nothing
# whatsoever. It is the single most common mechanical cause of "run as
# administrator does nothing" that is not malware, and it is a 10-second fix,
# so it is checked before anything harder.
# ---------------------------------------------------------------------------
$script:ElevationServices = @(
    @{ Name = 'Appinfo';  Label = 'Application Information (performs elevation)'; Critical = $true },
    @{ Name = 'RpcSs';    Label = 'Remote Procedure Call (AppInfo depends on it)'; Critical = $true },
    @{ Name = 'seclogon'; Label = 'Secondary Logon (Run as different user)';       Critical = $false },
    @{ Name = 'AppIDSvc'; Label = 'Application Identity (enforces AppLocker)';     Critical = $false },
    @{ Name = 'ProfSvc';  Label = 'User Profile Service';                          Critical = $false }
)

function Get-ElevationServiceState {
    $WhatIfPreference = $false
    $out = @()

    foreach ($svc in $script:ElevationServices) {
        $row = [pscustomobject]@{
            Name = $svc.Name; Label = $svc.Label; Critical = $svc.Critical
            Status = 'unknown'; StartType = 'unknown'; Readable = $false
        }
        try {
            $s = Get-Service -Name $svc.Name -ErrorAction Stop
            $row.Status = [string]$s.Status
            $row.Readable = $true
            # Get-Service.StartType is unreliable on 5.1 for some services;
            # the registry Start value is the authority and needs no elevation.
            $start = Read-RegValue -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $svc.Name) -Name 'Start'
            if ($start.Present) {
                switch ([int]$start.Value) {
                    0 { $row.StartType = 'Boot' }
                    1 { $row.StartType = 'System' }
                    2 { $row.StartType = 'Automatic' }
                    3 { $row.StartType = 'Manual' }
                    4 { $row.StartType = 'DISABLED' }
                    default { $row.StartType = 'unknown' }
                }
            }
        }
        catch { }
        $out += $row
    }
    return $out
}

# ---------------------------------------------------------------------------
# RUNG 4. UAC policy values.
# ---------------------------------------------------------------------------
$script:UacValues = @(
    @{ Name = 'EnableLUA';                  Default = 1; Note = 'UAC master switch. 0 disables UAC entirely and needs a reboot to take effect.' },
    @{ Name = 'ConsentPromptBehaviorAdmin'; Default = 5; Note = 'What an administrator is asked.' },
    @{ Name = 'ConsentPromptBehaviorUser';  Default = 3; Note = 'What a standard user is asked. 0 denies silently.' },
    @{ Name = 'PromptOnSecureDesktop';      Default = 1; Note = 'Dim the desktop for the prompt. If the secure desktop cannot paint, the prompt never appears.' },
    @{ Name = 'FilterAdministratorToken';   Default = 0; Note = 'Whether the built-in Administrator gets a filtered token too.' },
    @{ Name = 'EnableInstallerDetection';   Default = 1; Note = 'Detect installers and request elevation for them.' },
    @{ Name = 'ValidateAdminCodeSignatures'; Default = 0; Note = '1 blocks elevation of anything not validly signed - a silent failure after you click Yes.' },
    @{ Name = 'EnableSecureUIAPaths';       Default = 1; Note = 'Restrict UIAccess applications to secure locations.' },
    @{ Name = 'EnableVirtualization';       Default = 1; Note = 'Redirect legacy per-machine writes to per-user locations.' }
)

function Get-UacPolicy {
    $WhatIfPreference = $false

    $out = [pscustomobject]@{
        Readable      = $true
        Error         = ''
        Values        = @()
        LastWriteTime = $null
        NonDefault    = @()
    }

    foreach ($v in $script:UacValues) {
        $r = Read-RegValue -Path $script:UacPolicyKey -Name $v.Name
        if ($r.Error) { $out.Readable = $false; $out.Error = $r.Error }

        $effective = $v.Default
        if ($r.Present) { $effective = [int]$r.Value }

        $row = [pscustomobject]@{
            Name      = $v.Name
            Set       = $r.Present
            Value     = $(if ($r.Present) { [int]$r.Value } else { $null })
            Effective = $effective
            Default   = $v.Default
            IsDefault = ($effective -eq $v.Default)
            Note      = $v.Note
            Readable  = ($r.Error -eq '')
        }
        $out.Values += $row
        if (-not $row.IsDefault) { $out.NonDefault += $v.Name }
    }

    $out.LastWriteTime = Get-KeyLastWriteTime -Hive 'HKLM' -SubKey $script:UacPolicySub
    return $out
}

function Get-UacValue {
    param($Policy, [string]$Name)
    $row = @($Policy.Values | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if (-not $row) { return $null }
    return $row.Effective
}

# ---------------------------------------------------------------------------
# RUNG 5. Hijacks - the rung where "I click Yes and nothing happens" lives.
#
# Image File Execution Options is a supported debugging feature: a Debugger
# value under an executable's name makes Windows launch that debugger INSTEAD
# of the executable. Pointed at consent.exe it eats the elevation. Pointed at
# anything else it eats that program. SilentProcessExit does a similar job
# from the other end.
#
# Executable names are product facts, not customer data, so they are safe to
# report. Nothing here reads a command line into the report - a Debugger value
# is a path and paths can carry a profile name.
# ---------------------------------------------------------------------------
$script:IfeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$script:SilentExitRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'

# Checked by name because these are the ones that make elevation itself fail,
# rather than making one application fail.
$script:ElevationCriticalExes = @('consent.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe',
    'explorer.exe', 'msconfig.exe', 'mmc.exe', 'regedit.exe', 'taskmgr.exe',
    'msiexec.exe', 'rundll32.exe', 'userinit.exe', 'UserAccountControlSettings.exe')

function Get-HijackFindings {
    $WhatIfPreference = $false

    $out = [pscustomobject]@{
        IfeoReadable        = $false
        IfeoDebuggerCount   = 0
        IfeoDebuggerNames   = @()
        IfeoOnCriticalExe   = @()
        SilentExitNames     = @()
        VerbProblems        = @()
        PerUserClassOverride = @()
        VerbsReadable       = $true
    }

    # --- IFEO ---------------------------------------------------------
    try {
        $keys = Get-ChildItem -LiteralPath $script:IfeoRoot -ErrorAction Stop
        $out.IfeoReadable = $true
        foreach ($k in $keys) {
            $dbg = $k.GetValue('Debugger', $null)
            if ($dbg) {
                $out.IfeoDebuggerCount++
                $out.IfeoDebuggerNames += $k.PSChildName
                if ($script:ElevationCriticalExes -contains $k.PSChildName) {
                    $out.IfeoOnCriticalExe += $k.PSChildName
                }
            }
        }
    }
    catch { }

    # --- SilentProcessExit --------------------------------------------
    try {
        foreach ($k in (Get-ChildItem -LiteralPath $script:SilentExitRoot -ErrorAction Stop)) {
            $mon = $k.GetValue('MonitorProcess', $null)
            $flags = $k.GetValue('ReportingMode', $null)
            if ($mon -or $flags) { $out.SilentExitNames += $k.PSChildName }
        }
    }
    catch { }

    # --- runas / open verbs -------------------------------------------
    # HKCU\Software\Classes wins over HKLM\SOFTWARE\Classes for the logged-on
    # user. A per-user override is therefore invisible if you only look at the
    # merged HKCR view from an elevated session running as somebody else -
    # which is exactly how this one gets missed.
    foreach ($v in $script:ExpectedVerbs) {
        $machinePath = 'HKLM:\SOFTWARE\Classes\{0}\shell\{1}\command' -f $v.Class, $v.Verb
        $userPath = 'HKCU:\Software\Classes\{0}\shell\{1}\command' -f $v.Class, $v.Verb

        $machine = Get-RegDefault -Path $machinePath
        if ($null -eq $machine) {
            # Absent runas verb on exefile is itself the fault: no verb, no
            # "Run as administrator" entry and no way to invoke one.
            if ($v.Verb -eq 'runas') {
                $out.VerbProblems += ('{0}\{1} is missing entirely' -f $v.Class, $v.Verb)
            }
        }
        elseif (-not (Test-RunAsCommandSane -Actual $machine -Expected $v.Expected -MustContain $v.MustContain)) {
            $out.VerbProblems += ('{0}\{1} does not match the stock command' -f $v.Class, $v.Verb)
        }

        $user = Get-RegDefault -Path $userPath
        if ($null -ne $user) {
            $out.PerUserClassOverride += ('{0}\{1}' -f $v.Class, $v.Verb)
        }
    }

    return $out
}

# ---------------------------------------------------------------------------
# RUNG 6. Restrictions that block the LAUNCH rather than the elevation.
#
# The distinction is the whole point of this rung. If SRP or AppLocker or
# Smart App Control is refusing the binary, UAC is innocent and every minute
# spent on UAC is wasted. The symptom is nearly identical: a prompt that never
# comes, or a Yes that does nothing.
#
# The removable-media check is here because a toolkit on a USB stick meets a
# restriction ordinary local software never does: Group Policy can deny
# execute on removable disks outright, which is common on managed fleets.
# ---------------------------------------------------------------------------
function Get-RestrictionFindings {
    param([string]$ToolkitPath)
    $WhatIfPreference = $false

    $out = [pscustomobject]@{
        SrpDefaultLevel      = $null
        SrpActive            = $false
        AppLockerRuleTypes   = @()
        AppLockerActive      = $false
        SmartAppControlState = $null
        SacSupported         = $false
        OsBuild              = 0
        DisallowRun          = $false
        RestrictRun          = $false
        RemovableDenyExecute = $false
        ToolkitDriveType     = 'unknown'
        ToolkitOnRemovable   = $false
        ToolkitFileSystem    = ''
    }

    # Software Restriction Policy. DefaultLevel 0 is "Disallowed" - everything
    # not explicitly allowed is blocked.
    $srp = Read-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' -Name 'DefaultLevel'
    if ($srp.Present) {
        $out.SrpDefaultLevel = [int]$srp.Value
        $out.SrpActive = $true
    }

    # AppLocker rule collections that actually contain rules.
    try {
        foreach ($k in (Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2' -ErrorAction Stop)) {
            $ruleCount = @(Get-ChildItem -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).Count
            if ($ruleCount -gt 0) {
                $out.AppLockerRuleTypes += ('{0} ({1} rules)' -f $k.PSChildName, $ruleCount)
                $out.AppLockerActive = $true
            }
        }
    }
    catch { }

    # Smart App Control / WDAC reputation policy. On Windows 11 this blocks
    # unsigned binaries with no UAC involvement whatsoever, and an unsigned
    # bench utility on a stick is precisely its target.
    # Smart App Control needs Windows 11 22H2 (build 22621). Below that the
    # registry value may still be absent OR present and meaningless, and
    # naming the feature anyway is how this module produced a confident wrong
    # answer on a Windows 10 machine.
    try {
        $osb = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $out.OsBuild = [int]$osb.BuildNumber
    }
    catch { }
    $out.SacSupported = ($out.OsBuild -ge 22621)

    $sac = Read-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState'
    if ($sac.Present) { $out.SmartAppControlState = [int]$sac.Value }

    foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
                        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer')) {
        $dr = Read-RegValue -Path $hive -Name 'DisallowRun'
        if ($dr.Present -and [int]$dr.Value -ne 0) { $out.DisallowRun = $true }
        $rr = Read-RegValue -Path $hive -Name 'RestrictRun'
        if ($rr.Present -and [int]$rr.Value -ne 0) { $out.RestrictRun = $true }
    }

    # Removable disks class GUID. Deny_Execute here stops anything on the
    # stick from running at all - which reads exactly like UAC being broken
    # if you are only ever launching things from the stick.
    $removableClass = '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
    foreach ($hive in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices',
                        'HKCU:\Software\Policies\Microsoft\Windows\RemovableStorageDevices')) {
        $de = Read-RegValue -Path ($hive + '\' + $removableClass) -Name 'Deny_Execute'
        if ($de.Present -and [int]$de.Value -ne 0) { $out.RemovableDenyExecute = $true }
    }

    # Where is the toolkit actually running from?
    if ($ToolkitPath -and $ToolkitPath.Length -ge 2 -and $ToolkitPath[1] -eq ':') {
        $letter = $ToolkitPath.Substring(0, 1)
        try {
            $vol = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $letter + ":'") -ErrorAction Stop
            if ($vol) {
                $out.ToolkitFileSystem = [string]$vol.FileSystem
                switch ([int]$vol.DriveType) {
                    2 { $out.ToolkitDriveType = 'Removable'; $out.ToolkitOnRemovable = $true }
                    3 { $out.ToolkitDriveType = 'Fixed' }
                    4 { $out.ToolkitDriveType = 'Network' }
                    5 { $out.ToolkitDriveType = 'Optical' }
                    default { $out.ToolkitDriveType = 'other' }
                }
            }
        }
        catch { }
    }

    return $out
}

# ---------------------------------------------------------------------------
# RUNG 7. Tamper evidence - is the state stable, or is something rewriting it?
#
# Three independent signals, because any one of them alone has an innocent
# explanation:
#
#   A. RUNNING STATE vs REGISTRY STATE. EnableLUA only takes effect at boot.
#      So if the registry says one thing and this session's token says
#      another, the value was changed after the machine came up. That is a
#      fact about time, not an inference, and it is the strongest single piece
#      of evidence available without watching.
#   B. KEY WRITE TIME vs LAST BOOT. Same argument, from the other side.
#   C. SIGNATURES on the binaries that implement elevation.
#
# None of these proves malware on its own. A managed machine gets its UAC
# values rewritten by policy refresh, which trips A and B exactly the same
# way - which is why domain and MDM enrolment are reported right beside them.
# ---------------------------------------------------------------------------
$script:ElevationBinaries = @(
    'System32\consent.exe',
    'System32\appinfo.dll',
    'System32\userinit.exe',
    'System32\UserAccountControlSettings.exe'
)

function Get-TamperFindings {
    param($Token, $Policy)
    $WhatIfPreference = $false

    $out = [pscustomobject]@{
        LastBoot            = $null
        PolicyWrittenAfterBoot = $null
        MinutesSincePolicyWrite = $null
        RunningStateMismatch = $false
        MismatchDetail      = ''
        DomainJoined        = $null
        MdmEnrolled         = $false
        UnsignedBinaries    = @()
        SignatureCheckRan   = $false
        DefenderReadable    = $false
        RealTimeProtection  = $null
        TamperProtection    = $null
        SignatureAgeDays    = $null
        ExclusionCount      = $null
        BroadExclusion      = $false
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $out.LastBoot = $os.LastBootUpTime
    }
    catch { }

    if ($Policy.LastWriteTime -and $out.LastBoot) {
        $out.PolicyWrittenAfterBoot = ($Policy.LastWriteTime -gt $out.LastBoot)
        $out.MinutesSincePolicyWrite = [math]::Round(((Get-Date) - $Policy.LastWriteTime).TotalMinutes, 1)
    }

    # --- A. running state versus registry state -------------------------
    $enableLua = Get-UacValue -Policy $Policy -Name 'EnableLUA'
    $filterAdmin = Get-UacValue -Policy $Policy -Name 'FilterAdministratorToken'
    $type = $Token.ElevationType

    if ($null -ne $type -and $null -ne $enableLua) {
        if ($enableLua -eq 0 -and $type -eq 3) {
            $out.RunningStateMismatch = $true
            $out.MismatchDetail = 'The registry says UAC is OFF but this session still has a filtered token, so UAC is running. EnableLUA was set to 0 after this boot - or a reboot is pending. Nothing has taken effect yet.'
        }
        elseif ($enableLua -eq 1 -and $type -eq 1 -and -not $Token.IsBuiltInAdmin) {
            $out.RunningStateMismatch = $true
            $out.MismatchDetail = 'The registry says UAC is ON but this session has no filtered token, so UAC is NOT running. The machine booted with UAC off and the value has been set back to 1 since. UAC is off right now whatever Security Centre shows, and stays off until a reboot.'
        }
        elseif ($enableLua -eq 1 -and $type -eq 1 -and $Token.IsBuiltInAdmin -and $filterAdmin -eq 0) {
            # Built-in Administrator with Admin Approval Mode off. Expected,
            # not a fault, and must not be reported as one.
            $out.MismatchDetail = 'Running as the built-in Administrator with Admin Approval Mode off. An unfiltered token is expected here and is not a fault.'
        }
    }

    # --- management ------------------------------------------------------
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $out.DomainJoined = [bool]$cs.PartOfDomain
    }
    catch { }
    try {
        $enrol = Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop
        foreach ($e in $enrol) {
            $t = $e.GetValue('EnrollmentType', 0)
            if ([int]$t -gt 0) { $out.MdmEnrolled = $true }
        }
    }
    catch { }

    # --- C. signatures ---------------------------------------------------
    foreach ($rel in $script:ElevationBinaries) {
        $p = Join-Path $env:SystemRoot $rel
        if (-not (Test-Path -LiteralPath $p)) {
            $out.UnsignedBinaries += ($rel + ' (MISSING)')
            continue
        }
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
            $out.SignatureCheckRan = $true
            if ($sig.Status -ne 'Valid') {
                $out.UnsignedBinaries += ('{0} ({1})' -f $rel, $sig.Status)
            }
            elseif ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
                $out.UnsignedBinaries += ($rel + ' (signed by a non-Microsoft publisher)')
            }
        }
        catch { }
    }

    # --- Defender --------------------------------------------------------
    # Malware that turns UAC off almost always turns real-time protection off
    # too, or excludes its own directory. Reported as counts and booleans:
    # exclusion PATHS are not collected, they routinely contain a profile name.
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        $out.DefenderReadable = $true
        $out.RealTimeProtection = [bool]$st.RealTimeProtectionEnabled
        $out.TamperProtection = [bool]$st.IsTamperProtected
        $out.SignatureAgeDays = [int]$st.AntivirusSignatureAge
    }
    catch { }
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $paths = @($pref.ExclusionPath)
        $out.ExclusionCount = $paths.Count
        foreach ($x in $paths) {
            if ([string]::IsNullOrWhiteSpace($x)) { continue }
            $trimmed = $x.TrimEnd('\')
            # A whole-drive or whole-profile-root exclusion is not a tuning
            # choice, it is a hole big enough to hide anything in.
            if ($trimmed -match '^[A-Za-z]:$' -or $trimmed -match '^[A-Za-z]:\\Users$' -or
                $trimmed -match '^[A-Za-z]:\\Windows$' -or $trimmed -match '^[A-Za-z]:\\ProgramData$') {
                $out.BroadExclusion = $true
            }
        }
    }
    catch { }

    return $out
}

# ---------------------------------------------------------------------------
# RUNG 8. Corroborating events.
#
# Every query names a PROVIDER as well as an ID. Counting bare IDs across a
# log is how the toolkit once reported 84 benign power events as NTFS
# corruption - IDs are only unique within their provider. Message bodies are
# never read into the report; they are full of paths.
# ---------------------------------------------------------------------------
function Get-ProviderEventCount {
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][string]$ProviderName,
        [Parameter(Mandatory = $true)][int[]]$Ids,
        [int]$Days = 14
    )

    $out = [pscustomobject]@{
        Log = $LogName; Provider = $ProviderName; Ids = $Ids
        Count = 0; Readable = $false; Reason = ''
    }

    try {
        $filter = @{
            LogName      = $LogName
            ProviderName = $ProviderName
            Id           = $Ids
            StartTime    = (Get-Date).AddDays(-$Days)
        }
        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
        $out.Count = $events.Count
        $out.Readable = $true
    }
    catch {
        # "No events were found" is a successful query with a zero result and
        # must not be reported as unreadable - that would turn a clean check
        # into an unknown and hide a real answer.
        if ($_.Exception.Message -match 'No events were found') {
            $out.Readable = $true
            $out.Count = 0
        }
        elseif ($_.Exception.Message -match 'Attempted to perform an unauthorized operation|access is denied') {
            $out.Reason = 'RequiresElevation'
        }
        else {
            $out.Reason = $_.Exception.Message
        }
    }
    return $out
}

function Get-ElevationEvents {
    param([int]$Days = 14)
    $WhatIfPreference = $false

    # 3033/3034 and 3076/3077 are NOT the same finding and must never be added
    # together. A signing-level failure is a load refused inside a process -
    # usually an injection into something that will not accept it - and arrives
    # in storms of hundreds on perfectly healthy machines. A WDAC policy event
    # is a program actually being refused. Summing them produced a confident
    # "734 binaries blocked by Smart App Control" on a Windows 10 machine that
    # has no policy at all and cannot run Smart App Control. See the
    # codeintegrity module, which exists because of that.
    $checks = @(
        @{ Label = 'Code Integrity: WDAC policy block';   Log = 'Microsoft-Windows-CodeIntegrity/Operational'; Provider = 'Microsoft-Windows-CodeIntegrity'; Ids = @(3076, 3077, 3082) },
        @{ Label = 'Code Integrity: signing-level fail';  Log = 'Microsoft-Windows-CodeIntegrity/Operational'; Provider = 'Microsoft-Windows-CodeIntegrity'; Ids = @(3033, 3034) },
        @{ Label = 'AppLocker blocked an executable';   Log = 'Microsoft-Windows-AppLocker/EXE and DLL';     Provider = 'Microsoft-Windows-AppLocker';     Ids = @(8004, 8007) },
        @{ Label = 'Software Restriction Policy block'; Log = 'Application';                                 Provider = 'Microsoft-Windows-SoftwareRestrictionPolicies'; Ids = @(865, 866, 867, 868) },
        @{ Label = 'A service failed to start or died'; Log = 'System';                                      Provider = 'Service Control Manager';         Ids = @(7000, 7023, 7031, 7034) },
        @{ Label = 'Defender action / threat';          Log = 'Microsoft-Windows-Windows Defender/Operational'; Provider = 'Microsoft-Windows-Windows Defender'; Ids = @(1006, 1116, 1117) },
        @{ Label = 'Defender protection disabled';      Log = 'Microsoft-Windows-Windows Defender/Operational'; Provider = 'Microsoft-Windows-Windows Defender'; Ids = @(5001, 5010, 5012) }
    )

    $out = @()
    foreach ($c in $checks) {
        $r = Get-ProviderEventCount -LogName $c.Log -ProviderName $c.Provider -Ids $c.Ids -Days $Days
        $r | Add-Member -NotePropertyName 'Label' -NotePropertyValue $c.Label -Force
        $out += $r
    }
    return $out
}

# ---------------------------------------------------------------------------
# Baseline / Watch / Compare.
#
# A single reading cannot distinguish "somebody set this once" from "something
# is setting it back every few minutes". Watch is the only rung that answers
# the question the customer actually asked, so it exists despite the cost.
# The baseline persists because the answer usually needs a reboot in between.
# ---------------------------------------------------------------------------
function Get-UacSnapshot {
    $policy = Get-UacPolicy
    $svc = Get-ElevationServiceState
    $hij = Get-HijackFindings

    $vals = [ordered]@{}
    foreach ($v in $policy.Values) { $vals[$v.Name] = $v.Effective }

    $svcState = [ordered]@{}
    foreach ($s in $svc) { $svcState[$s.Name] = ('{0}/{1}' -f $s.Status, $s.StartType) }

    # Cast to pscustomobject, not left as [ordered]. Compare-UacSnapshot reads
    # members with .PSObject.Properties, and on an OrderedDictionary that
    # returns Keys/Values/Count instead of the entries - so the comparison
    # would silently find nothing to compare. It happens to work for the
    # baseline path because JSON round-trips into a pscustomobject anyway,
    # which is exactly the sort of bug that passes Compare and fails Watch.
    return [pscustomobject]@{
        TakenAt        = (Get-Date).ToString('o')
        Values         = [pscustomobject]$vals
        Services       = [pscustomobject]$svcState
        IfeoDebuggers  = @($hij.IfeoDebuggerNames | Sort-Object)
        PolicyWrite    = $(if ($policy.LastWriteTime) { $policy.LastWriteTime.ToString('o') } else { $null })
    }
}

function Compare-UacSnapshot {
    param($Before, $After)

    $changes = @()
    foreach ($k in @($Before.Values.PSObject.Properties.Name)) {
        $b = $Before.Values.$k
        $a = $After.Values.$k
        if ([string]$b -ne [string]$a) {
            $changes += ('{0}: {1} -> {2}' -f $k, $b, $a)
        }
    }
    foreach ($k in @($Before.Services.PSObject.Properties.Name)) {
        $b = $Before.Services.$k
        $a = $After.Services.$k
        if ([string]$b -ne [string]$a) {
            $changes += ('service {0}: {1} -> {2}' -f $k, $b, $a)
        }
    }
    $beforeIfeo = @($Before.IfeoDebuggers)
    $afterIfeo = @($After.IfeoDebuggers)
    foreach ($n in $afterIfeo) {
        if ($beforeIfeo -notcontains $n) { $changes += ('IFEO debugger appeared on ' + $n) }
    }
    foreach ($n in $beforeIfeo) {
        if ($afterIfeo -notcontains $n) { $changes += ('IFEO debugger removed from ' + $n) }
    }
    return $changes
}

function Save-UacBaseline {
    param($Snapshot)
    Initialize-LocalRoot
    $Snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:BaselinePath -Encoding UTF8 -WhatIf:$false
    return $script:BaselinePath
}

function Get-UacBaseline {
    if (-not (Test-Path -LiteralPath $script:BaselinePath)) { return $null }
    try { return Get-Content -LiteralPath $script:BaselinePath -Raw | ConvertFrom-Json }
    catch { return $null }
}

function Invoke-UacWatch {
    param([int]$Minutes = 3)

    Write-Banner ('Watching UAC state for ' + $Minutes + ' minute(s)')
    Write-Host '  This answers the question a single reading cannot: is something' -ForegroundColor Gray
    Write-Host '  putting these values back. Leave it running, and if you can,' -ForegroundColor Gray
    Write-Host '  set UAC back to its default in another window while it watches.' -ForegroundColor Gray
    Write-Host ''

    $intervalSeconds = 5
    $deadline = (Get-Date).AddMinutes($Minutes)
    $previous = Get-UacSnapshot
    $first = $previous
    $allChanges = @()
    $samples = 1

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $intervalSeconds
        $current = Get-UacSnapshot
        $samples++
        $changes = Compare-UacSnapshot -Before $previous -After $current
        foreach ($c in $changes) {
            $stamp = (Get-Date).ToString('HH:mm:ss')
            Write-Host ('  {0}  CHANGED  {1}' -f $stamp, $c) -ForegroundColor Red
            Write-Log -Message ('UAC watch: ' + $c) -Level WARN -Quiet
            $allChanges += ('{0} {1}' -f $stamp, $c)
        }
        $previous = $current
        Write-Host ('.') -NoNewline -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host ''

    $net = Compare-UacSnapshot -Before $first -After $previous

    if ($allChanges.Count -eq 0) {
        Write-Host ('  NOTHING MOVED in ' + $Minutes + ' minute(s), across ' + $samples + ' samples.') -ForegroundColor Green
        Write-Host '  That is evidence, but it is weak evidence, and it is worth saying' -ForegroundColor Yellow
        Write-Host '  exactly how weak: policy refresh runs on a 90-minute cycle and' -ForegroundColor Yellow
        Write-Host '  scheduled tasks can be triggered by logon or by idle. A quiet' -ForegroundColor Yellow
        Write-Host ('  {0}-minute window does not rule either out. What it does rule out' -f $Minutes) -ForegroundColor Yellow
        Write-Host '  is a tight loop rewriting the value every few seconds.' -ForegroundColor Yellow
        Write-Host '  Stronger test: set UAC to default, reboot, then run -Phase Compare.' -ForegroundColor Gray
    }
    else {
        Write-Host ('  SOMETHING IS WRITING TO UAC STATE: ' + $allChanges.Count + ' change(s) seen.') -ForegroundColor Red
        Write-Host '  This is the finding. A value that moves while nobody is touching' -ForegroundColor Red
        Write-Host '  it has a writer, and the next job is naming the writer - not' -ForegroundColor Red
        Write-Host '  setting the value back, which will just move again.' -ForegroundColor Red
        Write-Host ''
        Write-Host '  Narrowing it down, cheapest first:' -ForegroundColor Cyan
        Write-Host '    - Domain or MDM managed? Then policy refresh is the likeliest' -ForegroundColor Gray
        Write-Host '      writer and this is configuration, not infection.' -ForegroundColor Gray
        Write-Host '    - Run the startup module: a Run key or scheduled task that' -ForegroundColor Gray
        Write-Host '      shells out to reg.exe is the common persistence.' -ForegroundColor Gray
        Write-Host '    - Boot the machine offline and scan it from the stick. A writer' -ForegroundColor Gray
        Write-Host '      that is not running cannot fight the repair.' -ForegroundColor Gray
    }

    return [pscustomobject]@{
        Phase = 'Watch'; Minutes = $Minutes; Samples = $samples
        ChangeCount = $allChanges.Count; Changes = $allChanges
        NetChanges = $net
        LoadObserved = ($allChanges.Count -gt 0)
    }
}

# ---------------------------------------------------------------------------
# Verdict. Pure - takes gathered facts, returns a state and a cause. Pinned by
# the test suite because this is the part that decides where a tech spends the
# next hour.
#
# Three states, never two. "Could not establish" is a real answer and it is
# the one that must never be silently upgraded to "healthy".
# ---------------------------------------------------------------------------
function Get-ElevationVerdict {
    param(
        [Parameter(Mandatory = $true)]$Facts
    )

    $causes = @()
    $unknowns = @()

    if (-not $Facts.TokenReadable) { $unknowns += 'the session token could not be read' }
    if (-not $Facts.PolicyReadable) { $unknowns += 'the UAC policy key could not be read' }
    if (-not $Facts.MembershipReadable) { $unknowns += 'Administrators group membership could not be read' }

    # Rung 3 first: mechanical, cheap, and it makes everything above it moot.
    if ($Facts.AppInfoStartType -eq 'DISABLED') {
        $causes += 'The Application Information service is DISABLED. This alone stops every elevation on the machine.'
    }
    elseif ($Facts.AppInfoStatus -eq 'Stopped' -and $Facts.AppInfoStartType -eq 'Manual') {
        # Manual+Stopped is the normal resting state - it starts on demand.
        # Only worth reporting alongside evidence that it failed to start.
        if ($Facts.ServiceFailureEvents -gt 0) {
            $causes += 'The Application Information service is stopped and services have been failing to start on this machine.'
        }
    }

    # Rung 5: a debugger on consent.exe is the textbook "click Yes, nothing
    # happens". Nothing else produces that symptom so exactly.
    if ($Facts.IfeoOnCriticalExe -and @($Facts.IfeoOnCriticalExe).Count -gt 0) {
        $causes += ('An IFEO Debugger is set on: ' + (@($Facts.IfeoOnCriticalExe) -join ', ') + '. Windows launches the debugger instead of the program.')
    }
    if ($Facts.VerbProblems -and @($Facts.VerbProblems).Count -gt 0) {
        $causes += ('The Run as administrator verb is not stock: ' + (@($Facts.VerbProblems) -join '; ') + '.')
    }

    # Rung 4.
    if ($Facts.EnableLua -eq 0) {
        $causes += 'EnableLUA is 0 - UAC is switched off in the registry. A standard user then has no route to elevation at all, and an administrator gets no prompt.'
    }
    # -eq $false, not -not. Membership is tri-state: $null means the group
    # could not be enumerated, and `-not $null` is $true, which would report a
    # standard-user denial against an account whose membership is unknown.
    if ($Facts.ConsentUser -eq 0 -and $Facts.UserIsAdminMember -eq $false) {
        $causes += 'ConsentPromptBehaviorUser is 0 - elevation requests from this standard account are denied automatically, with no prompt.'
    }
    if ($Facts.ValidateAdminCodeSignatures -eq 1) {
        $causes += 'ValidateAdminCodeSignatures is 1 - anything not validly signed fails to elevate after you click Yes.'
    }

    # Rung 2: the stale-token case, which no UAC repair will fix.
    #
    # Two independent signals have to agree before this fires, because it is
    # an expensive thing to be wrong about - it ends with the tech signing a
    # customer out. TokenElevationType 3 means a split token exists, which
    # means the admin membership DID make it into the logon session and the
    # token is not stale, whatever the group SIDs look like. Only type 1 (no
    # split token) or an unreadable type can be stale.
    if ($Facts.UserIsAdminMember -eq $true -and -not $Facts.IsElevated -and
        -not $Facts.AdminSidInToken -and $Facts.ElevationType -ne 3 -and $Facts.ElevationType -ne 2) {
        $causes += 'This account is in Administrators but the running token does not carry that membership. It was granted after sign-in. Sign out and back in.'
    }

    # Rung 6.
    if ($Facts.RemovableDenyExecute) {
        $causes += 'Group Policy denies execute on removable disks. Nothing on the stick will run, elevated or not.'
    }
    if ($Facts.SrpDefaultLevel -eq 0) {
        $causes += 'Software Restriction Policy default level is Disallowed - anything not explicitly allowed is blocked before UAC is consulted.'
    }
    # Only a WDAC policy event is a program being refused, and only when a
    # policy is actually present. Signing-level failures are reported by the
    # module but are deliberately NOT a cause: they run to hundreds on healthy
    # machines, and calling them blocked binaries invented a fault complete
    # with a named culprit that the OS did not even support.
    if ($Facts.WdacBlocks -gt 0) {
        $causes += ('A Code Integrity policy blocked or audited ' + $Facts.WdacBlocks + ' item(s) - the binary is refused before UAC is consulted. Run the codeintegrity module.')
    }
    if ($Facts.AppLockerBlocks -gt 0) {
        $causes += ('AppLocker has blocked ' + $Facts.AppLockerBlocks + ' executables recently.')
    }

    # Rung 7.
    if ($Facts.RunningStateMismatch) {
        $causes += ('UAC''s running state does not match its registry state - the value changed since boot. ' + $Facts.MismatchDetail)
    }
    if ($Facts.UnsignedBinaryCount -gt 0) {
        $causes += ('An elevation binary failed its signature check (' + $Facts.UnsignedBinaryCount + '). Treat the install as compromised until proven otherwise.')
    }

    $state = 'NO BLOCKING CONDITION FOUND'
    if ($causes.Count -gt 0) { $state = 'CAUSE FOUND' }
    elseif ($unknowns.Count -gt 0) { $state = 'COULD NOT ESTABLISH' }

    return [pscustomobject]@{
        State = $state
        Causes = $causes
        Unknowns = $unknowns
    }
}

# ---------------------------------------------------------------------------
function Invoke-ElevationModule {
    [CmdletBinding()]
    param([switch]$Apply, [hashtable]$Options = @{})

    if ($Apply) {
        Write-Log -Message 'The elevation module is read-only. UAC, SRP, AppLocker and WDAC are security configuration - and on a machine something is actively rewriting, setting a value back before the writer is dealt with just gets it rewritten. It prints the commands.' -Level WARN
    }

    $phase = ''
    if ($Options.ContainsKey('Action') -and $Options.Action) { $phase = [string]$Options.Action }
    $minutes = 3
    if ($Options.ContainsKey('Minutes') -and [int]$Options.Minutes -gt 0) { $minutes = [int]$Options.Minutes }

    if ($phase -eq 'Watch') { return Invoke-UacWatch -Minutes $minutes }

    if ($phase -eq 'Baseline') {
        Write-Banner 'UAC baseline'
        $snap = Get-UacSnapshot
        $path = Save-UacBaseline -Snapshot $snap
        Write-Host ('  Baseline saved to ' + $path) -ForegroundColor Green
        Write-Host '  It stays on this machine, not on the stick. Reboot, or run the' -ForegroundColor Gray
        Write-Host '  repair, then come back with -Phase Compare.' -ForegroundColor Gray
        return [pscustomobject]@{ Phase = 'Baseline'; Snapshot = $snap; Path = $path }
    }

    if ($phase -eq 'Compare') {
        Write-Banner 'UAC state: now versus baseline'
        $before = Get-UacBaseline
        if (-not $before) {
            Write-Host '  No baseline on this machine. Run -Phase Baseline first.' -ForegroundColor Yellow
            return [pscustomobject]@{ Phase = 'Compare'; Compared = $false; Reason = 'no baseline' }
        }
        $after = Get-UacSnapshot
        $changes = Compare-UacSnapshot -Before $before -After $after
        Write-Host ('  Baseline taken: ' + $before.TakenAt) -ForegroundColor Gray
        Write-Host ''
        if ($changes.Count -eq 0) {
            Write-Host '  No change since the baseline.' -ForegroundColor Green
        }
        else {
            Write-Host ('  ' + $changes.Count + ' CHANGE(S) SINCE THE BASELINE:') -ForegroundColor Red
            foreach ($c in $changes) { Write-Host ('    ' + $c) -ForegroundColor Red }
            Write-Host ''
            Write-Host '  If you set these to default yourself and they have moved back,' -ForegroundColor Yellow
            Write-Host '  that is a writer. Check managed policy before assuming malware.' -ForegroundColor Yellow
        }
        return [pscustomobject]@{ Phase = 'Compare'; Compared = $true; ChangeCount = $changes.Count; Changes = $changes }
    }

    # --- full ladder ------------------------------------------------------
    Write-Banner 'Elevation and UAC failure diagnosis'

    $toolkitPath = $PSScriptRoot
    if ($toolkitPath) { $toolkitPath = Split-Path -Parent $toolkitPath }

    $token = Get-TokenFacts
    $members = Get-AdminMembership
    $svc = Get-ElevationServiceState
    $policy = Get-UacPolicy
    $hijack = Get-HijackFindings
    $restrict = Get-RestrictionFindings -ToolkitPath $toolkitPath
    $tamper = Get-TamperFindings -Token $token -Policy $policy
    $events = Get-ElevationEvents -Days 14

    $isMember = Test-CurrentUserInAdmins -Token $token -Membership $members
    $appinfo = @($svc | Where-Object { $_.Name -eq 'Appinfo' }) | Select-Object -First 1

    function Get-EventCountByLabel {
        param([string]$Label)
        $e = @($events | Where-Object { $_.Label -eq $Label }) | Select-Object -First 1
        if ($e -and $e.Readable) { return $e.Count }
        return 0
    }

    # --- 1. TOKEN ---------------------------------------------------------
    Write-Host ''
    Write-Host '  1  THIS SESSION' -ForegroundColor White
    if (-not $token.Readable) {
        Write-Host '     Could not read the session token.' -ForegroundColor Red
    }
    else {
        $elevText = 'not elevated'
        $elevColor = 'Yellow'
        if ($token.IsElevated) { $elevText = 'ELEVATED'; $elevColor = 'Green' }
        Write-Host ('     Elevated        : {0}' -f $elevText) -ForegroundColor $elevColor
        Write-Host ('     Integrity level : {0}' -f $token.IntegrityLevel) -ForegroundColor Gray
        Write-Host ('     Token type      : {0}' -f $token.ElevationMeaning) -ForegroundColor Gray
        if ($token.IsBuiltInAdmin) {
            Write-Host '     This is the built-in Administrator account (RID 500).' -ForegroundColor Cyan
        }
    }

    # --- 2. MEMBERSHIP ----------------------------------------------------
    Write-Host ''
    Write-Host '  2  ADMINISTRATORS MEMBERSHIP' -ForegroundColor White
    if (-not $members.Readable) {
        Write-Host ('     Could not enumerate the group: ' + $members.Error) -ForegroundColor Yellow
    }
    else {
        Write-Host ('     Members         : {0}' -f $members.MemberCount) -ForegroundColor Gray
        foreach ($n in $members.DisplayNames) {
            # Console only. Names never reach the returned object.
            Write-Host ('                       ' + $n) -ForegroundColor DarkGray
        }
        if ($isMember -eq $true) {
            Write-Host '     This account IS in Administrators.' -ForegroundColor Green
            if (-not $token.AdminSidInToken -and -not $token.IsElevated -and
                $token.ElevationType -ne 3 -and $token.ElevationType -ne 2) {
                Write-Host ''
                Write-Host '     STALE TOKEN: the membership is real but this logon session does' -ForegroundColor Red
                Write-Host '     not carry it. It was granted after sign-in. Sign out and back' -ForegroundColor Red
                Write-Host '     in - no amount of UAC repair changes this, and it is the most' -ForegroundColor Red
                Write-Host '     commonly misdiagnosed cause on this list.' -ForegroundColor Red
            }
        }
        elseif ($isMember -eq $false) {
            Write-Host '     This account is NOT in Administrators - it is a standard user.' -ForegroundColor Yellow
            Write-Host '     Elevation will ask for somebody else''s credentials, not for a' -ForegroundColor Yellow
            Write-Host '     yes/no. If it asks for nothing at all, see rung 4.' -ForegroundColor Yellow
        }
        if ($null -ne $members.BuiltInAdminEnabled) {
            $baText = 'disabled (Windows default)'
            if ($members.BuiltInAdminEnabled) { $baText = 'ENABLED' }
            Write-Host ('     Built-in Administrator account: {0}' -f $baText) -ForegroundColor DarkGray
        }
    }

    # --- 3. SERVICE -------------------------------------------------------
    Write-Host ''
    Write-Host '  3  THE SERVICE THAT PERFORMS ELEVATION' -ForegroundColor White
    foreach ($s in $svc) {
        $c = 'Gray'
        if ($s.StartType -eq 'DISABLED') { $c = 'Red' }
        elseif (-not $s.Readable) { $c = 'Yellow' }
        Write-Host ('     {0,-10} {1,-9} {2,-9}  {3}' -f $s.Name, $s.Status, $s.StartType, $s.Label) -ForegroundColor $c
    }
    if ($appinfo -and $appinfo.StartType -eq 'DISABLED') {
        Write-Host ''
        Write-Host '     APPINFO IS DISABLED. That is the whole fault - nothing on this' -ForegroundColor Red
        Write-Host '     machine can elevate, no prompt will ever appear, and every other' -ForegroundColor Red
        Write-Host '     rung below is untestable until it is back. From an elevated' -ForegroundColor Red
        Write-Host '     session (or Safe Mode, or offline via the stick):' -ForegroundColor Red
        Write-Host '       sc config Appinfo start= demand' -ForegroundColor DarkGray
        Write-Host '       sc start Appinfo' -ForegroundColor DarkGray
        Write-Host '     Note the chicken-and-egg: fixing this needs elevation, which is' -ForegroundColor Yellow
        Write-Host '     what is broken. Safe Mode with the built-in Administrator, or an' -ForegroundColor Yellow
        Write-Host '     offline registry edit, is usually the way in.' -ForegroundColor Yellow
    }

    # --- 4. POLICY --------------------------------------------------------
    Write-Host ''
    Write-Host '  4  UAC POLICY VALUES' -ForegroundColor White
    if (-not $policy.Readable) {
        Write-Host ('     Policies\System could not be read: ' + $policy.Error) -ForegroundColor Red
        Write-Host '     An unreadable UAC key is itself a finding. Check its permissions.' -ForegroundColor Yellow
    }
    foreach ($v in $policy.Values) {
        $shown = 'not set'
        if ($v.Set) { $shown = [string]$v.Value }
        $c = 'Gray'
        if (-not $v.IsDefault) { $c = 'Yellow' }
        Write-Host ('     {0,-28} {1,-8} (effective {2})' -f $v.Name, $shown, $v.Effective) -ForegroundColor $c
    }

    $enableLua = Get-UacValue -Policy $policy -Name 'EnableLUA'
    $consentAdmin = Get-UacValue -Policy $policy -Name 'ConsentPromptBehaviorAdmin'
    $consentUser = Get-UacValue -Policy $policy -Name 'ConsentPromptBehaviorUser'
    $validateSig = Get-UacValue -Policy $policy -Name 'ValidateAdminCodeSignatures'
    $secureDesktop = Get-UacValue -Policy $policy -Name 'PromptOnSecureDesktop'

    Write-Host ''
    Write-Host ('     Administrator prompt : ' + (Get-ConsentAdminMeaning -Value $consentAdmin)) -ForegroundColor Gray
    Write-Host ('     Standard user prompt : ' + (Get-ConsentUserMeaning -Value $consentUser)) -ForegroundColor Gray

    if ($enableLua -eq 0) {
        Write-Host ''
        Write-Host '     ENABLELUA IS 0 - UAC IS TURNED OFF.' -ForegroundColor Red
        Write-Host '     For a standard user this means there is no elevation route at all.' -ForegroundColor Red
        Write-Host '     For an administrator it means no prompt appears and everything' -ForegroundColor Red
        Write-Host '     runs with full rights, which is worse, not better. It also breaks' -ForegroundColor Red
        Write-Host '     Store and packaged apps, so "nothing opens" can be this too.' -ForegroundColor Red
        Write-Host '     Restore the default (needs elevation, and a reboot to take effect):' -ForegroundColor Yellow
        Write-Host '       reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f' -ForegroundColor DarkGray
    }
    if ($consentUser -eq 0 -and $isMember -eq $false) {
        Write-Host ''
        Write-Host '     CONSENTPROMPTBEHAVIORUSER IS 0 - elevation requests from a standard' -ForegroundColor Red
        Write-Host '     account are denied automatically. No prompt, no error, nothing' -ForegroundColor Red
        Write-Host '     happens. This is the setting that most exactly matches "it just' -ForegroundColor Red
        Write-Host '     does not do anything", and it is a legitimate hardening choice on' -ForegroundColor Red
        Write-Host '     a managed fleet - so check who owns it before changing it.' -ForegroundColor Red
    }
    if ($validateSig -eq 1) {
        Write-Host ''
        Write-Host '     VALIDATEADMINCODESIGNATURES IS 1 - only validly signed binaries can' -ForegroundColor Yellow
        Write-Host '     elevate. The prompt appears, you click Yes, and nothing runs. That' -ForegroundColor Yellow
        Write-Host '     symptom is this setting far more often than people expect, and it' -ForegroundColor Yellow
        Write-Host '     hits unsigned bench utilities hardest.' -ForegroundColor Yellow
    }
    if ($secureDesktop -eq 1) {
        Write-Host ''
        Write-Host '     Secure desktop is on (the default). If the screen dims and no' -ForegroundColor DarkGray
        Write-Host '     prompt paints, the prompt IS there and cannot draw - a broken' -ForegroundColor DarkGray
        Write-Host '     display driver or a screen-capture hook will do that. Test by' -ForegroundColor DarkGray
        Write-Host '     temporarily setting PromptOnSecureDesktop to 0.' -ForegroundColor DarkGray
    }

    # --- 5. HIJACKS -------------------------------------------------------
    Write-Host ''
    Write-Host '  5  HIJACKS - CLICK YES AND NOTHING HAPPENS' -ForegroundColor White
    if (-not $hijack.IfeoReadable) {
        Write-Host '     Image File Execution Options could not be read.' -ForegroundColor Yellow
    }
    else {
        Write-Host ('     IFEO debugger entries : {0}' -f $hijack.IfeoDebuggerCount) -ForegroundColor $(if ($hijack.IfeoDebuggerCount -gt 0) { 'Yellow' } else { 'Gray' })
        foreach ($n in $hijack.IfeoDebuggerNames) {
            $c = 'DarkGray'
            if ($script:ElevationCriticalExes -contains $n) { $c = 'Red' }
            Write-Host ('                             ' + $n) -ForegroundColor $c
        }
    }
    if (@($hijack.IfeoOnCriticalExe).Count -gt 0) {
        Write-Host ''
        Write-Host '     A DEBUGGER IS SET ON A BINARY THAT ELEVATION DEPENDS ON.' -ForegroundColor Red
        Write-Host '     IFEO makes Windows launch the debugger INSTEAD of the program.' -ForegroundColor Red
        Write-Host '     On consent.exe that eats the elevation itself: the prompt appears,' -ForegroundColor Red
        Write-Host '     Yes does nothing. It is a supported debugging feature, which is' -ForegroundColor Red
        Write-Host '     why it survives most cleaners, and it is the single best match for' -ForegroundColor Red
        Write-Host '     the symptom you described.' -ForegroundColor Red
        Write-Host '     Inspect before deleting - a legitimate debugger or an app-compat' -ForegroundColor Yellow
        Write-Host '     shim can live here too:' -ForegroundColor Yellow
        Write-Host ('       reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' + @($hijack.IfeoOnCriticalExe)[0] + '"') -ForegroundColor DarkGray
    }
    if (@($hijack.SilentExitNames).Count -gt 0) {
        Write-Host ''
        Write-Host ('     SilentProcessExit monitors are set on: ' + (@($hijack.SilentExitNames) -join ', ')) -ForegroundColor Yellow
        Write-Host '     This runs something when the named process exits. Same family of' -ForegroundColor Yellow
        Write-Host '     trick as IFEO and worth reading before anything is removed.' -ForegroundColor Yellow
    }
    if (@($hijack.VerbProblems).Count -gt 0) {
        Write-Host ''
        foreach ($p in $hijack.VerbProblems) {
            Write-Host ('     VERB PROBLEM: ' + $p) -ForegroundColor Red
        }
        Write-Host '     Stock value for exefile runas and open is:  "%1" %*' -ForegroundColor DarkGray
    }
    if (@($hijack.PerUserClassOverride).Count -gt 0) {
        Write-Host ''
        Write-Host ('     PER-USER CLASS OVERRIDE on: ' + (@($hijack.PerUserClassOverride) -join ', ')) -ForegroundColor Yellow
        Write-Host '     HKCU\Software\Classes beats HKLM for the logged-on user. Check it' -ForegroundColor Yellow
        Write-Host '     from the CUSTOMER account - an elevated session running as someone' -ForegroundColor Yellow
        Write-Host '     else reads a different HKCU and will report this clean.' -ForegroundColor Yellow
    }

    # --- 6. RESTRICTIONS --------------------------------------------------
    Write-Host ''
    Write-Host '  6  RESTRICTIONS ON RUNNING THE BINARY AT ALL' -ForegroundColor White
    Write-Host ('     Toolkit is running from : {0} ({1})' -f $toolkitPath, $restrict.ToolkitDriveType) -ForegroundColor Gray
    if ($restrict.SrpActive) {
        $srpText = 'set'
        if ($restrict.SrpDefaultLevel -eq 0) { $srpText = 'DISALLOWED by default' }
        elseif ($restrict.SrpDefaultLevel -eq 262144) { $srpText = 'Basic User' }
        elseif ($restrict.SrpDefaultLevel -eq 40960) { $srpText = 'Unrestricted' }
        Write-Host ('     Software Restriction Policy : {0}' -f $srpText) -ForegroundColor $(if ($restrict.SrpDefaultLevel -eq 0) { 'Red' } else { 'Yellow' })
    }
    if ($restrict.AppLockerActive) {
        Write-Host ('     AppLocker rules present : ' + (@($restrict.AppLockerRuleTypes) -join ', ')) -ForegroundColor Yellow
        $appid = @($svc | Where-Object { $_.Name -eq 'AppIDSvc' }) | Select-Object -First 1
        if ($appid -and $appid.Status -ne 'Running') {
            Write-Host '     ...but Application Identity is not running, so they are not' -ForegroundColor DarkGray
            Write-Host '     being enforced. Rules present does not mean rules applied.' -ForegroundColor DarkGray
        }
    }
    if (-not $restrict.SacSupported) {
        Write-Host ('     Smart App Control : not available on build {0} (needs Windows 11 22H2)' -f $restrict.OsBuild) -ForegroundColor DarkGray
    }
    elseif ($null -ne $restrict.SmartAppControlState) {
        $sacText = 'off'
        if ($restrict.SmartAppControlState -eq 1) { $sacText = 'ON - blocks unsigned and unknown binaries' }
        elseif ($restrict.SmartAppControlState -eq 2) { $sacText = 'evaluation mode' }
        Write-Host ('     Smart App Control : {0}' -f $sacText) -ForegroundColor $(if ($restrict.SmartAppControlState -eq 1) { 'Yellow' } else { 'Gray' })
    }
    if ($restrict.DisallowRun -or $restrict.RestrictRun) {
        Write-Host '     Explorer DisallowRun/RestrictRun policy is set - a named list of' -ForegroundColor Yellow
        Write-Host '     programs is being blocked or allowed. Classic lockdown, and also' -ForegroundColor Yellow
        Write-Host '     classic malware, since it is how taskmgr and regedit get blocked.' -ForegroundColor Yellow
    }
    if ($restrict.RemovableDenyExecute) {
        Write-Host ''
        Write-Host '     EXECUTE IS DENIED ON REMOVABLE DISKS BY GROUP POLICY.' -ForegroundColor Red
        Write-Host '     Nothing on this stick will run, elevated or not. If local' -ForegroundColor Red
        Write-Host '     shortcuts elevate fine and only the stick fails, this is why,' -ForegroundColor Red
        Write-Host '     and UAC is not involved at all. Copy the toolkit to the local' -ForegroundColor Red
        Write-Host '     disk to confirm, and expect a managed fleet to reapply it.' -ForegroundColor Red
    }
    elseif ($restrict.ToolkitOnRemovable) {
        Write-Host '     No removable-execute denial found. If launches from the stick' -ForegroundColor DarkGray
        Write-Host '     fail but local copies work, test that directly - copy the' -ForegroundColor DarkGray
        Write-Host '     toolkit to C:\ and launch it there. That one comparison splits' -ForegroundColor DarkGray
        Write-Host '     "the stick is blocked" from "elevation is broken" in a minute.' -ForegroundColor DarkGray
        if ($restrict.ToolkitFileSystem -and $restrict.ToolkitFileSystem -notmatch 'NTFS') {
            Write-Host ('     Stick is ' + $restrict.ToolkitFileSystem + ', which has no alternate data streams, so') -ForegroundColor DarkGray
            Write-Host '     files here cannot carry Mark of the Web. A SmartScreen block on' -ForegroundColor DarkGray
            Write-Host '     something launched from here did not come from MotW.' -ForegroundColor DarkGray
        }
    }

    # --- 7. TAMPER --------------------------------------------------------
    Write-Host ''
    Write-Host '  7  IS THE STATE STABLE?' -ForegroundColor White
    if ($tamper.LastBoot) {
        Write-Host ('     Last boot            : {0}' -f $tamper.LastBoot) -ForegroundColor Gray
    }
    if ($policy.LastWriteTime) {
        $c = 'Gray'
        if ($tamper.PolicyWrittenAfterBoot) { $c = 'Yellow' }
        Write-Host ('     UAC key last written : {0}' -f $policy.LastWriteTime) -ForegroundColor $c
        if ($tamper.PolicyWrittenAfterBoot) {
            Write-Host '     The UAC policy key was written AFTER this boot. Something running' -ForegroundColor Yellow
            Write-Host '     on this machine wrote it. That includes you, Windows Settings,' -ForegroundColor Yellow
            Write-Host '     and policy refresh - it is a lead, not a verdict.' -ForegroundColor Yellow
        }
    }
    else {
        Write-Host '     UAC key write time   : could not be read' -ForegroundColor DarkGray
    }

    if ($tamper.RunningStateMismatch) {
        Write-Host ''
        Write-Host '     RUNNING STATE DOES NOT MATCH REGISTRY STATE.' -ForegroundColor Red
        Write-Host ('     ' + $tamper.MismatchDetail) -ForegroundColor Red
        Write-Host '     This is the strongest single-sample evidence available: EnableLUA' -ForegroundColor Yellow
        Write-Host '     only takes effect at boot, so a disagreement between what the' -ForegroundColor Yellow
        Write-Host '     registry says and what this token is proves the value moved after' -ForegroundColor Yellow
        Write-Host '     the machine came up. It does not name the writer.' -ForegroundColor Yellow
    }
    elseif ($tamper.MismatchDetail) {
        Write-Host ('     ' + $tamper.MismatchDetail) -ForegroundColor Cyan
    }

    $mgmt = @()
    if ($tamper.DomainJoined) { $mgmt += 'domain-joined' }
    if ($tamper.MdmEnrolled) { $mgmt += 'MDM-enrolled' }
    if ($mgmt.Count -gt 0) {
        Write-Host ''
        Write-Host ('     MANAGED MACHINE (' + ($mgmt -join ', ') + ').') -ForegroundColor Cyan
        Write-Host '     Read every finding above in that light. Managed policy rewrites' -ForegroundColor Cyan
        Write-Host '     UAC values on refresh, which looks exactly like malware putting' -ForegroundColor Cyan
        Write-Host '     them back, and a hardened fleet legitimately denies elevation to' -ForegroundColor Cyan
        Write-Host '     standard users. Confirm with whoever manages it before treating' -ForegroundColor Cyan
        Write-Host '     configuration as infection - and before changing anything, since' -ForegroundColor Cyan
        Write-Host '     it will come back at the next refresh anyway.' -ForegroundColor Cyan
    }

    if (@($tamper.UnsignedBinaries).Count -gt 0) {
        Write-Host ''
        Write-Host '     ELEVATION BINARY SIGNATURE PROBLEM:' -ForegroundColor Red
        foreach ($b in $tamper.UnsignedBinaries) { Write-Host ('       ' + $b) -ForegroundColor Red }
        Write-Host '     A replaced consent.exe or appinfo.dll is a compromised install,' -ForegroundColor Red
        Write-Host '     not a misconfiguration. Get the data off before anything else.' -ForegroundColor Red
    }
    elseif ($tamper.SignatureCheckRan) {
        Write-Host '     Elevation binaries    : all validly Microsoft-signed' -ForegroundColor Green
    }

    if ($tamper.DefenderReadable) {
        $rtColor = 'Green'
        if ($tamper.RealTimeProtection -eq $false) { $rtColor = 'Red' }
        Write-Host ('     Defender real-time    : {0}' -f $tamper.RealTimeProtection) -ForegroundColor $rtColor
        Write-Host ('     Tamper protection     : {0}' -f $tamper.TamperProtection) -ForegroundColor $(if ($tamper.TamperProtection -eq $false) { 'Yellow' } else { 'Gray' })
        if ($null -ne $tamper.SignatureAgeDays) {
            Write-Host ('     Signature age         : {0} days' -f $tamper.SignatureAgeDays) -ForegroundColor $(if ($tamper.SignatureAgeDays -gt 7) { 'Yellow' } else { 'Gray' })
        }
        if ($tamper.RealTimeProtection -eq $false) {
            Write-Host '     REAL-TIME PROTECTION IS OFF. Combined with UAC being off, that' -ForegroundColor Red
            Write-Host '     pairing is a signature in itself - both get switched off by the' -ForegroundColor Red
            Write-Host '     same class of thing, and neither switches itself off.' -ForegroundColor Red
        }
        if ($tamper.BroadExclusion) {
            Write-Host '     A Defender exclusion covers an entire drive or system folder.' -ForegroundColor Red
            Write-Host '     That is not a tuning choice. Review the exclusion list.' -ForegroundColor Red
        }
    }

    # --- 8. EVENTS --------------------------------------------------------
    Write-Host ''
    Write-Host '  8  CORROBORATING EVENTS (last 14 days)' -ForegroundColor White
    foreach ($e in $events) {
        if (-not $e.Readable) {
            $why = $e.Reason
            if ($why -eq 'RequiresElevation') { $why = 'RequiresElevation - re-run from an elevated session for this one' }
            Write-Host ('     {0,-38} {1}' -f $e.Label, $why) -ForegroundColor Yellow
            continue
        }
        $c = 'Gray'
        if ($e.Count -gt 0) { $c = 'Yellow' }
        Write-Host ('     {0,-38} {1}' -f $e.Label, $e.Count) -ForegroundColor $c
    }
    Write-Host '     Every query above names its provider as well as its ID. IDs are' -ForegroundColor DarkGray
    Write-Host '     only unique within a provider - counting them bare invents faults.' -ForegroundColor DarkGray

    $signingFails = Get-EventCountByLabel -Label 'Code Integrity: signing-level fail'
    if ($signingFails -gt 0) {
        Write-Host ''
        Write-Host ('     {0} signing-level load failures. Deliberately NOT counted as a' -f $signingFails) -ForegroundColor Cyan
        Write-Host '     cause: these are loads refused inside a process, not programs' -ForegroundColor Cyan
        Write-Host '     being blocked, and they run to hundreds on healthy machines.' -ForegroundColor Cyan
        Write-Host '     Run the codeintegrity module to see what is repeating and' -ForegroundColor Cyan
        Write-Host '     whether any policy is enforcing at all.' -ForegroundColor Cyan
    }

    # --- verdict ----------------------------------------------------------
    $facts = [pscustomobject]@{
        TokenReadable       = $token.Readable
        PolicyReadable      = $policy.Readable
        MembershipReadable  = $members.Readable
        IsElevated          = $token.IsElevated
        AdminSidInToken     = $token.AdminSidInToken
        ElevationType       = $token.ElevationType
        UserIsAdminMember   = $isMember
        AppInfoStatus       = $(if ($appinfo) { $appinfo.Status } else { 'unknown' })
        AppInfoStartType    = $(if ($appinfo) { $appinfo.StartType } else { 'unknown' })
        ServiceFailureEvents = (Get-EventCountByLabel -Label 'A service failed to start or died')
        IfeoOnCriticalExe   = $hijack.IfeoOnCriticalExe
        VerbProblems        = $hijack.VerbProblems
        EnableLua           = $enableLua
        ConsentUser         = $consentUser
        ValidateAdminCodeSignatures = $validateSig
        RemovableDenyExecute = $restrict.RemovableDenyExecute
        SrpDefaultLevel     = $restrict.SrpDefaultLevel
        WdacBlocks          = (Get-EventCountByLabel -Label 'Code Integrity: WDAC policy block')
        SigningLevelFailures = (Get-EventCountByLabel -Label 'Code Integrity: signing-level fail')
        AppLockerBlocks     = (Get-EventCountByLabel -Label 'AppLocker blocked an executable')
        RunningStateMismatch = $tamper.RunningStateMismatch
        MismatchDetail      = $tamper.MismatchDetail
        UnsignedBinaryCount = @($tamper.UnsignedBinaries).Count
    }

    $verdict = Get-ElevationVerdict -Facts $facts

    Write-Host ''
    Write-Host ('  VERDICT: ' + $verdict.State) -ForegroundColor $(
        if ($verdict.State -eq 'CAUSE FOUND') { 'Red' }
        elseif ($verdict.State -eq 'COULD NOT ESTABLISH') { 'Yellow' }
        else { 'Green' })

    foreach ($c in $verdict.Causes) {
        Write-Host ('    - ' + $c) -ForegroundColor Yellow
    }
    foreach ($u in $verdict.Unknowns) {
        Write-Host ('    ? ' + $u) -ForegroundColor Yellow
    }

    if ($verdict.State -eq 'NO BLOCKING CONDITION FOUND') {
        Write-Host ''
        Write-Host '    Nothing on the ladder is refusing elevation right now. That is a' -ForegroundColor Gray
        Write-Host '    real result, not a shrug, but note what it does NOT cover: a' -ForegroundColor Gray
        Write-Host '    single reading cannot see a value that gets rewritten later. If' -ForegroundColor Gray
        Write-Host '    the complaint is that a fix does not stick, run:' -ForegroundColor Gray
        Write-Host '      -Module elevation -Phase Baseline    then reboot, then' -ForegroundColor DarkGray
        Write-Host '      -Module elevation -Phase Compare' -ForegroundColor DarkGray
        Write-Host '    or watch it live:  -Module elevation -Phase Watch -Minutes 5' -ForegroundColor DarkGray
    }

    if ($verdict.State -eq 'CAUSE FOUND' -and ($tamper.RunningStateMismatch -or $tamper.RealTimeProtection -eq $false -or @($tamper.UnsignedBinaries).Count -gt 0)) {
        Write-Host ''
        Write-Host '  IF THIS IS AN ACTIVE INFECTION, ORDER MATTERS:' -ForegroundColor Cyan
        Write-Host '    Repairing UAC while the writer is still running gets the repair' -ForegroundColor Gray
        Write-Host '    reverted and teaches you nothing. Data off first, then scan with' -ForegroundColor Gray
        Write-Host '    the machine offline or booted from the stick, then repair the' -ForegroundColor Gray
        Write-Host '    settings, then re-check with -Phase Compare. And be honest about' -ForegroundColor Gray
        Write-Host '    where the Level 1 line is: a confirmed rootkit or a replaced' -ForegroundColor Gray
        Write-Host '    consent.exe is a rebuild conversation, not a registry edit.' -ForegroundColor Gray
    }

    Write-Host ''
    Write-Host '  Read-only. Nothing was changed.' -ForegroundColor DarkGray
    Write-Host ''

    # Returned object carries SIDs, counts and booleans only. Account NAMES
    # went to the console and to the local log, both of which stay on the
    # customer's machine; they must not reach a report that leaves on a stick.
    return [pscustomobject]@{
        Verdict            = $verdict.State
        Causes             = $verdict.Causes
        Unknowns           = $verdict.Unknowns
        IsElevated         = $token.IsElevated
        ElevationType      = $token.ElevationType
        IntegrityLevel     = $token.IntegrityLevel
        UserSid            = $token.UserSid
        IsBuiltInAdmin     = $token.IsBuiltInAdmin
        AdminMemberCount   = $members.MemberCount
        AdminMemberSids    = $members.MemberSids
        CurrentUserIsAdminMember = $isMember
        BuiltInAdminEnabled = $members.BuiltInAdminEnabled
        Services           = $svc
        UacValues          = $policy.Values
        UacKeyLastWrite    = $(if ($policy.LastWriteTime) { $policy.LastWriteTime.ToString('o') } else { $null })
        PolicyWrittenAfterBoot = $tamper.PolicyWrittenAfterBoot
        RunningStateMismatch = $tamper.RunningStateMismatch
        IfeoDebuggerCount  = $hijack.IfeoDebuggerCount
        IfeoDebuggerNames  = $hijack.IfeoDebuggerNames
        IfeoOnCriticalExe  = $hijack.IfeoOnCriticalExe
        SilentExitNames    = $hijack.SilentExitNames
        VerbProblems       = $hijack.VerbProblems
        PerUserClassOverride = $hijack.PerUserClassOverride
        Restrictions       = $restrict
        DomainJoined       = $tamper.DomainJoined
        MdmEnrolled        = $tamper.MdmEnrolled
        UnsignedBinaries   = $tamper.UnsignedBinaries
        DefenderRealTime   = $tamper.RealTimeProtection
        DefenderTamperProtection = $tamper.TamperProtection
        DefenderExclusionCount = $tamper.ExclusionCount
        DefenderBroadExclusion = $tamper.BroadExclusion
        Events             = $events
    }
}
