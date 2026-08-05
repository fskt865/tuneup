<#MANIFEST
{
  "Key": "codeintegrity",
  "Title": "Code Integrity block detail",
  "Entry": "Invoke-CodeIntegrityModule",
  "Order": 13,
  "RequiresAdmin": false,
  "Description": "What Code Integrity actually refused, and whether any policy is enforcing at all - a 3033 storm is usually not a blocked program"
}
MANIFEST#>

# Get-CodeIntegrityDetail.ps1 - what did Code Integrity actually refuse?
# ASCII only, PowerShell 5.1 compatible. READ ONLY - reports, never changes.
#
# WHY THIS EXISTS. The elevation module counted CodeIntegrity events and called
# them "blocked binaries". On a Windows 10 Home machine with no policy of any
# kind that produced a confident finding naming Smart App Control - a feature
# that does not exist before Windows 11 22H2. The count was real; every word of
# the conclusion was wrong.
#
# That is the toolkit's own lesson one level up. It already knew an event ID
# means nothing without its provider (see the NTFS/power-event case). The same
# argument keeps going: an ID means nothing without its SEMANTICS and without
# checking that the feature being blamed exists on the OS in front of you.
#
# THE DISTINCTION THAT MATTERS. Two different things live in this log and they
# are not the same finding:
#
#   3033 / 3034   A LOAD failed a SIGNING LEVEL requirement. Usually something
#                 trying to load a DLL into a protected process that will not
#                 accept it. The program that tried is generally still running.
#                 These arrive in storms - hundreds is unremarkable - and on a
#                 machine with no policy they are noise, not a blocked launch.
#
#   3076 / 3077   A WDAC POLICY audited or blocked something. THIS is a program
#                 being refused. It cannot happen without a policy present, so
#                 the first thing to establish is whether one is.
#
# So this module answers, in order: is anything enforcing, what is actually in
# the log, and which file is repeating. Nothing else is worth reading until
# those three are settled.
#
# CUSTOMER DATA. Blocked file paths are exactly the sort of thing the tree
# forbids putting in anything that leaves the machine - they carry profile
# names and installed-software inventory. Full paths go to the CONSOLE, which
# stays on the customer's machine. The returned object carries counts, file
# extensions and a location bucket, never a path and never a file name.

$script:CiLog = 'Microsoft-Windows-CodeIntegrity/Operational'
$script:CiProvider = 'Microsoft-Windows-CodeIntegrity'

# Smart App Control did not exist before Windows 11 22H2. Blaming it on
# anything older is how the elevation module got this wrong.
$script:SacMinimumBuild = 22621

# Policy files Windows ships itself. Their presence is not a deployment.
$script:StockPolicyFiles = @('driversipolicy.p7b')

# Components that generate signing-level storms as a matter of course.
#
# This table ANNOTATES. It never suppresses a finding, never changes a count
# and never changes the verdict - matching is on file NAME alone, which is the
# weakest identification available and trivially forged. The signature status
# and location printed beside it are what actually confirm the identification;
# a name from this list sitting somewhere odd or failing its signature check is
# more interesting than one that is not on the list at all.
#
# Entries go in only when confirmed on a real machine. A padded list of
# half-remembered names would make the module confidently dismiss things it
# has no business dismissing, which is the failure mode this file exists to
# correct.
$script:KnownNoisySources = @(
    @{
        File = 'mdnsnsp.dll'
        What = 'Apple Bonjour - Winsock namespace provider'
        Why  = 'Registered as a namespace provider, so Winsock tries to load it into every process that resolves a name. Hardened processes refuse it and log one event each. Apple signs it validly; it simply is not Microsoft-signed. Ships with iTunes, Apple Software Update, Adobe Creative Cloud and some printer software.'
        Do   = 'Leave it. Removing Bonjour to quiet a log breaks AirPrint and Apple device discovery.'
    }
)

function Get-KnownNoiseNote {
    param([AllowNull()][string]$NormalizedPath)
    if ([string]::IsNullOrWhiteSpace($NormalizedPath)) { return $null }
    $leaf = ''
    try { $leaf = [IO.Path]::GetFileName($NormalizedPath) } catch { return $null }
    if (-not $leaf) { return $null }
    foreach ($entry in $script:KnownNoisySources) {
        if ($leaf.ToLowerInvariant() -eq $entry.File) { return $entry }
    }
    return $null
}

function Get-CiRegValue {
    param([string]$Path, [string]$Name)
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        return $key.GetValue($Name, $null)
    }
    catch { return $null }
}

# ---------------------------------------------------------------------------
# Pure decoders - pinned by the test suite.
# ---------------------------------------------------------------------------
function Get-CiEventMeaning {
    param($Id)
    switch ([string]$Id) {
        '3004' { return 'Image failed signature verification' }
        '3010' { return 'Image signed by a revoked certificate' }
        '3023' { return 'Driver load blocked - not compatible with memory integrity (HVCI)' }
        '3033' { return 'Load failed a SIGNING LEVEL requirement (not a policy block)' }
        '3034' { return 'Load would have failed a signing level requirement (audit)' }
        '3076' { return 'WDAC policy AUDIT - would have been blocked' }
        '3077' { return 'WDAC policy BLOCK - the program was refused' }
        '3082' { return 'WDAC policy blocked a script or MSI' }
        '3089' { return 'Signature detail for the preceding Code Integrity event (pairs 1:1, not a separate finding)' }
        '3099' { return 'A Code Integrity policy was loaded' }
        default { return 'other Code Integrity event' }
    }
}

# Is this ID a program actually being refused by a policy, or a signing-level
# complaint about a load? Everything downstream branches on this.
function Test-CiIsPolicyBlock {
    param($Id)
    return (@(3076, 3077, 3082) -contains [int]$Id)
}

function Test-CiIsSigningLevel {
    param($Id)
    return (@(3033, 3034) -contains [int]$Id)
}

# Event messages carry paths in several shapes:
#   \Device\HarddiskVolume3\Windows\System32\foo.dll
#   \??\C:\Program Files\Thing\bar.dll
#   C:\Users\someone\AppData\...\baz.dll
# Normalise all three to a volume-relative path so they can be bucketed and
# compared without caring which volume they came from.
function ConvertTo-CiNormalizedPath {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $p = $Path.Trim()
    $p = $p -replace '(?i)^\\Device\\HarddiskVolume\d+', ''
    $p = $p -replace '(?i)^\\\?\?\\', ''
    $p = $p -replace '(?i)^[a-z]:', ''
    if ($p -and $p[0] -ne '\') { $p = '\' + $p }
    return $p
}

# Where the refused file lives, as a category rather than a path. This is the
# only location information that reaches the report.
function Get-CiPathBucket {
    param([AllowNull()][string]$NormalizedPath)
    if ([string]::IsNullOrWhiteSpace($NormalizedPath)) { return 'unknown' }
    $p = $NormalizedPath
    # Longest / most specific first - System32 is under Windows.
    if ($p -match '(?i)^\\Windows\\System32\\') { return 'Windows\System32' }
    if ($p -match '(?i)^\\Windows\\SysWOW64\\') { return 'Windows\SysWOW64' }
    if ($p -match '(?i)^\\Windows\\Temp\\')     { return 'Windows\Temp' }
    if ($p -match '(?i)^\\Windows\\')           { return 'Windows' }
    if ($p -match '(?i)^\\Program Files \(x86\)\\') { return 'Program Files (x86)' }
    if ($p -match '(?i)^\\Program Files\\')     { return 'Program Files' }
    if ($p -match '(?i)^\\ProgramData\\')       { return 'ProgramData' }
    if ($p -match '(?i)\\AppData\\Local\\Temp\\') { return 'user temp' }
    if ($p -match '(?i)^\\Users\\')             { return 'user profile' }
    return 'other'
}

function Get-CiExtension {
    param([AllowNull()][string]$NormalizedPath)
    if ([string]::IsNullOrWhiteSpace($NormalizedPath)) { return '' }
    try {
        $e = [IO.Path]::GetExtension($NormalizedPath)
        if ($e) { return $e.ToLowerInvariant() }
    }
    catch { }
    return ''
}

# Pull path-shaped tokens out of an event message.
#
# Regex rather than $e.Properties indexes on purpose: the property layout
# differs per event ID, and reading the wrong index silently returns the wrong
# field - the exact class of failure this module exists to correct.
#
# WINDOWS PATHS CONTAIN SPACES, and that is not a detail. A pattern that stops
# at whitespace truncates "\Program Files\Vendor\thing.dll" to
# "\Program Files" - sorry, to "\Program" - which then has no extension, gets
# discarded as a non-binary, and the parser silently falls back to naming the
# PROCESS instead of the file. Every event for one repeating DLL would land in
# a different bucket and the "is one file retrying" grouping, which is the
# whole point of the module, would report noise.
#
# So anchor on the extension instead: lazily consume anything up to the first
# known binary extension. Matches resume after each hit, so both paths in a
# two-path message are found intact.
$script:CiBinaryPattern = '(?i)(?:\\Device\\HarddiskVolume\d+|\\\?\?\\[a-z]:|[a-z]:)\\[^\r\n]*?\.(?:dll|exe|sys|ocx|scr|msi|ps1|cpl|drv)\b'
$script:CiLoosePattern  = '(?i)(?:\\Device\\HarddiskVolume\d+|\\\?\?\\[a-z]:|[a-z]:)\\[^\s,;"''\)\]]+'

function Get-CiPathsFromMessage {
    param([AllowNull()][string]$Message)
    $out = @()
    if ([string]::IsNullOrWhiteSpace($Message)) { return $out }
    foreach ($m in [regex]::Matches($Message, $script:CiBinaryPattern)) { $out += $m.Value }
    if ($out.Count -eq 0) {
        foreach ($m in [regex]::Matches($Message, $script:CiLoosePattern)) { $out += $m.Value }
    }
    return $out
}

function Get-CiSubjectPath {
    param([AllowNull()][string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return '' }

    # These messages read "a process (P) attempted to load F", so the file the
    # event is ABOUT is the LAST binary path, not the first and not the
    # longest. Length was the first attempt and it happened to work on the
    # sample that was written to test it, which is exactly how a heuristic
    # gets shipped: right answer, wrong reason.
    $binaries = @([regex]::Matches($Message, $script:CiBinaryPattern) | ForEach-Object { $_.Value })
    if ($binaries.Count -gt 0) { return $binaries[$binaries.Count - 1] }

    $loose = @([regex]::Matches($Message, $script:CiLoosePattern) | ForEach-Object { $_.Value })
    if ($loose.Count -gt 0) { return $loose[$loose.Count - 1] }
    return ''
}

# ---------------------------------------------------------------------------
# Is anything actually enforcing?
# ---------------------------------------------------------------------------
# Is a policy PRESENT, judged on an explicit evidence hierarchy.
#
# The hierarchy is the whole point, and getting it wrong has now cost two
# rounds. Strongest to weakest:
#
#   1. Something is enforcing            - decisive, nothing else matters
#   2. DeviceGuard reports its status    - 0/0 is a POSITIVE statement that
#                                          nothing is applying a policy
#   3. Policy files on disk              - the weakest signal there is
#
# A .p7b that no subsystem is applying is a file, not a policy. The first fix
# stopped counting Windows' own driversipolicy.p7b, but left a single non-stock
# file able to outvote DeviceGuard saying 0/0 and zero policy events in the
# log - so the verdict still came back "policy present, check audit or
# enforce" on a machine where demonstrably nothing was enforcing anything.
# File presence is reported now, but it only decides the answer when the
# stronger signals are unavailable.
function Test-AnyPolicyPresent {
    param(
        [bool]$Enforcing,
        [bool]$DeviceGuardReadable,
        $KernelStatus,
        $UserModeStatus,
        [bool]$SacSupported,
        $SacState,
        [int]$PolicyFiles
    )

    if ($Enforcing) { return $true }

    $sacEvaluating = ($SacSupported -and $SacState -eq 2)

    # DeviceGuard answered, and it said nothing is on. Believe it.
    if ($DeviceGuardReadable -and $KernelStatus -eq 0 -and $UserModeStatus -eq 0 -and -not $sacEvaluating) {
        return $false
    }

    return (
        ($KernelStatus -gt 0) -or
        ($UserModeStatus -gt 0) -or
        $sacEvaluating -or
        ($PolicyFiles -gt 0)
    )
}

function Get-CiEnforcementState {
    $WhatIfPreference = $false

    $out = [pscustomobject]@{
        OsBuild                = 0
        SacSupported           = $false
        SacState               = $null
        SacText                = ''
        DeviceGuardReadable    = $false
        KernelPolicyStatus     = $null
        UserModePolicyStatus   = $null
        HvciEnabled            = $null
        VbsStatus              = $null
        ActivePolicyFiles      = 0
        StockPolicyFiles       = 0
        AnyPolicyEnforcing     = $false
        AnyPolicyPresent       = $false
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $out.OsBuild = [int]$os.BuildNumber
    }
    catch { }
    $out.SacSupported = ($out.OsBuild -ge $script:SacMinimumBuild)

    $sac = Get-CiRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState'
    if ($null -ne $sac) { $out.SacState = [int]$sac }

    if (-not $out.SacSupported) {
        $out.SacText = 'not available on this Windows build - Smart App Control needs Windows 11 22H2 or later'
    }
    elseif ($null -eq $out.SacState) { $out.SacText = 'not configured' }
    elseif ($out.SacState -eq 0) { $out.SacText = 'off' }
    elseif ($out.SacState -eq 1) { $out.SacText = 'ON - blocks unsigned and unknown binaries' }
    elseif ($out.SacState -eq 2) { $out.SacText = 'evaluation mode' }
    else { $out.SacText = ('unrecognised state ' + $out.SacState) }

    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop | Select-Object -First 1
        if ($dg) {
            $out.DeviceGuardReadable = $true
            $out.KernelPolicyStatus = [int]$dg.CodeIntegrityPolicyEnforcementStatus
            $out.UserModePolicyStatus = [int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus
            $out.VbsStatus = [int]$dg.VirtualizationBasedSecurityStatus
            $out.HvciEnabled = (@($dg.SecurityServicesRunning) -contains 2)
        }
    }
    catch { }

    if ($null -eq $out.HvciEnabled) {
        $hv = Get-CiRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled'
        if ($null -ne $hv) { $out.HvciEnabled = ([int]$hv -eq 1) }
    }

    # A DEPLOYED policy leaves files behind. Windows also ships policy files of
    # its own, and counting those as a deployment is a false signal that flips
    # every downstream conclusion.
    #
    # driversipolicy.p7b is present on a stock Windows 10 install. Counting it
    # made AnyPolicyPresent true on a machine with WDAC status 0/0 and zero
    # policy events, which pushed the verdict off "signing-level noise" and
    # onto the hedged "policy present, check audit or enforce" - sending a tech
    # to inspect a policy that does not exist. Enforcement status and policy
    # EVENTS are the real evidence; files on disk are the weakest of the three.
    try {
        $active = @(Get-ChildItem -LiteralPath "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active" -Filter '*.p7b' -ErrorAction Stop)
        $out.ActivePolicyFiles += $active.Count
    }
    catch { }
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath "$env:SystemRoot\System32\CodeIntegrity" -Filter '*.p7b' -ErrorAction Stop)) {
            if ($script:StockPolicyFiles -contains $f.Name.ToLowerInvariant()) {
                $out.StockPolicyFiles++
                continue
            }
            $out.ActivePolicyFiles++
        }
    }
    catch { }

    $out.AnyPolicyEnforcing = (
        ($out.SacSupported -and $out.SacState -eq 1) -or
        ($out.KernelPolicyStatus -eq 2) -or
        ($out.UserModePolicyStatus -eq 2)
    )
    $out.AnyPolicyPresent = Test-AnyPolicyPresent `
        -Enforcing $out.AnyPolicyEnforcing `
        -DeviceGuardReadable $out.DeviceGuardReadable `
        -KernelStatus $out.KernelPolicyStatus `
        -UserModeStatus $out.UserModePolicyStatus `
        -SacSupported $out.SacSupported `
        -SacState $out.SacState `
        -PolicyFiles $out.ActivePolicyFiles

    return $out
}

# ---------------------------------------------------------------------------
# What is actually in the log.
# ---------------------------------------------------------------------------
function Get-CiEventBreakdown {
    param([int]$Days = 14, [int]$MaxEvents = 2000)
    $WhatIfPreference = $false

    $out = [pscustomobject]@{
        Readable    = $false
        Reason      = ''
        Total       = 0
        Capped      = $false
        ById        = @()
        Subjects    = @()
        NoPathCount = 0
        PolicyBlocks = 0
        SigningLevel = 0
    }

    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
                LogName      = $script:CiLog
                ProviderName = $script:CiProvider
                StartTime    = (Get-Date).AddDays(-$Days)
            } -MaxEvents $MaxEvents -ErrorAction Stop)
        $out.Readable = $true
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            $out.Readable = $true
        }
        elseif ($_.Exception.Message -match 'Attempted to perform an unauthorized operation|access is denied') {
            $out.Reason = 'RequiresElevation'
            return $out
        }
        else {
            $out.Reason = $_.Exception.Message
            return $out
        }
    }

    $out.Total = $events.Count
    $out.Capped = ($events.Count -ge $MaxEvents)

    foreach ($g in ($events | Group-Object Id | Sort-Object Count -Descending)) {
        $id = [int]$g.Name
        $out.ById += [pscustomobject]@{
            Id       = $id
            Count    = $g.Count
            Meaning  = (Get-CiEventMeaning -Id $id)
            IsPolicy = (Test-CiIsPolicyBlock -Id $id)
            IsSigning = (Test-CiIsSigningLevel -Id $id)
        }
        if (Test-CiIsPolicyBlock -Id $id) { $out.PolicyBlocks += $g.Count }
        if (Test-CiIsSigningLevel -Id $id) { $out.SigningLevel += $g.Count }
    }

    # Group by the refused file. Full path kept for the console only; the
    # object that leaves carries the bucket and extension.
    # Events with no path in the message are counted, never bucketed.
    #
    # Bucketing them lumps every unrelated informational event into a single
    # synthetic "file", which then looks like one thing repeating hundreds of
    # times and fires the concentration warning on a machine where nothing is
    # wrong. Caught on the first live run: 171 events across eight
    # informational IDs, no paths in any of them, reported as "CONCENTRATED -
    # one thing is retrying in a loop".
    $byPath = @{}
    foreach ($e in $events) {
        $subject = Get-CiSubjectPath -Message $e.Message
        $norm = ConvertTo-CiNormalizedPath -Path $subject
        if (-not $norm) { $out.NoPathCount++; continue }
        $key = $norm
        if (-not $byPath.ContainsKey($key)) {
            $byPath[$key] = [pscustomobject]@{
                NormalizedPath = $norm
                RawPath        = $subject
                Count          = 0
                Ids            = @()
            }
        }
        $byPath[$key].Count++
        if ($byPath[$key].Ids -notcontains $e.Id) { $byPath[$key].Ids += $e.Id }
    }

    $out.Subjects = @($byPath.Values | Sort-Object Count -Descending)
    return $out
}

function Get-CiFileFacts {
    param([string]$NormalizedPath)
    $WhatIfPreference = $false

    $out = [pscustomobject]@{
        Exists    = $false
        Signature = 'not checked'
        Signer    = ''
    }
    if ([string]::IsNullOrWhiteSpace($NormalizedPath)) { return $out }

    # The event says which volume; we only kept the tail. The system volume is
    # right in the overwhelming majority of cases and a miss just reports
    # "not present", which is honest.
    $full = Join-Path $env:SystemDrive $NormalizedPath.TrimStart('\')
    if (-not (Test-Path -LiteralPath $full)) { return $out }
    $out.Exists = $true

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $full -ErrorAction Stop
        $out.Signature = [string]$sig.Status
        if ($sig.SignerCertificate) {
            $subject = [string]$sig.SignerCertificate.Subject
            if ($subject -match 'CN=([^,]+)') { $out.Signer = $Matches[1].Trim() }
        }
    }
    catch { $out.Signature = 'could not be read' }

    return $out
}

# ---------------------------------------------------------------------------
# Verdict. Pure, so the test suite can pin the branch that got this wrong.
# ---------------------------------------------------------------------------
function Get-CiVerdict {
    param([Parameter(Mandatory = $true)]$Facts)

    if (-not $Facts.Readable) {
        return [pscustomobject]@{
            State  = 'COULD NOT ESTABLISH'
            Detail = 'The Code Integrity log could not be read.'
        }
    }

    if ($Facts.Total -eq 0) {
        return [pscustomobject]@{
            State  = 'NOTHING LOGGED'
            Detail = 'No Code Integrity events in the window. Nothing here is refusing anything.'
        }
    }

    if ($Facts.PolicyBlocks -gt 0) {
        return [pscustomobject]@{
            State  = 'POLICY IS BLOCKING'
            Detail = ('A Code Integrity policy audited or blocked {0} item(s). This is a program being refused, and it happens before UAC is consulted.' -f $Facts.PolicyBlocks)
        }
    }

    if ($Facts.SigningLevel -gt 0 -and -not $Facts.AnyPolicyPresent) {
        return [pscustomobject]@{
            State  = 'SIGNING-LEVEL NOISE'
            Detail = ('{0} signing-level load failures and NO policy present - not Smart App Control, not WDAC, and not a blocked program. Something is repeatedly trying to load into a process that will not accept it. Large counts here are normal and are not, on their own, a fault.' -f $Facts.SigningLevel)
        }
    }

    if ($Facts.SigningLevel -gt 0) {
        return [pscustomobject]@{
            State  = 'SIGNING-LEVEL FAILURES, POLICY PRESENT'
            Detail = ('{0} signing-level load failures with a policy configured. Check whether the policy is in audit or enforce before blaming it.' -f $Facts.SigningLevel)
        }
    }

    return [pscustomobject]@{
        State  = 'OTHER EVENTS ONLY'
        Detail = 'Events present, but none are policy blocks or signing-level failures. Read the breakdown.'
    }
}

# ---------------------------------------------------------------------------
function Invoke-CodeIntegrityModule {
    [CmdletBinding()]
    param([switch]$Apply, [hashtable]$Options = @{})

    if ($Apply) {
        Write-Log -Message 'The codeintegrity module is read-only. It reads a log and checks what is enforcing; there is nothing here to change.' -Level WARN
    }

    $days = 14
    if ($Options.ContainsKey('Minutes') -and [int]$Options.Minutes -gt 0) { $days = [int]$Options.Minutes }

    Write-Banner 'Code Integrity block detail'

    $enf = Get-CiEnforcementState
    $brk = Get-CiEventBreakdown -Days $days

    # --- 1. is anything enforcing --------------------------------------
    Write-Host ''
    Write-Host '  1  IS ANYTHING ACTUALLY ENFORCING?' -ForegroundColor White
    Write-Host ('     Windows build       : {0}' -f $enf.OsBuild) -ForegroundColor Gray
    $sacColor = 'Gray'
    if ($enf.SacSupported -and $enf.SacState -eq 1) { $sacColor = 'Yellow' }
    Write-Host ('     Smart App Control   : {0}' -f $enf.SacText) -ForegroundColor $sacColor
    if (-not $enf.SacSupported) {
        Write-Host '                           (so nothing in this log can be blamed on it)' -ForegroundColor DarkGray
    }

    if ($enf.DeviceGuardReadable) {
        $kText = 'off'
        if ($enf.KernelPolicyStatus -eq 1) { $kText = 'audit' } elseif ($enf.KernelPolicyStatus -eq 2) { $kText = 'ENFORCED' }
        $uText = 'off'
        if ($enf.UserModePolicyStatus -eq 1) { $uText = 'audit' } elseif ($enf.UserModePolicyStatus -eq 2) { $uText = 'ENFORCED' }
        Write-Host ('     WDAC kernel policy  : {0}' -f $kText) -ForegroundColor $(if ($enf.KernelPolicyStatus -eq 2) { 'Yellow' } else { 'Gray' })
        Write-Host ('     WDAC usermode policy: {0}' -f $uText) -ForegroundColor $(if ($enf.UserModePolicyStatus -eq 2) { 'Yellow' } else { 'Gray' })
    }
    else {
        Write-Host '     WDAC policy status  : DeviceGuard WMI class not available on this edition' -ForegroundColor DarkGray
    }
    Write-Host ('     Memory integrity    : {0}' -f $(if ($null -eq $enf.HvciEnabled) { 'unknown' } else { $enf.HvciEnabled })) -ForegroundColor Gray
    Write-Host ('     Deployed policies   : {0}{1}' -f $enf.ActivePolicyFiles,
        $(if ($enf.StockPolicyFiles -gt 0) { ('   (+{0} shipped by Windows, not a deployment)' -f $enf.StockPolicyFiles) } else { '' })) -ForegroundColor Gray

    if (-not $enf.AnyPolicyPresent -and $enf.ActivePolicyFiles -gt 0) {
        Write-Host ''
        Write-Host ('     {0} policy file(s) exist on disk but nothing is applying them -' -f $enf.ActivePolicyFiles) -ForegroundColor DarkGray
        Write-Host '     DeviceGuard reports enforcement off. A policy file no subsystem' -ForegroundColor DarkGray
        Write-Host '     is applying is a file, not a policy.' -ForegroundColor DarkGray
    }

    if (-not $enf.AnyPolicyPresent) {
        Write-Host ''
        Write-Host '     NO CODE INTEGRITY POLICY IS ENFORCING ON THIS MACHINE.' -ForegroundColor Green
        Write-Host '     Whatever is in the log below, it is not a policy refusing to run' -ForegroundColor Green
        Write-Host '     programs, because there is no policy. Read the counts in that' -ForegroundColor Green
        Write-Host '     light before drawing any conclusion from their size.' -ForegroundColor Green
    }

    # --- 2. what is in the log ------------------------------------------
    Write-Host ''
    Write-Host ('  2  WHAT IS IN THE LOG (last {0} days)' -f $days) -ForegroundColor White
    if (-not $brk.Readable) {
        $why = $brk.Reason
        if ($why -eq 'RequiresElevation') { $why = 'RequiresElevation - re-run elevated' }
        Write-Host ('     Could not read the log: {0}' -f $why) -ForegroundColor Yellow
    }
    elseif ($brk.Total -eq 0) {
        Write-Host '     No events.' -ForegroundColor Green
    }
    else {
        Write-Host ('     Total events        : {0}{1}' -f $brk.Total, $(if ($brk.Capped) { ' (capped - there are more)' } else { '' })) -ForegroundColor Gray
        Write-Host ''
        foreach ($row in $brk.ById) {
            $c = 'Gray'
            if ($row.IsPolicy) { $c = 'Red' }
            elseif ($row.IsSigning) { $c = 'Cyan' }
            Write-Host ('     {0,-6} {1,6}   {2}' -f $row.Id, $row.Count, $row.Meaning) -ForegroundColor $c
        }
        Write-Host ''
        Write-Host ('     Policy blocks (3076/3077/3082) : {0}' -f $brk.PolicyBlocks) -ForegroundColor $(if ($brk.PolicyBlocks -gt 0) { 'Red' } else { 'Green' })
        Write-Host ('     Signing-level  (3033/3034)     : {0}' -f $brk.SigningLevel) -ForegroundColor Cyan
        Write-Host ''
        Write-Host '     These are NOT the same finding. A signing-level failure is a load' -ForegroundColor DarkGray
        Write-Host '     refused inside a process, typically an injection into something' -ForegroundColor DarkGray
        Write-Host '     that will not accept it. A policy block is a program refused.' -ForegroundColor DarkGray
    }

    # --- 3. what is repeating -------------------------------------------
    Write-Host ''
    Write-Host '  3  WHAT IS REPEATING' -ForegroundColor White
    $top = @($brk.Subjects | Select-Object -First 10)
    if ($brk.NoPathCount -gt 0) {
        Write-Host ('     {0} event(s) name no file at all - informational, nothing to' -f $brk.NoPathCount) -ForegroundColor DarkGray
        Write-Host '     identify. Not counted as a repeating file.' -ForegroundColor DarkGray
    }
    if ($top.Count -eq 0) {
        Write-Host '     No event named a file. Nothing to group.' -ForegroundColor Gray
    }
    else {
        $distinct = @($brk.Subjects).Count
        $withPath = 0
        foreach ($s in $brk.Subjects) { $withPath += $s.Count }
        Write-Host ('     Distinct files: {0}  (across {1} event(s) that name one)' -f $distinct, $withPath) -ForegroundColor Gray
        # Concentration is judged only against events that actually name a
        # file. Measuring it against the total lets informational noise decide.
        if ($distinct -le 3 -and $withPath -gt 50) {
            Write-Host '     CONCENTRATED: a handful of files account for a large count.' -ForegroundColor Yellow
            Write-Host '     One thing is retrying in a loop rather than many programs' -ForegroundColor Yellow
            Write-Host '     being refused. Identify it before deciding it matters.' -ForegroundColor Yellow
        }
        Write-Host ''
        Write-Host '     (paths shown here only - they are not written to the report)' -ForegroundColor DarkGray
        foreach ($s in $top) {
            $facts = Get-CiFileFacts -NormalizedPath $s.NormalizedPath
            $bucket = Get-CiPathBucket -NormalizedPath $s.NormalizedPath
            Write-Host ('     {0,6}x  {1}' -f $s.Count, $s.RawPath) -ForegroundColor Gray
            Write-Host ('             ids {0} | {1} | {2}{3}' -f `
                (($s.Ids | Sort-Object) -join ','), $bucket, $facts.Signature,
                $(if ($facts.Signer) { ' by ' + $facts.Signer } else { '' })) -ForegroundColor DarkGray

            $note = Get-KnownNoiseNote -NormalizedPath $s.NormalizedPath
            if ($note) {
                Write-Host ('             KNOWN NOISE: {0}' -f $note.What) -ForegroundColor Green
                Write-Host ('             {0}' -f $note.Why) -ForegroundColor DarkGray
                Write-Host ('             {0}' -f $note.Do) -ForegroundColor DarkGray
                Write-Host '             Matched on file name only - confirm the signature and' -ForegroundColor DarkGray
                Write-Host '             location above before accepting it as this component.' -ForegroundColor DarkGray
            }
        }
    }

    # --- verdict ---------------------------------------------------------
    $facts = [pscustomobject]@{
        Readable         = $brk.Readable
        Total            = $brk.Total
        PolicyBlocks     = $brk.PolicyBlocks
        SigningLevel     = $brk.SigningLevel
        AnyPolicyPresent = $enf.AnyPolicyPresent
    }
    $verdict = Get-CiVerdict -Facts $facts

    Write-Host ''
    $vColor = 'Green'
    if ($verdict.State -eq 'POLICY IS BLOCKING') { $vColor = 'Red' }
    elseif ($verdict.State -eq 'COULD NOT ESTABLISH') { $vColor = 'Yellow' }
    elseif ($verdict.State -like 'SIGNING-LEVEL*') { $vColor = 'Cyan' }
    Write-Host ('  VERDICT: ' + $verdict.State) -ForegroundColor $vColor
    Write-Host ('    ' + $verdict.Detail) -ForegroundColor Gray

    Write-Host ''
    Write-Host '  Read-only. Nothing was changed.' -ForegroundColor DarkGray
    Write-Host ''

    # Paths and file names deliberately absent. Extension plus location bucket
    # is enough to reason about a finding without carrying an inventory of the
    # customer's installed software off the machine.
    $summary = @()
    foreach ($s in @($brk.Subjects | Select-Object -First 20)) {
        $summary += [pscustomobject]@{
            Count     = $s.Count
            Extension = (Get-CiExtension -NormalizedPath $s.NormalizedPath)
            Bucket    = (Get-CiPathBucket -NormalizedPath $s.NormalizedPath)
            Ids       = @($s.Ids | Sort-Object)
        }
    }

    return [pscustomobject]@{
        Verdict            = $verdict.State
        VerdictDetail      = $verdict.Detail
        WindowDays         = $days
        OsBuild            = $enf.OsBuild
        SacSupported       = $enf.SacSupported
        SacState           = $enf.SacState
        SacText            = $enf.SacText
        WdacKernelStatus   = $enf.KernelPolicyStatus
        WdacUserModeStatus = $enf.UserModePolicyStatus
        HvciEnabled        = $enf.HvciEnabled
        ActivePolicyFiles  = $enf.ActivePolicyFiles
        StockPolicyFiles   = $enf.StockPolicyFiles
        AnyPolicyPresent   = $enf.AnyPolicyPresent
        AnyPolicyEnforcing = $enf.AnyPolicyEnforcing
        LogReadable        = $brk.Readable
        LogReason          = $brk.Reason
        TotalEvents        = $brk.Total
        EventsNamingNoFile = $brk.NoPathCount
        Capped             = $brk.Capped
        ById               = $brk.ById
        PolicyBlocks       = $brk.PolicyBlocks
        SigningLevelFailures = $brk.SigningLevel
        DistinctFiles      = @($brk.Subjects).Count
        TopFiles           = $summary
    }
}
