# Test-CodeIntegrity.ps1 - event semantics, path handling, verdict logic.
# ASCII only, PowerShell 5.1 compatible. Changes nothing.
#
# This whole module exists because a count was right and the conclusion drawn
# from it was wrong, so the tests that matter are the ones pinning MEANING:
# which IDs are a program being refused, which are a load failing inside a
# process, and the refusal to blame a feature the OS does not have.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'lib\Modules.ps1')

$ModulePath = Join-Path $Root 'modules\Get-CodeIntegrityDetail.ps1'
. $ModulePath

$pass = 0
$fail = 0

function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  PASS  " + $Name) -ForegroundColor Green; $script:pass++ }
    else { Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red; $script:fail++ }
}

Write-Host ''
Write-Host '  Manifest' -ForegroundColor Cyan
Write-Host '  --------' -ForegroundColor DarkGray

$mods = Get-TuneUpModules -ModuleRoot (Join-Path $Root 'modules')
$me = @($mods | Where-Object { $_.Key -eq 'codeintegrity' }) | Select-Object -First 1
Assert-True 'The codeintegrity module is discovered' ($null -ne $me)
if ($me) {
    Assert-True 'It does not require admin' (-not $me.RequiresAdmin)
    Assert-True 'It defines its entry point' ($null -ne (Get-Command -Name $me.Entry -ErrorAction SilentlyContinue))
}

Write-Host ''
Write-Host '  Event semantics' -ForegroundColor Cyan
Write-Host '  ---------------' -ForegroundColor DarkGray

# The core distinction. Getting either of these backwards reproduces the bug.
foreach ($id in @(3076, 3077, 3082)) {
    Assert-True "Event $id is a policy block" (Test-CiIsPolicyBlock -Id $id)
    Assert-True "Event $id is not a signing-level failure" (-not (Test-CiIsSigningLevel -Id $id))
}
foreach ($id in @(3033, 3034)) {
    Assert-True "Event $id is a signing-level failure" (Test-CiIsSigningLevel -Id $id)
    Assert-True "Event $id is NOT a policy block" (-not (Test-CiIsPolicyBlock -Id $id))
}
Assert-True 'Event 3099 is neither' `
((-not (Test-CiIsPolicyBlock -Id 3099)) -and (-not (Test-CiIsSigningLevel -Id 3099)))

Assert-True '3033 is described as a signing level failure, not a block' `
((Get-CiEventMeaning -Id 3033) -match 'SIGNING LEVEL')
Assert-True '3077 is described as the program being refused' `
((Get-CiEventMeaning -Id 3077) -match 'refused')
Assert-True 'An unknown ID is not invented a meaning' `
((Get-CiEventMeaning -Id 9999) -match 'other Code Integrity event')

Write-Host ''
Write-Host '  Path normalisation' -ForegroundColor Cyan
Write-Host '  ------------------' -ForegroundColor DarkGray

# Three shapes turn up in these messages and all must reduce to the same key,
# or the "is one file repeating" grouping splits into three piles and reports
# many distinct files where there is one.
$shapes = @(
    '\Device\HarddiskVolume3\Windows\System32\thing.dll',
    '\??\C:\Windows\System32\thing.dll',
    'C:\Windows\System32\thing.dll'
)
$normalised = @($shapes | ForEach-Object { ConvertTo-CiNormalizedPath -Path $_ })
Assert-True 'All three path shapes normalise identically' `
((@($normalised | Sort-Object -Unique).Count) -eq 1) ("got=" + ($normalised -join ' | '))
Assert-True 'And they normalise to a volume-relative path' `
($normalised[0] -eq '\Windows\System32\thing.dll')
Assert-True 'Empty input does not throw' ((ConvertTo-CiNormalizedPath -Path $null) -eq '')

Write-Host ''
Write-Host '  Location buckets' -ForegroundColor Cyan
Write-Host '  ----------------' -ForegroundColor DarkGray

$cases = @(
    @{ Path = '\Windows\System32\foo.dll';               Expect = 'Windows\System32' },
    @{ Path = '\Windows\SysWOW64\foo.dll';               Expect = 'Windows\SysWOW64' },
    @{ Path = '\Windows\Temp\foo.dll';                   Expect = 'Windows\Temp' },
    @{ Path = '\Windows\assembly\foo.dll';               Expect = 'Windows' },
    @{ Path = '\Program Files\Vendor\foo.dll';           Expect = 'Program Files' },
    @{ Path = '\Program Files (x86)\Vendor\foo.dll';     Expect = 'Program Files (x86)' },
    @{ Path = '\ProgramData\Vendor\foo.dll';             Expect = 'ProgramData' },
    @{ Path = '\Users\someone\AppData\Local\Temp\x.dll'; Expect = 'user temp' },
    @{ Path = '\Users\someone\Documents\x.dll';          Expect = 'user profile' },
    @{ Path = '\Weird\Place\x.dll';                      Expect = 'other' },
    @{ Path = '';                                        Expect = 'unknown' }
)
foreach ($c in $cases) {
    $got = Get-CiPathBucket -NormalizedPath $c.Path
    Assert-True ("{0,-20} -> {1}" -f $c.Expect, $c.Path) ($got -eq $c.Expect) "got=$got"
}

# System32 sits under Windows, so ordering matters - a naive check reports
# every System32 file as plain 'Windows' and the bucket stops distinguishing.
Assert-True 'System32 is not swallowed by the broader Windows rule' `
((Get-CiPathBucket -NormalizedPath '\Windows\System32\foo.dll') -ne 'Windows')

Assert-True 'Extension is lowercased' ((Get-CiExtension -NormalizedPath '\Windows\System32\FOO.DLL') -eq '.dll')
Assert-True 'No extension returns empty, not null' ((Get-CiExtension -NormalizedPath '\Windows\foo') -eq '')

Write-Host ''
Write-Host '  Message parsing' -ForegroundColor Cyan
Write-Host '  ---------------' -ForegroundColor DarkGray

# Shaped like a real 3033: two paths, and the one the event is ABOUT is the
# second. Taking the first would blame the process instead of the file.
$msg = 'Code Integrity determined that a process (\Device\HarddiskVolume3\Windows\System32\svchost.exe) attempted to load \Device\HarddiskVolume3\Program Files\Vendor\inject.dll that did not meet the Microsoft signing level requirements.'
$subject = Get-CiSubjectPath -Message $msg
Assert-True 'The subject is the loaded file, not the process' ($subject -match 'inject\.dll') ("got=$subject")

# REGRESSION. The first pattern stopped at whitespace, so this truncated to
# "\Device\HarddiskVolume3\Program", lost its extension, was discarded as a
# non-binary, and the parser named svchost.exe instead. Every event for one
# repeating DLL would then land in its own bucket and the concentration check
# - the entire point of the module - would report noise as many distinct files.
Assert-True 'A path containing spaces survives intact' `
($subject -eq '\Device\HarddiskVolume3\Program Files\Vendor\inject.dll') ("got=$subject")

# Both paths must still be found, not just the subject.
$all = @(Get-CiPathsFromMessage -Message $msg)
Assert-True 'Both paths in the message are extracted' ($all.Count -eq 2) ("count=" + $all.Count)

# Program Files (x86) has parentheses, which the loose pattern treats as a
# terminator. The extension anchor has to win here too.
$msg86 = 'attempted to load \??\C:\Program Files (x86)\Some Vendor\a b\thing.dll that did not meet'
Assert-True 'Parentheses and multiple spaces survive' `
((Get-CiSubjectPath -Message $msg86) -eq '\??\C:\Program Files (x86)\Some Vendor\a b\thing.dll') `
("got=" + (Get-CiSubjectPath -Message $msg86))

# Single-path messages (3004 shape) still work.
$msg1 = 'Code Integrity determined that the image hash of file \Device\HarddiskVolume2\Windows\System32\drivers\old.sys is not valid'
Assert-True 'A single-path message returns that path' ((Get-CiSubjectPath -Message $msg1) -match 'old\.sys')

Assert-True 'A message with no path returns empty' ((Get-CiSubjectPath -Message 'no paths here') -eq '')
Assert-True 'A null message does not throw' ((Get-CiSubjectPath -Message $null) -eq '')

# And the grouping key must collapse across volumes and shapes.
$a = ConvertTo-CiNormalizedPath -Path (Get-CiSubjectPath -Message $msg)
$msgAlt = 'attempted to load C:\Program Files\Vendor\inject.dll that did not meet'
$b = ConvertTo-CiNormalizedPath -Path (Get-CiSubjectPath -Message $msgAlt)
Assert-True 'The same file from two message shapes groups together' ($a -eq $b) ("a=$a b=$b")

Write-Host ''
Write-Host '  Verdict' -ForegroundColor Cyan
Write-Host '  -------' -ForegroundColor DarkGray

function New-CiFacts {
    param([bool]$Readable = $true, [int]$Total = 0, [int]$Policy = 0, [int]$Signing = 0, [bool]$PolicyPresent = $false)
    return [pscustomobject]@{
        Readable = $Readable; Total = $Total; PolicyBlocks = $Policy
        SigningLevel = $Signing; AnyPolicyPresent = $PolicyPresent
    }
}

Assert-True 'An unreadable log gives COULD NOT ESTABLISH' `
((Get-CiVerdict -Facts (New-CiFacts -Readable $false)).State -eq 'COULD NOT ESTABLISH')
Assert-True 'An empty log says nothing is logged' `
((Get-CiVerdict -Facts (New-CiFacts -Total 0)).State -eq 'NOTHING LOGGED')

# THE case. This is the customer machine: a large 3033 count, no policy.
$v = Get-CiVerdict -Facts (New-CiFacts -Total 734 -Signing 734 -PolicyPresent $false)
Assert-True 'A 3033 storm with no policy is called noise, not a block' ($v.State -eq 'SIGNING-LEVEL NOISE') ("got=" + $v.State)
Assert-True 'And it says plainly that it is not Smart App Control' ($v.Detail -match 'not Smart App Control')
Assert-True 'And it says plainly that it is not WDAC' ($v.Detail -match 'not WDAC')
Assert-True 'And it does not call the count a fault' ($v.Detail -match 'not, on their own, a fault')

$v = Get-CiVerdict -Facts (New-CiFacts -Total 5 -Policy 5 -PolicyPresent $true)
Assert-True 'Policy blocks are called out as a program being refused' ($v.State -eq 'POLICY IS BLOCKING')

# Policy blocks win even alongside a signing storm - the smaller number is
# the important one, and sorting by count would bury it.
$v = Get-CiVerdict -Facts (New-CiFacts -Total 739 -Policy 5 -Signing 734 -PolicyPresent $true)
Assert-True 'A few policy blocks outrank a big signing-level count' ($v.State -eq 'POLICY IS BLOCKING')

$v = Get-CiVerdict -Facts (New-CiFacts -Total 100 -Signing 100 -PolicyPresent $true)
Assert-True 'Signing failures WITH a policy present are hedged, not dismissed' `
($v.State -eq 'SIGNING-LEVEL FAILURES, POLICY PRESENT')

Write-Host ''
Write-Host '  Stock policy files are not a deployment' -ForegroundColor Cyan
Write-Host '  --------------------------------------' -ForegroundColor DarkGray

# REGRESSION from the customer machine. driversipolicy.p7b ships with Windows.
# Counting it as a deployed policy made AnyPolicyPresent true on a unit with
# WDAC status 0/0 and ZERO policy events, which pushed a correct
# "SIGNING-LEVEL NOISE" verdict onto the hedged "policy present - check audit
# or enforce" and would have sent a tech looking for a policy that isn't there.
Assert-True 'driversipolicy.p7b is on the stock list' `
($script:StockPolicyFiles -contains 'driversipolicy.p7b')

$enfLive = Get-CiEnforcementState
Assert-True 'Live: stock files are counted separately from deployments' `
($null -ne $enfLive.StockPolicyFiles)
if (-not $enfLive.AnyPolicyEnforcing -and $enfLive.ActivePolicyFiles -eq 0) {
    Assert-True 'Live: no enforcement and no deployed policy means none present' `
    (-not $enfLive.AnyPolicyPresent) `
    ("active=" + $enfLive.ActivePolicyFiles + " stock=" + $enfLive.StockPolicyFiles)
}

# The exact customer shape: 756 signing-level, zero policy events, nothing
# enforcing. Must read as noise, not as a policy question.
$v = Get-CiVerdict -Facts (New-CiFacts -Total 1514 -Policy 0 -Signing 756 -PolicyPresent $false)
Assert-True 'The customer shape verdicts as signing-level noise' ($v.State -eq 'SIGNING-LEVEL NOISE') ("got=" + $v.State)

Write-Host ''
Write-Host '  Live breakdown' -ForegroundColor Cyan
Write-Host '  --------------' -ForegroundColor DarkGray

# REGRESSION, caught on the first live run. Events whose messages name no file
# were bucketed under a single synthetic key, so 171 unrelated informational
# events looked like one file repeating and fired the concentration warning on
# a healthy machine. They are counted now, never grouped.
$live = Get-CiEventBreakdown -Days 14 -MaxEvents 500
if ($live.Readable) {
    Assert-True 'Live: pathless events are counted separately' ($null -ne $live.NoPathCount)
    $bogus = @($live.Subjects | Where-Object { -not $_.NormalizedPath })
    Assert-True 'Live: no subject bucket has an empty path' ($bogus.Count -eq 0) ("count=" + $bogus.Count)
    $sum = 0
    foreach ($s in $live.Subjects) { $sum += $s.Count }
    Assert-True 'Live: named + unnamed accounts for every event' `
    (($sum + $live.NoPathCount) -eq $live.Total) `
    ("named=$sum unnamed=" + $live.NoPathCount + " total=" + $live.Total)
}
else {
    Write-Host '  SKIP  live breakdown (log unreadable)' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '  Smart App Control support gate' -ForegroundColor Cyan
Write-Host '  ------------------------------' -ForegroundColor DarkGray

# The live check on this machine. Whatever it reports must be consistent with
# the build it is running on - that consistency is the thing that failed.
$enf = Get-CiEnforcementState
Assert-True 'Enforcement state reports an OS build' ($enf.OsBuild -gt 0) ("build=" + $enf.OsBuild)
Assert-True 'SacSupported agrees with the build number' `
($enf.SacSupported -eq ($enf.OsBuild -ge 22621)) ("supported=" + $enf.SacSupported + " build=" + $enf.OsBuild)
if (-not $enf.SacSupported) {
    Assert-True 'An unsupported build says so instead of naming a state' ($enf.SacText -match 'not available on this Windows build')
}

Write-Host ''
Write-Host '  Customer-data invariant' -ForegroundColor Cyan
Write-Host '  -----------------------' -ForegroundColor DarkGray

# Blocked file paths are an inventory of the customer's installed software.
# Full paths go to the console; the returned object gets extension + bucket.
$src = Get-Content -LiteralPath $ModulePath -Raw
$idx = $src.LastIndexOf('return [pscustomobject]@{')
Assert-True 'The module ends with a returned result object' ($idx -gt 0)
if ($idx -gt 0) {
    $returned = $src.Substring($idx)
    Assert-True 'No raw path field is returned' ($returned -notmatch 'RawPath')
    Assert-True 'No normalised path field is returned either' ($returned -notmatch 'NormalizedPath')
    Assert-True 'Only the classified summary leaves' ($returned -match 'TopFiles')
}

# And prove it on real data rather than by reading the source.
$summaryProbe = [pscustomobject]@{
    Count = 3; Extension = '.dll'; Bucket = (Get-CiPathBucket -NormalizedPath '\Users\someone\AppData\Local\Temp\x.dll'); Ids = @(3033)
}
$json = Protect-Object -InputObject $summaryProbe | ConvertTo-Json -Depth 5
Assert-True 'A classified summary carries no file name' ($json -notmatch 'x\.dll')
$verify = Test-SanitizedText -Text $json
Assert-True 'A classified summary passes the sanitizer' $verify.Clean ("hits=" + (($verify.Hits | Sort-Object -Unique) -join ','))

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
