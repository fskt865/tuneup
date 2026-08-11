# Test-Sanitizer.ps1 - verifies the redaction layer on the machine it runs on.
# ASCII only, PowerShell 5.1 compatible.
#
# Prints PASS/FAIL and token classes ONLY. It never echoes a value it found,
# because a test that proves the sanitizer works by printing the hostname it
# leaked is not a test, it is the leak.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')

$pass = 0
$fail = 0

function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) {
        Write-Host ("  PASS  " + $Name) -ForegroundColor Green
        $script:pass++
    }
    else {
        Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red
        $script:fail++
    }
}

Write-Host ''
Write-Host '  Sanitizer tests' -ForegroundColor Cyan
Write-Host '  ---------------' -ForegroundColor DarkGray

$map = New-RedactionMap
Assert-True 'Redaction map is non-empty' (@($map).Count -gt 0) "count=$(@($map).Count)"

# Map must be longest-first, or a short literal chews a hole in a longer one.
$lengths = @($map | ForEach-Object { $_.Value.Length })
$sorted = @($lengths | Sort-Object -Descending)
$ordered = $true
for ($i = 0; $i -lt $lengths.Count; $i++) { if ($lengths[$i] -ne $sorted[$i]) { $ordered = $false } }
Assert-True 'Map is sorted longest-literal-first' $ordered

# No literal shorter than 4 chars survived the filter.
$tooShort = @($map | Where-Object { $_.Value.Length -lt 4 })
Assert-True 'No literals shorter than 4 chars' ($tooShort.Count -eq 0) "count=$($tooShort.Count)"

# REGRESSION. C:\Users holds built-in profiles as well as real accounts, and
# feeding those into the map is worse than useless: they exist on every
# install so they identify nobody, and "Default" and "Public" are ordinary
# words that appear in report prose and in field names.
#
# The failure this pins was total, not cosmetic. A module returned a field
# called Default; the word was redacted out of every VALUE, survived in the
# JSON PROPERTY NAMES - which Protect-Object deliberately never rewrites,
# because they are schema authored in this repo rather than data read off the
# machine - and final verification then refused to write the report at all.
# Correct behaviour from the write path, but nothing downstream could fix it.
foreach ($builtin in @('Default', 'Public', 'All Users', 'Default User', 'WDAGUtilityAccount', 'Administrator', 'User', 'Guest')) {
    $hit = @($map | Where-Object { $_.Value -eq $builtin })
    Assert-True ("Built-in profile name '$builtin' is not treated as an account") ($hit.Count -eq 0)
}

# --- REGRESSION: a literal must never rewrite an emitted TOKEN -----------
#
# Found in the field 2026-08-09. Replacements used to run one pass per literal,
# so each pass re-scanned the previous pass's output. Every token contains the
# word USER, so an account literally named "User" - the OEM default, and
# exactly 4 characters so it survives the length filter - turned <USER1> into
# <<USER5>1> and C:\Users\ into C:\<USER5>s\. Verification then found the
# literal still present and refused to write, so the toolkit could not produce
# a report at all on a machine with a default account name.
#
# Longest-first sorting does not help: this is literal-vs-token, not
# literal-vs-literal. Only a single pass fixes it.
$savedMap = $script:RedactionMap
$script:RedactionMap = @(
    [pscustomobject]@{ Value = 'JenniferLongName'; Token = '<USER1>' }
    [pscustomobject]@{ Value = 'MarcusOther';      Token = '<USER2>' }
    [pscustomobject]@{ Value = 'User';             Token = '<USER5>' }
)

$mangled = Protect-String -Text 'JenniferLongName and MarcusOther both exist'
Assert-True 'A short literal does not rewrite emitted tokens' `
    ($mangled -notmatch '<<') "got=$mangled"
Assert-True 'Long literals still map to their own tokens' `
    (($mangled -match '<USER1>') -and ($mangled -match '<USER2>')) "got=$mangled"

$verifyTok = Test-SanitizedText -Text $mangled
Assert-True 'Output with a token-colliding literal verifies clean' `
    $verifyTok.Clean ("hits=" + ($verifyTok.Hits -join ','))

# The literal itself must still be redacted when it genuinely appears.
$plain = Protect-String -Text 'the User account'
Assert-True 'A colliding literal is still redacted in ordinary text' ($plain -match '<USER5>') "got=$plain"

# Substring matching mid-word is DELIBERATE and stays - an account name
# embedded in a longer string still has to be caught. With 'User' forced into
# the map here it does chew "Users" into "<USER5>s", which is ugly but not a
# leak; the real defence is that 'User' is excluded from the map in the first
# place (asserted in the built-in loop above). What must hold either way is
# that the result still VERIFIES, rather than the tool refusing to write.
$pathProbe = Protect-String -Text 'C:\Users\MarcusOther\AppData'
Assert-True 'A mid-word literal match does not nest tokens' ($pathProbe -notmatch '<<') "got=$pathProbe"
Assert-True 'A mid-word literal match still verifies clean' `
    ((Test-SanitizedText -Text $pathProbe).Clean) "got=$pathProbe"

# --- REGRESSION: verification must not flag its own tokens ---------------
#
# Second half of the same field failure. Test-SanitizedText scanned the text it
# had just redacted, and the token vocabulary contains ordinary words - "User"
# lives inside <USER5>, "Host" inside <HOST>. Verification reported a leak for
# perfectly redacted text, and the write path refused to write anything.
$script:RedactionMap = @(
    [pscustomobject]@{ Value = 'Host'; Token = '<USER1>' }
    [pscustomobject]@{ Value = 'RealAccountName'; Token = '<USER2>' }
)
$hostProbe = Protect-String -Text 'RealAccountName signed in'
Assert-True 'A literal appearing inside a token is not a leak' `
    ((Test-SanitizedText -Text $hostProbe).Clean) "got=$hostProbe"

# ...but a genuine survivor must still be caught. This is the check that makes
# the token-stripping above safe rather than a hole punched in verification.
$leak = 'RealAccountName was not redacted'
Assert-True 'A genuinely surviving literal is still detected' `
    (-not (Test-SanitizedText -Text $leak).Clean) "got=$leak"

$script:RedactionMap = $savedMap

# ...but the skip is whole-string, so a real account whose name merely starts
# with one of them must still be redacted.
$probe = 'The user Defaults and the user Publisher and IsDefault=true'
$protected = Protect-String -Text $probe
Assert-True 'The word Default is left alone in ordinary prose' ($protected -match 'IsDefault=true')
Assert-True 'A field name containing Default survives redaction' ($protected -notmatch '<USER')

# The end-to-end guarantee: schema-shaped output must verify clean. This is
# the exact shape that failed - property names carrying the built-in words.
$schemaProbe = [pscustomobject]@{
    Default = 1; IsDefault = $true; SrpDefaultLevel = $null
    PublicProfile = 'Public'; Note = 'not set - Windows default applies'
}
$json = Protect-Object -InputObject $schemaProbe | ConvertTo-Json -Depth 5
$verify = Test-SanitizedText -Text $json
Assert-True 'A report whose field names contain built-in words verifies clean' `
    $verify.Clean ("hits=" + (($verify.Hits | Sort-Object -Unique) -join ','))

# --- Live identifiers from this machine must not survive ----------------
$live = @{
    'hostname'     = $env:COMPUTERNAME
    'username'     = $env:USERNAME
    'profile path' = $env:USERPROFILE
}
foreach ($k in $live.Keys) {
    $v = $live[$k]
    if ([string]::IsNullOrEmpty($v) -or $v.Length -lt 4) {
        Write-Host ("  SKIP  live $k too short to redact safely") -ForegroundColor Yellow
        continue
    }
    $probe = "Diagnostic line mentioning $v in the middle of a sentence."
    $out = Protect-String -Text $probe
    Assert-True "Live $k is redacted" ($out -notmatch [regex]::Escape($v))
}

# --- Synthetic identifiers, safe to hardcode ---------------------------
$cases = @(
    @{ Name = 'MAC colon';     In = 'Adapter 00:1A:2B:3C:4D:5E up';        Bad = '00:1A:2B:3C:4D:5E' },
    @{ Name = 'MAC dash';      In = 'Adapter 00-1A-2B-3C-4D-5E up';        Bad = '00-1A-2B-3C-4D-5E' },
    @{ Name = 'IPv4';          In = 'Gateway 192.168.1.254 reachable';     Bad = '192.168.1.254' },
    @{ Name = 'Email';         In = 'Account owner.name@example.com sync'; Bad = 'owner.name@example.com' },
    @{ Name = 'User path';     In = 'Failed C:\Users\Margaret\Documents';  Bad = 'C:\Users\Margaret' },
    @{ Name = 'Product key';   In = 'Key ABCDE-FGHIJ-KLMNO-PQRST-UVWXY';   Bad = 'ABCDE-FGHIJ-KLMNO-PQRST-UVWXY' },
    @{ Name = 'GUID';          In = 'Id 3f2504e0-4f89-11d3-9a0c-0305e82c3301'; Bad = '3f2504e0-4f89-11d3-9a0c-0305e82c3301' },
    @{ Name = 'Account SID';   In = 'Task OneDrive Startup Task-S-1-5-21-515117657-1038125042-334280290-1001';
        Bad = 'S-1-5-21-515117657-1038125042-334280290-1001'
    },
    @{ Name = 'Azure AD SID';  In = 'User S-1-12-1-1234567890-1234567890-1234567890-1234567890';
        Bad = 'S-1-12-1-1234567890'
    }
)
foreach ($c in $cases) {
    $out = Protect-String -Text $c.In
    Assert-True ("Redacts: " + $c.Name) ($out -notmatch [regex]::Escape($c.Bad))
}

# --- Nested object graph -----------------------------------------------
$graph = [pscustomobject]@{
    Host    = $env:COMPUTERNAME
    Nested  = [pscustomobject]@{ Mac = '00:1A:2B:3C:4D:5E'; Depth = 2 }
    List    = @('192.168.0.1', 'harmless string', 'user@example.com')
    Number  = 42
    Boolean = $true
}
$clean = Protect-Object -InputObject $graph
$json = $clean | ConvertTo-Json -Depth 10

Assert-True 'Object graph: nested MAC redacted'  ($json -notmatch '00:1A:2B:3C:4D:5E')
Assert-True 'Object graph: list IPv4 redacted'   ($json -notmatch '192\.168\.0\.1')
Assert-True 'Object graph: list email redacted'  ($json -notmatch 'user@example\.com')
Assert-True 'Object graph: numbers preserved'    ($json -match '42')
Assert-True 'Object graph: booleans preserved'   ($json -match 'true')
Assert-True 'Object graph: harmless text kept'   ($json -match 'harmless string')

# List shape must survive the round trip at the 0 and 1 boundaries, or a
# report with a single finding parses differently from one with two.
$shapes = [pscustomobject]@{
    EmptyList  = @()
    SingleList = @('one')
    MultiList  = @('one', 'two')
}
$shapeJson = Protect-Object -InputObject $shapes | ConvertTo-Json -Depth 6
Assert-True 'Empty list serializes as []'       ($shapeJson -match '"EmptyList"\s*:\s*\[\s*\]')
Assert-True 'Single-item list stays an array'   ($shapeJson -match '(?s)"SingleList"\s*:\s*\[')
Assert-True 'Multi-item list stays an array'    ($shapeJson -match '(?s)"MultiList"\s*:\s*\[')

$shapeBack = $shapeJson | ConvertFrom-Json
Assert-True 'Single-item list round-trips to 1 element' (@($shapeBack.SingleList).Count -eq 1) `
("count=" + @($shapeBack.SingleList).Count)
Assert-True 'Empty list round-trips to 0 elements'      (@($shapeBack.EmptyList).Count -eq 0) `
("count=" + @($shapeBack.EmptyList).Count)

# --- Verifier must actually catch a leak -------------------------------
$dirty = "Machine $env:COMPUTERNAME at 10.20.30.40"
$verdictDirty = Test-SanitizedText -Text $dirty
Assert-True 'Verifier flags unsanitized text' (-not $verdictDirty.Clean)

$verdictClean = Test-SanitizedText -Text (Protect-String -Text $dirty)
Assert-True 'Verifier passes sanitized text' ($verdictClean.Clean) ("hits=" + ($verdictClean.Hits -join ','))

# Well-known SIDs are the same on every Windows machine, so they identify
# nobody. Redacting them would throw away diagnostic value for no privacy gain.
$wellKnown = Protect-String -Text 'Ran as S-1-5-18 in group S-1-5-32-544'
Assert-True 'Well-known SIDs are NOT redacted' ($wellKnown -match 'S-1-5-18' -and $wellKnown -match 'S-1-5-32-544') "got=$wellKnown"

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
