# Sanitize.ps1 - redaction for anything leaving the customer's machine.
# Dot-sourced by Invoke-TuneUp.ps1. ASCII only, PowerShell 5.1 compatible.
#
# Two passes, in this order:
#   1. Literals gathered from the live machine (hostname, account names,
#      serials, machine GUIDs) replaced with stable tokens.
#   2. Regex sweep for shapes that identify regardless of value (MAC, IPv4,
#      email, GUID, product key, user profile paths).
#
# Literals run first and longest-first, so "AnnPC" is consumed before "Ann"
# can chew a hole in the middle of it. Literals shorter than 4 characters are
# skipped entirely - a 2-character account name would shred the whole report.

$script:RedactionMap = $null

# Profile directories that exist on every Windows install and identify nobody.
#
# Same reasoning as the well-known SIDs below: these are machine-invariant, so
# redacting them protects no one - and two of them are ordinary English words,
# which makes redacting them actively harmful. "Default" appears in report
# prose and in field names like IsDefault and SrpDefaultLevel; "Public" turns
# up in any discussion of network profiles.
#
# This bit for real. A module returning a field called Default tripped the
# final verification and the toolkit correctly refused to write the report -
# correctly, but unfixably, because the surviving hits were JSON PROPERTY
# NAMES and Protect-Object only ever rewrites values. Property names are
# schema authored in this repo, never data read off the machine, so they must
# not be redacted; the fix has to be keeping machine-invariant names out of
# the map in the first place.
#
# Matched whole, case-insensitively, so a customer account called Publisher
# or Defaults is still redacted normally.
#
# 'User' and 'Guest' added 2026-08-09 for the same reason as 'Default' and
# 'Public'. "User" is the OEM default account name on a large fraction of
# consumer machines, so it identifies nobody - and it is an ordinary English
# word that appears throughout report prose. It is also, at exactly 4
# characters, the shortest thing the length filter lets through, which is what
# made it the literal that exposed the single-pass bug in Protect-String.
#
# Note the profile PATH is still redacted regardless, by the C:\Users\<name>
# pattern below - so leaving the bare name in the map buys nothing anyway.
$script:BuiltInProfileNames = @(
    'Default', 'Default User', 'Public', 'All Users',
    'defaultuser0', 'WDAGUtilityAccount', 'Administrator',
    'User', 'Guest'
)

function New-RedactionMap {
    $map = New-Object 'System.Collections.Generic.List[object]'

    function Add-Literal {
        param($Value, $Token)
        if ($null -eq $Value) { return }
        $s = [string]$Value
        $s = $s.Trim()
        if ($s.Length -lt 4) { return }
        if ($s -match '^(To be filled|Default string|System Serial|None|N/A|00000000)') { return }
        foreach ($builtin in $script:BuiltInProfileNames) {
            if ($s -eq $builtin) { return }
        }
        foreach ($existing in $map) { if ($existing.Value -eq $s) { return } }
        $map.Add([pscustomobject]@{ Value = $s; Token = $Token })
    }

    Add-Literal $env:COMPUTERNAME '<HOST>'
    Add-Literal $env:USERDOMAIN   '<DOMAIN>'

    # Every local profile name, not just the one running the tool.
    $userIndex = 0
    try {
        $profileRoot = Join-Path $env:SystemDrive 'Users'
        Get-ChildItem -LiteralPath $profileRoot -Directory -Force -ErrorAction Stop | ForEach-Object {
            $userIndex++
            Add-Literal $_.Name ('<USER{0}>' -f $userIndex)
        }
    }
    catch { }
    Add-Literal $env:USERNAME ('<USER{0}>' -f ($userIndex + 1))

    try {
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
        Add-Literal $bios.SerialNumber '<BIOS_SERIAL>'
    }
    catch { }

    try {
        $board = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
        Add-Literal $board.SerialNumber '<BOARD_SERIAL>'
    }
    catch { }

    try {
        $sys = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
        Add-Literal $sys.IdentifyingNumber '<SYS_SERIAL>'
        Add-Literal $sys.UUID '<SYS_UUID>'
    }
    catch { }

    $diskIndex = 0
    try {
        Get-CimInstance Win32_DiskDrive -ErrorAction Stop | ForEach-Object {
            $diskIndex++
            Add-Literal $_.SerialNumber ('<DISK{0}_SERIAL>' -f $diskIndex)
        }
    }
    catch { }

    try {
        $mg = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop
        Add-Literal $mg.MachineGuid '<MACHINE_GUID>'
    }
    catch { }

    # Longest first so no literal is a substring of a later replacement.
    $sorted = $map | Sort-Object { $_.Value.Length } -Descending
    $script:RedactionMap = @($sorted)
    return $script:RedactionMap
}

$script:RedactionPatterns = @(
    @{ Pattern = '(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b';                          Token = '<MAC>' },
    @{ Pattern = '(?i)\b[0-9a-f]{2}(?:-[0-9a-f]{2}){5}\b';                          Token = '<MAC>' },
    @{ Pattern = '\b(?:\d{1,3}\.){3}\d{1,3}\b';                                     Token = '<IPV4>' },
    @{ Pattern = '(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}';                       Token = '<EMAIL>' },
    @{ Pattern = '(?i)\b[a-z]:\\Users\\[^\\/:*?"<>|\r\n]+';                          Token = '<USERPROFILE>' },
    @{ Pattern = '\b[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}\b';                              Token = '<PRODUCT_KEY>' },
    @{ Pattern = '(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b';             Token = '<GUID>' },

    # Account SIDs. S-1-5-21-... is unique to a machine or domain and names a
    # specific user - it turned up embedded in a scheduled task name, which is
    # exactly the kind of place identifying data hides. S-1-12-1-... is the
    # Azure AD equivalent.
    #
    # Well-known SIDs (S-1-5-18 LocalSystem, S-1-5-32-544 Administrators) are
    # deliberately NOT matched: they are identical on every Windows machine,
    # so they identify nobody and are worth keeping for diagnosis.
    @{ Pattern = '(?i)\bS-1-5-21(?:-\d+)+';                                          Token = '<SID>' },
    @{ Pattern = '(?i)\bS-1-12-1(?:-\d+)+';                                          Token = '<SID>' }
)

function Protect-String {
    param([Parameter(ValueFromPipeline = $true)][AllowNull()][string]$Text)

    process {
        if ([string]::IsNullOrEmpty($Text)) { return $Text }
        if ($null -eq $script:RedactionMap) { New-RedactionMap | Out-Null }

        $out = $Text

        # ONE pass over all literals, not one pass per literal.
        #
        # REGRESSION. The old loop re-scanned its own output. Every token
        # contains the word USER, so a machine with an account literally named
        # "User" - the OEM default, and exactly 4 characters so it survives the
        # length filter - rewrote <USER1> into <<USER5>1> and C:\Users\ into
        # C:\<USER5>s\. Verification then found the literal still present and
        # correctly refused to write the report. On a default-named account
        # that meant the toolkit could never produce a report at all.
        #
        # Longest-first ordering does NOT prevent this: it only protects
        # literal-vs-literal collisions, and this is literal-vs-TOKEN. A single
        # pass does prevent it, because each character position is consumed
        # once and emitted tokens are never re-examined.
        #
        # The map's longest-first order is still load-bearing: .NET alternation
        # is leftmost-FIRST, not leftmost-longest, so listing longer literals
        # earlier is what makes the longest one win at a given position.
        if (@($script:RedactionMap).Count -gt 0) {
            $alternation = ($script:RedactionMap | ForEach-Object { [regex]::Escape($_.Value) }) -join '|'

            $lookup = @{}
            foreach ($item in $script:RedactionMap) {
                $lookup[$item.Value.ToLowerInvariant()] = $item.Token
            }

            # GetNewClosure so the evaluator carries $lookup with it rather than
            # depending on scope still being alive when the regex engine calls back.
            $evaluator = {
                param($m)
                $hit = $lookup[$m.Value.ToLowerInvariant()]
                # A miss should be impossible - the alternation is built from
                # this same map. Fail closed anyway: returning the match would
                # leak the literal, and returning $null would silently delete
                # text from the report.
                if ($null -eq $hit) { return '<REDACTED>' }
                return $hit
            }.GetNewClosure()

            $out = [regex]::Replace($out, $alternation, $evaluator, 'IgnoreCase')
        }

        foreach ($p in $script:RedactionPatterns) {
            $out = [regex]::Replace($out, $p.Pattern, $p.Token)
        }
        return $out
    }
}

# Walk an arbitrary object graph and redact every string in it. Used on the
# whole report right before it is written, so a new collector field cannot
# leak by forgetting to call Protect-String.
function Protect-Object {
    param([Parameter(Mandatory = $false)][AllowNull()]$InputObject, [int]$Depth = 0)

    if ($Depth -gt 12) { return '<TRUNCATED_DEPTH>' }
    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [string]) { return Protect-String -Text $InputObject }
    if ($InputObject -is [bool] -or $InputObject -is [int] -or $InputObject -is [long] -or
        $InputObject -is [double] -or $InputObject -is [decimal]) { return $InputObject }
    if ($InputObject -is [datetime]) { return $InputObject.ToString('o') }

    # Ordered, so the JSON that comes back off the stick reads top-down in the
    # order the collector gathered it rather than hash order.
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in @($InputObject.Keys)) {
            $h[$k] = Protect-Object -InputObject $InputObject[$k] -Depth ($Depth + 1)
        }
        return $h
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = @()
        foreach ($item in $InputObject) { $list += , (Protect-Object -InputObject $item -Depth ($Depth + 1)) }

        # The leading comma is load-bearing. PowerShell unrolls arrays on
        # return, so a plain `return $list` hands back nothing for an empty
        # list and a bare scalar for a single-item one - which serialize as
        # {} and as an object instead of [] and [ {...} ]. A report with one
        # finding would then have a different shape from one with two, and
        # anything parsing it downstream breaks on the boundary case.
        return , $list
    }

    if ($InputObject -is [psobject] -and $InputObject.PSObject.Properties.Count -gt 0) {
        $h = [ordered]@{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $h[$prop.Name] = Protect-Object -InputObject $prop.Value -Depth ($Depth + 1)
        }
        return $h
    }

    return Protect-String -Text ([string]$InputObject)
}

# Last line of defence. Run over the finished report text; if anything that
# looks identifying survived both passes, say so rather than shipping it.
function Test-SanitizedText {
    param([Parameter(Mandatory = $true)][string]$Text)

    # Remove every token we emit BEFORE scanning for surviving literals.
    #
    # REGRESSION, found alongside the single-pass fix above. This check used to
    # scan its own output: the token vocabulary contains ordinary words, so an
    # account named "User" matches inside <USER5> and one named "Host" matches
    # inside <HOST>. Verification then reported a leak for text that had been
    # redacted perfectly, and the write path correctly-but-uselessly refused to
    # write any report at all.
    #
    # Removing exact token strings is safe because they are strings this file
    # produces, never data read off the machine. Longest-first again, so
    # <USERPROFILE> is consumed before <USER1> can bite a piece out of it.
    $scan = $Text

    $tokens = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in $script:RedactionMap) { $tokens.Add($item.Token) }
    foreach ($p in $script:RedactionPatterns) { $tokens.Add($p.Token) }
    # Emitted by Protect-String / Protect-Object but not present in either list.
    $tokens.Add('<REDACTED>')
    $tokens.Add('<TRUNCATED_DEPTH>')

    foreach ($t in (@($tokens) | Select-Object -Unique | Sort-Object -Property Length -Descending)) {
        if ($t) { $scan = $scan.Replace($t, '') }
    }

    $hits = @()
    foreach ($item in $script:RedactionMap) {
        # .Contains, not -match: the literal is data off the machine and may
        # contain regex metacharacters. Same reasoning as the escaped pattern
        # this replaces, minus the chance of forgetting the escape.
        if ($scan.IndexOf($item.Value, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $hits += ('literal:' + $item.Token)
        }
    }
    foreach ($p in $script:RedactionPatterns) {
        if ($scan -match $p.Pattern) { $hits += ('pattern:' + $p.Token) }
    }

    return [pscustomobject]@{
        Clean = ($hits.Count -eq 0)
        Hits  = $hits
    }
}
