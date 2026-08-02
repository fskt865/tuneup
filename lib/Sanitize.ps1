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

function New-RedactionMap {
    $map = New-Object 'System.Collections.Generic.List[object]'

    function Add-Literal {
        param($Value, $Token)
        if ($null -eq $Value) { return }
        $s = [string]$Value
        $s = $s.Trim()
        if ($s.Length -lt 4) { return }
        if ($s -match '^(To be filled|Default string|System Serial|None|N/A|00000000)') { return }
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
        foreach ($item in $script:RedactionMap) {
            $out = [regex]::Replace($out, [regex]::Escape($item.Value), $item.Token, 'IgnoreCase')
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
        return $list
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

    $hits = @()
    foreach ($item in $script:RedactionMap) {
        if ($Text -match [regex]::Escape($item.Value)) { $hits += ('literal:' + $item.Token) }
    }
    foreach ($p in $script:RedactionPatterns) {
        if ($Text -match $p.Pattern) { $hits += ('pattern:' + $p.Token) }
    }

    return [pscustomobject]@{
        Clean = ($hits.Count -eq 0)
        Hits  = $hits
    }
}
