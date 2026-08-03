# Test-Network.ps1 - address classification and ladder logic.
# ASCII only, PowerShell 5.1 compatible.
#
# Runs no repairs. What is verified is the reasoning: classifying an address,
# and picking the LOWEST failing rung - because acting on the wrong layer is
# the whole failure mode this module exists to prevent.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'modules\Repair-Network.ps1')

$pass = 0
$fail = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  PASS  " + $Name) -ForegroundColor Green; $script:pass++ }
    else { Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red; $script:fail++ }
}

Write-Host ''
Write-Host '  Address classification' -ForegroundColor Cyan
Write-Host '  ----------------------' -ForegroundColor DarkGray

$addrCases = @(
    @{ Ip = '169.254.10.5';   Expect = 'APIPA' },
    @{ Ip = '192.168.1.20';   Expect = 'PrivateRFC1918' },
    @{ Ip = '10.0.0.5';       Expect = 'PrivateRFC1918' },
    @{ Ip = '172.16.4.9';     Expect = 'PrivateRFC1918' },
    @{ Ip = '172.31.255.1';   Expect = 'PrivateRFC1918' },
    @{ Ip = '127.0.0.1';      Expect = 'Loopback' },
    @{ Ip = '8.8.8.8';        Expect = 'Public' },
    @{ Ip = '';               Expect = 'None' }
)
foreach ($c in $addrCases) {
    $got = Get-IpAddressKind -Address $c.Ip
    Assert-True ("{0,-16} -> {1}" -f $(if ($c.Ip) { $c.Ip } else { '(empty)' }), $c.Expect) ($got -eq $c.Expect) "got=$got"
}

# 172.15 and 172.32 are OUTSIDE RFC1918. Getting the boundary wrong would
# label a public address private and send a tech looking at the wrong side.
Assert-True '172.15.0.1 is NOT private' ((Get-IpAddressKind -Address '172.15.0.1') -eq 'Public')
Assert-True '172.32.0.1 is NOT private' ((Get-IpAddressKind -Address '172.32.0.1') -eq 'Public')

Write-Host ''
Write-Host '  Address verdicts' -ForegroundColor Cyan
Write-Host '  ----------------' -ForegroundColor DarkGray

Assert-True 'APIPA verdict names DHCP as the suspect' `
((Get-AddressVerdict -Kind 'APIPA' -IsDhcp $true) -match 'DHCP')
Assert-True 'Static verdict warns about the stack reset' `
((Get-AddressVerdict -Kind 'PrivateRFC1918' -IsDhcp $false) -match 'Static')
Assert-True 'DHCP verdict does not warn about static' `
((Get-AddressVerdict -Kind 'PrivateRFC1918' -IsDhcp $true) -notmatch 'Static')

Write-Host ''
Write-Host '  Ladder: lowest failing rung wins' -ForegroundColor Cyan
Write-Host '  --------------------------------' -ForegroundColor DarkGray

function New-Rung { param($n, $ok) [pscustomobject]@{ Name = $n; Ok = $ok; Detail = 'x' } }

# DNS failing while the gateway is down is NOT a DNS problem. The module must
# report the gateway, which is the lowest thing broken.
$ladder = @(
    (New-Rung 'link' $true), (New-Rung 'address' $true), (New-Rung 'gateway' $false),
    (New-Rung 'internet' $false), (New-Rung 'dns' $false), (New-Rung 'http' $false)
)
$f = Get-FailedLayer -Rungs $ladder
Assert-True 'Reports gateway, not dns, when both are down' ($f.Layer -eq 'gateway') ("got=" + $f.Layer)

# THE ICMP-FILTERED CASE. A gateway that drops ping while everything above it
# works is not a fault - it is a blocked probe. Calling it the failing layer
# sends a tech to reboot a perfectly healthy router. Seen for real on the
# first live run of this module.
$filtered = @(
    (New-Rung 'link' $true), (New-Rung 'address' $true), (New-Rung 'gateway' $false),
    (New-Rung 'internet' $true), (New-Rung 'dns' $true), (New-Rung 'http' $true)
)
$ff = Get-FailedLayer -Rungs $filtered
Assert-True 'Silent gateway with working internet is NOT a fault' ($ff.AllPass) ("layer=" + $ff.Layer)
Assert-True 'Silent gateway is reported as superseded'            ($ff.Superseded -contains 'gateway')

# A real fault above a filtered probe must still be found.
$filteredPlusReal = @(
    (New-Rung 'link' $true), (New-Rung 'address' $true), (New-Rung 'gateway' $false),
    (New-Rung 'internet' $true), (New-Rung 'dns' $false), (New-Rung 'http' $false)
)
$fr = Get-FailedLayer -Rungs $filteredPlusReal
Assert-True 'Real dns fault found despite a filtered gateway' ($fr.Layer -eq 'dns') ("got=" + $fr.Layer)
Assert-True 'Filtered gateway still marked superseded'       ($fr.Superseded -contains 'gateway')

# A genuine DNS-only fault: everything below passes.
$ladder2 = @(
    (New-Rung 'link' $true), (New-Rung 'address' $true), (New-Rung 'gateway' $true),
    (New-Rung 'internet' $true), (New-Rung 'dns' $false), (New-Rung 'http' $false)
)
Assert-True 'Reports dns when routing works but names do not' `
((Get-FailedLayer -Rungs $ladder2).Layer -eq 'dns')

# Link down: everything above is meaningless, and must not be blamed.
$ladder3 = @(
    (New-Rung 'link' $false), (New-Rung 'address' $false), (New-Rung 'gateway' $false),
    (New-Rung 'internet' $false), (New-Rung 'dns' $false), (New-Rung 'http' $false)
)
Assert-True 'Reports link when nothing works' ((Get-FailedLayer -Rungs $ladder3).Layer -eq 'link')

$allOk = @(
    (New-Rung 'link' $true), (New-Rung 'address' $true), (New-Rung 'gateway' $true),
    (New-Rung 'internet' $true), (New-Rung 'dns' $true), (New-Rung 'http' $true)
)
$fp = Get-FailedLayer -Rungs $allOk
Assert-True 'All rungs passing reports none' ($fp.Layer -eq 'none')
Assert-True 'All rungs passing sets AllPass'  ($fp.AllPass)

# Captive portal: http fails while dns and routing are fine.
$portal = @(
    (New-Rung 'link' $true), (New-Rung 'address' $true), (New-Rung 'gateway' $true),
    (New-Rung 'internet' $true), (New-Rung 'dns' $true), (New-Rung 'http' $false)
)
Assert-True 'Captive-portal shape reports http' ((Get-FailedLayer -Rungs $portal).Layer -eq 'http')

Write-Host ''
Write-Host '  Disruptive resets are gated off' -ForegroundColor Cyan
Write-Host '  ------------------------------' -ForegroundColor DarkGray

# winsock reset and int ip reset have never been run end to end, need a reboot,
# and the stack reset wipes static IP configuration. They stay off until Tier C
# of the bench checklist passes on a scratch machine. If this fails, someone
# re-enabled them - confirm that was deliberate and that they were verified.
Assert-True 'Disruptive network resets are disabled' (-not $script:DisruptiveEnabled)

Write-Host ''
Write-Host '  Snapshot is read-only' -ForegroundColor Cyan
Write-Host '  ---------------------' -ForegroundColor DarkGray

$snap = Get-NetworkSnapshot
Assert-True 'Snapshot returns an object'          ($null -ne $snap)
Assert-True 'Snapshot enumerates adapters'        ($null -ne $snap.Adapters)
Assert-True 'Snapshot reports firewall profiles'  ($null -ne $snap.FirewallProfiles)

# Addresses and MACs must never reach the report - they would be redacted to
# uselessness anyway, and the classification is the actual diagnostic content.
$snapJson = Protect-Object -InputObject $snap | ConvertTo-Json -Depth 8
Assert-True 'Snapshot carries no raw IPv4 address' ($snapJson -notmatch '\b(?:\d{1,3}\.){3}\d{1,3}\b')
Assert-True 'Snapshot carries no MAC address' ($snapJson -notmatch '(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b')

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
