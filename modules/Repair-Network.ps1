<#MANIFEST
{
  "Key": "network",
  "Title": "Network diagnosis and repair",
  "Entry": "Invoke-NetworkModule",
  "Order": 25,
  "RequiresAdmin": false,
  "Description": "Walks the connectivity ladder to find which layer failed; repairs are tiered by blast radius"
}
MANIFEST#>

# Repair-Network.ps1 - connectivity diagnosis and the network reset stack.
# ASCII only, PowerShell 5.1 compatible.
#
# The value here is the LADDER, not the reset commands. "No internet" is a
# symptom with six candidate layers underneath it, and running the whole reset
# stack because someone said the wifi is broken is how you turn a bad DNS
# entry into a machine that has lost its static address. Find the rung that
# failed first, then fix that.
#
#   1 link      adapter up, cable or radio associated
#   2 address   an IP that is not APIPA
#   3 gateway   the router answers
#   4 internet  a public IP answers - routing works
#   5 dns       names resolve
#   6 http      traffic actually completes, and is not a captive portal
#
# Each rung only means something given the ones below it. DNS failing while
# ping to a public IP works is a DNS problem. DNS failing when the gateway is
# unreachable tells you nothing about DNS at all.
#
# REPAIRS ARE TIERED BY BLAST RADIUS:
#   Safe        flush DNS, clear ARP/NetBIOS, DHCP release+renew
#   Disruptive  winsock reset, TCP/IP stack reset - BOTH NEED A REBOOT, and
#               the stack reset WIPES STATIC IP CONFIGURATION
#
# Disruptive repairs are opt-in and back the IP configuration up first. A
# machine with a static address is usually static for a reason - a printer,
# a line-of-business host, a site with no DHCP - and handing it back on DHCP
# is a fault you introduced.
#
# PRIVACY: addresses are classified, never recorded. The report says "static",
# "APIPA", "gateway reachable" - which is the diagnostic content - and never
# an IP or MAC, both of which would be redacted into uselessness anyway.

$script:ConnectTestUrl = 'http://www.msftconnecttest.com/connecttest.txt'
$script:ConnectTestBody = 'Microsoft Connect Test'
$script:ConnectTestName = 'www.msftconnecttest.com'
$script:PublicProbes = @('1.1.1.1', '8.8.8.8')

function Get-IpAddressKind {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return 'None' }
    if ($Address -like '169.254.*') { return 'APIPA' }
    if ($Address -like '127.*') { return 'Loopback' }
    if ($Address -like '10.*' -or $Address -like '192.168.*') { return 'PrivateRFC1918' }
    if ($Address -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return 'PrivateRFC1918' }
    if ($Address -like '100.6*' -or $Address -like '100.7*') { return 'CarrierGradeNAT' }
    return 'Public'
}

# APIPA is the single most informative address a repair tech can see: the
# adapter is fine and the stack is fine, but nothing answered DHCP.
function Get-AddressVerdict {
    param([string]$Kind, [bool]$IsDhcp)
    switch ($Kind) {
        'APIPA' { return 'DHCP got no answer - self-assigned. Look at the router, the cable, or a dead DHCP scope.' }
        'None' { return 'No address at all.' }
        'Loopback' { return 'Loopback only - no usable interface.' }
        'CarrierGradeNAT' { return 'Carrier-grade NAT address - normal on some ISPs and mobile broadband.' }
        default {
            if ($IsDhcp) { return 'Address obtained from DHCP.' }
            return 'Static address - do NOT reset the TCP/IP stack without recording it first.'
        }
    }
}

function Test-NetRung {
    param([string]$Name, [scriptblock]$Probe)
    $ok = $false
    $detail = ''
    try {
        $r = & $Probe
        $ok = [bool]$r.Ok
        $detail = [string]$r.Detail
    }
    catch { $detail = $_.Exception.Message }
    return [pscustomobject]@{ Name = $Name; Ok = $ok; Detail = $detail }
}

function Get-ConnectivityLadder {
    $rungs = @()

    # --- 1 link ---------------------------------------------------------
    $adapters = @()
    try { $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { -not $_.Virtual }) } catch { }
    $up = @($adapters | Where-Object { $_.Status -eq 'Up' })
    $rungs += [pscustomobject]@{
        Name = 'link'; Ok = ($up.Count -gt 0)
        Detail = ('{0} physical adapter(s), {1} up' -f $adapters.Count, $up.Count)
    }

    # --- 2 address ------------------------------------------------------
    $addrKind = 'None'
    $isDhcp = $false
    $addrOk = $false
    try {
        $cfg = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4Address })
        if ($cfg.Count -gt 0) {
            $primary = $cfg | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1
            if (-not $primary) { $primary = $cfg[0] }
            $addr = [string]$primary.IPv4Address.IPAddress
            $addrKind = Get-IpAddressKind -Address $addr
            try {
                $ipIf = Get-NetIPInterface -InterfaceIndex $primary.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
                $isDhcp = ($ipIf.Dhcp -eq 'Enabled')
            }
            catch { }
            $addrOk = @('PrivateRFC1918', 'Public', 'CarrierGradeNAT') -contains $addrKind
        }
    }
    catch { }
    $rungs += [pscustomobject]@{
        Name = 'address'; Ok = $addrOk
        Detail = ('{0} - {1}' -f $addrKind, (Get-AddressVerdict -Kind $addrKind -IsDhcp $isDhcp))
    }

    # --- 3 gateway ------------------------------------------------------
    $gwOk = $false
    $gwDetail = 'No default gateway configured'
    try {
        $gw = @(Get-NetIPConfiguration -ErrorAction Stop |
                Where-Object { $_.IPv4DefaultGateway } |
                ForEach-Object { $_.IPv4DefaultGateway.NextHop })
        if ($gw.Count -gt 0) {
            $gwOk = [bool](Test-Connection -ComputerName $gw[0] -Count 2 -Quiet -ErrorAction SilentlyContinue)
            $gwDetail = $(if ($gwOk) { 'Gateway answers' } else { 'Gateway configured but does not answer' })
        }
    }
    catch { }
    $rungs += [pscustomobject]@{ Name = 'gateway'; Ok = $gwOk; Detail = $gwDetail }

    # --- 4 internet by IP -----------------------------------------------
    $netOk = $false
    foreach ($p in $script:PublicProbes) {
        if (Test-Connection -ComputerName $p -Count 2 -Quiet -ErrorAction SilentlyContinue) { $netOk = $true; break }
    }
    $rungs += [pscustomobject]@{
        Name = 'internet'; Ok = $netOk
        Detail = $(if ($netOk) { 'Public IP answers - routing works' } else { 'No public IP answers - routing or upstream is down' })
    }

    # --- 5 dns ------------------------------------------------------------
    $dnsOk = $false
    $dnsDetail = 'Resolution failed'
    try {
        $r = Resolve-DnsName -Name $script:ConnectTestName -Type A -DnsOnly -ErrorAction Stop
        if ($r) { $dnsOk = $true; $dnsDetail = 'Names resolve' }
    }
    catch { $dnsDetail = 'Resolution failed - check DNS servers, or the resolver is being intercepted' }
    $rungs += [pscustomobject]@{ Name = 'dns'; Ok = $dnsOk; Detail = $dnsDetail }

    # --- 6 http -----------------------------------------------------------
    # A captive portal answers 200 with the wrong body. Checking the body is
    # the difference between "working" and "a hotel wifi login page".
    $httpOk = $false
    $httpDetail = 'No HTTP response'
    try {
        $resp = Invoke-WebRequest -Uri $script:ConnectTestUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if ($resp.Content -match $script:ConnectTestBody) {
            $httpOk = $true; $httpDetail = 'HTTP completes end to end'
        }
        else {
            $httpDetail = 'HTTP answered but the body is wrong - captive portal or an intercepting proxy'
        }
    }
    catch { $httpDetail = 'HTTP request failed' }
    $rungs += [pscustomobject]@{ Name = 'http'; Ok = $httpOk; Detail = $httpDetail }

    return $rungs
}

# Find the layer actually worth working on.
#
# NOT simply "the lowest failing rung". A rung that fails while something
# ABOVE it passes has not failed - its probe is unreliable. The common case is
# a gateway that drops ICMP: ping fails, yet traffic routes to the internet
# perfectly well. Blaming the gateway there sends a tech to reboot a healthy
# router while the real fault sits somewhere else entirely.
#
# So: take the highest rung that passed. Anything failing below it is a probe
# artifact and is reported as superseded, not as a fault. The real failing
# layer is the lowest failure ABOVE the highest pass.
function Get-FailedLayer {
    param([Parameter(Mandatory = $true)]$Rungs)

    $list = @($Rungs)
    $highestPass = -1
    for ($i = 0; $i -lt $list.Count; $i++) {
        if ($list[$i].Ok) { $highestPass = $i }
    }

    $superseded = @()
    for ($i = 0; $i -lt $highestPass; $i++) {
        if (-not $list[$i].Ok) { $superseded += $list[$i].Name }
    }

    for ($i = $highestPass + 1; $i -lt $list.Count; $i++) {
        if (-not $list[$i].Ok) {
            return [pscustomobject]@{
                Layer      = $list[$i].Name
                Detail     = $list[$i].Detail
                AllPass    = $false
                Superseded = $superseded
            }
        }
    }

    # Nothing failed above the highest pass, so the stack works end to end.
    return [pscustomobject]@{
        Layer      = 'none'
        Detail     = $(if ($superseded.Count -gt 0) {
                'Connectivity works end to end. Lower probes that failed are filtered, not faults.'
            }
            else { 'Every rung passed' })
        AllPass    = $true
        Superseded = $superseded
    }
}

function Get-NetworkSnapshot {
    $snap = [ordered]@{
        Adapters      = @()
        DhcpEnabled   = $null
        AddressKind   = 'Unknown'
        ProxyEnabled  = $false
        ProxyAutoConfig = $false
        HostsEntries  = 0
        FirewallProfiles = @()
        DomainJoined  = $false
    }

    try { $snap.DomainJoined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }

    try {
        foreach ($a in (Get-NetAdapter -ErrorAction Stop)) {
            $snap.Adapters += [ordered]@{
                Name        = $a.Name
                Description = $a.InterfaceDescription
                Status      = [string]$a.Status
                LinkSpeed   = [string]$a.LinkSpeed
                Virtual     = [bool]$a.Virtual
            }
        }
    }
    catch { }

    try {
        $is = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $snap.ProxyEnabled = ($is.ProxyEnable -eq 1)
        $snap.ProxyAutoConfig = [bool]$is.AutoConfigURL
    }
    catch { }

    try {
        $hosts = Get-Content -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -ErrorAction Stop
        $snap.HostsEntries = @($hosts | Where-Object {
                $t = $_.Trim()
                $t -ne '' -and -not $t.StartsWith('#') -and ($t -split '\s+').Count -ge 2 -and ($t -split '\s+')[1] -notlike 'localhost*'
            }).Count
    }
    catch { }

    try {
        foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
            $snap.FirewallProfiles += [ordered]@{ Name = [string]$p.Name; Enabled = [bool]$p.Enabled }
        }
    }
    catch { }

    return [pscustomobject]$snap
}

function Backup-IpConfiguration {
    $path = Join-Path $script:LocalRoot 'network-ipconfig-backup.txt'
    $lines = @()
    $lines += "Captured before a network reset. Restore static settings by hand if needed."
    $lines += ''
    try {
        foreach ($cfg in (Get-NetIPConfiguration -Detailed -ErrorAction Stop)) {
            $lines += ('Interface : ' + $cfg.InterfaceAlias)
            $lines += ('  IPv4    : ' + ($cfg.IPv4Address.IPAddress -join ', '))
            $lines += ('  Gateway : ' + ($cfg.IPv4DefaultGateway.NextHop -join ', '))
            $lines += ('  DNS     : ' + ($cfg.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses -join ', ' }))
            try {
                $ipIf = Get-NetIPInterface -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
                $lines += ('  DHCP    : ' + $ipIf.Dhcp)
            }
            catch { }
            $lines += ''
        }
    }
    catch { $lines += ('Capture failed: ' + $_.Exception.Message) }

    Set-Content -LiteralPath $path -Value $lines -Encoding UTF8 -WhatIf:$false
    return $path
}

function Invoke-NetworkModule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$Apply,
        [hashtable]$Options = @{}
    )

    $disruptive = [bool]$Options['Disruptive']

    Write-Banner 'Network diagnosis'

    $result = [ordered]@{
        Mode          = $(if ($Apply) { 'Apply' } else { 'DiagnoseOnly' })
        Rungs         = @()
        FailedLayer   = $null
        Superseded    = @()
        Snapshot      = $null
        RepairsRun    = @()
        RebootNeeded  = $false
        BackupFile    = $null
    }

    $snap = Get-NetworkSnapshot
    $result.Snapshot = $snap

    Write-Log -Message 'Walking the connectivity ladder' -Level STEP
    $rungs = @(Get-ConnectivityLadder)
    foreach ($r in $rungs) {
        $result.Rungs += [ordered]@{ Name = $r.Name; Ok = $r.Ok; Detail = $r.Detail }
    }

    $failed = Get-FailedLayer -Rungs $rungs
    $result.FailedLayer = $failed.Layer

    $result.Superseded = @($failed.Superseded)

    Write-Host ''
    foreach ($r in $rungs) {
        $mark = '  ok  '
        $color = 'Green'
        if (-not $r.Ok) {
            if ($failed.Superseded -contains $r.Name) { $mark = 'filtd'; $color = 'DarkGray' }
            else { $mark = 'FAIL '; $color = 'Red' }
        }
        Write-Host ('    [{0}] {1,-9} {2}' -f $mark, $r.Name, $r.Detail) -ForegroundColor $color
    }

    if (@($failed.Superseded).Count -gt 0) {
        Write-Host ''
        Write-Host ('  "filtd" = probe blocked, not broken: {0}' -f (@($failed.Superseded) -join ', ')) -ForegroundColor DarkGray
        Write-Host '  Something above it answered, so that layer is passing traffic. Most routers' -ForegroundColor DarkGray
        Write-Host '  and firewalls drop ICMP by default - a silent gateway is normal.' -ForegroundColor DarkGray
    }

    Write-Host ''
    if ($failed.AllPass) {
        Write-Host '  Connectivity works end to end right now.' -ForegroundColor Green
        Write-Host '  If the complaint is intermittent, this proves nothing - it proves it works' -ForegroundColor DarkGray
        Write-Host '  at this moment. Ask what they were doing when it failed.' -ForegroundColor DarkGray
    }
    else {
        Write-Host ('  LOWEST FAILING LAYER: {0}' -f $failed.Layer.ToUpper()) -ForegroundColor Yellow
        Write-Host ('  {0}' -f $failed.Detail) -ForegroundColor Yellow
        Write-Host '  Rungs above this one mean nothing until it is fixed.' -ForegroundColor DarkGray
    }

    # --- Context that changes the diagnosis --------------------------------
    Write-Host ''
    if ($snap.ProxyAutoConfig -or $snap.ProxyEnabled) {
        Write-Host '  A proxy is configured. On a consumer machine that is often adware -' -ForegroundColor Yellow
        Write-Host '  run the browser module. On a work machine it is probably legitimate.' -ForegroundColor Yellow
    }
    if ($snap.HostsEntries -gt 0) {
        Write-Host ('  hosts file has {0} non-default entr(y/ies) - can override DNS entirely.' -f $snap.HostsEntries) -ForegroundColor Yellow
    }
    foreach ($fp in $snap.FirewallProfiles) {
        if (-not $fp.Enabled) {
            Write-Host ('  Firewall profile "{0}" is OFF - reported only, never changed here.' -f $fp.Name) -ForegroundColor Yellow
        }
    }
    if ($snap.DomainJoined) {
        Write-Host '  Domain-joined. Proxy, DNS and firewall settings are probably managed -' -ForegroundColor Yellow
        Write-Host '  do not "fix" them, and do not reset the stack without asking their IT.' -ForegroundColor Yellow
    }

    if (-not $Apply) {
        Write-Host ''
        Write-Host '  Diagnosis only. Nothing was changed.' -ForegroundColor Cyan
        Write-Host '  -Apply runs the SAFE repairs: flush DNS, clear ARP/NetBIOS, DHCP renew.' -ForegroundColor Cyan
        Write-Host '  -Apply -Disruptive adds winsock and TCP/IP stack resets. Both need a' -ForegroundColor Cyan
        Write-Host '  reboot, and the stack reset WIPES STATIC IP CONFIGURATION.' -ForegroundColor Cyan
        Write-Host ''
        return [pscustomobject]$result
    }

    Assert-Admin

    # --- Safe repairs -------------------------------------------------------
    Write-Banner 'Safe network repairs'

    $safe = @(
        @{ Label = 'Flush DNS cache';     Exe = 'ipconfig'; Args = @('/flushdns') },
        @{ Label = 'Clear ARP cache';     Exe = 'netsh';    Args = @('interface', 'ip', 'delete', 'arpcache') },
        @{ Label = 'Reload NetBIOS';      Exe = 'nbtstat';  Args = @('-R') },
        @{ Label = 'Release DHCP lease';  Exe = 'ipconfig'; Args = @('/release') },
        @{ Label = 'Renew DHCP lease';    Exe = 'ipconfig'; Args = @('/renew') }
    )

    foreach ($s in $safe) {
        # Releasing a lease on a static machine does nothing useful and just
        # muddies the picture, so skip DHCP work when the address is static.
        if ($s.Label -like '*DHCP*' -and $rungs[1].Detail -like '*Static*') {
            Write-Log -Message ('Skipping "{0}" - this machine has a static address' -f $s.Label) -Level WARN
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($s.Label, 'Run network repair')) { continue }

        $r = Invoke-Native -FilePath $s.Exe -ArgumentList $s.Args -TimeoutMinutes 3
        $ok = ($r.ExitCode -eq 0)
        $result.RepairsRun += [ordered]@{ Label = $s.Label; ExitCode = $r.ExitCode; Ok = $ok }
        Write-Log -Message ('{0}: exit {1}' -f $s.Label, $r.ExitCode) -Level $(if ($ok) { 'OK' } else { 'WARN' })
    }

    # --- Disruptive repairs -------------------------------------------------
    if (-not $disruptive) {
        Write-Host ''
        Write-Host '  Safe repairs done. Winsock and TCP/IP stack resets NOT run.' -ForegroundColor Cyan
        Write-Host '  Re-test first - those two need a reboot and the stack reset wipes' -ForegroundColor Cyan
        Write-Host '  static IP configuration. Add -Disruptive only if you still need them.' -ForegroundColor Cyan
        Write-Host ''
        return [pscustomobject]$result
    }

    Write-Banner 'Disruptive repairs - reboot required afterwards'

    $result.BackupFile = Backup-IpConfiguration
    Write-Log -Message ('IP configuration recorded at ' + $result.BackupFile) -Level OK
    Write-Host ('  Current IP configuration written to {0}' -f $result.BackupFile) -ForegroundColor Green
    Write-Host '  That file stays on this machine. Read it before re-entering static settings.' -ForegroundColor DarkGray

    if ($rungs[1].Detail -like '*Static*') {
        Write-Host ''
        Write-Host '  WARNING: this machine has a STATIC address. The TCP/IP stack reset will' -ForegroundColor Red
        Write-Host '  put it back on DHCP and the static settings will be gone. They are in the' -ForegroundColor Red
        Write-Host '  backup file above - you will have to re-enter them by hand.' -ForegroundColor Red
    }

    $hard = @(
        @{ Label = 'Winsock reset';       Exe = 'netsh'; Args = @('winsock', 'reset') },
        @{ Label = 'TCP/IP stack reset';  Exe = 'netsh'; Args = @('int', 'ip', 'reset') }
    )

    foreach ($h in $hard) {
        if (-not $PSCmdlet.ShouldProcess($h.Label, 'Run DISRUPTIVE network repair (needs reboot)')) { continue }
        $r = Invoke-Native -FilePath $h.Exe -ArgumentList $h.Args -TimeoutMinutes 5
        $result.RepairsRun += [ordered]@{ Label = $h.Label; ExitCode = $r.ExitCode; Ok = ($r.ExitCode -eq 0) }
        $result.RebootNeeded = $true
        Write-Log -Message ('{0}: exit {1}' -f $h.Label, $r.ExitCode) -Level OK
    }

    Write-Host ''
    Write-Host '  REBOOT REQUIRED before these take effect. Re-test connectivity afterwards -' -ForegroundColor Yellow
    Write-Host '  a reset that did not fix it is information too.' -ForegroundColor Yellow
    Write-Host ''

    return [pscustomobject]$result
}
