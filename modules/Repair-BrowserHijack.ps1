<#MANIFEST
{
  "Key": "browser",
  "Title": "Browser hijack and redirect detection",
  "Entry": "Invoke-BrowserHijackModule",
  "Order": 20,
  "RequiresAdmin": false,
  "Description": "Finds shortcut/proxy/policy/extension redirects; fixes only the unambiguous ones"
}
MANIFEST#>

# Repair-BrowserHijack.ps1 - find and (narrowly) fix browser redirects.
# ASCII only, PowerShell 5.1 compatible.
#
# Detection is broad. Repair is deliberately narrow, and only covers changes
# that are unambiguous, reversible and backed up first:
#
#   FIXED   shortcut .lnk with a URL appended to a browser's arguments
#   FIXED   Internet Settings AutoConfigURL / ProxyServer  (skipped if the
#           machine is domain-joined, where those are probably legitimate)
#
#   REPORT  browser policy keys, including ExtensionInstallForcelist
#   REPORT  installed extensions
#   REPORT  hosts file entries
#   REPORT  scheduled tasks that launch a browser at a URL
#   REPORT  static DNS servers
#
# Extensions are never removed automatically. Telling a hijacker from a
# password manager the customer depends on needs a human, and the cost of
# guessing wrong is their saved logins.
#
# Browser profiles are NEVER deleted or reset. That is where bookmarks and
# saved passwords live. A "reset the browser" fix belongs to the customer.
#
# PRIVACY: only the HOST of a hijack URL is ever recorded, never the full
# URL. Redirect URLs routinely carry a machine-tied id in the query string.

$script:BrowserExes = @('chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe',
    'opera.exe', 'vivaldi.exe', 'iexplore.exe', 'launcher.exe')

function Get-UrlHostOnly {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
    try { return ([uri]$Url).Host }
    catch {
        if ($Url -match '^[a-z]+://([^/\s?]+)') { return $Matches[1] }
        return 'unparseable'
    }
}

function Get-HijackBackupDir {
    $dir = Join-Path $script:LocalRoot 'browser-backup'
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null
    }
    return $dir
}

# Split out from the main entry so the one code path in this module that
# WRITES can be tested directly against a synthetic shortcut, without the test
# run also touching real proxy or policy settings.

function Get-ShortcutHijackRoots {
    return @(
        (Join-Path $env:PUBLIC 'Desktop'),
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu'),
        (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch'),
        (Join-Path $env:USERPROFILE 'Desktop')
    )
}

# Returns the URL-shaped tokens in a shortcut's arguments, and what should
# remain afterwards. Real switches such as --profile-directory="Default" are
# not URLs and must survive untouched.
function Split-ShortcutArguments {
    param([string]$Arguments)

    $tokens = @()
    if (-not [string]::IsNullOrWhiteSpace($Arguments)) { $tokens = $Arguments -split '\s+' }

    $bad = @($tokens | Where-Object { $_ -match '^(https?://|www\.)' -or $_ -match '\.url$' })
    $keep = @($tokens | Where-Object { $bad -notcontains $_ })

    return [pscustomobject]@{
        Redirects = $bad
        Keep      = ($keep -join ' ').Trim()
    }
}

function Get-ShortcutHijacks {
    param([string[]]$Roots)

    $findings = @()
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { return $findings }

    foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $lnks = @()
        try { $lnks = Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -Force -ErrorAction SilentlyContinue } catch { }

        foreach ($lnk in $lnks) {
            try {
                $sc = $shell.CreateShortcut($lnk.FullName)
                $targetLeaf = ''
                if ($sc.TargetPath) { $targetLeaf = (Split-Path -Leaf $sc.TargetPath).ToLower() }
                if ($script:BrowserExes -notcontains $targetLeaf) { continue }

                $split = Split-ShortcutArguments -Arguments $sc.Arguments
                if ($split.Redirects.Count -eq 0) { continue }

                $findings += [pscustomobject]@{
                    Path          = $lnk.FullName
                    ShortcutName  = $lnk.Name
                    Browser       = $targetLeaf
                    RedirectHosts = @($split.Redirects | ForEach-Object { Get-UrlHostOnly -Url $_ })
                    KeepArguments = $split.Keep
                }
            }
            catch { }
        }
    }
    return $findings
}

function Repair-ShortcutHijack {
    param([Parameter(Mandatory = $true)]$Finding)

    $backupDir = Get-HijackBackupDir
    Copy-Item -LiteralPath $Finding.Path -Destination (Join-Path $backupDir $Finding.ShortcutName) -Force -ErrorAction SilentlyContinue -WhatIf:$false

    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($Finding.Path)
    $sc.Arguments = $Finding.KeepArguments
    $sc.Save()
}

function Invoke-BrowserHijackModule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$Apply,
        [hashtable]$Options = @{}
    )

    Write-Banner 'Browser hijack and redirect detection'

    $result = [ordered]@{
        Mode              = $(if ($Apply) { 'Apply' } else { 'DetectOnly' })
        DomainJoined      = $false
        ShortcutHijacks   = @()
        ProxyFindings     = @()
        PolicyFindings    = @()
        Extensions        = @()
        HostsFindings     = @()
        ScheduledTasks    = @()
        DnsFindings       = @()
        Fixed             = @()
        BackupLocation    = $null
    }

    try { $result.DomainJoined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }
    if ($result.DomainJoined) {
        Write-Log -Message 'Machine is domain-joined. Proxy and policy settings are likely legitimate management, not a hijack - proxy auto-fix is disabled.' -Level WARN
    }

    # --- 1. Shortcut hijacking -------------------------------------------
    Write-Log -Message 'Scanning shortcuts for appended URLs' -Level STEP

    $lnkRoots = Get-ShortcutHijackRoots
    if ($Options['ShortcutRoots']) { $lnkRoots = @($Options['ShortcutRoots']) }

    foreach ($hit in (Get-ShortcutHijacks -Roots $lnkRoots)) {
        $finding = [ordered]@{
            ShortcutName  = $hit.ShortcutName
            Browser       = $hit.Browser
            RedirectHosts = $hit.RedirectHosts
            Fixed         = $false
        }

        if ($Apply -and $PSCmdlet.ShouldProcess($hit.ShortcutName, 'Strip redirect URL from shortcut arguments')) {
            Repair-ShortcutHijack -Finding $hit
            $finding.Fixed = $true
            $result.Fixed += ('shortcut:' + $hit.ShortcutName)
            Write-Log -Message ('Cleaned shortcut ' + $hit.ShortcutName) -Level OK
        }

        $result.ShortcutHijacks += $finding
    }
    Write-Log ('Shortcut hijacks found: ' + @($result.ShortcutHijacks).Count)

    # --- 2. Proxy settings -------------------------------------------------
    Write-Log -Message 'Checking proxy configuration' -Level STEP
    $isKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    try {
        $is = Get-ItemProperty -LiteralPath $isKey -ErrorAction Stop

        if ($is.AutoConfigURL) {
            $f = [ordered]@{ Setting = 'AutoConfigURL'; Host = (Get-UrlHostOnly -Url $is.AutoConfigURL); Fixed = $false }
            if ($Apply -and -not $result.DomainJoined) {
                if ($PSCmdlet.ShouldProcess('AutoConfigURL', 'Remove proxy auto-config URL')) {
                    Set-Content -LiteralPath (Join-Path (Get-HijackBackupDir) 'AutoConfigURL.txt') -Value $is.AutoConfigURL -Encoding UTF8 -WhatIf:$false
                    Remove-ItemProperty -LiteralPath $isKey -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
                    $f.Fixed = $true
                    $result.Fixed += 'proxy:AutoConfigURL'
                    Write-Log -Message 'Removed AutoConfigURL (backed up)' -Level OK
                }
            }
            $result.ProxyFindings += $f
        }

        if ($is.ProxyEnable -eq 1 -and $is.ProxyServer) {
            $f = [ordered]@{ Setting = 'ProxyServer'; Host = ($is.ProxyServer -split ':')[0]; Fixed = $false }
            if ($Apply -and -not $result.DomainJoined) {
                if ($PSCmdlet.ShouldProcess('ProxyServer', 'Disable manual proxy')) {
                    Set-Content -LiteralPath (Join-Path (Get-HijackBackupDir) 'ProxyServer.txt') -Value $is.ProxyServer -Encoding UTF8 -WhatIf:$false
                    Set-ItemProperty -LiteralPath $isKey -Name 'ProxyEnable' -Value 0 -ErrorAction SilentlyContinue
                    Remove-ItemProperty -LiteralPath $isKey -Name 'ProxyServer' -ErrorAction SilentlyContinue
                    $f.Fixed = $true
                    $result.Fixed += 'proxy:ProxyServer'
                    Write-Log -Message 'Disabled manual proxy (backed up)' -Level OK
                }
            }
            $result.ProxyFindings += $f
        }
    }
    catch { }
    Write-Log ('Proxy findings: ' + @($result.ProxyFindings).Count)

    # --- 3. Browser policy keys -------------------------------------------
    # Reported, never auto-cleared: these are also how a legitimate workplace
    # or a parental-controls product configures a browser.
    Write-Log -Message 'Checking browser policy keys' -Level STEP
    $policyRoots = @(
        'HKLM:\SOFTWARE\Policies\Google\Chrome',
        'HKCU:\SOFTWARE\Policies\Google\Chrome',
        'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
        'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
        'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave'
    )
    $interesting = @('HomepageLocation', 'NewTabPageLocation', 'DefaultSearchProviderSearchURL',
        'DefaultSearchProviderName', 'RestoreOnStartupURLs', 'DefaultSearchProviderEnabled')

    foreach ($root in $policyRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        try {
            $props = Get-ItemProperty -LiteralPath $root -ErrorAction Stop
            foreach ($name in $interesting) {
                if ($null -ne $props.$name) {
                    $result.PolicyFindings += [ordered]@{
                        Key   = ($root -replace '^HK(LM|CU):\\SOFTWARE\\Policies\\', '')
                        Scope = $(if ($root -like 'HKLM*') { 'Machine' } else { 'User' })
                        Value = $name
                        Host  = (Get-UrlHostOnly -Url ([string]$props.$name))
                    }
                }
            }
            # Force-installed extensions are the strongest single hijack signal.
            $forced = Join-Path $root 'ExtensionInstallForcelist'
            if (Test-Path -LiteralPath $forced) {
                $count = @((Get-ItemProperty -LiteralPath $forced -ErrorAction SilentlyContinue).PSObject.Properties |
                        Where-Object { $_.Name -notlike 'PS*' }).Count
                $result.PolicyFindings += [ordered]@{
                    Key   = ($root -replace '^HK(LM|CU):\\SOFTWARE\\Policies\\', '')
                    Scope = $(if ($root -like 'HKLM*') { 'Machine' } else { 'User' })
                    Value = 'ExtensionInstallForcelist'
                    Count = $count
                }
            }
        }
        catch { }
    }
    Write-Log ('Policy findings: ' + @($result.PolicyFindings).Count)

    # --- 4. Installed extensions (inventory only) --------------------------
    Write-Log -Message 'Inventorying browser extensions' -Level STEP
    $extRoots = @(
        @{ Browser = 'Chrome'; Path = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') },
        @{ Browser = 'Edge';   Path = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') },
        @{ Browser = 'Brave';  Path = (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data') }
    )
    foreach ($er in $extRoots) {
        if (-not (Test-Path -LiteralPath $er.Path)) { continue }
        try {
            foreach ($profileDir in (Get-ChildItem -LiteralPath $er.Path -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
                $extDir = Join-Path $profileDir.FullName 'Extensions'
                if (-not (Test-Path -LiteralPath $extDir)) { continue }

                foreach ($ext in (Get-ChildItem -LiteralPath $extDir -Directory -ErrorAction SilentlyContinue)) {
                    $name = $null
                    try {
                        $ver = Get-ChildItem -LiteralPath $ext.FullName -Directory -ErrorAction Stop | Select-Object -First 1
                        $mf = Join-Path $ver.FullName 'manifest.json'
                        if (Test-Path -LiteralPath $mf) {
                            $name = (Get-Content -LiteralPath $mf -Raw | ConvertFrom-Json).name
                        }
                    }
                    catch { }
                    $result.Extensions += [ordered]@{
                        Browser = $er.Browser
                        Id      = $ext.Name
                        Name    = $name
                    }
                }
            }
        }
        catch { }
    }
    Write-Log ('Extensions found: ' + @($result.Extensions).Count + ' (reported only, never auto-removed)')

    # --- 5. Hosts file ------------------------------------------------------
    Write-Log -Message 'Checking hosts file' -Level STEP
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    try {
        $lines = Get-Content -LiteralPath $hostsPath -ErrorAction Stop
        foreach ($line in $lines) {
            $t = $line.Trim()
            if ($t -eq '' -or $t.StartsWith('#')) { continue }
            $parts = $t -split '\s+'
            if ($parts.Count -lt 2) { continue }
            # 127.0.0.1 localhost and ::1 localhost are the shipped defaults.
            if ($parts[1] -like 'localhost*') { continue }
            $result.HostsFindings += [ordered]@{ MappedHost = $parts[1] }
        }
    }
    catch { }
    if (@($result.HostsFindings).Count -gt 0) {
        Write-Log -Message ('Hosts file has {0} non-default entries - reported, NOT modified. Back it up before editing.' -f @($result.HostsFindings).Count) -Level WARN
    }

    # --- 6. Scheduled tasks launching a browser at a URL -------------------
    Write-Log -Message 'Checking scheduled tasks' -Level STEP
    try {
        foreach ($task in (Get-ScheduledTask -ErrorAction Stop)) {
            foreach ($action in @($task.Actions)) {
                $exe = ''
                if ($action.Execute) { $exe = (Split-Path -Leaf $action.Execute).ToLower() }
                $args = [string]$action.Arguments
                if ($script:BrowserExes -contains $exe -and $args -match '(https?://|www\.)') {
                    $result.ScheduledTasks += [ordered]@{
                        TaskName = $task.TaskName
                        Browser  = $exe
                        Host     = (Get-UrlHostOnly -Url (($args -split '\s+' | Where-Object { $_ -match '^(https?://|www\.)' })[0]))
                    }
                }
            }
        }
    }
    catch { }
    Write-Log ('Suspicious scheduled tasks: ' + @($result.ScheduledTasks).Count)

    # --- 7. DNS ------------------------------------------------------------
    # Classify rather than record the addresses: a resolver IP would be
    # redacted out of the report anyway, and "static, not a known public
    # resolver" is the part that actually matters.
    Write-Log -Message 'Checking DNS configuration' -Level STEP
    $knownGood = @('8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112',
        '208.67.222.222', '208.67.220.220')
    try {
        foreach ($n in (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.ServerAddresses.Count -gt 0 })) {
            $unknown = @($n.ServerAddresses | Where-Object { $knownGood -notcontains $_ -and $_ -notlike '192.168.*' -and $_ -notlike '10.*' -and $_ -notlike '172.*' })
            if ($unknown.Count -gt 0) {
                $result.DnsFindings += [ordered]@{
                    Interface       = $n.InterfaceAlias
                    UnknownResolvers = $unknown.Count
                    Note            = 'Static DNS not matching a well-known public resolver or a local gateway'
                }
            }
        }
    }
    catch { }

    # --- Summary -----------------------------------------------------------
    $total = @($result.ShortcutHijacks).Count + @($result.ProxyFindings).Count +
    @($result.PolicyFindings).Count + @($result.ScheduledTasks).Count

    Write-Host ''
    Write-Host ('  Shortcut hijacks   : {0}' -f @($result.ShortcutHijacks).Count) -ForegroundColor $(if (@($result.ShortcutHijacks).Count) { 'Yellow' } else { 'Green' })
    Write-Host ('  Proxy findings     : {0}' -f @($result.ProxyFindings).Count) -ForegroundColor $(if (@($result.ProxyFindings).Count) { 'Yellow' } else { 'Green' })
    Write-Host ('  Policy findings    : {0}' -f @($result.PolicyFindings).Count) -ForegroundColor $(if (@($result.PolicyFindings).Count) { 'Yellow' } else { 'Green' })
    Write-Host ('  Scheduled tasks    : {0}' -f @($result.ScheduledTasks).Count) -ForegroundColor $(if (@($result.ScheduledTasks).Count) { 'Yellow' } else { 'Green' })
    Write-Host ('  Hosts entries      : {0}  (report only)' -f @($result.HostsFindings).Count) -ForegroundColor Gray
    Write-Host ('  Extensions         : {0}  (report only - review by hand)' -f @($result.Extensions).Count) -ForegroundColor Gray
    Write-Host ('  Static DNS flags   : {0}  (report only)' -f @($result.DnsFindings).Count) -ForegroundColor Gray
    Write-Host ''

    if (-not $Apply) {
        if ($total -gt 0) {
            Write-Host '  Detection only. Add -Apply to fix shortcuts and proxy settings.' -ForegroundColor Cyan
            Write-Host '  Policy keys, extensions and hosts entries are never auto-fixed - review them.' -ForegroundColor Cyan
        }
        else {
            Write-Host '  No redirect indicators found in the fixable categories.' -ForegroundColor Green
        }
    }
    else {
        $result.BackupLocation = Get-HijackBackupDir
        Write-Host ('  Fixed {0} item(s). Backups: {1}' -f @($result.Fixed).Count, $result.BackupLocation) -ForegroundColor Green
        Write-Host '  Backups are on THIS machine, not the stick. Purge them with option 7.' -ForegroundColor DarkGray
    }
    Write-Host ''

    return [pscustomobject]$result
}
