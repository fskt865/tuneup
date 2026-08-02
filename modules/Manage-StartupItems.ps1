<#MANIFEST
{
  "Key": "startup",
  "Title": "Startup item inventory and control",
  "Entry": "Invoke-StartupModule",
  "Order": 15,
  "RequiresAdmin": false,
  "Description": "Lists what runs at logon with measured boot impact; disables (never deletes) safe items"
}
MANIFEST#>

# Manage-StartupItems.ps1 - inventory and disable logon startup items.
# ASCII only, PowerShell 5.1 compatible.
#
# DISABLE, NEVER DELETE. This writes to the same StartupApproved keys Task
# Manager uses, so:
#   - the original Run value and its command line are left completely intact
#   - the customer can re-enable it themselves from Task Manager > Startup
#   - -Restore here undoes everything this module disabled
# Deleting a Run entry throws away the command line, and reconstructing one
# from memory on a machine you no longer have is not a repair.
#
# Classification asymmetry, which matters:
#   Protected patterns may be BROAD. Over-matching means declining to disable
#   something - harmless.
#   Optional patterns must be SPECIFIC. Over-matching means disabling
#   something the machine needed - not harmless.
#
# Scheduled tasks with logon triggers are REPORTED, never disabled. That is
# where updaters hide, but it is also where OEM and Windows machinery lives,
# and the blast radius of getting it wrong is larger than the benefit. The
# module prints the command so the tech can decide.

$script:StartupCatalog = @(
    # --- Protected: security. Never disabled. ---------------------------
    @{ Pattern = '*Defender*';        Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = 'SecurityHealth*';   Tier = 'Protected'; Note = 'Windows Security tray' },
    @{ Pattern = '*McAfee*';          Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*Norton*';          Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*Avast*';           Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*AVG*';             Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*Bitdefender*';     Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*ESET*';            Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*Kaspersky*';       Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*Malwarebytes*';    Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*Webroot*';         Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*Sophos*';          Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*Trend*Micro*';     Tier = 'Protected'; Note = 'Security' },
    @{ Pattern = '*VPN*';             Tier = 'Protected'; Note = 'May be required for network access' },

    # --- Protected: input, audio, display, power. Disabling these is how
    # --- you hand back a laptop with a dead touchpad or no sound.
    @{ Pattern = '*Synaptics*';       Tier = 'Protected'; Note = 'Touchpad' },
    @{ Pattern = 'SynTPEnh*';         Tier = 'Protected'; Note = 'Touchpad' },
    @{ Pattern = '*ELAN*';            Tier = 'Protected'; Note = 'Touchpad' },
    @{ Pattern = 'ETD*';              Tier = 'Protected'; Note = 'Touchpad' },
    @{ Pattern = '*Alps*';            Tier = 'Protected'; Note = 'Touchpad' },
    @{ Pattern = '*Realtek*';         Tier = 'Protected'; Note = 'Audio / NIC' },
    @{ Pattern = 'RtkAud*';           Tier = 'Protected'; Note = 'Audio' },
    @{ Pattern = 'RAVCpl*';           Tier = 'Protected'; Note = 'Audio' },
    @{ Pattern = '*Nahimic*';         Tier = 'Protected'; Note = 'Audio' },
    @{ Pattern = '*Dolby*';           Tier = 'Protected'; Note = 'Audio' },
    @{ Pattern = '*Waves*';           Tier = 'Protected'; Note = 'Audio' },
    @{ Pattern = '*Audio*';           Tier = 'Protected'; Note = 'Audio' },
    @{ Pattern = 'Igfx*';             Tier = 'Protected'; Note = 'Intel graphics' },
    @{ Pattern = 'HotKeysCmds*';      Tier = 'Protected'; Note = 'Graphics hotkeys' },
    @{ Pattern = '*Intel*';           Tier = 'Protected'; Note = 'Intel platform' },
    @{ Pattern = '*NVIDIA*';          Tier = 'Protected'; Note = 'Display' },
    @{ Pattern = 'Nv*';               Tier = 'Protected'; Note = 'Display' },
    @{ Pattern = '*AMD*';             Tier = 'Protected'; Note = 'Display / platform' },
    @{ Pattern = '*ATI*';             Tier = 'Protected'; Note = 'Display' },
    @{ Pattern = '*Bluetooth*';       Tier = 'Protected'; Note = 'Radio' },
    @{ Pattern = '*Touchpad*';        Tier = 'Protected'; Note = 'Input' },
    @{ Pattern = '*Hotkey*';          Tier = 'Protected'; Note = 'Fn keys' },
    @{ Pattern = '*Power*Manager*';   Tier = 'Protected'; Note = 'Battery / thermal' },

    # --- Protected: OEM ---------------------------------------------------
    @{ Pattern = '*Lenovo*';          Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*ThinkPad*';        Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = 'TP*HOTKEY*';        Tier = 'Protected'; Note = 'OEM hotkeys' },
    @{ Pattern = '*Dell*';            Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*ASUS*';            Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*Acer*';            Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*MSI*';             Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*Killer*';          Tier = 'Protected'; Note = 'Network stack' },
    @{ Pattern = 'Ctfmon*';           Tier = 'Protected'; Note = 'Text input' },

    # --- Optional: specific names only. Never broad wildcards here. ------
    @{ Pattern = 'Adobe ARM*';        Tier = 'Optional'; Note = 'Updater - runs on demand anyway' },
    @{ Pattern = 'AdobeAAMUpdater*';  Tier = 'Optional'; Note = 'Updater' },
    @{ Pattern = 'AdobeGCInvoker*';   Tier = 'Optional'; Note = 'Updater' },
    @{ Pattern = 'Acrobat Assistant*'; Tier = 'Optional'; Note = 'Tray helper' },
    @{ Pattern = 'SunJavaUpdateSched*'; Tier = 'Optional'; Note = 'Java updater' },
    @{ Pattern = 'jusched*';          Tier = 'Optional'; Note = 'Java updater' },
    @{ Pattern = 'GoogleChromeAutoLaunch*'; Tier = 'Optional'; Note = 'Chrome autostart - browser still updates on launch' },
    @{ Pattern = 'GoogleDriveFS*';    Tier = 'Optional'; Note = 'Sync stops until launched' },
    @{ Pattern = 'iTunesHelper*';     Tier = 'Optional'; Note = 'Tray helper' },
    @{ Pattern = 'QuickTime Task*';   Tier = 'Optional'; Note = 'Tray helper' },
    @{ Pattern = 'APSDaemon*';        Tier = 'Optional'; Note = 'Apple Push - not needed at boot' },
    @{ Pattern = 'Spotify*';          Tier = 'Optional'; Note = 'Media app' },
    @{ Pattern = 'Steam*';            Tier = 'Optional'; Note = 'Game launcher' },
    @{ Pattern = 'EpicGamesLauncher*'; Tier = 'Optional'; Note = 'Game launcher' },
    @{ Pattern = 'GOG Galaxy*';       Tier = 'Optional'; Note = 'Game launcher' },
    @{ Pattern = 'Origin*';           Tier = 'Optional'; Note = 'Game launcher' },
    @{ Pattern = 'Uplay*';            Tier = 'Optional'; Note = 'Game launcher' },
    @{ Pattern = 'Ubisoft*';          Tier = 'Optional'; Note = 'Game launcher' },
    @{ Pattern = 'Discord*';          Tier = 'Optional'; Note = 'Chat app' },
    @{ Pattern = 'Zoom*';             Tier = 'Optional'; Note = 'Meeting app' },
    @{ Pattern = 'Skype*';            Tier = 'Optional'; Note = 'Chat app' },
    @{ Pattern = 'Slack*';            Tier = 'Optional'; Note = 'Chat app' },
    @{ Pattern = 'com.squirrel.Teams*'; Tier = 'Optional'; Note = 'Chat app' },
    @{ Pattern = 'Microsoft Teams*';  Tier = 'Optional'; Note = 'Chat app' },
    @{ Pattern = 'Dropbox*';          Tier = 'Optional'; Note = 'Sync stops until launched' },
    @{ Pattern = 'OneDrive*';         Tier = 'Optional'; Note = 'Sync stops until launched - confirm with the customer' },
    @{ Pattern = 'CCleaner*';         Tier = 'Optional'; Note = 'Third-party cleaner' },
    @{ Pattern = 'WildTangent*';      Tier = 'Optional'; Note = 'OEM game portal' },
    @{ Pattern = 'Booking.com*';      Tier = 'Optional'; Note = 'Preinstalled promo' },
    @{ Pattern = 'Amazon*Assistant*'; Tier = 'Optional'; Note = 'Shopping helper' },
    @{ Pattern = 'Wondershare*';      Tier = 'Optional'; Note = 'Third-party utility' },
    @{ Pattern = 'Nero*';             Tier = 'Optional'; Note = 'Third-party utility' },
    @{ Pattern = 'Roxio*';            Tier = 'Optional'; Note = 'Third-party utility' }
)

function Get-StartupTier {
    param([string]$Name)

    # Protected is evaluated first and wins, so a future Optional entry added
    # carelessly can never downgrade something protected.
    foreach ($tier in @('Protected', 'Optional')) {
        foreach ($entry in $script:StartupCatalog) {
            if ($entry.Tier -ne $tier) { continue }
            if ($Name -like $entry.Pattern) {
                return [pscustomobject]@{ Tier = $tier; Note = $entry.Note }
            }
        }
    }
    return [pscustomobject]@{ Tier = 'Unclassified'; Note = 'Not in catalog - never auto-disabled' }
}

# --- StartupApproved encoding -------------------------------------------
# Task Manager records enable/disable state as a REG_BINARY blob. Byte 0 is
# the flag; bit 0 set means disabled (2 = enabled, 3 = disabled; some builds
# use 6/7 the same way). Bytes 4-11 are a timestamp Task Manager writes and
# Windows does not require. Absence of a value means enabled.

function Test-StartupApprovalDisabled {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Count -eq 0) { return $false }
    return (($Bytes[0] -band 1) -eq 1)
}

function New-StartupApprovalBytes {
    param([bool]$Enabled)
    $b = New-Object byte[] 12
    if ($Enabled) { $b[0] = 2 } else { $b[0] = 3 }
    return $b
}

$script:StartupLocations = @(
    @{ Label = 'HKLM Run';           Scope = 'Machine'; Type = 'Registry';
        Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';
        Approval = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    },
    @{ Label = 'HKLM Run (32-bit)';  Scope = 'Machine'; Type = 'Registry';
        Key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';
        Approval = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
    },
    @{ Label = 'HKCU Run';           Scope = 'User'; Type = 'Registry';
        Key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';
        Approval = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    },
    @{ Label = 'HKCU Run (32-bit)';  Scope = 'User'; Type = 'Registry';
        Key = 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';
        Approval = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
    },
    @{ Label = 'Startup folder (user)'; Scope = 'User'; Type = 'Folder';
        Key = (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup');
        Approval = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    },
    @{ Label = 'Startup folder (all users)'; Scope = 'Machine'; Type = 'Folder';
        Key = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup');
        Approval = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    }
)

function Get-StartupItems {
    $items = @()

    foreach ($loc in $script:StartupLocations) {
        $approvals = $null
        if (Test-Path -LiteralPath $loc.Approval) {
            $approvals = Get-ItemProperty -LiteralPath $loc.Approval -ErrorAction SilentlyContinue
        }

        if ($loc.Type -eq 'Registry') {
            if (-not (Test-Path -LiteralPath $loc.Key)) { continue }
            $props = Get-ItemProperty -LiteralPath $loc.Key -ErrorAction SilentlyContinue
            if (-not $props) { continue }

            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -like 'PS*') { continue }
                $disabled = $false
                if ($approvals -and $approvals.PSObject.Properties.Name -contains $p.Name) {
                    $disabled = Test-StartupApprovalDisabled -Bytes $approvals.$($p.Name)
                }
                $class = Get-StartupTier -Name $p.Name
                $items += [pscustomobject]@{
                    Name        = $p.Name
                    Command     = [string]$p.Value
                    Location    = $loc.Label
                    Scope       = $loc.Scope
                    Type        = 'Registry'
                    RegKey      = $loc.Key
                    ApprovalKey = $loc.Approval
                    Enabled     = (-not $disabled)
                    Tier        = $class.Tier
                    Note        = $class.Note
                }
            }
        }
        else {
            if (-not (Test-Path -LiteralPath $loc.Key)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $loc.Key -File -ErrorAction SilentlyContinue)) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $disabled = $false
                if ($approvals -and $approvals.PSObject.Properties.Name -contains $f.Name) {
                    $disabled = Test-StartupApprovalDisabled -Bytes $approvals.$($f.Name)
                }
                $class = Get-StartupTier -Name $f.BaseName
                $items += [pscustomobject]@{
                    Name        = $f.Name
                    Command     = $f.FullName
                    Location    = $loc.Label
                    Scope       = $loc.Scope
                    Type        = 'Folder'
                    RegKey      = $loc.Key
                    ApprovalKey = $loc.Approval
                    Enabled     = (-not $disabled)
                    Tier        = $class.Tier
                    Note        = $class.Note
                }
            }
        }
    }
    return $items
}

function Set-StartupItemEnabled {
    param(
        [Parameter(Mandatory = $true)]$Item,
        [Parameter(Mandatory = $true)][bool]$Enabled
    )

    if (-not (Test-Path -LiteralPath $Item.ApprovalKey)) {
        New-Item -Path $Item.ApprovalKey -Force -WhatIf:$false | Out-Null
    }

    $bytes = New-StartupApprovalBytes -Enabled $Enabled
    New-ItemProperty -LiteralPath $Item.ApprovalKey -Name $Item.Name -Value $bytes `
        -PropertyType Binary -Force -WhatIf:$false | Out-Null
}

# --- Measured boot impact ------------------------------------------------
# Real numbers from Windows' own diagnostics log rather than a guess. Event
# 100 is the boot itself; 101 and 103 name what degraded it and by how much.
function Get-BootPerformance {
    # Reading this log needs elevation. "Could not read it" and "there is
    # nothing wrong" are different answers and must not print the same way.
    $perf = [ordered]@{
        Available          = $false
        Status             = 'Unknown'
        LastBootSeconds    = $null
        MainPathSeconds    = $null
        SlowApps           = @()
        SlowServices       = @()
    }

    if (-not (Test-IsAdmin)) {
        $perf.Status = 'RequiresElevation'
        return [pscustomobject]$perf
    }

    function Get-EventDataMap {
        param($Event)
        $map = @{}
        try {
            $xml = [xml]$Event.ToXml()
            foreach ($d in $xml.Event.EventData.Data) { $map[$d.Name] = $d.'#text' }
        }
        catch { }
        return $map
    }

    try {
        $boot = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100
        } -MaxEvents 1 -ErrorAction Stop
        if ($boot) {
            $m = Get-EventDataMap -Event $boot
            $perf.Available = $true
            $perf.Status = 'Read'
            if ($m['BootTime']) { $perf.LastBootSeconds = [math]::Round(([double]$m['BootTime']) / 1000, 1) }
            if ($m['MainPathBootTime']) { $perf.MainPathSeconds = [math]::Round(([double]$m['MainPathBootTime']) / 1000, 1) }
        }
    }
    catch {
        if ($_.Exception.Message -match 'unauthorized') { $perf.Status = 'AccessDenied' }
        else { $perf.Status = 'NoData' }
        return [pscustomobject]$perf
    }

    foreach ($spec in @(@{ Id = 101; Bucket = 'SlowApps' }, @{ Id = 103; Bucket = 'SlowServices' })) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = $spec.Id
            } -MaxEvents 60 -ErrorAction Stop

            $agg = @{}
            foreach ($e in $events) {
                $m = Get-EventDataMap -Event $e
                $nm = $m['Name']
                if (-not $nm) { continue }
                $deg = 0
                if ($m['DegradationTime']) { $deg = [double]$m['DegradationTime'] }
                elseif ($m['TotalTime']) { $deg = [double]$m['TotalTime'] }
                if (-not $agg.ContainsKey($nm) -or $agg[$nm] -lt $deg) { $agg[$nm] = $deg }
            }

            $list = @()
            foreach ($k in $agg.Keys) {
                $list += [pscustomobject]@{ Name = $k; WorstDelaySeconds = [math]::Round($agg[$k] / 1000, 1) }
            }
            $perf[$spec.Bucket] = @($list | Sort-Object WorstDelaySeconds -Descending | Select-Object -First 10)
        }
        catch { }
    }

    return [pscustomobject]$perf
}

function Invoke-StartupModule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$Apply,
        [hashtable]$Options = @{}
    )

    $restore = [bool]$Options['Restore']
    $backupFile = Join-Path $script:LocalRoot 'startup-backup.json'

    Write-Banner 'Startup item inventory'

    $result = [ordered]@{
        Mode            = $(if ($restore) { 'Restore' } elseif ($Apply) { 'Apply' } else { 'InventoryOnly' })
        Counts          = @{}
        Items           = @()
        BootPerformance = $null
        LogonTasks      = @()
        Disabled        = @()
        Restored        = @()
        BackupFile      = $null
    }

    # --- Restore path ----------------------------------------------------
    if ($restore) {
        Write-Banner 'Restoring startup items this tool disabled'
        if (-not (Test-Path -LiteralPath $backupFile)) {
            Write-Log -Message "No backup at $backupFile - nothing to restore on this machine." -Level WARN
            return [pscustomobject]$result
        }
        $saved = Get-Content -LiteralPath $backupFile -Raw | ConvertFrom-Json
        foreach ($s in @($saved)) {
            if ($PSCmdlet.ShouldProcess($s.Name, 'Re-enable startup item')) {
                try {
                    Set-StartupItemEnabled -Item $s -Enabled $true
                    $result.Restored += $s.Name
                    Write-Log -Message ('Re-enabled ' + $s.Name) -Level OK
                }
                catch {
                    Write-Log -Message ('Could not re-enable {0}: {1}' -f $s.Name, $_.Exception.Message) -Level WARN
                }
            }
        }
        Write-Host ''
        Write-Host ('  Re-enabled {0} item(s).' -f @($result.Restored).Count) -ForegroundColor Green
        Write-Host ''
        return [pscustomobject]$result
    }

    # --- Inventory --------------------------------------------------------
    $items = @(Get-StartupItems)
    foreach ($t in @('Protected', 'Optional', 'Unclassified')) {
        $result.Counts[$t] = @($items | Where-Object { $_.Tier -eq $t }).Count
    }
    $result.Counts['Enabled'] = @($items | Where-Object { $_.Enabled }).Count
    $result.Counts['AlreadyDisabled'] = @($items | Where-Object { -not $_.Enabled }).Count

    foreach ($i in $items) {
        $result.Items += [ordered]@{
            Name = $i.Name; Location = $i.Location; Scope = $i.Scope
            Enabled = $i.Enabled; Tier = $i.Tier; Note = $i.Note
        }
    }

    Write-Host ''
    Write-Host ('  Startup entries: {0}  ({1} enabled, {2} already disabled)' -f `
            $items.Count, $result.Counts['Enabled'], $result.Counts['AlreadyDisabled']) -ForegroundColor Cyan
    Write-Host ('    Protected (never disabled)  : {0}' -f $result.Counts['Protected']) -ForegroundColor Green
    Write-Host ('    Optional  (safe to disable) : {0}' -f $result.Counts['Optional']) -ForegroundColor Yellow
    Write-Host ('    Unclassified (left alone)   : {0}' -f $result.Counts['Unclassified']) -ForegroundColor DarkGray
    Write-Host ''

    foreach ($i in ($items | Sort-Object Tier, Name)) {
        $state = 'on '
        $color = 'Gray'
        if (-not $i.Enabled) { $state = 'off'; $color = 'DarkGray' }
        if ($i.Tier -eq 'Optional' -and $i.Enabled) { $color = 'Yellow' }
        if ($i.Tier -eq 'Protected') { $color = 'Green' }
        Write-Host ('    [{0}] {1,-12} {2,-30} {3}' -f $state, $i.Tier, $i.Name, $i.Note) -ForegroundColor $color
    }

    # --- Measured boot impact --------------------------------------------
    Write-Log -Message 'Reading boot performance diagnostics' -Level STEP
    $perf = Get-BootPerformance
    $result.BootPerformance = $perf

    Write-Host ''
    if ($perf.Available) {
        Write-Host ('  Last boot: {0}s total, {1}s main path' -f $perf.LastBootSeconds, $perf.MainPathSeconds) -ForegroundColor Cyan
        if (@($perf.SlowApps).Count -gt 0) {
            Write-Host '  Worst measured startup delays (from Windows diagnostics):' -ForegroundColor Cyan
            foreach ($a in $perf.SlowApps) {
                Write-Host ('    {0,6}s  {1}' -f $a.WorstDelaySeconds, $a.Name) -ForegroundColor Gray
            }
        }
    }
    elseif ($perf.Status -eq 'RequiresElevation' -or $perf.Status -eq 'AccessDenied') {
        Write-Host '  Boot performance: NOT CHECKED - the diagnostics log needs elevation.' -ForegroundColor Yellow
        Write-Host '  That is "not measured", not "boot is fine". Re-run via RUN.cmd.' -ForegroundColor Yellow
    }
    else {
        Write-Host '  Boot performance: no data in the diagnostics log on this machine.' -ForegroundColor DarkGray
    }

    # --- Logon scheduled tasks: reported only ----------------------------
    Write-Log -Message 'Listing logon-triggered scheduled tasks (report only)' -Level STEP
    try {
        foreach ($task in (Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' })) {
            $hasLogon = @($task.Triggers | Where-Object { $_.CimClass.CimClassName -match 'Logon|Boot' }).Count -gt 0
            if (-not $hasLogon) { continue }
            if ($task.TaskPath -like '\Microsoft\Windows\*') { continue }

            # Classify on path AND name. A task called "Background monitor"
            # matches nothing on its own, but under \Lenovo\Power Manager\ it
            # is plainly OEM machinery - and reporting it as Unclassified
            # invites someone to switch off the battery manager.
            $fullName = ($task.TaskPath + $task.TaskName)
            $tier = (Get-StartupTier -Name $fullName).Tier
            if ($tier -eq 'Unclassified') { $tier = (Get-StartupTier -Name $task.TaskName).Tier }

            $result.LogonTasks += [ordered]@{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                Tier     = $tier
            }
        }
    }
    catch { }

    if (@($result.LogonTasks).Count -gt 0) {
        Write-Host ''
        Write-Host '  Logon/boot scheduled tasks - NOT disabled, run these yourself if wanted:' -ForegroundColor Yellow
        foreach ($t in $result.LogonTasks) {
            Write-Host ('    {0,-14} {1}' -f $t.Tier, $t.TaskName) -ForegroundColor Gray
            Write-Host ("        Disable-ScheduledTask -TaskPath '{0}' -TaskName '{1}'" -f $t.TaskPath, $t.TaskName) -ForegroundColor DarkGray
        }
    }

    # --- Apply ------------------------------------------------------------
    if (-not $Apply) {
        Write-Host ''
        Write-Host '  Inventory only. Nothing was changed.' -ForegroundColor Cyan
        Write-Host '  -Apply disables the Optional tier. Items are DISABLED, never deleted -' -ForegroundColor Cyan
        Write-Host '  the customer can re-enable them in Task Manager > Startup.' -ForegroundColor Cyan
        Write-Host ''
        return [pscustomobject]$result
    }

    $targets = @($items | Where-Object { $_.Tier -eq 'Optional' -and $_.Enabled })
    Write-Banner ('Disabling {0} startup item(s)' -f $targets.Count)

    $backup = @()
    foreach ($i in $targets) {
        # Re-check at the point of writing rather than trusting the earlier list.
        $recheck = Get-StartupTier -Name $i.Name
        if ($recheck.Tier -ne 'Optional') {
            Write-Log -Message ('Refusing to disable {0} - tier {1}' -f $i.Name, $recheck.Tier) -Level WARN
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($i.Name, 'Disable startup item (reversible)')) { continue }

        try {
            $backup += [ordered]@{
                Name = $i.Name; ApprovalKey = $i.ApprovalKey
                Location = $i.Location; Command = $i.Command
            }
            Set-StartupItemEnabled -Item $i -Enabled $false
            $result.Disabled += $i.Name
            Write-Log -Message ('Disabled ' + $i.Name) -Level OK
        }
        catch {
            Write-Log -Message ('Could not disable {0}: {1}' -f $i.Name, $_.Exception.Message) -Level WARN
        }
    }

    if ($backup.Count -gt 0) {
        $backup | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupFile -Encoding UTF8 -WhatIf:$false
        $result.BackupFile = $backupFile
        Write-Log -Message ('Backup written to ' + $backupFile) -Level OK
    }

    Write-Host ''
    Write-Host ('  Disabled {0} item(s). Nothing was deleted.' -f @($result.Disabled).Count) -ForegroundColor Green
    Write-Host '  Undo everything:  .\Invoke-TuneUp.ps1 -Module startup -Apply -Restore' -ForegroundColor DarkGray
    Write-Host '  Or the customer can re-enable individually in Task Manager > Startup.' -ForegroundColor DarkGray
    Write-Host ''

    return [pscustomobject]$result
}
