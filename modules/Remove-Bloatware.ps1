<#MANIFEST
{
  "Key": "bloatware",
  "Title": "Bloatware inventory and removal",
  "Entry": "Invoke-BloatwareModule",
  "Order": 10,
  "RequiresAdmin": true,
  "Description": "Classifies installed apps; removes consumer junk only, never OEM hardware utilities"
}
MANIFEST#>

# Remove-Bloatware.ps1 - classify installed apps, remove the safe tier.
# ASCII only, PowerShell 5.1 compatible.
#
# The catalog below is the entire safety story. Classification is by explicit
# pattern, never by heuristic, because "looks like bloat" is exactly how you
# remove the utility that owns a laptop's fan curve.
#
# Three tiers:
#   Consumer  - games, promo tiles and social apps. No system function.
#               Removed by default when -Apply is passed.
#   Optional  - plausibly wanted, or holds user data, or is load-bearing on
#               some builds. Requires -IncludeOptional on top of -Apply.
#   Protected - never removed by this module under any flag. Runtimes, store
#               infrastructure, security UI, OEM hardware utilities, and any
#               antivirus (which the customer may have paid for).
#
# Anything not in the catalog at all is reported as Unclassified and is never
# removed. An unrecognised app is a reason to look, not a reason to delete.

$script:BloatCatalog = @(
    # --- Consumer: games and promo installs -----------------------------
    @{ Pattern = 'king.com.*';                          Tier = 'Consumer'; Note = 'Candy Crush family' },
    @{ Pattern = '*CandyCrush*';                        Tier = 'Consumer'; Note = 'Game' },
    @{ Pattern = '*BubbleWitch*';                       Tier = 'Consumer'; Note = 'Game' },
    @{ Pattern = '*DisneyMagicKingdom*';                Tier = 'Consumer'; Note = 'Game' },
    @{ Pattern = '*MarchofEmpires*';                    Tier = 'Consumer'; Note = 'Game' },
    @{ Pattern = '*RoyalRevolt*';                       Tier = 'Consumer'; Note = 'Game' },
    @{ Pattern = 'Microsoft.MicrosoftSolitaireCollection'; Tier = 'Consumer'; Note = 'Game with ads' },
    @{ Pattern = '*WildTangent*';                       Tier = 'Consumer'; Note = 'OEM game portal' },

    # --- Consumer: social and streaming promo tiles ---------------------
    @{ Pattern = '*Facebook*';                          Tier = 'Consumer'; Note = 'Promo install' },
    @{ Pattern = '*Instagram*';                         Tier = 'Consumer'; Note = 'Promo install' },
    @{ Pattern = '*TikTok*';                            Tier = 'Consumer'; Note = 'Promo install' },
    @{ Pattern = '*Twitter*';                           Tier = 'Consumer'; Note = 'Promo install' },
    @{ Pattern = '*LinkedIn*';                          Tier = 'Consumer'; Note = 'Promo install' },
    @{ Pattern = '*Netflix*';                           Tier = 'Consumer'; Note = 'Promo install' },
    @{ Pattern = '*SpotifyMusic*';                      Tier = 'Consumer'; Note = 'Promo install' },
    @{ Pattern = '*Hulu*';                              Tier = 'Consumer'; Note = 'Promo install' },
    @{ Pattern = '*AmazonVideo*';                       Tier = 'Consumer'; Note = 'Promo install' },
    @{ Pattern = '*PrimeVideo*';                        Tier = 'Consumer'; Note = 'Promo install' },

    # --- Consumer: Microsoft first-party clutter ------------------------
    @{ Pattern = 'Microsoft.BingNews';                  Tier = 'Consumer'; Note = 'News feed' },
    @{ Pattern = 'Microsoft.BingWeather';               Tier = 'Consumer'; Note = 'Weather tile' },
    @{ Pattern = 'Microsoft.BingFinance';               Tier = 'Consumer'; Note = 'Finance tile' },
    @{ Pattern = 'Microsoft.BingSports';                Tier = 'Consumer'; Note = 'Sports tile' },
    @{ Pattern = 'Microsoft.3DBuilder';                 Tier = 'Consumer'; Note = 'Legacy 3D app' },
    @{ Pattern = 'Microsoft.Print3D';                   Tier = 'Consumer'; Note = 'Legacy 3D app' },
    @{ Pattern = 'Microsoft.Microsoft3DViewer';         Tier = 'Consumer'; Note = 'Legacy 3D app' },
    @{ Pattern = 'Microsoft.MixedReality.Portal';       Tier = 'Consumer'; Note = 'WMR portal' },
    @{ Pattern = 'Microsoft.SkypeApp';                  Tier = 'Consumer'; Note = 'Preinstalled Skype' },
    @{ Pattern = 'Microsoft.GetHelp';                   Tier = 'Consumer'; Note = 'Support stub' },
    @{ Pattern = 'Microsoft.Getstarted';                Tier = 'Consumer'; Note = 'Tips app' },
    @{ Pattern = 'Microsoft.People';                    Tier = 'Consumer'; Note = 'Contacts tile' },
    @{ Pattern = 'Microsoft.Wallet';                    Tier = 'Consumer'; Note = 'Deprecated' },
    @{ Pattern = 'Microsoft.WindowsFeedbackHub';        Tier = 'Consumer'; Note = 'Telemetry feedback' },
    @{ Pattern = 'Microsoft.MicrosoftOfficeHub';        Tier = 'Consumer'; Note = 'Office promo tile, not Office' },
    @{ Pattern = 'Microsoft.MicrosoftJournal';          Tier = 'Consumer'; Note = 'Optional app' },
    @{ Pattern = 'Clipchamp.Clipchamp';                 Tier = 'Consumer'; Note = 'Video editor promo' },
    @{ Pattern = 'MicrosoftTeams';                      Tier = 'Consumer'; Note = 'Teams personal (not work Teams)' },
    @{ Pattern = 'MSTeams';                             Tier = 'Consumer'; Note = 'Teams personal (not work Teams)' },
    @{ Pattern = 'Microsoft.Windows.DevHome';           Tier = 'Consumer'; Note = 'Dev Home' },
    @{ Pattern = 'Microsoft.WindowsMaps';               Tier = 'Consumer'; Note = 'Maps' },

    # --- Optional: judgment required ------------------------------------
    # ZuneMusic/ZuneVideo ARE Media Player and Movies+TV on Windows 11.
    # Removing them takes the media player with them.
    @{ Pattern = 'Microsoft.ZuneMusic';                 Tier = 'Optional'; Note = 'This IS Media Player on Win11' },
    @{ Pattern = 'Microsoft.ZuneVideo';                 Tier = 'Optional'; Note = 'This IS Movies and TV on Win11' },
    @{ Pattern = 'Microsoft.MicrosoftStickyNotes';      Tier = 'Optional'; Note = 'Holds user notes - data loss risk' },
    @{ Pattern = 'Microsoft.Windows.Photos';            Tier = 'Optional'; Note = 'Default image viewer' },
    @{ Pattern = 'microsoft.windowscommunicationsapps'; Tier = 'Optional'; Note = 'Mail and Calendar - holds account data' },
    @{ Pattern = 'Microsoft.YourPhone';                 Tier = 'Optional'; Note = 'Phone Link - may be actively paired' },
    @{ Pattern = 'Microsoft.Todos';                     Tier = 'Optional'; Note = 'Holds user tasks' },
    @{ Pattern = 'Microsoft.OutlookForWindows';         Tier = 'Optional'; Note = 'May hold account data' },
    @{ Pattern = 'Microsoft.Xbox*';                     Tier = 'Optional'; Note = 'Removing GamingOverlay breaks Win+G capture' },
    @{ Pattern = 'Microsoft.GamingApp';                 Tier = 'Optional'; Note = 'Xbox app' },
    @{ Pattern = 'Microsoft.WindowsSoundRecorder';      Tier = 'Optional'; Note = 'May hold recordings' },
    @{ Pattern = 'Microsoft.WindowsCamera';             Tier = 'Optional'; Note = 'Default camera app' },
    @{ Pattern = 'Microsoft.WindowsAlarms';             Tier = 'Optional'; Note = 'May hold set alarms' },
    @{ Pattern = 'Microsoft.PowerAutomateDesktop';      Tier = 'Optional'; Note = 'May hold user flows' },
    @{ Pattern = 'Microsoft.OneDriveSync';              Tier = 'Optional'; Note = 'Sync client - data implications' },

    # --- Protected: never removed, any flag -----------------------------
    @{ Pattern = 'Microsoft.WindowsStore';              Tier = 'Protected'; Note = 'Store - nothing reinstalls without it' },
    @{ Pattern = 'Microsoft.StorePurchaseApp';          Tier = 'Protected'; Note = 'Store infrastructure' },
    @{ Pattern = 'Microsoft.DesktopAppInstaller';       Tier = 'Protected'; Note = 'winget / app installer' },
    @{ Pattern = 'Microsoft.VCLibs*';                   Tier = 'Protected'; Note = 'C++ runtime - other apps depend on it' },
    @{ Pattern = 'Microsoft.NET.Native*';               Tier = 'Protected'; Note = '.NET native runtime' },
    @{ Pattern = 'Microsoft.UI.Xaml*';                  Tier = 'Protected'; Note = 'XAML runtime' },
    @{ Pattern = 'Microsoft.WindowsAppRuntime*';        Tier = 'Protected'; Note = 'App runtime' },
    @{ Pattern = 'Microsoft.SecHealthUI';               Tier = 'Protected'; Note = 'Windows Security UI' },
    @{ Pattern = 'Microsoft.AAD.BrokerPlugin';          Tier = 'Protected'; Note = 'Account authentication' },
    @{ Pattern = 'Microsoft.AccountsControl';           Tier = 'Protected'; Note = 'Account authentication' },
    @{ Pattern = 'Microsoft.LockApp';                   Tier = 'Protected'; Note = 'Lock screen' },
    @{ Pattern = 'Microsoft.Windows.ShellExperienceHost'; Tier = 'Protected'; Note = 'Shell' },
    @{ Pattern = 'Microsoft.Windows.StartMenuExperienceHost'; Tier = 'Protected'; Note = 'Start menu' },
    @{ Pattern = 'Microsoft.Windows.Search*';           Tier = 'Protected'; Note = 'Search' },
    @{ Pattern = 'Microsoft.WindowsNotepad';            Tier = 'Protected'; Note = 'Core tool' },
    @{ Pattern = 'Microsoft.Paint';                     Tier = 'Protected'; Note = 'Core tool' },
    @{ Pattern = 'Microsoft.ScreenSketch';              Tier = 'Protected'; Note = 'Snipping Tool' },
    @{ Pattern = 'Microsoft.WindowsCalculator';         Tier = 'Protected'; Note = 'Core tool' },
    @{ Pattern = 'Microsoft.WindowsTerminal';           Tier = 'Protected'; Note = 'Core tool' },
    @{ Pattern = 'Microsoft.HEIF*';                     Tier = 'Protected'; Note = 'Codec' },
    @{ Pattern = 'Microsoft.VP9*';                      Tier = 'Protected'; Note = 'Codec' },
    @{ Pattern = 'Microsoft.WebMediaExtensions';        Tier = 'Protected'; Note = 'Codec' },
    @{ Pattern = 'Microsoft.WebpImageExtension';        Tier = 'Protected'; Note = 'Codec' },
    @{ Pattern = 'Microsoft.RawImageExtension';         Tier = 'Protected'; Note = 'Codec' },

    # OEM hardware utilities. These look like bloat and are not: they own
    # battery charge thresholds, fan curves, hotkeys and firmware updates.
    @{ Pattern = '*Lenovo*';                            Tier = 'Protected'; Note = 'OEM utility - owns battery/fan/hotkeys' },
    @{ Pattern = '*ThinkPad*';                          Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*Dell*';                              Tier = 'Protected'; Note = 'OEM utility - owns power/thermal' },
    @{ Pattern = '*Alienware*';                         Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*HPInc*';                             Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = 'AD2F1837.*';                          Tier = 'Protected'; Note = 'HP publisher prefix' },
    @{ Pattern = '*ASUS*';                              Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*Acer*';                              Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*MSI*';                               Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*Samsung*';                           Tier = 'Protected'; Note = 'OEM utility' },
    @{ Pattern = '*Realtek*';                           Tier = 'Protected'; Note = 'Audio/NIC control' },
    @{ Pattern = '*Intel*';                             Tier = 'Protected'; Note = 'Driver control panel' },
    @{ Pattern = '*NVIDIA*';                            Tier = 'Protected'; Note = 'Driver control panel' },
    @{ Pattern = '*AMD*';                               Tier = 'Protected'; Note = 'Driver control panel' },
    @{ Pattern = '*Synaptics*';                         Tier = 'Protected'; Note = 'Touchpad' },
    @{ Pattern = '*Elan*';                              Tier = 'Protected'; Note = 'Touchpad' },
    @{ Pattern = '*Dolby*';                             Tier = 'Protected'; Note = 'Audio stack' },
    @{ Pattern = '*Waves*';                             Tier = 'Protected'; Note = 'Audio stack' },
    @{ Pattern = '*Nahimic*';                           Tier = 'Protected'; Note = 'Audio stack' },

    # Security products. Never touched: the customer may be paying for it,
    # and half-removing AV is worse than leaving it.
    @{ Pattern = '*McAfee*';                            Tier = 'Protected'; Note = 'AV - may be a paid subscription' },
    @{ Pattern = '*Norton*';                            Tier = 'Protected'; Note = 'AV - may be a paid subscription' },
    @{ Pattern = '*Webroot*';                           Tier = 'Protected'; Note = 'AV - may be a paid subscription' },
    @{ Pattern = '*Kaspersky*';                         Tier = 'Protected'; Note = 'AV - may be a paid subscription' },
    @{ Pattern = '*Bitdefender*';                       Tier = 'Protected'; Note = 'AV - may be a paid subscription' },
    @{ Pattern = '*ESET*';                              Tier = 'Protected'; Note = 'AV - may be a paid subscription' },
    @{ Pattern = '*Avast*';                             Tier = 'Protected'; Note = 'AV - may be a paid subscription' },
    @{ Pattern = '*AVG*';                               Tier = 'Protected'; Note = 'AV - may be a paid subscription' },
    @{ Pattern = '*Malwarebytes*';                      Tier = 'Protected'; Note = 'AV - may be a paid subscription' }
)

function Get-BloatTier {
    param([string]$Name)

    # Protected wins over everything, then Optional, then Consumer. Order the
    # checks by severity rather than by catalog position, so a future entry
    # added in the wrong place cannot downgrade something protected.
    foreach ($tier in @('Protected', 'Optional', 'Consumer')) {
        foreach ($entry in $script:BloatCatalog) {
            if ($entry.Tier -ne $tier) { continue }
            if ($Name -like $entry.Pattern) {
                return [pscustomobject]@{ Tier = $tier; Note = $entry.Note }
            }
        }
    }
    return [pscustomobject]@{ Tier = 'Unclassified'; Note = 'Not in catalog - never auto-removed' }
}

# Classify an actual package rather than just a name.
#
# Windows already knows which packages are OS components: they are System
# signed and flagged NonRemovable. Trusting that beats pattern-matching forty
# more names like Microsoft.BioEnrollment and Microsoft.CredDialogHost, and it
# keeps working on builds that ship components this catalog has never seen.
#
# Windows wins over the catalog, always. If the OS says a package is a system
# component, it is not removable regardless of what the catalog thinks - and
# that is the fail-safe direction.
function Get-BloatClassificationForPackage {
    param($Package)

    $byName = Get-BloatTier -Name $Package.Name

    if ($Package.SignatureKind -eq 'System' -or $Package.NonRemovable -eq $true) {
        return [pscustomobject]@{
            Tier = 'SystemComponent'
            Note = 'Windows system component (System-signed) - not removable'
        }
    }

    return $byName
}

function Invoke-BloatwareModule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$Apply,
        [hashtable]$Options = @{}
    )

    $includeOptional = [bool]$Options['IncludeOptional']
    $alsoProvisioned = [bool]$Options['Provisioned']

    Write-Banner 'Bloatware inventory'

    $result = [ordered]@{
        Mode           = $(if ($Apply) { 'Apply' } else { 'InventoryOnly' })
        IncludeOptional = $includeOptional
        Counts         = @{}
        Apps           = @()
        Removed        = @()
        Failed         = @()
        Win32Suspects  = @()
    }

    # --- Appx inventory --------------------------------------------------
    $packages = @()
    try {
        if (Test-IsAdmin) { $packages = @(Get-AppxPackage -AllUsers -ErrorAction Stop) }
        else { $packages = @(Get-AppxPackage -ErrorAction Stop) }
    }
    catch {
        Write-Log -Message ("Could not enumerate Appx packages: " + $_.Exception.Message) -Level FAIL
        return [pscustomobject]$result
    }

    $byTier = @{ Consumer = @(); Optional = @(); Protected = @(); SystemComponent = @(); Unclassified = @() }

    foreach ($p in $packages) {
        if ($p.IsFramework) { continue }
        $class = Get-BloatClassificationForPackage -Package $p
        $entry = [ordered]@{
            Name         = $p.Name
            Tier         = $class.Tier
            Note         = $class.Note
            NonRemovable = [bool]$p.NonRemovable
        }
        $result.Apps += $entry
        $byTier[$class.Tier] += $p
    }

    foreach ($t in @('Consumer', 'Optional', 'Protected', 'SystemComponent', 'Unclassified')) {
        $result.Counts[$t] = @($byTier[$t]).Count
    }

    Write-Host ''
    Write-Host ('  Consumer junk (safe to remove) : {0}' -f $result.Counts['Consumer']) -ForegroundColor Yellow
    Write-Host ('  Optional (your call)           : {0}' -f $result.Counts['Optional']) -ForegroundColor Gray
    Write-Host ('  Protected (never auto-removed) : {0}' -f $result.Counts['Protected']) -ForegroundColor Green
    Write-Host ('  Windows system components      : {0}' -f $result.Counts['SystemComponent']) -ForegroundColor DarkGray
    Write-Host ('  Unclassified (left alone)      : {0}' -f $result.Counts['Unclassified']) -ForegroundColor DarkGray
    Write-Host ''

    foreach ($p in $byTier['Consumer']) {
        Write-Host ('    REMOVE   ' + $p.Name) -ForegroundColor Yellow
    }
    foreach ($p in $byTier['Optional']) {
        $note = (Get-BloatTier -Name $p.Name).Note
        Write-Host ('    OPTIONAL ' + $p.Name + '  - ' + $note) -ForegroundColor DarkYellow
    }

    # --- Win32 suspects: reported, never uninstalled ---------------------
    # Silent uninstall strings for consumer trialware are wildly inconsistent
    # and several hang forever without a console. Print them and let the tech
    # drive - this is the "print the commands" rule, same as partitioning.
    $win32Patterns = @('*McAfee*', '*Norton*', '*WildTangent*', '*Booking.com*', '*ExpressVPN*',
        '*Dropbox Promotion*', '*Amazon*Assistant*', '*Web Companion*', '*Driver Booster*',
        '*PC Accelerate*', '*Advanced SystemCare*', '*MyPC*', '*Reimage*', '*PC Optimizer*')

    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($root in $uninstallRoots) {
        try {
            foreach ($k in (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
                if (-not $k.DisplayName) { continue }
                foreach ($pat in $win32Patterns) {
                    if ($k.DisplayName -like $pat) {
                        $result.Win32Suspects += [ordered]@{
                            DisplayName     = $k.DisplayName
                            Publisher       = $k.Publisher
                            UninstallString = $k.UninstallString
                        }
                        break
                    }
                }
            }
        }
        catch { }
    }

    if ($result.Win32Suspects.Count -gt 0) {
        Write-Host ''
        Write-Host '  Desktop-app suspects - NOT uninstalled, run these yourself:' -ForegroundColor Yellow
        foreach ($s in $result.Win32Suspects) {
            Write-Host ('    ' + $s.DisplayName) -ForegroundColor Gray
            Write-Host ('        ' + $s.UninstallString) -ForegroundColor DarkGray
        }
    }

    # --- Removal ---------------------------------------------------------
    if (-not $Apply) {
        Write-Host ''
        Write-Host '  Inventory only. Nothing was removed. Add -Apply to remove the Consumer tier.' -ForegroundColor Cyan
        Write-Host ''
        return [pscustomobject]$result
    }

    $targets = @($byTier['Consumer'])
    if ($includeOptional) {
        Write-Log -Message 'IncludeOptional set - the Optional tier is in scope for removal' -Level WARN
        $targets += @($byTier['Optional'])
    }

    Write-Banner ('Removing {0} package(s)' -f @($targets).Count)

    foreach ($p in $targets) {
        # Belt and braces: re-check the tier at the point of removal rather
        # than trusting the list we built earlier.
        $recheck = Get-BloatClassificationForPackage -Package $p
        if (@('Consumer', 'Optional') -notcontains $recheck.Tier) {
            Write-Log -Message ("Refusing to remove {0} - tier {1}" -f $p.Name, $recheck.Tier) -Level WARN
            continue
        }
        if ($recheck.Tier -eq 'Optional' -and -not $includeOptional) {
            Write-Log -Message ("Refusing to remove {0} - Optional tier without -IncludeOptional" -f $p.Name) -Level WARN
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($p.Name, 'Remove-AppxPackage')) { continue }

        try {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction Stop
            $result.Removed += $p.Name
            Write-Log -Message ('Removed ' + $p.Name) -Level OK
        }
        catch {
            $result.Failed += [ordered]@{ Name = $p.Name; Error = $_.Exception.Message }
            Write-Log -Message ('Could not remove {0}: {1}' -f $p.Name, $_.Exception.Message) -Level WARN
        }
    }

    # --- Provisioned copies ----------------------------------------------
    # Without this, every new user profile gets the junk back.
    if ($alsoProvisioned -and (Test-IsAdmin)) {
        Write-Log -Message 'Removing provisioned copies so new profiles do not get them back' -Level STEP
        try {
            foreach ($prov in (Get-AppxProvisionedPackage -Online -ErrorAction Stop)) {
                $class = Get-BloatTier -Name $prov.DisplayName
                $inScope = ($class.Tier -eq 'Consumer') -or ($includeOptional -and $class.Tier -eq 'Optional')
                if (-not $inScope) { continue }

                if ($PSCmdlet.ShouldProcess($prov.DisplayName, 'Remove-AppxProvisionedPackage')) {
                    try {
                        Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
                        Write-Log -Message ('Deprovisioned ' + $prov.DisplayName) -Level OK
                    }
                    catch {
                        Write-Log -Message ('Could not deprovision {0}: {1}' -f $prov.DisplayName, $_.Exception.Message) -Level WARN
                    }
                }
            }
        }
        catch {
            Write-Log -Message ('Provisioned package enumeration failed: ' + $_.Exception.Message) -Level WARN
        }
    }

    Write-Log -Message ('Removed {0}, failed {1}' -f @($result.Removed).Count, @($result.Failed).Count) -Level OK
    Write-Host ''
    Write-Host '  Anything removed here can be reinstalled from the Store by the customer.' -ForegroundColor DarkGray
    Write-Host ''

    return [pscustomobject]$result
}
