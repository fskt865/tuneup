# Test-Modules.ps1 - module discovery and bloatware classification.
# ASCII only, PowerShell 5.1 compatible. Changes nothing.
#
# The classification tests matter more than the discovery ones. A wrong tier
# on an OEM utility means uninstalling the thing that owns a laptop's fan
# curve or battery charge threshold.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'lib\Modules.ps1')

$pass = 0
$fail = 0

function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  PASS  " + $Name) -ForegroundColor Green; $script:pass++ }
    else { Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red; $script:fail++ }
}

Write-Host ''
Write-Host '  Module discovery' -ForegroundColor Cyan
Write-Host '  ----------------' -ForegroundColor DarkGray

$mods = Get-TuneUpModules -ModuleRoot (Join-Path $Root 'modules')
Assert-True 'Discovers at least two modules' (@($mods).Count -ge 2) ("count=" + @($mods).Count)

foreach ($key in @('bloatware', 'browser', 'startup', 'driver', 'evidence', 'network', 'crashes', 'clocks')) {
    $m = @($mods | Where-Object { $_.Key -eq $key })
    Assert-True ("Module '$key' is discovered") ($m.Count -eq 1)
}

foreach ($m in $mods) {
    Assert-True ("Module '$($m.Key)' declares an existing file") (Test-Path -LiteralPath $m.Path)
    $text = Get-Content -LiteralPath $m.Path -Raw
    Assert-True ("Module '$($m.Key)' defines its declared entry point") ($text -match ('function\s+' + [regex]::Escape($m.Entry)))
}

# Keys must be unique or the menu dispatches to whichever sorted first.
$keys = @($mods | ForEach-Object { $_.Key })
Assert-True 'Module keys are unique' (($keys | Sort-Object -Unique).Count -eq $keys.Count)

Write-Host ''
Write-Host '  Bloatware classification' -ForegroundColor Cyan
Write-Host '  ------------------------' -ForegroundColor DarkGray

# Load the catalog without running the module.
$bloatPath = @($mods | Where-Object { $_.Key -eq 'bloatware' })[0].Path
. $bloatPath

$cases = @(
    # Must never be removed - runtimes and store infrastructure
    @{ Name = 'Microsoft.VCLibs.140.00';            Expect = 'Protected' },
    @{ Name = 'Microsoft.NET.Native.Framework.2.2'; Expect = 'Protected' },
    @{ Name = 'Microsoft.UI.Xaml.2.8';              Expect = 'Protected' },
    @{ Name = 'Microsoft.WindowsStore';             Expect = 'Protected' },
    @{ Name = 'Microsoft.DesktopAppInstaller';      Expect = 'Protected' },
    @{ Name = 'Microsoft.SecHealthUI';              Expect = 'Protected' },

    # Must never be removed - OEM hardware utilities
    @{ Name = 'E046963F.LenovoCompanion';           Expect = 'Protected' },
    @{ Name = 'E046963F.LenovoSettingsforEnterprise'; Expect = 'Protected' },
    @{ Name = 'DellInc.DellPowerManager';           Expect = 'Protected' },
    @{ Name = 'AD2F1837.HPPowerManager';            Expect = 'Protected' },
    @{ Name = 'RealtekSemiconductorCorp.RealtekAudioControl'; Expect = 'Protected' },
    @{ Name = 'AdvancedMicroDevicesInc.AMDRadeonSoftware'; Expect = 'Protected' },
    @{ Name = 'SynapticsIncorporated.SynapticsControlPanel'; Expect = 'Protected' },

    # Must never be removed - security products the customer may pay for
    @{ Name = 'McAfeeWPSSecurity';                  Expect = 'Protected' },
    @{ Name = 'NortonSecurity';                     Expect = 'Protected' },

    # Safe to remove
    @{ Name = 'king.com.CandyCrushSaga';            Expect = 'Consumer' },
    @{ Name = 'Microsoft.BingNews';                 Expect = 'Consumer' },
    @{ Name = 'Microsoft.SkypeApp';                 Expect = 'Consumer' },
    @{ Name = 'Microsoft.MicrosoftOfficeHub';       Expect = 'Consumer' },
    @{ Name = 'Clipchamp.Clipchamp';                Expect = 'Consumer' },
    @{ Name = 'Microsoft.MixedReality.Portal';      Expect = 'Consumer' },

    # Judgment required
    @{ Name = 'Microsoft.ZuneMusic';                Expect = 'Optional' },
    @{ Name = 'Microsoft.ZuneVideo';                Expect = 'Optional' },
    @{ Name = 'Microsoft.MicrosoftStickyNotes';     Expect = 'Optional' },
    @{ Name = 'Microsoft.XboxGamingOverlay';        Expect = 'Optional' },
    @{ Name = 'microsoft.windowscommunicationsapps'; Expect = 'Optional' },

    # Unknown must never be auto-removed
    @{ Name = 'SomeVendor.SomethingNobodyHasSeen';  Expect = 'Unclassified' },
    @{ Name = 'ContosoLtd.LineOfBusinessApp';       Expect = 'Unclassified' }
)

foreach ($c in $cases) {
    $got = (Get-BloatTier -Name $c.Name).Tier
    Assert-True ("{0,-14} {1}" -f $c.Expect, $c.Name) ($got -eq $c.Expect) "got=$got"
}

# The safety-critical invariant: only Consumer and Optional are ever eligible.
$eligible = @('Consumer', 'Optional')
$protectedProbe = @('Microsoft.VCLibs.140.00', 'E046963F.LenovoCompanion', 'McAfeeWPSSecurity',
    'Microsoft.WindowsStore', 'SomeVendor.SomethingNobodyHasSeen')
$leak = @($protectedProbe | Where-Object { $eligible -contains (Get-BloatTier -Name $_).Tier })
Assert-True 'No protected or unknown package is removal-eligible' ($leak.Count -eq 0) ("leaked=" + ($leak -join ','))

Write-Host ''
Write-Host '  System-component override' -ForegroundColor Cyan
Write-Host '  -------------------------' -ForegroundColor DarkGray

# Windows must win over the catalog. A System-signed package is not removable
# even when the catalog would happily class it as consumer junk.
$fakeSystem = [pscustomobject]@{ Name = 'Microsoft.BingNews'; SignatureKind = 'System'; NonRemovable = $false }
Assert-True 'System-signed beats a Consumer catalog entry' `
((Get-BloatClassificationForPackage -Package $fakeSystem).Tier -eq 'SystemComponent')

$fakeNonRemovable = [pscustomobject]@{ Name = 'king.com.CandyCrushSaga'; SignatureKind = 'Store'; NonRemovable = $true }
Assert-True 'NonRemovable beats a Consumer catalog entry' `
((Get-BloatClassificationForPackage -Package $fakeNonRemovable).Tier -eq 'SystemComponent')

$fakeStore = [pscustomobject]@{ Name = 'Microsoft.BingNews'; SignatureKind = 'Store'; NonRemovable = $false }
Assert-True 'Ordinary Store package keeps its catalog tier' `
((Get-BloatClassificationForPackage -Package $fakeStore).Tier -eq 'Consumer')

# Real machine sweep: nothing System-signed may ever be removal-eligible.
$realLeak = @()
try {
    foreach ($p in (Get-AppxPackage -ErrorAction Stop | Where-Object { -not $_.IsFramework })) {
        $t = (Get-BloatClassificationForPackage -Package $p).Tier
        if ($eligible -contains $t -and ($p.SignatureKind -eq 'System' -or $p.NonRemovable)) {
            $realLeak += $p.Name
        }
    }
    Assert-True 'Live sweep: no System-signed package is removal-eligible' ($realLeak.Count -eq 0) ("leaked=" + ($realLeak -join ','))
}
catch {
    Write-Host '  SKIP  live sweep (Appx enumeration unavailable)' -ForegroundColor Yellow
}

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }

