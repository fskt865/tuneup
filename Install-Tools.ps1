# Install-Tools.ps1 - provision the open-source diagnostic tools.
# ASCII only, PowerShell 5.1 compatible.
#
# RUN THIS ON YOUR OWN BENCH MACHINE, NOT ON A CUSTOMER'S.
#
# It installs software. Installing anything on a machine you were handed to
# repair is a change you did not agree with the owner, and it is not needed:
# -CopyToStick puts the binaries on the stick afterwards so the toolkit can
# use them in the field without installing anything on the target.
#
# Read-only by default, like everything else here. -Install is the switch that
# changes the machine.
#
# Why these three:
#   smartmontools        SMART attribute detail. Windows' own counters return
#                        blank PowerOnHours and no attribute table, which is
#                        useless for predicting a drive failure.
#   LibreHardwareMonitor Temperatures AND fan RPM on the many laptops that
#                        expose no ACPI thermal zone. Without it the stress
#                        module cannot abort on heat or spot a dead fan.
#   CrystalDiskInfo      A readable SMART GUI to show a customer.
#
# MemTest86+ is not here because it is a bootable image, not an installable
# program - see the note the script prints.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Install,
    [switch]$CopyToStick
)

$ErrorActionPreference = 'Continue'
$Root = $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.Path }
$ToolRoot = Join-Path $Root 'tools'

# Licences as commonly published at the time of writing. Verify before relying
# on them commercially - terms change, and "free" often means free for
# personal use only, which is not the same thing on a paid bench.
$Packages = @(
    @{
        Name = 'smartmontools'; Id = 'smartmontools.smartmontools'
        Licence = 'GPL v2'; Exe = 'smartctl.exe'
        CopyFrom = @('smartmontools\bin')
        Why = 'SMART attributes - reallocated and pending sectors, media errors'
    },
    @{
        Name = 'LibreHardwareMonitor'; Id = 'LibreHardwareMonitor.LibreHardwareMonitor'
        Licence = 'MPL 2.0'; Exe = 'LibreHardwareMonitor.exe'
        CopyFrom = @('LibreHardwareMonitor')
        Why = 'Temperatures and fan RPM where ACPI exposes nothing'
    },
    @{
        Name = 'CrystalDiskInfo'; Id = 'CrystalDewWorld.CrystalDiskInfo'
        Licence = 'MIT'; Exe = 'DiskInfo64.exe'
        CopyFrom = @('CrystalDiskInfo')
        Why = 'Readable SMART GUI for showing a customer'
    }
)

# Defined before first use - a script runs top to bottom, so a helper called
# from the inventory branch has to exist by then.
function Show-MemTestNote {
    Write-Host '  MEMORY - not installable, and not optional' -ForegroundColor Cyan
    Write-Host '    Nothing running inside Windows can test RAM the OS is already using,' -ForegroundColor DarkGray
    Write-Host '    so the stress module does not pretend to. MemTest86+ (GPL v2) boots the' -ForegroundColor DarkGray
    Write-Host '    machine into its own environment and is the real test.' -ForegroundColor DarkGray
    Write-Host '      memtest.org  - free, open source, bootable image' -ForegroundColor DarkGray
    Write-Host '    Put the image on a Ventoy partition on this stick and boot it. Give it' -ForegroundColor DarkGray
    Write-Host '    several passes; a single pass misses intermittent faults.' -ForegroundColor DarkGray
    Write-Host '    Windows has mdsched.exe built in - weaker, but it needs no media.' -ForegroundColor DarkGray
    Write-Host ''
}

function Find-InstalledExe {
    param([string]$ExeName)

    if (Test-Path -LiteralPath $ToolRoot) {
        $hit = Get-ChildItem -LiteralPath $ToolRoot -Recurse -File -Filter $ExeName -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return @{ Path = $hit.FullName; Where = 'stick' } }
    }
    $cmd = Get-Command $ExeName -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return @{ Path = $cmd.Source; Where = 'PATH' } }

    # Program Files, then winget's portable-package location. winget installs
    # some packages (LibreHardwareMonitor among them) under LOCALAPPDATA, so
    # searching only Program Files reports "MISSING" straight after winget has
    # said "Successfully installed".
    $bases = @(${env:ProgramFiles}, ${env:ProgramFiles(x86)}, (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'))
    foreach ($base in $bases) {
        if (-not $base -or -not (Test-Path -LiteralPath $base)) { continue }
        $hit = Get-ChildItem -LiteralPath $base -Recurse -File -Filter $ExeName -Depth 4 -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return @{ Path = $hit.FullName; Where = 'installed' } }
    }
    return $null
}

Write-Host ''
Write-Host '  DIAGNOSTIC TOOL PROVISIONING' -ForegroundColor White
Write-Host '  ----------------------------' -ForegroundColor DarkGray
Write-Host '  Run this on YOUR bench machine. Do not install software on a' -ForegroundColor Yellow
Write-Host '  customer machine - use -CopyToStick and carry the binaries instead.' -ForegroundColor Yellow
Write-Host ''

$wingetOk = [bool](Get-Command winget -ErrorAction SilentlyContinue)
Write-Host ('  winget available : ' + $wingetOk) -ForegroundColor $(if ($wingetOk) { 'Green' } else { 'Red' })
Write-Host ('  tools\ folder    : ' + $ToolRoot) -ForegroundColor Gray
Write-Host ''

$state = @()
foreach ($p in $Packages) {
    $found = Find-InstalledExe -ExeName $p.Exe
    $state += [pscustomobject]@{ Package = $p; Found = $found }

    $status = 'MISSING'
    $color = 'Yellow'
    if ($found) { $status = 'found (' + $found.Where + ')'; $color = 'Green' }

    Write-Host ('  {0,-22} {1,-18} {2}' -f $p.Name, $status, $p.Licence) -ForegroundColor $color
    Write-Host ('    {0}' -f $p.Why) -ForegroundColor DarkGray
}

$missing = @($state | Where-Object { -not $_.Found })

# --- Inventory only -----------------------------------------------------
if (-not $Install -and -not $CopyToStick) {
    Write-Host ''
    if ($missing.Count -eq 0) {
        Write-Host '  All three present. The stress module will use them automatically.' -ForegroundColor Green
    }
    else {
        Write-Host ('  {0} missing. To install them on THIS machine:' -f $missing.Count) -ForegroundColor Cyan
        Write-Host '    .\Install-Tools.ps1 -Install' -ForegroundColor Gray
        Write-Host '  Then copy the binaries onto the stick so the field toolkit is' -ForegroundColor Cyan
        Write-Host '  self-contained and installs nothing on a customer machine:' -ForegroundColor Cyan
        Write-Host '    .\Install-Tools.ps1 -CopyToStick' -ForegroundColor Gray
    }
    Write-Host ''
    Show-MemTestNote
    return
}

# --- Install ------------------------------------------------------------
if ($Install) {
    if (-not $wingetOk) {
        Write-Host '  winget is not available - install the three by hand.' -ForegroundColor Red
        return
    }

    Write-Host ''
    Write-Host '  Installing via winget...' -ForegroundColor Cyan
    foreach ($s in $missing) {
        $p = $s.Package
        if (-not $PSCmdlet.ShouldProcess($p.Name, 'winget install')) { continue }

        Write-Host ('    {0} ({1})' -f $p.Name, $p.Id) -ForegroundColor Gray
        & winget install --id $p.Id --exact --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -eq 0) { Write-Host ('      installed') -ForegroundColor Green }
        else { Write-Host ("      winget exit $LASTEXITCODE - install by hand if this persists") -ForegroundColor Yellow }
    }
}

# --- Copy to the stick --------------------------------------------------
if ($CopyToStick) {
    Write-Host ''
    Write-Host '  Copying binaries into tools\ ...' -ForegroundColor Cyan

    if (-not (Test-Path -LiteralPath $ToolRoot)) {
        New-Item -ItemType Directory -Path $ToolRoot -Force | Out-Null
    }

    foreach ($p in $Packages) {
        # Derive the source folder from where the exe actually is, rather than
        # guessing a path under Program Files. Different packages install to
        # different places - Program Files, or winget's portable location -
        # and a hardcoded relative path silently copies nothing.
        $found = Find-InstalledExe -ExeName $p.Exe
        if (-not $found -or $found.Where -eq 'stick') {
            if ($found -and $found.Where -eq 'stick') { Write-Host ('    {0}: already on the stick' -f $p.Name) -ForegroundColor Green }
            else { Write-Host ('    {0}: not installed, nothing to copy' -f $p.Name) -ForegroundColor Yellow }
            continue
        }

        $src = Split-Path -Parent $found.Path
        $dst = Join-Path $ToolRoot $p.Name
        if ($PSCmdlet.ShouldProcess($dst, ('Copy ' + $p.Name))) {
            if (-not (Test-Path -LiteralPath $dst)) { New-Item -ItemType Directory -Path $dst -Force | Out-Null }
            # Copy contents, not the folder: Copy-Item -Recurse onto an
            # existing destination nests it one level deeper instead.
            Copy-Item -Path (Join-Path $src '*') -Destination $dst -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host ('    {0} -> tools\{1}' -f $src, $p.Name) -ForegroundColor Gray
        }
    }

    # Verify rather than assume.
    Write-Host ''
    foreach ($p in $Packages) {
        $hit = Get-ChildItem -LiteralPath $ToolRoot -Recurse -File -Filter $p.Exe -ErrorAction SilentlyContinue |
            Select-Object -First 1
        Write-Host ('    {0,-22} on stick: {1}' -f $p.Name, [bool]$hit) -ForegroundColor $(if ($hit) { 'Green' } else { 'Yellow' })
    }
    Write-Host ''
    Write-Host '  Remember: LibreHardwareMonitor must be RUNNING for the stress module' -ForegroundColor Yellow
    Write-Host '  to read temperatures and fan RPM. Installed but closed is no use.' -ForegroundColor Yellow
    Write-Host '  It also needs elevation to reach most sensors.' -ForegroundColor Yellow
}

Write-Host ''
Show-MemTestNote
