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
# Why these four:
#   smartmontools        SMART attribute detail. Windows' own counters return
#                        blank PowerOnHours and no attribute table, which is
#                        useless for predicting a drive failure.
#   LibreHardwareMonitor Temperatures AND fan RPM on the many laptops that
#                        expose no ACPI thermal zone. Without it the stress
#                        module cannot abort on heat or spot a dead fan.
#   CrystalDiskInfo      A readable SMART GUI to show a customer.
#   Everything           Instant filename search over the whole volume, read
#                        straight from the MFT. Finding where a customer's
#                        data actually lives is most of a Level 1 job, and
#                        Windows Search is indexed, partial and slow.
#   Prime95              The hardest CPU and thermal load that exists. The
#                        evidence module generates no load on purpose; this is
#                        one of the tools it is built to wrap and record.
#
# Prime95 is the SECOND exception to the open-source rule, and for a weaker
# reason than Everything's: it is simply the standard. Mersenne Research
# publishes it as freeware, not open source, and GIMPS attaches its own terms.
# Verify them before relying on it commercially - the header note above about
# "free" not meaning the same thing on a paid bench applies to this one most
# of all. OCCT and Cinebench already on the stick are in the same category.
#
# What it is FOR is narrow and worth stating, because the wrong test proves
# nothing: Small FFTs is maximum heat in minimum memory and is the cooling
# test; Blend exercises RAM and the memory controller; Large FFTs sits between
# them. Match the test to the complaint.
#
# What it is NOT is a pass/fail oracle. Prime95's AVX torture generates more
# heat than any real workload a customer will ever produce, so a machine that
# throttles or trips a thermal limit under it is not thereby faulty. Judge the
# result against what the customer actually reported, not against the tool.
#
# Everything is the odd one out and it is worth being explicit about why: it
# is FREEWARE, NOT OPEN SOURCE. voidtools publishes no source and the terms
# are whatever the EULA in the download says. The other three were picked
# specifically to avoid that. It earns the exception because nothing open
# source searches a volume this fast, and it is used on the ticket that
# matters most here - find the data before touching anything.
#
# It also creates a hazard none of the others do. Everything builds an index
# of every filename on the machine, and in portable mode it writes that index
# next to its own exe - i.e. onto the stick. A complete file listing of a
# customer's disk leaving on the stick is exactly the thing this toolkit
# exists to prevent. So -CopyToStick writes a config beside the exe and a
# SEARCH.cmd launcher that passes -nodb; see Write-EverythingConfig below.
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
    },
    @{
        Name = 'Everything'; Id = 'voidtools.Everything'
        Licence = 'Freeware (closed)'; Exe = 'Everything.exe'
        CopyFrom = @('Everything')
        Why = 'Instant filename search from the MFT - find the data before touching anything'
    },
    @{
        Name = 'Prime95'; Id = 'mersenne.prime95'
        Licence = 'Freeware (closed)'; Exe = 'prime95.exe'
        CopyFrom = @('Prime95')
        Why = 'Hardest CPU and thermal load available - the external load the evidence module records'
    }
)

# Defined before first use - a script runs top to bottom, so a helper called
# from the inventory branch has to exist by then.
function Show-MemTestNote {
    Write-Host '  MEMORY - not installable, and not optional' -ForegroundColor Cyan
    Write-Host '    Nothing running inside Windows can test RAM the OS is already using,' -ForegroundColor DarkGray
    Write-Host '    so the evidence module does not pretend to. MemTest86+ (GPL v2) boots the' -ForegroundColor DarkGray
    Write-Host '    machine into its own environment and is the real test.' -ForegroundColor DarkGray
    Write-Host '      memtest.org  - free, open source, bootable image' -ForegroundColor DarkGray
    Write-Host '    Put the image on a Ventoy partition on this stick and boot it. Give it' -ForegroundColor DarkGray
    Write-Host '    several passes; a single pass misses intermittent faults.' -ForegroundColor DarkGray
    Write-Host '    Windows has mdsched.exe built in - weaker, but it needs no media.' -ForegroundColor DarkGray
    Write-Host ''
}

# Printed wherever the tool list is, because the interlock matters more than
# the tool does. Same rule as the disk one: a torture test is the last thing
# you run on a machine whose data is not safe yet, not the first.
function Show-Prime95Note {
    Write-Host '  CPU LOAD - Prime95, and when NOT to start it' -ForegroundColor Cyan
    Write-Host '    Get the data off FIRST. Prime95 is the hardest load the machine will' -ForegroundColor DarkGray
    Write-Host '    ever see; if it is going to fall over, it falls over during the test.' -ForegroundColor DarkGray
    Write-Host '    That is fine on a machine that is backed up and unacceptable on one' -ForegroundColor DarkGray
    Write-Host '    that is not. Same interlock as stressing a failing disk.' -ForegroundColor DarkGray
    Write-Host '    Pick the test to match the complaint:' -ForegroundColor DarkGray
    Write-Host '      Small FFTs  max heat, min memory - cooling, paste, fans, throttling' -ForegroundColor DarkGray
    Write-Host '      Blend       RAM and memory controller as well as the CPU' -ForegroundColor DarkGray
    Write-Host '      Large FFTs  between the two' -ForegroundColor DarkGray
    Write-Host '    It is NOT a pass/fail oracle. AVX torture makes more heat than any real' -ForegroundColor DarkGray
    Write-Host '    workload, so throttling under it does not make a machine faulty.' -ForegroundColor DarkGray
    Write-Host '    Wrap it, do not just watch it - the evidence module makes it evidence:' -ForegroundColor DarkGray
    Write-Host '      -Module evidence -Phase Baseline    then start Prime95, then' -ForegroundColor DarkGray
    Write-Host '      -Module evidence -Phase Watch       then stop it, then' -ForegroundColor DarkGray
    Write-Host '      -Module evidence -Phase Compare' -ForegroundColor DarkGray
    Write-Host '    Needs LibreHardwareMonitor running for temperatures, and it writes' -ForegroundColor DarkGray
    Write-Host '    results.txt and prime.txt beside its own exe - on the stick, if you' -ForegroundColor DarkGray
    Write-Host '    launch it from there.' -ForegroundColor DarkGray
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

# Everything indexes every filename on the machine it runs on. Left to its
# own defaults in portable mode it writes that index to Everything.db beside
# the exe - on the stick. That is a complete file listing of a customer's
# disk leaving the premises, so it gets three layers rather than one:
#
#   1. SEARCH.cmd passes -nodb. The index is built in RAM from the MFT and
#      dies with the process. Nothing is written anywhere. This is the path
#      you are meant to use, and it costs a few seconds of re-indexing.
#   2. Everything.ini points db_location at C:\ProgramData\GSTuneUp, so even
#      a bare double-click of the exe puts the index on the customer's own
#      machine rather than on the stick - and menu option 7 (Purge) deletes
#      that directory with everything else the toolkit leaves behind.
#   3. Deploy-ToUsb.ps1 checks the stick for an index file and shouts if one
#      is there. Layer 2 is a fallback path and fallbacks go wrong quietly.
#
# The ini is written read-only so Everything cannot save state back into it.
# It saves the current search text on exit, and a search box on a real job
# has a customer's name or filename in it.
#
# Search and run history are off, update checks are off (no outbound traffic
# from a customer's machine), and both built-in servers are off.
function Write-EverythingConfig {
    param([string]$Folder)

    $ini = Join-Path $Folder 'Everything.ini'
    $cmd = Join-Path $Folder 'SEARCH.cmd'

    $iniText = @'
[Everything]
app_data=0
db_location=C:\ProgramData\GSTuneUp\Everything.db
search_history_enabled=0
run_history_enabled=0
check_for_updates_on_startup=0
http_server_enabled=0
etp_server_enabled=0
debug_log=0
'@

    # Clear read-only from the previous run before rewriting it.
    if (Test-Path -LiteralPath $ini) { Set-ItemProperty -LiteralPath $ini -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue }
    Set-Content -LiteralPath $ini -Value $iniText -Encoding ASCII -WhatIf:$false
    Set-ItemProperty -LiteralPath $ini -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue

    # No PowerShell one-liners inside if-blocks: a ) closes the block early in
    # cmd. Branch with goto and labels. No %* either - there is nothing to
    # forward, and Start-Process -ArgumentList '' is a binding error.
    $cmdText = @'
@echo off
setlocal
title Everything - portable, no index file

REM Launches Everything from the stick with -nodb: the index lives in RAM and
REM is gone when you close it. Nothing is written to the stick or to the
REM customer's machine. Launch it this way, not by the exe.

net session >nul 2>&1
if errorlevel 1 goto elevate
goto run

:elevate
echo.
echo   Everything needs administrator rights to read the NTFS index directly.
echo   Unelevated it offers to install the Everything service instead, which
echo   is a permanent change to a machine you were handed to repair.
echo.
echo   Requesting administrator rights...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:run
start "" "%~dp0Everything.exe" -nodb
exit /b
'@
    Set-Content -LiteralPath $cmd -Value $cmdText -Encoding ASCII -WhatIf:$false

    return @{ Ini = $ini; Cmd = $cmd }
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
        Write-Host ('  All {0} present. The evidence module uses the first three automatically;' -f $Packages.Count) -ForegroundColor Green
        Write-Host '  Everything is launched by hand from tools\Everything\SEARCH.cmd.' -ForegroundColor Green
    }
    else {
        Write-Host ('  {0} missing. To install them on THIS machine:' -f $missing.Count) -ForegroundColor Cyan
        Write-Host '    .\Install-Tools.ps1 -Install' -ForegroundColor Gray
        Write-Host '  Then copy the binaries onto the stick so the field toolkit is' -ForegroundColor Cyan
        Write-Host '  self-contained and installs nothing on a customer machine:' -ForegroundColor Cyan
        Write-Host '    .\Install-Tools.ps1 -CopyToStick' -ForegroundColor Gray
    }
    Write-Host ''
    Show-Prime95Note
    Show-MemTestNote
    return
}

# --- Install ------------------------------------------------------------
if ($Install) {
    if (-not $wingetOk) {
        Write-Host '  winget is not available - install them by hand.' -ForegroundColor Red
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

    # Everything gets its config written whether or not it was copied this
    # run - it may have been on the stick already, and the point of the ini
    # is that it is never absent.
    $everythingExe = Get-ChildItem -LiteralPath $ToolRoot -Recurse -File -Filter 'Everything.exe' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($everythingExe) {
        $folder = Split-Path -Parent $everythingExe.FullName
        if ($PSCmdlet.ShouldProcess($folder, 'Write Everything.ini and SEARCH.cmd')) {
            $written = Write-EverythingConfig -Folder $folder
            Write-Host ''
            Write-Host ('    Everything: portable config written') -ForegroundColor Gray
            Write-Host ('      {0}  (read-only, so it cannot save a search term back)' -f (Split-Path -Leaf $written.Ini)) -ForegroundColor DarkGray
            Write-Host ('      {0}  (launch with this, not the exe - it passes -nodb)' -f (Split-Path -Leaf $written.Cmd)) -ForegroundColor DarkGray
        }
    }

    # Verify rather than assume.
    Write-Host ''
    foreach ($p in $Packages) {
        $hit = Get-ChildItem -LiteralPath $ToolRoot -Recurse -File -Filter $p.Exe -ErrorAction SilentlyContinue |
            Select-Object -First 1
        Write-Host ('    {0,-22} on stick: {1}' -f $p.Name, [bool]$hit) -ForegroundColor $(if ($hit) { 'Green' } else { 'Yellow' })
    }

    # A stale index from a previous job is the one failure that matters here,
    # so look for it now rather than trusting that the config held.
    $index = @(Get-ChildItem -LiteralPath $ToolRoot -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'Everything*.db' -or $_.Name -like '*History.csv' })
    if ($index.Count -gt 0) {
        Write-Host ''
        Write-Host '    CUSTOMER FILE LISTING PRESENT IN tools\ - DELETE IT:' -ForegroundColor Red
        foreach ($f in $index) { Write-Host ('      Remove-Item -LiteralPath "{0}" -Force' -f $f.FullName) -ForegroundColor Gray }
    }

    Write-Host ''
    Write-Host '  Remember: LibreHardwareMonitor must be RUNNING for the evidence module' -ForegroundColor Yellow
    Write-Host '  to read temperatures and fan RPM. Installed but closed is no use.' -ForegroundColor Yellow
    Write-Host '  It also needs elevation to reach most sensors.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  And: launch Everything from SEARCH.cmd. The exe on its own writes an' -ForegroundColor Yellow
    Write-Host '  index of the machine it is run on, and it is not yours to carry away.' -ForegroundColor Yellow
}

Write-Host ''
Show-Prime95Note
Show-MemTestNote
