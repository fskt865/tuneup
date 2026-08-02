# Deploy-ToUsb.ps1 - copy the toolkit from this repo onto a stick.
# ASCII only, PowerShell 5.1 compatible.
#
# Read-only by default: with no -Destination it lists candidate removable
# volumes and exits. It never formats, partitions or deletes a volume, and it
# refuses to write to a fixed disk without -Force.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Destination,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$Root = $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.Path }

# Get-Volume pulls in the Storage module, which announces its alias creation
# under -WhatIf and buries the actual copy plan. Reading volumes changes
# nothing, so it runs for real. Function-scoped preference; caller untouched.
function Get-VolumeQuiet {
    param([string]$Letter)
    $WhatIfPreference = $false
    if ($Letter) { return Get-Volume -DriveLetter $Letter -ErrorAction SilentlyContinue }
    return Get-Volume -ErrorAction SilentlyContinue
}

# --- Inventory mode: what you get when you forget an argument. ---------
if (-not $Destination) {
    Write-Host ''
    Write-Host '  Removable volumes:' -ForegroundColor Cyan
    Write-Host ''
    $found = $false
    Get-VolumeQuiet |
        Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } |
        ForEach-Object {
            $found = $true
            Write-Host ('    {0}:  {1,-8} {2,7} GB total, {3,7} GB free   label "{4}"' -f `
                    $_.DriveLetter, $_.FileSystem,
                [math]::Round($_.Size / 1GB, 1),
                [math]::Round($_.SizeRemaining / 1GB, 1),
                $_.FileSystemLabel)
        }
    if (-not $found) { Write-Host '    (none found)' -ForegroundColor Yellow }

    Write-Host ''
    Write-Host '  Deploy with:  .\Deploy-ToUsb.ps1 -Destination D:' -ForegroundColor Gray
    Write-Host '  Preview with: .\Deploy-ToUsb.ps1 -Destination D: -WhatIf' -ForegroundColor Gray
    Write-Host ''
    return
}

# --- Target validation -------------------------------------------------
$Destination = $Destination.TrimEnd('\')
if ($Destination -notmatch '^[A-Za-z]:$') {
    throw "Destination must be a drive letter like 'D:'. Got '$Destination'."
}

$letter = $Destination.Substring(0, 1)
$vol = Get-VolumeQuiet -Letter $letter
if (-not $vol) { throw "No volume at $Destination." }

if ($letter -eq $env:SystemDrive.TrimEnd(':')) {
    throw "Refusing to deploy to the live system drive ($Destination)."
}

if ($vol.DriveType -ne 'Removable' -and -not $Force) {
    throw "$Destination is $($vol.DriveType), not Removable. Re-run with -Force if that is genuinely what you want."
}

$target = Join-Path ($letter + ':\') 'tuneup'

# Version comparison, so an update in the field says what it is replacing
# rather than silently overwriting.
function Get-VersionAt {
    param([string]$Base)
    $f = Join-Path $Base 'VERSION'
    if (Test-Path -LiteralPath $f) { return (Get-Content -LiteralPath $f -Raw).Trim() }
    return $null
}
$newVersion = Get-VersionAt -Base $Root
$oldVersion = Get-VersionAt -Base $target

Write-Host ''
Write-Host ('  Source:      ' + $Root) -ForegroundColor Gray
Write-Host ('  Destination: ' + $target) -ForegroundColor Gray
Write-Host ('  Volume:      {0} {1}, {2} GB free' -f $vol.DriveType, $vol.FileSystem, [math]::Round($vol.SizeRemaining / 1GB, 1)) -ForegroundColor Gray
if ($oldVersion) {
    if ($oldVersion -eq $newVersion) {
        Write-Host ('  Version:     {0} -> {1}  (reinstall, same version)' -f $oldVersion, $newVersion) -ForegroundColor DarkGray
    }
    else {
        Write-Host ('  Version:     {0} -> {1}  (UPDATE)' -f $oldVersion, $newVersion) -ForegroundColor Cyan
    }
}
else {
    Write-Host ('  Version:     {0}  (fresh install)' -f $newVersion) -ForegroundColor Cyan
}

# Reports already on the stick are field output and are never touched by a
# deploy. Say so explicitly rather than leaving it to be inferred.
$existingReports = @()
if (Test-Path -LiteralPath (Join-Path $target 'reports')) {
    $existingReports = @(Get-ChildItem -LiteralPath (Join-Path $target 'reports') -File -ErrorAction SilentlyContinue)
}
if ($existingReports.Count -gt 0) {
    Write-Host ('  Reports:     {0} existing file(s) on the stick - left untouched' -f $existingReports.Count) -ForegroundColor DarkGray
}
Write-Host ''

# Toolkit only. Reports and git metadata never get pushed to a stick - the
# reports directory on the stick is an OUTPUT, populated in the field.
$items = @(
    @{ Src = 'RUN.cmd';           Dst = 'RUN.cmd' },
    @{ Src = 'Invoke-TuneUp.ps1'; Dst = 'Invoke-TuneUp.ps1' },
    @{ Src = 'README.md';         Dst = 'README.md' },
    @{ Src = 'VERSION';           Dst = 'VERSION' },
    @{ Src = 'lib';               Dst = 'lib' },
    @{ Src = 'tasks';             Dst = 'tasks' },
    # Drop-in capability modules. This is the update surface: a new .ps1 here
    # appears in the field menu with no other change to the toolkit.
    @{ Src = 'modules';           Dst = 'modules' },
    # Shipped deliberately: lets you verify redaction ON the customer's machine
    # before trusting a report off it, rather than taking the tool's word.
    @{ Src = 'tests';             Dst = 'tests' }
)

foreach ($i in $items) {
    $src = Join-Path $Root $i.Src
    if (-not (Test-Path -LiteralPath $src)) {
        Write-Host ("  MISSING  " + $i.Src) -ForegroundColor Red
        continue
    }
    $dst = Join-Path $target $i.Dst
    Write-Host ("  copy  {0,-22} -> {1}" -f $i.Src, $dst) -ForegroundColor DarkGray

    if (-not $PSCmdlet.ShouldProcess($dst, 'Copy toolkit item')) { continue }

    if ((Get-Item -LiteralPath $src).PSIsContainer) {
        # Copy the directory's CONTENTS, not the directory.
        #
        # Copy-Item -Recurse against an EXISTING destination directory copies
        # the source folder INSIDE it, producing lib\lib and tasks\tasks. That
        # is silent, and it only bites on the second deploy - which is exactly
        # the update case. The wildcard form merges instead.
        if (-not (Test-Path -LiteralPath $dst)) { New-Item -ItemType Directory -Path $dst -Force | Out-Null }
        Copy-Item -Path (Join-Path $src '*') -Destination $dst -Recurse -Force
    }
    else {
        $parent = Split-Path -Parent $dst
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Copy-Item -LiteralPath $src -Destination $dst -Force
    }
}

$reportDir = Join-Path $target 'reports'
if ($PSCmdlet.ShouldProcess($reportDir, 'Create reports directory')) {
    if (-not (Test-Path -LiteralPath $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
}

# --- Verify -------------------------------------------------------------
# Verify every expected FILE, not just that the directories exist.
#
# The weaker check passed happily while lib\ held stale files and the real
# ones sat in lib\lib. A verification that cannot fail is not a verification.
if (-not $WhatIfPreference) {
    Write-Host ''

    $expected = @()
    foreach ($i in $items) {
        $src = Join-Path $Root $i.Src
        if (-not (Test-Path -LiteralPath $src)) { continue }
        if ((Get-Item -LiteralPath $src).PSIsContainer) {
            foreach ($f in (Get-ChildItem -LiteralPath $src -Recurse -File)) {
                $rel = $f.FullName.Substring($src.Length).TrimStart('\')
                $expected += (Join-Path $i.Dst $rel)
            }
        }
        else { $expected += $i.Dst }
    }

    $missing = @($expected | Where-Object { -not (Test-Path -LiteralPath (Join-Path $target $_)) })

    # Stale files: on the stick, inside a toolkit directory, absent from the
    # source. Reported, never deleted - reports\ is field output and this
    # script does not get to decide what on a stick is disposable.
    $stale = @()
    foreach ($i in $items) {
        $srcDir = Join-Path $Root $i.Src
        $dstDir = Join-Path $target $i.Dst
        if (-not (Test-Path -LiteralPath $dstDir)) { continue }
        if (-not (Get-Item -LiteralPath $dstDir).PSIsContainer) { continue }
        if (-not (Test-Path -LiteralPath $srcDir)) { continue }

        foreach ($f in (Get-ChildItem -LiteralPath $dstDir -Recurse -File -ErrorAction SilentlyContinue)) {
            $rel = $f.FullName.Substring($dstDir.Length).TrimStart('\')
            if (-not (Test-Path -LiteralPath (Join-Path $srcDir $rel))) {
                $stale += (Join-Path $i.Dst $rel)
            }
        }
    }

    if ($missing.Count -eq 0) {
        Write-Host ('  Deployed and verified: {0} file(s) present.' -f $expected.Count) -ForegroundColor Green
        Write-Host '  Launch on the target machine with RUN.cmd.' -ForegroundColor Green
    }
    else {
        Write-Host ('  INCOMPLETE - {0} file(s) missing after copy:' -f $missing.Count) -ForegroundColor Red
        foreach ($m in $missing) { Write-Host ('    ' + $m) -ForegroundColor Red }
    }

    if ($stale.Count -gt 0) {
        Write-Host ''
        Write-Host ('  {0} stale file(s) on the stick, not in this version - delete by hand:' -f $stale.Count) -ForegroundColor Yellow
        foreach ($s in $stale) { Write-Host ('    ' + $s) -ForegroundColor Yellow }
    }
    Write-Host ''
}
