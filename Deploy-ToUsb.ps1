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

Write-Host ''
Write-Host ('  Source:      ' + $Root) -ForegroundColor Gray
Write-Host ('  Destination: ' + $target) -ForegroundColor Gray
Write-Host ('  Volume:      {0} {1}, {2} GB free' -f $vol.DriveType, $vol.FileSystem, [math]::Round($vol.SizeRemaining / 1GB, 1)) -ForegroundColor Gray
Write-Host ''

# Toolkit only. Reports and git metadata never get pushed to a stick - the
# reports directory on the stick is an OUTPUT, populated in the field.
$items = @(
    @{ Src = 'RUN.cmd';           Dst = 'RUN.cmd' },
    @{ Src = 'Invoke-TuneUp.ps1'; Dst = 'Invoke-TuneUp.ps1' },
    @{ Src = 'README.md';         Dst = 'README.md' },
    @{ Src = 'lib';               Dst = 'lib' },
    @{ Src = 'tasks';             Dst = 'tasks' },
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

    if ($PSCmdlet.ShouldProcess($dst, 'Copy toolkit item')) {
        $parent = Split-Path -Parent $dst
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force
    }
}

$reportDir = Join-Path $target 'reports'
if ($PSCmdlet.ShouldProcess($reportDir, 'Create reports directory')) {
    if (-not (Test-Path -LiteralPath $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
}

# --- Verify -------------------------------------------------------------
if (-not $WhatIfPreference) {
    Write-Host ''
    $missing = @()
    foreach ($i in $items) {
        if (-not (Test-Path -LiteralPath (Join-Path $target $i.Dst))) { $missing += $i.Dst }
    }
    if ($missing.Count -eq 0) {
        Write-Host '  Deployed and verified. Launch on the target machine with RUN.cmd.' -ForegroundColor Green
    }
    else {
        Write-Host ('  INCOMPLETE - missing after copy: ' + ($missing -join ', ')) -ForegroundColor Red
    }
    Write-Host ''
}
