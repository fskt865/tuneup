# Modules.ps1 - discovery and dispatch for drop-in capability modules.
# ASCII only, PowerShell 5.1 compatible.
#
# A module is a single .ps1 in modules\ carrying a MANIFEST block. Drop the
# file on the stick and it appears in the menu; nothing else needs editing.
#
# Discovery reads the manifest with a regex and does NOT execute the file.
# That matters for two reasons: listing the menu must not run arbitrary code,
# and every module is free to declare functions with whatever names it likes
# without colliding with its neighbours. Only the module actually selected
# gets dot-sourced, and only into the calling function's scope.
#
# Manifest block, at the top of the module file:
#
#   <#MANIFEST
#   {
#     "Key": "bloatware",
#     "Title": "Bloatware inventory and removal",
#     "Entry": "Invoke-BloatwareModule",
#     "Order": 10,
#     "RequiresAdmin": true,
#     "Description": "one line for the menu"
#   }
#   MANIFEST#>
#
# Contract for every module, non-negotiable:
#   - It is READ-ONLY unless -Apply is passed. Inventory is the default.
#   - It honours $WhatIfPreference for anything it would change.
#   - It returns an object; the caller folds that into the sanitized report.

function Get-TuneUpModules {
    param([Parameter(Mandatory = $true)][string]$ModuleRoot)

    $found = @()
    if (-not (Test-Path -LiteralPath $ModuleRoot)) { return $found }

    foreach ($file in (Get-ChildItem -LiteralPath $ModuleRoot -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $text) { continue }

        if ($text -notmatch '(?s)<\#MANIFEST(.*?)MANIFEST\#>') {
            Write-Log -Message ("Module '{0}' has no MANIFEST block - skipped" -f $file.Name) -Level WARN -Quiet
            continue
        }

        try {
            $manifest = $Matches[1] | ConvertFrom-Json
        }
        catch {
            Write-Log -Message ("Module '{0}' has an unreadable MANIFEST: {1}" -f $file.Name, $_.Exception.Message) -Level WARN
            continue
        }

        foreach ($required in @('Key', 'Title', 'Entry')) {
            if (-not $manifest.$required) {
                Write-Log -Message ("Module '{0}' MANIFEST is missing '{1}' - skipped" -f $file.Name, $required) -Level WARN
                $manifest = $null
                break
            }
        }
        if (-not $manifest) { continue }

        $manifest | Add-Member -NotePropertyName 'Path' -NotePropertyValue $file.FullName -Force
        if (-not $manifest.Order) { $manifest | Add-Member -NotePropertyName 'Order' -NotePropertyValue 99 -Force }
        $found += $manifest
    }

    return @($found | Sort-Object Order, Key)
}

function Invoke-TuneUpModuleByInfo {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$ModuleInfo,
        [switch]$Apply,
        [hashtable]$Options = @{}
    )

    if ($ModuleInfo.RequiresAdmin -and -not (Test-IsAdmin)) {
        # Inventory of most things still works unelevated and is worth having,
        # so warn rather than refuse. The module marks what it could not read.
        Write-Log -Message ("Module '{0}' wants elevation - results will be partial. Re-launch with RUN.cmd for the full picture." -f $ModuleInfo.Key) -Level WARN
    }

    if ($Apply -and -not (Test-IsAdmin) -and -not $WhatIfPreference) {
        throw ("Module '{0}' cannot apply changes without elevation. Re-launch with RUN.cmd." -f $ModuleInfo.Key)
    }

    Write-Log -Message ("Loading module '{0}' from {1}" -f $ModuleInfo.Key, (Split-Path -Leaf $ModuleInfo.Path)) -Quiet

    # Dot-source into THIS function's scope, so module functions vanish when
    # the call returns and two modules can never stomp on each other.
    . $ModuleInfo.Path

    $entry = Get-Command -Name $ModuleInfo.Entry -CommandType Function -ErrorAction SilentlyContinue
    if (-not $entry) {
        throw ("Module '{0}' declares entry point '{1}' but the file does not define it." -f $ModuleInfo.Key, $ModuleInfo.Entry)
    }

    return & $ModuleInfo.Entry -Apply:$Apply -Options $Options
}

function Show-ModuleList {
    param([Parameter(Mandatory = $true)]$Modules)

    if (@($Modules).Count -eq 0) {
        Write-Host '   (no modules installed)' -ForegroundColor DarkGray
        return
    }
    foreach ($m in $Modules) {
        Write-Host ('   {0,-10} {1}' -f $m.Key, $m.Title) -ForegroundColor Gray
        if ($m.Description) {
            Write-Host ('              {0}' -f $m.Description) -ForegroundColor DarkGray
        }
    }
}
