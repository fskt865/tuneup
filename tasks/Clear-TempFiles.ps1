# Clear-TempFiles.ps1 - reclaim space from caches that regenerate.
# ASCII only, PowerShell 5.1 compatible.
#
# Scope is deliberately narrow: only locations Windows rebuilds on its own.
# No Recycle Bin (that is the customer's data and emptying it is their call),
# no browser profiles, no Downloads, no "cleaner" heuristics.

function Clear-TuneUpTempFiles {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$IncludeComponentCleanup
    )

    Write-Banner 'Reclaim space from regenerable caches'
    Assert-Admin

    $before = Get-FreeSpacePercent
    $script:TotalReclaimedMB = 0
    $result = [ordered]@{
        FreePercentBefore = $before
        FreePercentAfter  = $null
        ReclaimedMB       = 0
        Targets           = @()
        ComponentCleanup  = $null
    }

    $targets = @(
        @{ Name = 'WindowsTemp'; Path = (Join-Path $env:SystemRoot 'Temp') },
        @{ Name = 'UserTemp';    Path = $env:TEMP },
        @{ Name = 'Prefetch';    Path = (Join-Path $env:SystemRoot 'Prefetch') },
        @{ Name = 'CbsLogs';     Path = (Join-Path $env:SystemRoot 'Logs\CBS') },
        @{ Name = 'WerReports';  Path = (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue') }
    )

    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t.Path)) { continue }

        $sizeMB = 0
        try {
            $sizeMB = [math]::Round(
                ((Get-ChildItem -LiteralPath $t.Path -Recurse -Force -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum / 1MB), 1)
        }
        catch { }

        Write-Log ("{0,-14} {1,10} MB" -f $t.Name, $sizeMB)

        $removed = 0
        $locked = 0
        $reclaimedBytes = 0

        if ($PSCmdlet.ShouldProcess($t.Path, "Delete cache contents ($sizeMB MB)")) {
            foreach ($item in (Get-ChildItem -LiteralPath $t.Path -Force -ErrorAction SilentlyContinue)) {
                # Measure before deleting. Volume free space is not a reliable
                # measure of what a clean achieved - Windows' counters lag, and
                # a run that genuinely reclaimed 1.3 GB reported 88.3% -> 88.3%
                # and read as having done nothing.
                $itemBytes = 0
                try {
                    if ($item.PSIsContainer) {
                        $itemBytes = (Get-ChildItem -LiteralPath $item.FullName -Recurse -Force -File -ErrorAction SilentlyContinue |
                                Measure-Object -Property Length -Sum).Sum
                    }
                    else { $itemBytes = $item.Length }
                }
                catch { }
                if (-not $itemBytes) { $itemBytes = 0 }

                try {
                    Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
                    $removed++
                    $reclaimedBytes += $itemBytes
                }
                catch {
                    # Files in use are normal here - locked, not broken. Counted
                    # rather than silenced, so "nothing was reclaimed" can be
                    # told apart from "everything was in use".
                    $locked++
                }
            }
        }

        $reclaimedMB = [math]::Round($reclaimedBytes / 1MB, 1)
        $script:TotalReclaimedMB += $reclaimedMB

        if ($removed -gt 0 -or $locked -gt 0) {
            Write-Log ("{0,-14} reclaimed {1} MB, {2} removed, {3} locked" -f $t.Name, $reclaimedMB, $removed, $locked)
        }

        $result.Targets += [ordered]@{
            Name = $t.Name; SizeMB = $sizeMB
            ItemsRemoved = $removed; ItemsLocked = $locked; ReclaimedMB = $reclaimedMB
        }
    }

    # --- Windows Update download cache. Needs the services stopped or the
    # --- delete half-fails and leaves WU in a worse state than it started.
    $sdPath = Join-Path $env:SystemRoot 'SoftwareDistribution\Download'
    if (Test-Path -LiteralPath $sdPath) {
        $sdMB = 0
        try {
            $sdMB = [math]::Round(
                ((Get-ChildItem -LiteralPath $sdPath -Recurse -Force -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum / 1MB), 1)
        }
        catch { }
        Write-Log ("{0,-14} {1,10} MB" -f 'WUDownload', $sdMB)

        $wuRemoved = 0
        $wuLocked = 0
        $wuBytes = 0

        if ($PSCmdlet.ShouldProcess($sdPath, "Stop wuauserv/bits, clear WU download cache ($sdMB MB), restart")) {
            $svcs = @('wuauserv', 'bits')
            foreach ($s in $svcs) { try { Stop-Service -Name $s -Force -ErrorAction Stop } catch { } }
            Start-Sleep -Seconds 2

            foreach ($item in (Get-ChildItem -LiteralPath $sdPath -Force -ErrorAction SilentlyContinue)) {
                $b = 0
                try {
                    if ($item.PSIsContainer) {
                        $b = (Get-ChildItem -LiteralPath $item.FullName -Recurse -Force -File -ErrorAction SilentlyContinue |
                                Measure-Object -Property Length -Sum).Sum
                    }
                    else { $b = $item.Length }
                }
                catch { }
                if (-not $b) { $b = 0 }

                try { Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop; $wuRemoved++; $wuBytes += $b }
                catch { $wuLocked++ }
            }

            # Restarting these matters more than the space. A clean that leaves
            # Windows Update stopped is a worse fault than the one it fixed.
            foreach ($s in $svcs) { try { Start-Service -Name $s -ErrorAction Stop } catch { } }

            $stillStopped = @(Get-Service -Name $svcs -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Running' })
            if ($stillStopped.Count -gt 0) {
                Write-Log -Message ('WU cache cleared BUT these services did not restart: ' +
                    (($stillStopped | ForEach-Object { $_.Name }) -join ', ') +
                    ' - start them before handing the machine back.') -Level FAIL
            }
            else {
                Write-Log -Message 'WU cache cleared, wuauserv and bits confirmed running' -Level OK
            }
        }

        $wuMB = [math]::Round($wuBytes / 1MB, 1)
        $script:TotalReclaimedMB += $wuMB
        $result.Targets += [ordered]@{
            Name = 'WUDownload'; SizeMB = $sdMB
            ItemsRemoved = $wuRemoved; ItemsLocked = $wuLocked; ReclaimedMB = $wuMB
        }
    }

    # --- Component cleanup. Opt-in: it is slow, and ResetBase makes every
    # --- installed update permanent (no uninstall). Never reset the base
    # --- automatically on a machine that just took updates.
    if ($IncludeComponentCleanup) {
        Write-Log -Message 'DISM /StartComponentCleanup (no /ResetBase - updates stay uninstallable)' -Level STEP
        if ($PSCmdlet.ShouldProcess('WinSxS', 'DISM /StartComponentCleanup')) {
            $cc = Invoke-Native -FilePath 'dism.exe' `
                -ArgumentList @('/Online', '/Cleanup-Image', '/StartComponentCleanup') -TimeoutMinutes 60
            $result.ComponentCleanup = @{ ExitCode = $cc.ExitCode }
            Write-Log "StartComponentCleanup exit $($cc.ExitCode)"
        }
    }

    $result.ReclaimedMB = $script:TotalReclaimedMB
    $result.FreePercentAfter = Get-FreeSpacePercent

    # Reclaimed bytes is the number that is actually true. The free-space
    # figure is reported alongside it, and explicitly not trusted when the two
    # disagree - the volume counter lags behind deletions.
    Write-Log -Message ("Reclaimed {0} MB" -f $result.ReclaimedMB) -Level OK
    Write-Log ("System drive free: {0}% -> {1}% (volume counters lag; the MB figure above is the real one)" -f `
            $before, $result.FreePercentAfter)

    return [pscustomobject]$result
}
