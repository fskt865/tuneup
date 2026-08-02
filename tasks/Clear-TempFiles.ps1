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
    $result = [ordered]@{
        FreePercentBefore = $before
        FreePercentAfter  = $null
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
        if ($PSCmdlet.ShouldProcess($t.Path, "Delete cache contents ($sizeMB MB)")) {
            Get-ChildItem -LiteralPath $t.Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
                    $removed++
                }
                catch {
                    # Files in use are normal here and not worth reporting one
                    # by one - they are locked, not broken.
                }
            }
        }

        $result.Targets += [ordered]@{ Name = $t.Name; SizeMB = $sizeMB; ItemsRemoved = $removed }
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

        if ($PSCmdlet.ShouldProcess($sdPath, "Stop wuauserv/bits, clear WU download cache ($sdMB MB), restart")) {
            $svcs = @('wuauserv', 'bits')
            foreach ($s in $svcs) { try { Stop-Service -Name $s -Force -ErrorAction Stop } catch { } }
            Start-Sleep -Seconds 2

            Get-ChildItem -LiteralPath $sdPath -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop } catch { }
            }

            foreach ($s in $svcs) { try { Start-Service -Name $s -ErrorAction Stop } catch { } }
            Write-Log -Message 'WU cache cleared and services restarted' -Level OK
        }
        $result.Targets += [ordered]@{ Name = 'WUDownload'; SizeMB = $sdMB; ItemsRemoved = -1 }
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

    $result.FreePercentAfter = Get-FreeSpacePercent
    Write-Log -Message ("System drive free: {0}% -> {1}%" -f $before, $result.FreePercentAfter) -Level OK

    return [pscustomobject]$result
}
