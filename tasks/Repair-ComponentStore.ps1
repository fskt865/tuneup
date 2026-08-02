# Repair-ComponentStore.ps1 - the DISM / SFC ladder, in the order that works.
# ASCII only, PowerShell 5.1 compatible.
#
# DISM before SFC, always. SFC repairs system files USING the component store;
# if the store itself is corrupt, SFC will fail or "repair" from bad sources
# and you will have burned 30 minutes to learn nothing. Repair the store first,
# then let SFC use it.

function Repair-ComponentStore {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$SkipScanHealth,
        [string]$SourcePath
    )

    Write-Banner 'Component store and system file repair'
    Assert-Admin

    $result = [ordered]@{
        CheckHealth        = $null
        ScanHealth         = $null
        RestoreHealth      = $null
        Sfc                = $null
        SfcSecondPass      = $null
        StoreHealthUnknown = $false
        RebootNeeded       = $false
        Verdict            = 'Unknown'
    }

    # --- Step 1: CheckHealth. Reads a flag, takes seconds. -------------
    Write-Log -Message 'Step 1/4 DISM /CheckHealth (reads the corruption flag only)' -Level STEP
    $check = Invoke-Native -FilePath 'dism.exe' `
        -ArgumentList @('/Online', '/Cleanup-Image', '/CheckHealth') -TimeoutMinutes 10
    $checkVerdict = Get-DismVerdict -Text $check.StdOut
    $result.CheckHealth = @{ ExitCode = $check.ExitCode; Verdict = $checkVerdict }
    Write-Log "CheckHealth: $checkVerdict (exit $($check.ExitCode))"

    # --- Step 2: ScanHealth. Real scan, slow. --------------------------
    #
    # Three states, not two. "Corruption found" and "confirmed healthy" are
    # both conclusions; "the check did not run or did not parse" is NOT a
    # conclusion and must never be reported as healthy. A tech who reads
    # "healthy" off a check that never ran will go looking in the wrong layer.
    $needsRestore = $false
    $establishedHealthy = $false

    if ($checkVerdict -eq 'Repairable' -or $checkVerdict -eq 'NotRepairable') {
        $needsRestore = $true
        Write-Log 'CheckHealth already flagged corruption - skipping ScanHealth, going straight to repair'
    }
    elseif (-not $SkipScanHealth) {
        Write-Log -Message 'Step 2/4 DISM /ScanHealth (full scan - this takes a while)' -Level STEP
        if ($PSCmdlet.ShouldProcess('component store', 'DISM /ScanHealth')) {
            $scan = Invoke-Native -FilePath 'dism.exe' `
                -ArgumentList @('/Online', '/Cleanup-Image', '/ScanHealth') -TimeoutMinutes 60
            $scanVerdict = Get-DismVerdict -Text $scan.StdOut
            $result.ScanHealth = @{ ExitCode = $scan.ExitCode; Verdict = $scanVerdict }
            Write-Log "ScanHealth: $scanVerdict (exit $($scan.ExitCode))"

            if ($scanVerdict -eq 'Repairable' -or $scanVerdict -eq 'NotRepairable') { $needsRestore = $true }
            elseif ($scanVerdict -eq 'Healthy') { $establishedHealthy = $true }
        }
    }
    elseif ($checkVerdict -eq 'Healthy') {
        $establishedHealthy = $true
        Write-Log 'Step 2/4 ScanHealth skipped by request - CheckHealth flag was clean'
    }
    else {
        Write-Log -Message 'Step 2/4 ScanHealth skipped by request and CheckHealth was inconclusive - store health UNKNOWN' -Level WARN
    }

    # --- Step 3: RestoreHealth. Needs a source: WU, or -SourcePath. ----
    if ($needsRestore) {
        Write-Log -Message 'Step 3/4 DISM /RestoreHealth' -Level STEP
        $args = @('/Online', '/Cleanup-Image', '/RestoreHealth')
        if ($SourcePath) {
            $args += ('/Source:' + $SourcePath)
            $args += '/LimitAccess'
            Write-Log "Using local source: $SourcePath"
        }

        if ($PSCmdlet.ShouldProcess('component store', ($args -join ' '))) {
            $restore = Invoke-Native -FilePath 'dism.exe' -ArgumentList $args -TimeoutMinutes 90
            $result.RestoreHealth = @{ ExitCode = $restore.ExitCode; Verdict = (Get-DismVerdict -Text $restore.StdOut) }
            Write-Log "RestoreHealth exit $($restore.ExitCode)"

            if ($restore.ExitCode -eq 3010) { $result.RebootNeeded = $true }

            # 0x800f081f - source files not found. Almost always no usable WU
            # source: metered/blocked network, WSUS pointing somewhere dead,
            # or a genuinely gutted store. Needs an install.wim to proceed.
            if ($restore.StdOut -match '0x800f081f' -or $restore.StdOut -match '0x800F081F') {
                Write-Log -Message 'DISM 0x800f081f - no usable repair source. Supply -SourcePath pointing at a matching install.wim/esd, or fix network/WSUS access.' -Level FAIL
                $result.Verdict = 'NeedsSource'
            }
        }
    }
    elseif ($establishedHealthy) {
        Write-Log -Message 'Component store confirmed healthy - no DISM repair needed' -Level OK
    }
    else {
        Write-Log -Message 'Component store health could not be established (DISM did not return a verdict). Not claiming healthy. If SFC below also comes back unclear, check elevation and whether another servicing operation is running.' -Level WARN
        $result.StoreHealthUnknown = $true
    }

    # --- Step 4: SFC, now that the store is trustworthy. ---------------
    Write-Log -Message 'Step 4/4 sfc /scannow' -Level STEP
    if ($PSCmdlet.ShouldProcess('protected system files', 'sfc /scannow')) {
        $sfc = Invoke-Native -FilePath 'sfc.exe' -ArgumentList @('/scannow') -TimeoutMinutes 60
        $sfcVerdict = Get-SfcVerdict -Text $sfc.StdOut
        $result.Sfc = @{ ExitCode = $sfc.ExitCode; Verdict = $sfcVerdict }
        Write-Log "SFC: $sfcVerdict"

        if ($sfcVerdict -eq 'RepairedSome') { $result.RebootNeeded = $true }

        # A second pass genuinely helps: SFC repairs in dependency order and
        # one run does not always reach everything.
        if ($sfcVerdict -eq 'UnrepairedRemain') {
            Write-Log 'Unrepaired files remain - running a second SFC pass'
            $sfc2 = Invoke-Native -FilePath 'sfc.exe' -ArgumentList @('/scannow') -TimeoutMinutes 60
            $sfc2Verdict = Get-SfcVerdict -Text $sfc2.StdOut
            $result.SfcSecondPass = @{ ExitCode = $sfc2.ExitCode; Verdict = $sfc2Verdict }
            Write-Log "SFC pass 2: $sfc2Verdict"
        }
    }

    # --- Verdict -------------------------------------------------------
    if ($result.Verdict -eq 'Unknown') {
        $final = $result.Sfc.Verdict
        if ($result.SfcSecondPass) { $final = $result.SfcSecondPass.Verdict }

        if ($final -eq 'Clean')                 { $result.Verdict = 'Clean' }
        elseif ($final -eq 'RepairedAll')       { $result.Verdict = 'Repaired' }
        elseif ($final -eq 'UnrepairedRemain')  { $result.Verdict = 'UnrepairableFilesRemain' }
        else                                    { $result.Verdict = 'Inconclusive' }
    }

    Write-Log -Message ("Component store verdict: {0}" -f $result.Verdict) -Level OK
    if ($result.Verdict -eq 'UnrepairableFilesRemain') {
        Write-Log -Message 'SFC cannot fix everything. Next rung is an in-place repair install, which is above the scripted line - make that call by hand.' -Level WARN
    }

    return [pscustomobject]$result
}

function Get-SfcVerdict {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 'NoOutput' }
    if ($Text -match 'did not find any integrity violations')            { return 'Clean' }
    if ($Text -match 'successfully repaired them')                       { return 'RepairedAll' }
    if ($Text -match 'was unable to fix some')                           { return 'UnrepairedRemain' }
    if ($Text -match 'could not perform the requested operation')        { return 'CouldNotRun' }
    if ($Text -match 'another servicing operation')                      { return 'ServicingBusy' }
    if ($Text -match 'pending repair')                                   { return 'RebootThenRerun' }
    return 'Unrecognized'
}
