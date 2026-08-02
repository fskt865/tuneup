# Invoke-WindowsUpdate.ps1 - Windows Update via the COM agent.
# ASCII only, PowerShell 5.1 compatible.
#
# Deliberately uses the Windows Update Agent COM API rather than the
# PSWindowsUpdate module. The module means installing something from the
# internet onto a customer's machine before you can start; the COM API is
# already present on every Windows box and needs nothing.
#
# Drivers are OFF by default and stay that way unless asked. WU driver
# packages are a common way to turn a working machine into a broken one.

function Invoke-WindowsUpdateRun {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$IncludeDrivers,
        [int]$MaxUpdates = 50
    )

    Write-Banner 'Windows Update'
    Assert-Admin

    $result = [ordered]@{
        Searched     = 0
        Downloaded   = 0
        Installed    = 0
        Failed       = 0
        RebootNeeded = $false
        Items        = @()
        Error        = $null
    }

    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()

        $criteria = "IsInstalled=0 and Type='Software' and IsHidden=0"
        if ($IncludeDrivers) { $criteria = "IsInstalled=0 and IsHidden=0" }

        Write-Log "Searching: $criteria"
        $search = $searcher.Search($criteria)
        $result.Searched = $search.Updates.Count
        Write-Log "Found $($search.Updates.Count) applicable update(s)"

        if ($search.Updates.Count -eq 0) {
            Write-Log -Message 'Nothing to install' -Level OK
            return [pscustomobject]$result
        }

        # Build the list and show the plan before touching anything.
        $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        $n = 0
        foreach ($u in $search.Updates) {
            if ($n -ge $MaxUpdates) { break }

            $kb = ''
            if ($u.KBArticleIDs.Count -gt 0) { $kb = 'KB' + $u.KBArticleIDs.Item(0) }
            $sizeMB = Get-PlausibleSizeMB -Bytes $u.MaxDownloadSize
            $result.Items += [ordered]@{ KB = $kb; SizeMB = $sizeMB; Severity = [string]$u.MsrcSeverity }
            Write-Log ("  {0,-12} {1,12}  {2}" -f $kb, (Format-SizeMB -SizeMB $sizeMB), $u.MsrcSeverity)

            # EULA has to be accepted before an update can be installed. This
            # is Microsoft's licence for a patch on a machine the owner already
            # licensed - not a third-party agreement being signed for anyone.
            if (-not $u.EulaAccepted) {
                if ($PSCmdlet.ShouldProcess($kb, 'Accept Microsoft update EULA')) { $u.AcceptEula() }
            }

            $toInstall.Add($u) | Out-Null
            $n++
        }

        if ($search.Updates.Count -gt $MaxUpdates) {
            Write-Log -Message "Capped at $MaxUpdates updates this pass - re-run after reboot for the rest" -Level WARN
        }

        if (-not $PSCmdlet.ShouldProcess("$($toInstall.Count) update(s)", 'Download and install')) {
            Write-Log 'Dry run - nothing downloaded or installed'
            return [pscustomobject]$result
        }

        Write-Log -Message 'Downloading' -Level STEP
        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $toInstall
        $dl = $downloader.Download()
        Write-Log "Download result code $($dl.ResultCode) hresult 0x$('{0:X8}' -f $dl.HResult)"

        $ready = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $toInstall) { if ($u.IsDownloaded) { $ready.Add($u) | Out-Null } }
        $result.Downloaded = $ready.Count

        if ($ready.Count -eq 0) {
            Write-Log -Message 'Nothing downloaded successfully - check network, WSUS policy, or metered connection' -Level FAIL
            return [pscustomobject]$result
        }

        Write-Log -Message "Installing $($ready.Count) update(s)" -Level STEP
        $installer = $session.CreateUpdateInstaller()
        $installer.Updates = $ready
        $inst = $installer.Install()

        # ResultCode 2 = succeeded, 3 = succeeded with errors.
        if ($inst.ResultCode -eq 2 -or $inst.ResultCode -eq 3) { $result.Installed = $ready.Count }
        else { $result.Failed = $ready.Count }

        $result.RebootNeeded = [bool]$inst.RebootRequired
        Write-Log ("Install result code {0}, reboot required: {1}" -f $inst.ResultCode, $inst.RebootRequired)

        if ($result.RebootNeeded) {
            Write-Log -Message 'Reboot required before the rest of the queue will apply' -Level WARN
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Log -Message "Windows Update failed: $($_.Exception.Message)" -Level FAIL
    }

    return [pscustomobject]$result
}
