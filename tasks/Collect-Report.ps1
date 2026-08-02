# Collect-Report.ps1 - read-only diagnostic collection.
# Returns an object. The caller sanitizes it before anything is written.
# ASCII only, PowerShell 5.1 compatible. Changes nothing on the machine.

function Get-TuneUpReport {
    param([switch]$SkipEventLogs)

    Write-Banner 'Collecting diagnostic report (read-only)'

    # Collection changes nothing, so it runs for real even inside a dry run -
    # otherwise -WhatIf floods the console with "What if: New Alias" noise from
    # the CIM and Storage modules loading, and reports nothing useful.
    # Function-scoped: the caller's preference is untouched on return.
    $WhatIfPreference = $false

    $isAdmin = Test-IsAdmin
    if (-not $isAdmin) {
        Write-Log -Message 'Not elevated - SMART counters and component store cannot be read. They will be marked RequiresElevation, not reported as healthy.' -Level WARN
    }

    $r = [ordered]@{
        Schema      = 'gs-tuneup/report/1'
        CollectedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Elevated    = $isAdmin
    }

    # --- OS ------------------------------------------------------------
    Write-Log 'Reading OS build and uptime'
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue

        $installAge = $null
        if ($os.InstallDate) { $installAge = [math]::Round(((Get-Date) - $os.InstallDate).TotalDays, 0) }
        $uptimeHours = $null
        if ($os.LastBootUpTime) { $uptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1) }

        $r.OS = [ordered]@{
            Caption         = $os.Caption
            Version         = $os.Version
            DisplayVersion  = $cv.DisplayVersion
            Build           = $cv.CurrentBuild
            UBR             = $cv.UBR
            Architecture    = $os.OSArchitecture
            InstallAgeDays  = $installAge
            UptimeHours     = $uptimeHours
        }
    }
    catch { $r.OS = @{ Error = $_.Exception.Message } }

    # --- Hardware (models are generic product facts; serials are not) ---
    Write-Log 'Reading hardware class'
    try {
        $cs  = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        $fw  = 'BIOS'
        try { if ($env:firmware_type) { $fw = $env:firmware_type } } catch { }
        $secureBoot = $null
        try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $secureBoot = 'Unavailable' }

        $r.Hardware = [ordered]@{
            Manufacturer  = $cs.Manufacturer
            Model         = $cs.Model
            CpuName       = $cpu.Name
            CpuCores      = $cpu.NumberOfCores
            RamGB         = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            FirmwareType  = $fw
            SecureBoot    = $secureBoot
        }
    }
    catch { $r.Hardware = @{ Error = $_.Exception.Message } }

    # --- Storage. Volume labels are omitted on purpose: a label is free ---
    # --- text and is frequently the owner's name.                      ---
    Write-Log 'Reading disk health and SMART counters'
    $disks = @()
    try {
        foreach ($pd in (Get-PhysicalDisk -ErrorAction Stop)) {
            # Reliability counters need elevation. A blank wear figure must not
            # be readable as "wear is fine" - say why it is blank.
            $rc = $null
            $rcStatus = 'Read'
            if (-not $isAdmin) {
                $rcStatus = 'RequiresElevation'
            }
            else {
                try { $rc = $pd | Get-StorageReliabilityCounter -ErrorAction Stop }
                catch { $rcStatus = 'Unsupported' }
                if ($null -eq $rc) { $rcStatus = 'Unsupported' }
            }

            $disks += [ordered]@{
                FriendlyName        = $pd.FriendlyName
                MediaType           = [string]$pd.MediaType
                BusType             = [string]$pd.BusType
                SizeGB              = [math]::Round($pd.Size / 1GB, 1)
                HealthStatus        = [string]$pd.HealthStatus
                OperationalStatus   = [string]$pd.OperationalStatus
                SmartStatus         = $rcStatus
                Wear                = $rc.Wear
                # A drive reporting 0 C is not at freezing, it is not reporting.
                # Printing 0 invites someone to read it as a real measurement.
                TemperatureC        = $(if ($rc.Temperature -and $rc.Temperature -gt 0) { $rc.Temperature } else { $null })
                ReadErrorsTotal     = $rc.ReadErrorsTotal
                WriteErrorsTotal    = $rc.WriteErrorsTotal
                PowerOnHours        = $rc.PowerOnHours
            }
        }
    }
    catch { $disks = @(@{ Error = $_.Exception.Message }) }
    $r.Disks = $disks

    $vols = @()
    try {
        foreach ($v in (Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -and $_.Size -gt 0 })) {
            $vols += [ordered]@{
                DriveLetter   = [string]$v.DriveLetter
                FileSystem    = [string]$v.FileSystem
                DriveType     = [string]$v.DriveType
                SizeGB        = [math]::Round($v.Size / 1GB, 1)
                FreePercent   = [math]::Round(($v.SizeRemaining / $v.Size) * 100, 1)
                HealthStatus  = [string]$v.HealthStatus
            }
        }
    }
    catch { }
    $r.Volumes = $vols

    # --- Component store flag (CheckHealth only - reads the flag, fast) --
    if (-not $isAdmin) {
        Write-Log 'Skipping component store check - needs elevation'
        $r.ComponentStore = [ordered]@{ ExitCode = $null; Verdict = 'RequiresElevation' }
    }
    else {
        Write-Log 'Reading component store health flag'
        try {
            $dism = Invoke-Native -FilePath 'dism.exe' `
                -ArgumentList @('/Online', '/Cleanup-Image', '/CheckHealth') -TimeoutMinutes 10
            $r.ComponentStore = [ordered]@{
                ExitCode = $dism.ExitCode
                Verdict  = (Get-DismVerdict -Text $dism.StdOut)
            }
        }
        catch { $r.ComponentStore = @{ Error = $_.Exception.Message } }
    }

    # --- Windows Update -------------------------------------------------
    Write-Log 'Querying Windows Update agent'
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()

        $pending = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $pendingList = @()
        foreach ($u in $pending.Updates) {
            $kb = ''
            if ($u.KBArticleIDs.Count -gt 0) { $kb = 'KB' + $u.KBArticleIDs.Item(0) }
            $pendingList += [ordered]@{
                KB       = $kb
                Severity = [string]$u.MsrcSeverity
                SizeMB   = (Get-PlausibleSizeMB -Bytes $u.MaxDownloadSize)
            }
        }

        # Recent failures - KB numbers and HRESULTs are generic facts.
        $failures = @()
        try {
            $count = $searcher.GetTotalHistoryCount()
            if ($count -gt 0) {
                $take = [math]::Min($count, 50)
                foreach ($h in $searcher.QueryHistory(0, $take)) {
                    if ($h.ResultCode -ne 2 -and $h.ResultCode -ne 3) {
                        $failures += [ordered]@{
                            ResultCode = $h.ResultCode
                            HResult    = ('0x{0:X8}' -f $h.HResult)
                            Operation  = $h.Operation
                        }
                    }
                }
            }
        }
        catch { }

        $r.WindowsUpdate = [ordered]@{
            PendingCount   = $pendingList.Count
            Pending        = $pendingList
            RecentFailures = $failures
        }
    }
    catch {
        $r.WindowsUpdate = @{ Error = $_.Exception.Message }
    }

    # --- Event log signatures. Counts and codes only - message bodies ---
    # --- routinely contain file paths and account names.              ---
    if (-not $SkipEventLogs) {
        Write-Log 'Scanning event logs for fault signatures (30 days)'
        $since = (Get-Date).AddDays(-30)

        $bugchecks = @()
        try {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001; StartTime = $since } `
                -MaxEvents 25 -ErrorAction Stop | ForEach-Object {
                if ($_.ProviderName -like '*BugCheck*') {
                    $code = ''
                    if ($_.Message -match '(0x[0-9a-fA-F]{8,16})') { $code = $Matches[1] }
                    $bugchecks += @{ StopCode = $code }
                }
            }
        }
        catch { }

        # ---------------------------------------------------------------
        # An event ID is only unique WITHIN a provider. Counting by ID alone
        # is how you end up reporting 84 "NTFS corruption" events that were
        # really Kernel-Processor-Power ID 55, and sending a tech to tear
        # apart a filesystem that was never broken. Always match the provider.
        #
        # Filtering happens client-side rather than in the FilterHashtable so
        # that a provider which does not exist on this machine cannot make the
        # whole query throw and silently zero out a real signal.
        # ---------------------------------------------------------------
        $specs = @(
            @{ Name = 'UnexpectedShutdown';  Log = 'System';      Id = 41;   Providers = @('Microsoft-Windows-Kernel-Power') },
            @{ Name = 'DiskControllerError'; Log = 'System';      Id = 11;   Providers = @('disk', 'storahci', 'stornvme', 'iaStorA', 'iaStorAC') },
            @{ Name = 'BadBlock';            Log = 'System';      Id = 7;    Providers = @('disk') },
            @{ Name = 'PagingIoError';       Log = 'System';      Id = 51;   Providers = @('disk', 'Ntfs') },
            @{ Name = 'DiskIoRetry';         Log = 'System';      Id = 153;  Providers = @('disk') },
            @{ Name = 'DiskResetTimeout';    Log = 'System';      Id = 129;  Providers = @('storahci', 'stornvme', 'iaStorA', 'iaStorAC') },
            @{ Name = 'NtfsCorruption';      Log = 'System';      Id = 55;   Providers = @('Ntfs', 'Microsoft-Windows-Ntfs') },
            @{ Name = 'ServiceCrash';        Log = 'System';      Id = 7034; Providers = @('Service Control Manager') },
            @{ Name = 'AppCrash';            Log = 'Application'; Id = 1000; Providers = @('Application Error') }
        )

        $counts = @{}
        foreach ($spec in $specs) {
            try {
                $ev = Get-WinEvent -FilterHashtable @{ LogName = $spec.Log; Id = $spec.Id; StartTime = $since } `
                    -MaxEvents 1000 -ErrorAction Stop
                $matched = @($ev | Where-Object { $spec.Providers -contains $_.ProviderName })
                $counts[$spec.Name] = $matched.Count
            }
            catch {
                # Get-WinEvent throws when the filter matches nothing at all.
                $counts[$spec.Name] = 0
            }
        }

        $r.EventSignatures = [ordered]@{
            WindowDays = 30
            Bugchecks  = $bugchecks
            Counts     = $counts
        }
    }

    # --- Defender -------------------------------------------------------
    Write-Log 'Reading Defender status'
    try {
        $d = Get-MpComputerStatus -ErrorAction Stop
        $r.Defender = [ordered]@{
            RealTimeProtection = $d.RealTimeProtectionEnabled
            AntivirusEnabled   = $d.AntivirusEnabled
            SignatureAgeDays   = $d.AntivirusSignatureAge
            TamperProtection   = $d.IsTamperProtected
        }
    }
    catch { $r.Defender = @{ Error = 'Unavailable (third-party AV or policy)' } }

    # --- Startup load. Publishers only, never command lines - those ---
    # --- are full of user profile paths.                            ---
    Write-Log 'Reading startup load'
    try {
        $startup = Get-CimInstance Win32_StartupCommand -ErrorAction Stop
        $r.Startup = [ordered]@{
            Count      = @($startup).Count
            Names      = @($startup | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue)
        }
    }
    catch { $r.Startup = @{ Error = $_.Exception.Message } }

    # --- Pending reboot -------------------------------------------------
    $pr = Get-PendingReboot
    $r.PendingReboot = [ordered]@{
        Pending = $pr.Pending
        Reasons = $pr.Reasons
    }

    Write-Log -Message 'Collection complete' -Level OK
    return [pscustomobject]$r
}

function Get-DismVerdict {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 'Unknown' }
    if ($Text -match 'No component store corruption detected') { return 'Healthy' }
    if ($Text -match 'The component store is repairable')       { return 'Repairable' }
    if ($Text -match 'not repairable')                          { return 'NotRepairable' }
    return 'Unknown'
}
