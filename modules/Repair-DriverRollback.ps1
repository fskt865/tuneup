<#MANIFEST
{
  "Key": "driver",
  "Title": "Driver problem and rollback assistant",
  "Entry": "Invoke-DriverModule",
  "Order": 30,
  "RequiresAdmin": true,
  "Description": "Finds problem devices and recent driver packages; prints rollback commands, never runs them"
}
MANIFEST#>

# Repair-DriverRollback.ps1 - driver fault diagnosis and rollback assistance.
# ASCII only, PowerShell 5.1 compatible.
#
# THIS MODULE DOES NOT ROLL BACK DRIVERS. Read that again before extending it.
#
# Two reasons, and neither is laziness:
#
# 1. Windows has no supported scripted rollback. "Roll Back Driver" in Device
#    Manager calls into SetupAPI with the retained previous package; there is
#    no pnputil verb and no cmdlet for it. Everything a script CAN do is a
#    blunter instrument - deleting a driver package outright and hoping the
#    next best driver binds.
# 2. The blast radius is the worst of any module here. Delete the wrong
#    storage package and the machine will not boot (0x7B). Delete the display
#    package remotely and you have a black screen with no way back.
#
# So: this finds the fault, identifies the candidate packages, and PRINTS the
# exact commands. The tech runs them, having seen what is at stake. Same rule
# as partition layout in bootrepair - the judgement is not automatable and the
# downside is someone's machine.
#
# The one thing -Apply does is create a System Restore point, which is purely
# additive and is the safety net you want before doing any of this by hand.
#
# PRIVACY: device instance IDs frequently embed hardware serial numbers
# (USB\VID_xxxx&PID_xxxx\<serial>, disk instance paths). They are printed to
# the local console because the tech needs them to act, and are deliberately
# NEVER placed in the report, which travels.

# Problem codes worth recognising. The value is not the number, it is knowing
# which layer to go look at next.
$script:DriverProblemCodes = @{
    0  = @{ Short = 'No problem code reported';       Layer = 'Status is not OK but Windows reports no fault code - often needs elevation to read, or the device is simply hidden' }
    1  = @{ Short = 'Not configured correctly';       Layer = 'Driver missing or INF mismatch' }
    3  = @{ Short = 'Driver corrupted or low memory'; Layer = 'Driver package' }
    9  = @{ Short = 'Invalid device ID';              Layer = 'Firmware or hardware reporting' }
    10 = @{ Short = 'Device cannot start';            Layer = 'Driver loaded, device or driver rejected start - very often hardware' }
    12 = @{ Short = 'Not enough free resources';      Layer = 'Resource conflict, firmware' }
    14 = @{ Short = 'Needs a restart';                Layer = 'Benign - reboot and re-check' }
    18 = @{ Short = 'Reinstall the drivers';          Layer = 'Driver package' }
    19 = @{ Short = 'Registry is corrupt';            Layer = 'Registry - device class keys' }
    21 = @{ Short = 'System is removing the device';  Layer = 'Transient - re-check after reboot' }
    22 = @{ Short = 'Device is disabled';             Layer = 'Config, not a fault - someone disabled it' }
    24 = @{ Short = 'Not present or not working';     Layer = 'Often a phantom entry for absent hardware' }
    28 = @{ Short = 'Drivers not installed';          Layer = 'Missing driver - the common one after a clean install' }
    29 = @{ Short = 'Firmware not providing resources'; Layer = 'BIOS/UEFI - device may be disabled in firmware' }
    31 = @{ Short = 'Driver failed to load';          Layer = 'Driver package or a dependency' }
    32 = @{ Short = 'Driver start type is disabled';  Layer = 'Service start type in registry' }
    35 = @{ Short = 'Firmware MPS table entry missing'; Layer = 'BIOS/UEFI - needs a firmware update' }
    37 = @{ Short = 'Driver failed DriverEntry';      Layer = 'Driver package - bad or mismatched version' }
    38 = @{ Short = 'Previous instance still loaded'; Layer = 'Needs a reboot' }
    39 = @{ Short = 'Driver corrupted or missing';    Layer = 'Driver package' }
    40 = @{ Short = 'Service key info invalid';       Layer = 'Registry' }
    41 = @{ Short = 'Driver loaded, no device found'; Layer = 'Hardware absent or not detected' }
    42 = @{ Short = 'Duplicate device';               Layer = 'Bus or enumeration fault' }
    43 = @{ Short = 'Device reported a problem';      Layer = 'Device stopped itself - very often failing hardware' }
    44 = @{ Short = 'Stopped by an application';      Layer = 'Software stopped it' }
    45 = @{ Short = 'Not currently connected';        Layer = 'Phantom entry - hardware simply absent' }
    47 = @{ Short = 'Prepared for safe removal';      Layer = 'Transient' }
    48 = @{ Short = 'Driver blocked as incompatible'; Layer = 'Windows blocked a known-bad driver' }
    49 = @{ Short = 'System hive exceeded size limit'; Layer = 'Registry - needs cleanup of stale devices' }
    52 = @{ Short = 'Driver signature not verified';  Layer = 'Unsigned or tampered driver package' }
}

function Get-DriverProblemMeaning {
    param([int]$Code)
    if ($script:DriverProblemCodes.ContainsKey($Code)) {
        return [pscustomobject]@{
            Code  = $Code
            Short = $script:DriverProblemCodes[$Code].Short
            Layer = $script:DriverProblemCodes[$Code].Layer
        }
    }
    return [pscustomobject]@{ Code = $Code; Short = 'Unrecognised problem code'; Layer = 'Look it up before acting' }
}

# Device classes where removing a driver package can cost you the machine.
# This is a belt-and-braces overlay on Windows' own BootCritical flag, not a
# replacement for it - a class list cannot know that this particular NIC is
# the only way onto the network.
$script:BootCriticalClasses = @(
    'SCSIAdapter',      # storage controllers - delete this and you get 0x7B
    'HDC',              # IDE/ATA controllers
    'DiskDrive',
    'Volume',
    'VolumeSnapshot',
    'System',           # chipset, ACPI, host bridges
    'Processor',
    'Computer',
    'SecurityDevices'   # TPM - BitLocker implications
)

# Not boot-critical, but removing one blind still ruins the tech's day.
$script:HighRiskClasses = @(
    'Display',          # black screen, and remote work becomes impossible
    'Net',              # strands a machine with no other path on
    'Keyboard',
    'Mouse',
    'HIDClass',
    'USB'
)

function Test-BootCriticalClass {
    param([string]$ClassName)
    if ([string]::IsNullOrWhiteSpace($ClassName)) { return $false }
    return ($script:BootCriticalClasses -contains $ClassName)
}

function Get-DriverRiskTier {
    param([string]$ClassName, $BootCriticalFlag)

    # Windows' own flag wins. Same principle as SignatureKind in the bloatware
    # module: when the OS tells you something is load-bearing, believe it.
    if ($BootCriticalFlag -eq $true) {
        return [pscustomobject]@{ Tier = 'BootCritical'; Note = 'Windows flags this package boot-critical' }
    }
    if (Test-BootCriticalClass -ClassName $ClassName) {
        return [pscustomobject]@{ Tier = 'BootCritical'; Note = "Class '$ClassName' is boot-critical" }
    }
    if ($script:HighRiskClasses -contains $ClassName) {
        return [pscustomobject]@{ Tier = 'HighRisk'; Note = "Class '$ClassName' - removal can leave the machine unusable" }
    }
    return [pscustomobject]@{ Tier = 'Standard'; Note = '' }
}

# Returns real faults plus a count of what was filtered, so the caller can
# say what it discarded instead of silently shrinking the list.
#
# "Status is not OK" is NOT the same as "this device has a problem". Windows
# reports Status='Unknown' for hidden and unqueryable devices - phantom
# entries, things behind a bus it cannot interrogate, anything absent. On a
# healthy machine that is dozens of devices. Reporting them as faults buries
# the one that matters and sends a tech after driver problems that do not
# exist. A device counts only when Windows says Error/Degraded, or it carries
# a real non-zero problem code.
function Get-ProblemDevices {
    $result = [pscustomobject]@{
        Devices        = @()
        SkippedPhantom = 0
        SkippedUnknown = 0
    }

    try {
        $devices = @(Get-PnpDevice -ErrorAction Stop | Where-Object { $_.Status -ne 'OK' })
    }
    catch { return $result }

    $found = @()
    foreach ($d in $devices) {
        $code = 0
        try {
            $p = Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction Stop
            if ($null -ne $p.Data) { $code = [int]$p.Data }
        }
        catch { }

        # 45 = hardware simply not plugged in.
        if ($code -eq 45) { $result.SkippedPhantom++; continue }

        $isRealFault = ($d.Status -eq 'Error' -or $d.Status -eq 'Degraded' -or $code -ne 0)
        if (-not $isRealFault) { $result.SkippedUnknown++; continue }

        $meaning = Get-DriverProblemMeaning -Code $code
        $risk = Get-DriverRiskTier -ClassName $d.Class -BootCriticalFlag $null

        $found += [pscustomobject]@{
            FriendlyName = $d.FriendlyName
            Class        = $d.Class
            Status       = [string]$d.Status
            ProblemCode  = $code
            Meaning      = $meaning.Short
            Layer        = $meaning.Layer
            RiskTier     = $risk.Tier
            InstanceId   = $d.InstanceId   # console only - stripped from the report
        }
    }

    $result.Devices = $found
    return $result
}

function Get-ThirdPartyDrivers {
    param([int]$RecentDays = 30)

    $result = [ordered]@{
        Status   = 'Unknown'
        Packages = @()
        Recent   = @()
    }

    if (-not (Test-IsAdmin)) {
        $result.Status = 'RequiresElevation'
        return [pscustomobject]$result
    }

    $drivers = $null
    try {
        $drivers = Get-WindowsDriver -Online -ErrorAction Stop
        $result.Status = 'Read'
    }
    catch {
        $result.Status = 'Unavailable'
        return [pscustomobject]$result
    }

    $cutoff = (Get-Date).AddDays(-$RecentDays)

    foreach ($d in $drivers) {
        $risk = Get-DriverRiskTier -ClassName $d.ClassName -BootCriticalFlag $d.BootCritical
        $ver = ''
        try { $ver = '{0}.{1}.{2}.{3}' -f $d.MajorVersion, $d.MinorVersion, $d.Build, $d.Revision } catch { }

        $entry = [pscustomobject]@{
            InfName      = $d.Driver
            OriginalName = $d.OriginalFileName
            Provider     = $d.ProviderName
            ClassName    = $d.ClassName
            Version      = $ver
            Date         = $d.Date
            BootCritical = [bool]$d.BootCritical
            RiskTier     = $risk.Tier
            RiskNote     = $risk.Note
        }
        $result.Packages += $entry

        if ($d.Date -and $d.Date -gt $cutoff) { $result.Recent += $entry }
    }

    $result.Recent = @($result.Recent | Sort-Object Date -Descending)
    return [pscustomobject]$result
}

function Get-RestoreStatus {
    $status = [ordered]@{
        Readable          = $false
        Status            = 'Unknown'
        RestorePointCount = 0
        NewestAgeDays     = $null
    }

    if (-not (Test-IsAdmin)) {
        $status.Status = 'RequiresElevation'
        return [pscustomobject]$status
    }

    try {
        $points = @(Get-ComputerRestorePoint -ErrorAction Stop)
        $status.Readable = $true
        $status.RestorePointCount = $points.Count
        $status.Status = $(if ($points.Count -gt 0) { 'PointsPresent' } else { 'NoPointsFound' })

        if ($points.Count -gt 0) {
            $newest = $points | Sort-Object CreationTime -Descending | Select-Object -First 1
            $ct = $null
            try { $ct = [Management.ManagementDateTimeConverter]::ToDateTime($newest.CreationTime) } catch { }
            if ($ct) { $status.NewestAgeDays = [math]::Round(((Get-Date) - $ct).TotalDays, 1) }
        }
    }
    catch {
        # An empty list and System Protection being switched off look very
        # similar from here. Do not guess which - say it is indeterminate.
        $status.Status = 'UnreadableOrDisabled'
    }

    return [pscustomobject]$status
}

function Invoke-DriverModule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$Apply,
        [hashtable]$Options = @{}
    )

    $recentDays = 30
    if ($Options['RecentDays']) { $recentDays = [int]$Options['RecentDays'] }

    Write-Banner 'Driver problems and rollback candidates'

    $result = [ordered]@{
        Mode              = $(if ($Apply) { 'Apply' } else { 'InventoryOnly' })
        RecentDays        = $recentDays
        ProblemDevices    = @()
        SkippedPhantom    = 0
        SkippedUnknown    = 0
        DriverStoreStatus = 'Unknown'
        RecentDrivers     = @()
        PackageCount      = 0
        BootCriticalCount = 0
        RestorePoint      = $null
        RestorePointMade  = $false
        RestorePointBlockedBy = $null
    }

    # --- Problem devices --------------------------------------------------
    Write-Log -Message 'Enumerating devices reporting a problem' -Level STEP
    $scan = Get-ProblemDevices
    $problems = @($scan.Devices)
    $result.SkippedPhantom = $scan.SkippedPhantom
    $result.SkippedUnknown = $scan.SkippedUnknown

    Write-Host ''
    # Say what was filtered. A shorter list must never look like a cleaner
    # machine than it is.
    Write-Host ('  Filtered out: {0} not-connected phantom(s), {1} hidden/unqueryable device(s).' -f `
            $scan.SkippedPhantom, $scan.SkippedUnknown) -ForegroundColor DarkGray

    if ($problems.Count -eq 0) {
        Write-Host '  No devices reporting an actual fault.' -ForegroundColor Green
    }
    else {
        Write-Host ('  {0} device(s) reporting a problem:' -f $problems.Count) -ForegroundColor Yellow
        Write-Host ''
        foreach ($p in $problems) {
            $color = 'Yellow'
            if ($p.RiskTier -eq 'BootCritical') { $color = 'Red' }
            Write-Host ('    {0}' -f $p.FriendlyName) -ForegroundColor $color
            Write-Host ('      class {0}   code {1} - {2}' -f $p.Class, $p.ProblemCode, $p.Meaning) -ForegroundColor Gray
            Write-Host ('      look at: {0}' -f $p.Layer) -ForegroundColor DarkGray
            if ($p.RiskTier -ne 'Standard') {
                Write-Host ('      {0} - do not remove this package casually' -f $p.RiskTier) -ForegroundColor Red
            }
            # Instance ID to the console only. The tech needs it; the report
            # must not carry it, because these embed hardware serials.
            Write-Host ('      instance: {0}' -f $p.InstanceId) -ForegroundColor DarkGray
            Write-Host ''
        }
    }

    # Strip InstanceId on the way into the report.
    foreach ($p in $problems) {
        $result.ProblemDevices += [ordered]@{
            FriendlyName = $p.FriendlyName
            Class        = $p.Class
            Status       = $p.Status
            ProblemCode  = $p.ProblemCode
            Meaning      = $p.Meaning
            Layer        = $p.Layer
            RiskTier     = $p.RiskTier
        }
    }

    # --- Driver store -----------------------------------------------------
    Write-Log -Message 'Reading third-party driver packages' -Level STEP
    $store = Get-ThirdPartyDrivers -RecentDays $recentDays
    $result.DriverStoreStatus = $store.Status
    $result.PackageCount = @($store.Packages).Count
    $result.BootCriticalCount = @($store.Packages | Where-Object { $_.RiskTier -eq 'BootCritical' }).Count

    foreach ($r in $store.Recent) {
        $result.RecentDrivers += [ordered]@{
            Provider = $r.Provider; ClassName = $r.ClassName; Version = $r.Version
            Date = $r.Date; RiskTier = $r.RiskTier; BootCritical = $r.BootCritical
        }
    }

    Write-Host ''
    if ($store.Status -eq 'RequiresElevation') {
        Write-Host '  Driver store: NOT READ - needs elevation. That is "not checked", not "nothing recent".' -ForegroundColor Yellow
    }
    elseif ($store.Status -ne 'Read') {
        Write-Host ('  Driver store: unavailable ({0}).' -f $store.Status) -ForegroundColor Yellow
    }
    else {
        Write-Host ('  Third-party driver packages: {0}  ({1} boot-critical)' -f `
                $result.PackageCount, $result.BootCriticalCount) -ForegroundColor Cyan
        Write-Host ('  Installed in the last {0} days: {1}' -f $recentDays, @($store.Recent).Count) -ForegroundColor Cyan
        Write-Host ''

        if (@($store.Recent).Count -gt 0) {
            Write-Host '  Recent packages - correlate these against when the fault started:' -ForegroundColor Cyan
            foreach ($r in $store.Recent) {
                $color = 'Gray'
                if ($r.RiskTier -eq 'BootCritical') { $color = 'Red' }
                elseif ($r.RiskTier -eq 'HighRisk') { $color = 'Yellow' }
                Write-Host ('    {0:yyyy-MM-dd}  {1,-14} {2,-22} {3}' -f `
                        $r.Date, $r.ClassName, $r.Provider, $r.InfName) -ForegroundColor $color
                if ($r.RiskTier -ne 'Standard') {
                    Write-Host ('                  {0}: {1}' -f $r.RiskTier, $r.RiskNote) -ForegroundColor Red
                }
            }
        }
    }

    # --- Restore status ---------------------------------------------------
    $restore = Get-RestoreStatus
    $result.RestorePoint = $restore

    Write-Host ''
    switch ($restore.Status) {
        'PointsPresent' {
            Write-Host ('  System Restore: {0} point(s), newest {1} days old.' -f `
                    $restore.RestorePointCount, $restore.NewestAgeDays) -ForegroundColor Green
        }
        'NoPointsFound' {
            Write-Host '  System Restore: no restore points. There is no safety net on this machine.' -ForegroundColor Yellow
        }
        'RequiresElevation' {
            Write-Host '  System Restore: not checked - needs elevation.' -ForegroundColor Yellow
        }
        default {
            Write-Host '  System Restore: could not be read. Cannot tell whether protection is off or' -ForegroundColor Yellow
            Write-Host '  simply empty - check System Properties > System Protection before relying on it.' -ForegroundColor Yellow
        }
    }

    # --- Rollback guidance ------------------------------------------------
    Write-Host ''
    Write-Host '  ROLLBACK IS NOT AUTOMATED. Options, safest first:' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '    1. Device Manager > device > Properties > Driver > Roll Back Driver' -ForegroundColor Gray
    Write-Host '       Only available if Windows retained the previous package. Always try first -' -ForegroundColor DarkGray
    Write-Host '       it is the only option that restores exactly what was there before.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '    2. System Restore to a point before the driver was installed.' -ForegroundColor Gray
    Write-Host '       rstrui.exe' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '    3. Delete the driver package and let Windows bind the next best driver:' -ForegroundColor Gray
    Write-Host '       pnputil /delete-driver oemNN.inf /uninstall /force' -ForegroundColor DarkGray
    Write-Host '       BLUNT. It affects every device using that package, and if nothing else' -ForegroundColor Red
    Write-Host '       binds, that hardware stops working. NEVER on a boot-critical package -' -ForegroundColor Red
    Write-Host '       a storage controller will cost you the boot (0x7B).' -ForegroundColor Red
    Write-Host ''
    Write-Host '    Have the replacement driver in hand BEFORE removing anything, and take a' -ForegroundColor Yellow
    Write-Host '    restore point first (option 4 below, or -Apply here).' -ForegroundColor Yellow
    Write-Host ''

    # --- Apply: restore point only ----------------------------------------
    if (-not $Apply) {
        Write-Host '  Read-only. Nothing was changed.' -ForegroundColor Cyan
        Write-Host '  -Apply creates a System Restore point. It does not roll anything back.' -ForegroundColor Cyan
        Write-Host ''
        return [pscustomobject]$result
    }

    Assert-Admin
    Write-Banner 'Creating a System Restore point'

    if ($PSCmdlet.ShouldProcess('System Restore', 'Create a restore point')) {
        try {
            Checkpoint-Computer -Description 'Tune-up stick: before driver work' `
                -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
            $result.RestorePointMade = $true
            Write-Log -Message 'Restore point created' -Level OK
            Write-Host '  Restore point created.' -ForegroundColor Green
        }
        catch {
            $msg = $_.Exception.Message
            Write-Log -Message ('Restore point NOT created: ' + $msg) -Level FAIL
            Write-Host '  Restore point was NOT created.' -ForegroundColor Red

            # Name the actual cause instead of listing candidates. "The service
            # cannot be started because it is disabled" means System Protection
            # is switched off for this machine - a different problem from the
            # 24-hour throttle, and a much more important one to know about.
            if ($msg -match 'disabled or does not have enabled devices') {
                $result.RestorePointBlockedBy = 'SystemProtectionDisabled'
                Write-Host '  Cause: SYSTEM PROTECTION IS OFF on this machine. There are no restore' -ForegroundColor Yellow
                Write-Host '  points and none can be made, so there is no rollback safety net at all.' -ForegroundColor Yellow
                Write-Host '' -ForegroundColor Yellow
                Write-Host '  Turn it on before driver work (allocates disk, so it is the owner''s call):' -ForegroundColor Yellow
                Write-Host '    Enable-ComputerRestore -Drive "C:\"' -ForegroundColor DarkGray
                Write-Host '    or System Properties > System Protection > Configure' -ForegroundColor DarkGray
                Write-Host '  Not done automatically - it changes a system setting and consumes disk.' -ForegroundColor DarkGray
            }
            elseif ($msg -match 'frequency|already') {
                $result.RestorePointBlockedBy = 'Throttled'
                Write-Host '  Cause: Windows throttles restore points to one per 24 hours. An earlier' -ForegroundColor Yellow
                Write-Host '  point today already covers you - check the list above.' -ForegroundColor Yellow
            }
            else {
                $result.RestorePointBlockedBy = 'Unknown'
                Write-Host '  Cause could not be determined from the error. Check System Properties >' -ForegroundColor Yellow
                Write-Host '  System Protection before doing driver work without a net.' -ForegroundColor Yellow
            }
        }
    }
    Write-Host ''

    return [pscustomobject]$result
}
