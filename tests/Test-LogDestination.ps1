# Test-LogDestination.ps1 - verifies -LogToStick behaviour in lib\Common.ps1.
# ASCII only, PowerShell 5.1 compatible. Writes only into a temp directory.
#
# Prints PASS/FAIL and token classes ONLY - never a value it found. A test that
# proves redaction works by printing the hostname it leaked is the leak.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')

$pass = 0
$fail = 0

function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) {
        Write-Host ("  PASS  " + $Name) -ForegroundColor Green
        $script:pass++
    }
    else {
        Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red
        $script:fail++
    }
}

function Test-Contains {
    param([string]$Haystack, [string]$Needle)
    if ([string]::IsNullOrEmpty($Needle)) { return $false }
    return ($Haystack.IndexOf($Needle, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}

Write-Host ''
Write-Host '  Log destination tests' -ForegroundColor Cyan
Write-Host '  ---------------------' -ForegroundColor DarkGray

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('gstuneup-logtest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))

try {
    # --- default: local and unsanitized ------------------------------------
    Assert-True 'Default destination is the local root' ((Get-LogDestination) -eq $script:LocalRoot)
    Assert-True 'Default log is NOT sanitized' (-not (Test-LogIsSanitized))

    $unchecked = Test-LogFileClean
    Assert-True 'Unsanitized log reports Checked=false (three states, not two)' (-not $unchecked.Checked)
    Assert-True 'Unsanitized log gives a reason rather than a bare false' ($unchecked.Reason -ne '')

    # --- redirect to a stick-like directory --------------------------------
    Set-LogDestination -Path $tempRoot -Sanitize

    Assert-True 'Destination follows Set-LogDestination' ((Get-LogDestination) -eq $tempRoot)
    Assert-True 'Redirected log is marked sanitized' (Test-LogIsSanitized)

    # The stamped filename must be recreated under the NEW root. Reusing the
    # old path here would write to the machine while reporting the stick.
    Write-Log -Message 'log destination test - first line' -Quiet
    Assert-True 'Log file was created under the new root' ($script:LogPath -like (Join-Path $tempRoot '*'))
    Assert-True 'Log file is not under the local root' (-not ($script:LogPath -like (Join-Path $script:LocalRoot '*')))
    Assert-True 'Log file exists on disk' (Test-Path -LiteralPath $script:LogPath)

    # --- redaction actually happens on the way to the file -----------------
    $map = New-RedactionMap
    $hostLiteral = $env:COMPUTERNAME
    $hostInMap = @($map | Where-Object { $_.Value -eq $hostLiteral }).Count -gt 0

    Write-Log -Message ("machine is {0} and profile is C:\Users\SomeAccountName" -f $hostLiteral) -Quiet
    Write-Log -Message 'contact someone@example.com from 192.168.1.50' -Quiet

    $text = Get-Content -LiteralPath $script:LogPath -Raw

    if ($hostInMap) {
        Assert-True 'Hostname does NOT survive into the log file' (-not (Test-Contains -Haystack $text -Needle $hostLiteral))
        Assert-True 'Hostname was replaced with its token' (Test-Contains -Haystack $text -Needle '<HOST>')
    }
    else {
        Write-Host '  SKIP  Hostname checks (hostname not eligible for the map)' -ForegroundColor DarkGray
    }

    Assert-True 'User profile path was redacted' (Test-Contains -Haystack $text -Needle '<USERPROFILE>')
    Assert-True 'Email was redacted'             (Test-Contains -Haystack $text -Needle '<EMAIL>')
    Assert-True 'IPv4 was redacted'              (Test-Contains -Haystack $text -Needle '<IPV4>')
    Assert-True 'Raw email did not survive'      (-not (Test-Contains -Haystack $text -Needle 'someone@example.com'))
    Assert-True 'Raw IPv4 did not survive'       (-not (Test-Contains -Haystack $text -Needle '192.168.1.50'))

    # The message text itself must still be readable - redaction that eats the
    # diagnostic content produces a clean log that is worth nothing.
    Assert-True 'Non-identifying text survives redaction' (Test-Contains -Haystack $text -Needle 'log destination test')

    # --- verification passes on a clean log --------------------------------
    $clean = Test-LogFileClean
    Assert-True 'Clean log verifies as checked' $clean.Checked
    Assert-True 'Clean log verifies as clean'   $clean.Clean ("hits=" + ($clean.Hits -join ','))
    Assert-True 'Clean log was not removed'     (Test-Path -LiteralPath $script:LogPath)

    # --- verification catches and destroys a dirty log ---------------------
    # Simulates a redaction miss by writing an identifier straight past
    # Write-Log. This is the case the end-of-run check exists for.
    if ($hostInMap) {
        $dirtyPath = $script:LogPath
        Add-Content -LiteralPath $dirtyPath -Value ('leaked: ' + $hostLiteral) -Encoding UTF8

        $dirty = Test-LogFileClean -RemoveIfDirty
        Assert-True 'Dirty log is detected'              ($dirty.Checked -and -not $dirty.Clean)
        Assert-True 'Dirty log reports which class leaked' (@($dirty.Hits).Count -gt 0)
        Assert-True 'Dirty log is deleted from the stick' $dirty.Removed
        Assert-True 'Dirty log is really gone'            (-not (Test-Path -LiteralPath $dirtyPath))
    }
    else {
        Write-Host '  SKIP  Dirty-log checks (hostname not eligible for the map)' -ForegroundColor DarkGray
    }

    # --- missing file is "not checked", never "clean" ----------------------
    $script:LogPath = Join-Path $tempRoot 'does-not-exist.log'
    $missing = Test-LogFileClean
    Assert-True 'Missing log is not reported as clean' (-not $missing.Clean)
    Assert-True 'Missing log is reported as unchecked' (-not $missing.Checked)
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
exit 0
