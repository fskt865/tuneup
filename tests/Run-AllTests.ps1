# Run-AllTests.ps1 - run every test suite. Changes nothing outside temp dirs.
# ASCII only, PowerShell 5.1 compatible.

$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot

$suites = @('Test-Sanitizer.ps1', 'Test-Modules.ps1', 'Test-BrowserHijack.ps1', 'Test-Startup.ps1')
$failed = @()

foreach ($s in $suites) {
    $path = Join-Path $here $s
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host ("  MISSING SUITE: " + $s) -ForegroundColor Red
        $failed += $s
        continue
    }

    Write-Host ''
    Write-Host ('==== ' + $s + ' ' + ('=' * [math]::Max(1, 50 - $s.Length))) -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $path
    if ($LASTEXITCODE -ne 0) { $failed += $s }
}

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkCyan
if ($failed.Count -eq 0) {
    Write-Host '  ALL SUITES PASSED' -ForegroundColor Green
}
else {
    Write-Host ('  FAILED SUITES: ' + ($failed -join ', ')) -ForegroundColor Red
}
Write-Host ''
if ($failed.Count -gt 0) { exit 1 }
