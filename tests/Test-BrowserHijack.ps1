# Test-BrowserHijack.ps1 - shortcut hijack detection and repair.
# ASCII only, PowerShell 5.1 compatible.
#
# Builds synthetic shortcuts in a temp directory and runs the real detector
# and the real fixer against them. Touches nothing outside its own temp dir.
#
# This is the only code path in the browser module that WRITES, so it is the
# one that has to be proved: it must catch the hijack, must NOT destroy
# legitimate command-line switches, and must not record the query string of a
# redirect URL (which routinely carries a machine-tied id).

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'lib\Common.ps1')
. (Join-Path $Root 'lib\Sanitize.ps1')
. (Join-Path $Root 'modules\Repair-BrowserHijack.ps1')

$pass = 0
$fail = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  PASS  " + $Name) -ForegroundColor Green; $script:pass++ }
    else { Write-Host ("  FAIL  " + $Name + $(if ($Detail) { "  [$Detail]" } else { '' })) -ForegroundColor Red; $script:fail++ }
}

Write-Host ''
Write-Host '  Argument splitting' -ForegroundColor Cyan
Write-Host '  ------------------' -ForegroundColor DarkGray

$s1 = Split-ShortcutArguments -Arguments '--profile-directory="Default" http://evil.example/?uid=abc123'
Assert-True 'Detects the redirect URL'            ($s1.Redirects.Count -eq 1)
Assert-True 'Preserves the legitimate switch'     ($s1.Keep -eq '--profile-directory="Default"') "keep=$($s1.Keep)"

$s2 = Split-ShortcutArguments -Arguments '--profile-directory="Default" --no-first-run'
Assert-True 'Clean arguments produce no findings' ($s2.Redirects.Count -eq 0)
Assert-True 'Clean arguments are left intact'     ($s2.Keep -eq '--profile-directory="Default" --no-first-run')

$s3 = Split-ShortcutArguments -Arguments 'www.searchthing.example/redirect'
Assert-True 'Detects a bare www. redirect'        ($s3.Redirects.Count -eq 1)
Assert-True 'Nothing left to keep'                ($s3.Keep -eq '')

$s4 = Split-ShortcutArguments -Arguments ''
Assert-True 'Empty arguments are safe'            ($s4.Redirects.Count -eq 0)

Write-Host ''
Write-Host '  Live shortcut detection and repair' -ForegroundColor Cyan
Write-Host '  ----------------------------------' -ForegroundColor DarkGray

$temp = Join-Path ([IO.Path]::GetTempPath()) ('tuneup-lnk-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $temp -Force | Out-Null

try {
    $shell = New-Object -ComObject WScript.Shell

    # Hijacked: browser target, legitimate switch, plus an appended redirect.
    $hijacked = Join-Path $temp 'Google Chrome.lnk'
    $sc = $shell.CreateShortcut($hijacked)
    $sc.TargetPath = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
    $sc.Arguments = '--profile-directory="Default" http://evil.example/?uid=abc123'
    $sc.Save()

    # Clean: same browser, only a real switch.
    $clean = Join-Path $temp 'Chrome Clean.lnk'
    $sc2 = $shell.CreateShortcut($clean)
    $sc2.TargetPath = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
    $sc2.Arguments = '--no-first-run'
    $sc2.Save()

    # Non-browser target with a URL argument - must be ignored entirely.
    $other = Join-Path $temp 'Some App.lnk'
    $sc3 = $shell.CreateShortcut($other)
    $sc3.TargetPath = 'C:\Windows\System32\notepad.exe'
    $sc3.Arguments = 'http://example.com/thing'
    $sc3.Save()

    $found = @(Get-ShortcutHijacks -Roots @($temp))

    Assert-True 'Finds exactly one hijacked shortcut' ($found.Count -eq 1) ("count=" + $found.Count)

    if ($found.Count -eq 1) {
        $f = $found[0]
        Assert-True 'Identifies the right shortcut'   ($f.ShortcutName -eq 'Google Chrome.lnk')
        Assert-True 'Identifies the browser'          ($f.Browser -eq 'chrome.exe')
        Assert-True 'Records the redirect host'       ($f.RedirectHosts -contains 'evil.example')

        # Privacy: the uid in the query string must never be recorded.
        $asText = ($f | ConvertTo-Json -Depth 5)
        Assert-True 'Does NOT record the query string' ($asText -notmatch 'abc123') 'uid leaked into finding'
        Assert-True 'Does NOT record the full URL'     ($asText -notmatch 'evil\.example/')

        # Repair, then re-read the shortcut from disk.
        Repair-ShortcutHijack -Finding $f

        $after = $shell.CreateShortcut($hijacked)
        Assert-True 'Redirect removed from arguments'  ($after.Arguments -notmatch 'evil\.example')
        Assert-True 'Legitimate switch survived repair' ($after.Arguments -eq '--profile-directory="Default"') "args=$($after.Arguments)"
        Assert-True 'Target path untouched'            ($after.TargetPath -like '*chrome.exe')

        # A repaired shortcut must not be found again.
        $second = @(Get-ShortcutHijacks -Roots @($temp))
        Assert-True 'Repaired shortcut no longer flagged' ($second.Count -eq 0) ("count=" + $second.Count)

        # Backup must exist, and must be on this machine, not the stick.
        $backup = Join-Path (Get-HijackBackupDir) 'Google Chrome.lnk'
        Assert-True 'Backup was written before the fix' (Test-Path -LiteralPath $backup)
        Assert-True 'Backup lives under ProgramData'    ((Get-HijackBackupDir) -like (Join-Path $env:ProgramData '*'))
    }

    # The clean and non-browser shortcuts must be untouched.
    $cleanAfter = $shell.CreateShortcut($clean)
    Assert-True 'Clean shortcut untouched'      ($cleanAfter.Arguments -eq '--no-first-run')
    $otherAfter = $shell.CreateShortcut($other)
    Assert-True 'Non-browser shortcut untouched' ($otherAfter.Arguments -eq 'http://example.com/thing')
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path (Get-HijackBackupDir) 'Google Chrome.lnk') -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
