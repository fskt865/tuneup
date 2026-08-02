@echo off
rem RUN.cmd - launcher for the tune-up stick.
rem
rem Exists because you cannot rely on a customer machine letting you run a
rem .ps1 by double-click: execution policy is Restricted by default and the
rem stick will not be the same drive letter twice. This handles both, plus
rem elevation.

setlocal
title Tune-Up Stick

rem fltmc is a more reliable admin probe than "net session" - the latter
rem fails when the Server service is disabled, which it often is.
fltmc >nul 2>&1
if %errorlevel% equ 0 goto :run

echo.
echo   Requesting administrator rights...
echo.

rem Pass -ArgumentList ONLY when there are arguments to pass.
rem
rem Start-Process rejects an empty string for that parameter, so the old
rem unconditional -ArgumentList '%%*' threw a binding error the moment anyone
rem double-clicked this file with no arguments. The relaunch died before UAC
rem was ever requested and the window just closed - it looked like UAC had
rem been suppressed when nothing had actually asked for it.
rem
rem Branching is done with goto rather than parenthesised if-blocks on purpose:
rem the PowerShell one-liners below contain ")" characters, which would close a
rem cmd if-block early and break the script in a far more confusing way.
if "%~1"=="" goto :elevate_plain

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%*'"
goto :elevate_done

:elevate_plain
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; Start-Process -FilePath '%~f0' -Verb RunAs"

:elevate_done
if errorlevel 1 goto :elevate_failed
exit /b

:elevate_failed
echo.
echo   Elevation was declined, or it failed.
echo.
echo   If you did not see a UAC prompt at all, right-click RUN.cmd and choose
echo   "Run as administrator" instead.
echo.
echo   Everything read-only still works without elevation - the report, and
echo   every module without -Apply. Repairs and SMART do need it.
echo.
pause
exit /b

:run
pushd "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-TuneUp.ps1" %*
popd

endlocal
