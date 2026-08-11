@echo off
rem TRIAGE.cmd - double-click and the stick works the machine.
rem
rem No menu, no choices up front: elevate, scan everything read-only, rank
rem what was found, then ask before each fix, one YES at a time. This is the
rem front door for "let's get the whole picture"; RUN.cmd remains the menu
rem for running one thing on its own.
rem
rem Windows has not allowed a USB stick to run anything by itself on insert
rem since Windows 7, deliberately. Double-clicking this file is the floor.

setlocal
title Triage

rem fltmc is a more reliable admin probe than "net session" - the latter
rem fails when the Server service is disabled, which it often is.
fltmc >nul 2>&1
if %errorlevel% equ 0 goto :run

echo.
echo   Requesting administrator rights...
echo.

rem No -ArgumentList: this launcher takes no arguments, and Start-Process
rem rejects an empty string for that parameter - the binding error would kill
rem the relaunch before UAC ever appeared. Branching uses goto, not
rem parenthesised if-blocks, because the PowerShell one-liner contains ")".
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; Start-Process -FilePath '%~f0' -Verb RunAs"
if errorlevel 1 goto :elevate_failed
exit /b

:elevate_failed
echo.
echo   Elevation was declined, or it failed.
echo.
echo   If you did not see a UAC prompt at all, right-click TRIAGE.cmd and
echo   choose "Run as administrator" instead.
echo.
echo   An unelevated triage still scans, but SMART and the component store
echo   come back UNKNOWN and no fix can be applied. Worth it only when the
echo   machine cannot elevate at all - and that symptom has its own module.
echo.
pause
exit /b

:run
pushd "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-TuneUp.ps1" -Action Triage -Walk
popd

rem The window was almost certainly opened by a double-click, so without this
rem it closes the moment the run ends - taking the findings with it.
echo.
pause
endlocal
