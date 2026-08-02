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
if %errorlevel% neq 0 (
    echo.
    echo   Requesting administrator rights...
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%*'"
    exit /b
)

pushd "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-TuneUp.ps1" %*
popd

endlocal
