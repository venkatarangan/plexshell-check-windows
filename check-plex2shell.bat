@echo off
setlocal
pushd "%~dp0" || exit /b 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Check-Plex2Shell.ps1" %*
set "scanExitCode=%errorlevel%"
popd
exit /b %scanExitCode%
