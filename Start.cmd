@echo off
setlocal
cd /d "%~dp0"
echo Starting VPN Share web dashboard...
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0VPNShareWeb.ps1"
if errorlevel 1 (
  echo.
  echo Launch failed. Check errors above.
  pause
)
