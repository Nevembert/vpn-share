@echo off
setlocal
cd /d "%~dp0"
echo Starting VPN Share web dashboard...
set "VPN_SHARE_DIR=%~dp0"
rem Normalize UTF-8 BOM before Windows PowerShell 5.1 parses Cyrillic source.
rem This also repairs copies whose BOM was stripped by editors or ZIP tools.
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p=Join-Path $env:VPN_SHARE_DIR 'VPNShareWeb.ps1'; $b=[IO.File]::ReadAllBytes($p); if($b.Length -lt 3 -or $b[0] -ne 239 -or $b[1] -ne 187 -or $b[2] -ne 191){$u=New-Object Text.UTF8Encoding($false,$true); try{$t=$u.GetString($b)}catch{throw 'Script is not valid UTF-8; download a fresh copy.'}; [IO.File]::WriteAllText($p,$t,(New-Object Text.UTF8Encoding($true))); Write-Host 'Repaired UTF-8 BOM.'}"
if errorlevel 1 (
  echo Encoding repair failed. Download a fresh ZIP.
  pause
  exit /b 1
)
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0VPNShareWeb.ps1"
if errorlevel 1 (
  echo.
  echo Launch failed. Check errors above.
  pause
)
