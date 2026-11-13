#requires -Version 5.1
# Run on Windows: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Smoke.ps1
# Read-only: never imports/executes VPNShareWeb.ps1, never modifies ICS.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$source = Join-Path $root 'VPNShareWeb.ps1'
if (-not (Test-Path $source)) { throw 'VPNShareWeb.ps1 not found' }
$code = Get-Content -LiteralPath $source -Raw -Encoding UTF8
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($code,[ref]$tokens,[ref]$errors)
if ($errors.Count -gt 0) {
  $errors | ForEach-Object { Write-Host ('PS syntax: ' + $_.Message + ' at ' + $_.Extent.StartLineNumber) -ForegroundColor Red }
  throw ('PowerShell parser reported ' + $errors.Count + ' errors')
}
Write-Host 'PASS: PowerShell syntax' -ForegroundColor Green
$functions = @($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true) | ForEach-Object Name)
foreach ($required in @('Adapters','Roles','Chosen','RoutesOn','BuildStatus','Configure','SaveSelection','TrafficSample','ClientResponse','ClientReport','StartClientListener','StopClientListener')) {
  if ($required -notin $functions) { throw ('Missing function: ' + $required) }
}
Write-Host 'PASS: required PowerShell functions exist' -ForegroundColor Green
if ($code -notmatch [regex]::Escape('127.0.0.1:') -or $code -notmatch 'X-VPN-Share-Token') {
  throw 'Dashboard binding or token guard missing'
}
if ($code -notmatch 'if \(\$path -eq ''/api/client-start''\)' -or $code -notmatch 'if \(\$path -eq ''/api/client-stop''\)') {
  throw 'Client listener controls missing'
}
Write-Host 'PASS: expected local dashboard and client listener guards present' -ForegroundColor Green
$match = [regex]::Match($code,'(?s)\$script:html\s*=\s*@''\r?\n(.*?)\r?\n''@')
if (-not $match.Success) { throw 'Dashboard HTML here-string not found' }
$html = $match.Groups[1].Value
foreach ($id in @('path','speeds','speedTests','history','comparison','checkIp','enableClient','disableClient')) {
  if ($html -notmatch ('id="' + [regex]::Escape($id) + '"')) { throw ('Missing dashboard element: ' + $id) }
}
Write-Host 'PASS: expected dashboard elements exist' -ForegroundColor Green
$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) {
  $js = [regex]::Match($html,'(?s)<script>(.*?)</script>')
  if (-not $js.Success) { throw 'Dashboard script not found' }
  $temp = Join-Path ([IO.Path]::GetTempPath()) ('vpnshare-check-' + [guid]::NewGuid().ToString('N') + '.js')
  try {
    [IO.File]::WriteAllText($temp,$js.Groups[1].Value,[Text.UTF8Encoding]::new($false))
    & $node.Source --check $temp
    if ($LASTEXITCODE -ne 0) { throw 'Dashboard JavaScript syntax invalid' }
    Write-Host 'PASS: dashboard JavaScript syntax' -ForegroundColor Green
  } finally { Remove-Item -LiteralPath $temp -ErrorAction SilentlyContinue }
} else {
  Write-Warning 'Node.js not found; JavaScript syntax check skipped (optional).'
}
Write-Host 'Smoke checks complete. These checks do NOT test ICS, VPN routing or Quest connectivity.' -ForegroundColor Cyan
