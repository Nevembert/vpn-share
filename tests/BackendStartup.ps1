#requires -Version 5.1
# Read-only startup integration test. Does not configure or change ICS.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$source = Join-Path $root 'VPNShareWeb.ps1'
$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$id = [guid]::NewGuid().ToString('N')
$portFile = Join-Path $tempRoot ('vpnshare-port-' + $id + '.txt')
$outFile = Join-Path $tempRoot ('vpnshare-out-' + $id + '.txt')
$errFile = Join-Path $tempRoot ('vpnshare-err-' + $id + '.txt')
$process = $null
try {
  $argsLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $source + '" -NoBrowser -PortFile "' + $portFile + '"'
  $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $argsLine -PassThru -WindowStyle Hidden -RedirectStandardOutput $outFile -RedirectStandardError $errFile
  $ready = $false
  for ($i=0; $i -lt 100; $i++) {
    $process.Refresh()
    if ($process.HasExited) { break }
    if (Test-Path $portFile) {
      try {
        $port = [int]([IO.File]::ReadAllText($portFile).Trim())
        if ($port -ge 18761 -and $port -le 18780) {
          $response = Invoke-WebRequest -Uri ('http://127.0.0.1:' + $port + '/') -UseBasicParsing -TimeoutSec 2
          if ($response.StatusCode -eq 200 -and $response.Content -match '<title>VPN Share') {
            $ready = $true
            break
          }
        }
      } catch { }
    }
    Start-Sleep -Milliseconds 200
  }
  if (-not $ready) {
    $stdout = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { '' }
    $stderr = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { '' }
    throw ('Backend failed to start and serve HTML. stdout=' + $stdout + ' stderr=' + $stderr)
  }
  Write-Host ('PASS: backend serves HTTP on localhost port ' + $port) -ForegroundColor Green
} finally {
  if ($process) {
    try { if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } } catch {}
    $process.Dispose()
  }
  foreach ($path in @($portFile,$outFile,$errFile)) {
    Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
  }
}
