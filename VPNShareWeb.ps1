#requires -Version 5.1
param([switch]$NoBrowser, [string]$PortFile = '')
# VPN Share Web - local-only Windows 11 dashboard
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"')
  exit
}
Add-Type -AssemblyName System.Web
$script:logPath = Join-Path $PSScriptRoot 'vpn-share-web.log'
$script:configPath = Join-Path $env:LOCALAPPDATA 'VPNShare\selection.json'
$script:token = [guid]::NewGuid().ToString('N')
$script:selection = @{ input=''; vpn=''; hotspot='' }
if (Test-Path $script:configPath) {
  try {
    $saved = Get-Content -LiteralPath $script:configPath -Raw | ConvertFrom-Json
    foreach ($k in @('input','vpn','hotspot')) { if ($saved.$k) { $script:selection[$k] = [string]$saved.$k } }
  } catch {}
}
function Log([string]$message) {
  $line = ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date),$message)
  Write-Host $line
  try { Add-Content -LiteralPath $script:logPath -Value $line -Encoding UTF8 } catch {}
}
function GuidText($value) { return ([string]$value).Trim('{}').ToLowerInvariant() }
function Adapters {
  return @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object InterfaceGuid | ForEach-Object {
    [pscustomobject]@{
      id = (GuidText $_.InterfaceGuid); name = [string]$_.Name
      description = [string]$_.InterfaceDescription
      status = [string]$_.Status; ifIndex = [int]$_.ifIndex
      vpnCandidate = [bool](($_.Name + ' ' + $_.InterfaceDescription) -match 'tun|tap|vpn|wintun|wireguard|happ|hub|sockstunnel|openvpn|amnezia|hiddify')
      hotspotCandidate = [bool]($_.InterfaceDescription -match 'Wi-Fi Direct Virtual Adapter')
    }
  })
}
function Roles {
  $manager = New-Object -ComObject HNetCfg.HNetShare
  $list = @()
  foreach ($conn in @($manager.EnumEveryConnection())) {
    $p = $manager.NetConnectionProps($conn)
    $c = $manager.INetSharingConfigurationForINetConnection($conn)
    $kind = -1
    if ($c.SharingEnabled) { $kind = [int]$c.SharingConnectionType }
    $list += [pscustomobject]@{ id=(GuidText $p.Guid); name=[string]$p.Name; shared=[bool]$c.SharingEnabled; kind=$kind; config=$c }
  }
  return $list
}
function Chosen($all,$key) {
  $id = [string]$script:selection[$key]
  return @($all | Where-Object { $_.id -eq $id } | Select-Object -First 1)[0]
}
function IncomingReady($adapter) {
  if (-not $adapter -or $adapter.status -ne 'Up') { return $false }
  $ip = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(169\.254\.|127\.)' })
  return ($ip.Count -gt 0)
}
function RoutesOn($adapter) {
  if (-not $adapter) { return $false }
  return @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') }).Count -gt 0
}

# Traffic sampling uses Windows interface byte counters. This is NOT a speed test.
$script:trafficSamples = @{}
function TrafficSample($adapter) {
  $empty = @{ rxMbps=$null; txMbps=$null; available=$false; label='No sample yet' }
  if (-not $adapter -or $adapter.status -ne 'Up') { return $empty }
  try {
    $stats = Get-NetAdapterStatistics -Name $adapter.name -ErrorAction Stop
    $now = [DateTime]::UtcNow
    $key = [string]$adapter.id
    $rx = [double]$stats.ReceivedBytes
    $tx = [double]$stats.SentBytes
    $prev = $script:trafficSamples[$key]
    $script:trafficSamples[$key] = @{ at=$now; rx=$rx; tx=$tx }
    if (-not $prev) { return $empty }
    $seconds = ($now - $prev.at).TotalSeconds
    if ($seconds -le 0.5 -or $seconds -gt 60 -or $rx -lt $prev.rx -or $tx -lt $prev.tx) { return $empty }
    return @{
      rxMbps=[math]::Round((($rx-$prev.rx)*8/1000000)/$seconds,2)
      txMbps=[math]::Round((($tx-$prev.tx)*8/1000000)/$seconds,2)
      available=$true
      label='Interface throughput, not an internet speed test'
    }
  } catch { return @{rxMbps=$null;txMbps=$null;available=$false;label='Adapter counters unavailable'} }
}
function AutoSuggest($all) {
  $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object DestinationPrefix -eq '0.0.0.0/0' | Sort-Object RouteMetric)
  $internet = $null
  foreach ($route in $routes) {
    $match = @($all | Where-Object { $_.ifIndex -eq $route.InterfaceIndex -and $_.status -eq 'Up' -and -not $_.vpnCandidate -and -not $_.hotspotCandidate })
    if ($match.Count -eq 1) { $internet = $match[0]; break }
  }
  $vpnCandidates = @($all | Where-Object { $_.vpnCandidate -and $_.status -eq 'Up' -and (RoutesOn $_) })
  $hotspotCandidates = @($all | Where-Object { $_.hotspotCandidate -and $_.status -eq 'Up' })
  $proposal = @{input='';vpn='';hotspot='';ambiguous=@()}
  if (-not $internet) {
    $physical = @($all | Where-Object { $_.status -eq 'Up' -and -not $_.vpnCandidate -and -not $_.hotspotCandidate -and (IncomingReady $_) })
    if ($physical.Count -eq 1) { $internet=$physical[0] }
  }
  if ($internet) { $proposal.input=$internet.id } else { $proposal.ambiguous+= 'Incoming internet adapter not determined.' }
  if ($vpnCandidates.Count -eq 1) { $proposal.vpn=$vpnCandidates[0].id } else { $proposal.ambiguous+= 'VPN adapter: zero or multiple candidates.' }
  if ($hotspotCandidates.Count -eq 1) { $proposal.hotspot=$hotspotCandidates[0].id } else { $proposal.ambiguous+= 'Hotspot adapter: zero or multiple candidates.' }
  return $proposal
}


function PublicIpProbe {
  $result = @{ ip=$null; status='unavailable'; checkedAt=(Get-Date).ToString('HH:mm:ss'); note='External IP reflects the host routing at test time; not proof of client VPN.' }
  try {
    $request = [Net.HttpWebRequest]::Create('https://api.ipify.org?format=text')
    $request.Method = 'GET'; $request.Timeout = 4500; $request.ReadWriteTimeout = 4500
    $request.UserAgent = 'VPNShare/1.5'
    $response = $request.GetResponse()
    try {
      $reader = New-Object IO.StreamReader($response.GetResponseStream())
      $ip = $reader.ReadToEnd().Trim()
      $parsed = $null
      if ([Net.IPAddress]::TryParse($ip,[ref]$parsed)) { $result.ip=$ip; $result.status='ok' }
    } finally { $response.Close() }
  } catch { $result.note='IP probe failed: '+$_.Exception.Message }
  return $result
}
$script:clientReport = $null
$script:lastIpProbe = $null
$script:lastIpProbeAt = [datetime]::MinValue
function CachedPublicIp {
  if (((Get-Date) - $script:lastIpProbeAt).TotalSeconds -ge 60 -or -not $script:lastIpProbe) {
    $script:lastIpProbeAt = Get-Date
    $script:lastIpProbe = PublicIpProbe
  }
  return $script:lastIpProbe
}
function HotspotAddress {
  $all = @(Adapters)
  $c = Chosen $all 'hotspot'
  if (-not $c -or $c.status -ne 'Up') { return $null }
  $addresses = @(Get-NetIPAddress -InterfaceIndex $c.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -match '^192\.168\.' -or $_.IPAddress -match '^10\.' -or $_.IPAddress -match '^172\.(1[6-9]|2[0-9]|3[01])\.' })
  if ($addresses.Count -eq 0) { return $null }
  return [string]$addresses[0].IPAddress
}
function ClientHtml {
return @'
<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Share — проверка клиента</title>
<style>body{margin:0;background:#0a1020;color:#ecf3ff;font:16px/1.55 system-ui,Segoe UI,sans-serif}main{max-width:640px;margin:35px auto;padding:24px}section{background:#152238;border:1px solid #2b3c56;border-radius:18px;padding:24px}h1{margin:0 0 10px}p{color:#b6c8e1}button{padding:12px 17px;border:0;border-radius:10px;background:#43dea3;color:#06231a;font-weight:700;cursor:pointer}a{color:#9cc4ff}.value{font-size:26px;font-weight:700;word-break:break-word}small{color:#a5b7cf}</style></head>
<body><main><section><h1>Проверка устройства</h1><p>Эта страница открыта через Wi-Fi хот-спот ноутбука. Она не изменяет настройки Windows.</p><p>Внешний IPv4 устройства</p><div id="ip" class="value">Не проверен</div><button id="test">Проверить IP</button><p id="result">Для проверки нужен доступ в интернет и разрешённые запросы к api.ipify.org.</p><p><a href="https://www.dnsleaktest.com/" target="_blank" rel="noopener">Проверить DNS</a> · <a href="https://test-ipv6.com/" target="_blank" rel="noopener">Проверить IPv6</a></p><small>Внешний IP не доказывает, что весь трафик проходит через VPN. Страница отправляет только внешний IP и время проверки на ноутбук. Это не подтверждает шестой узел автоматически.</small></section></main>
<script>document.getElementById('test').onclick=async()=>{const el=document.getElementById('ip');el.textContent='Проверяем…';try{const c=new AbortController();const timer=setTimeout(()=>c.abort(),7000);let r;try{r=await fetch('https://api.ipify.org?format=json',{signal:c.signal,cache:'no-store'})}finally{clearTimeout(timer)}if(!r.ok)throw Error('HTTP '+r.status);const d=await r.json();el.textContent=d.ip||'Нет IP';document.getElementById('result').textContent='Внешний IP определён. Отправляем результат в панель ноутбука…';try{const sent=await fetch('/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:d.ip})});document.getElementById('result').textContent=sent.ok?'IP отправлен на ноутбук. Это не доказывает отсутствие утечек.':'IP определён, но не удалось передать результат ноутбуку.'}catch(e){document.getElementById('result').textContent='IP определён, но отчёт не отправлен.'}}catch(e){el.textContent='Ошибка проверки';document.getElementById('result').textContent=e.message}}</script></body></html>
'@
}
function ClientReport($context) {
  if ($context.Request.ContentLength64 -gt 512 -or $context.Request.ContentLength64 -lt 1) {
    Respond $context 413 'Too large' 'text/plain; charset=utf-8'; return
  }
  $reader = New-Object IO.StreamReader($context.Request.InputStream,[Text.Encoding]::UTF8)
  try { $data = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
  $ip = [string]$data.ip
  $parsed = $null
  if (-not [Net.IPAddress]::TryParse($ip,[ref]$parsed)) {
    Respond $context 400 'Invalid IP' 'text/plain; charset=utf-8'; return
  }
  $script:clientReport = @{
    ip=$ip; source=[string]$context.Request.RemoteEndPoint.Address
    time=(Get-Date).ToString('HH:mm:ss'); receivedAt=(Get-Date).ToString('o')
    note='Client-reported public IP only. This is NOT verification of VPN or DNS/IPv6.'
  }
  Respond $context 200 '{"ok":true}' 'application/json; charset=utf-8'
}
function ClientResponse($context) {
  $context.Response.Headers['Cache-Control']='no-store'
  $context.Response.Headers['X-Content-Type-Options']='nosniff'
  $context.Response.Headers['Content-Security-Policy']="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self' https://api.ipify.org"
  Respond $context 200 (ClientHtml) 'text/html; charset=utf-8'
}
function StartClientListener {
  $ip = HotspotAddress
  if (-not $ip) { throw 'Hotspot IPv4 address not found. Enable hotspot and select Wi-Fi Direct.' }
  if ($script:clientListener) {
    if ($script:clientIp -eq $ip) { return ('http://'+$ip+':18782/') }
    try { $script:clientListener.Stop(); $script:clientListener.Close() } catch {}
  }
  $server = New-Object Net.HttpListener
  $server.Prefixes.Add(('http://'+$ip+':18782/'))
  $server.Start()
  $script:clientListener=$server; $script:clientIp=$ip
  Log ('Client read-only diagnostic listener started on '+$ip)
  return ('http://'+$ip+':18782/')
}
function StopClientListener {
  if ($script:clientListener) { try { $script:clientListener.Stop(); $script:clientListener.Close() } catch {} }
  $script:clientListener=$null;$script:clientIp=$null
  $script:clientReport=$null
}
# Prevent idle system sleep only while this PowerShell process is alive.
# SetThreadExecutionState does not override manual sleep, lid closure or hibernation.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class VPNSharePower {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern uint SetThreadExecutionState(uint flags);
}
'@
$script:keepAwake = $false
$script:lastPowerRefresh = [datetime]::MinValue
function SetKeepAwake([bool]$enabled) {
  $flags = if ($enabled) { [uint32]0x80000001 } else { [uint32]0x80000000 }
  $result = [VPNSharePower]::SetThreadExecutionState($flags)
  if ($result -eq 0) { throw 'Windows rejected the sleep-prevention request.' }
  $script:keepAwake = $enabled
  $script:lastPowerRefresh = Get-Date
  Log ('Background sharing sleep prevention: ' + $(if ($enabled) {'ON'} else {'OFF'}))
}
function RefreshKeepAwake {
  if (-not $script:keepAwake) { return }
  if (((Get-Date)-$script:lastPowerRefresh).TotalSeconds -ge 30) {
    $result = [VPNSharePower]::SetThreadExecutionState([uint32]0x80000001)
    if ($result -eq 0) { Log 'Warning: sleep-prevention refresh failed.' }
    $script:lastPowerRefresh = Get-Date
  }
}
function BuildStatus {
  $all = @(Adapters)
  $a = Chosen $all 'input'; $b = Chosen $all 'vpn'; $c = Chosen $all 'hotspot'
  $roles = @(Roles)
  $ics = $false
  if ($b -and $c) {
    $ics = (@($roles | Where-Object { $_.id -eq $b.id -and $_.shared -and $_.kind -eq 0 }).Count -gt 0) -and
           (@($roles | Where-Object { $_.id -eq $c.id -and $_.shared -and $_.kind -eq 1 }).Count -gt 0)
  }
  $internet = [bool](IncomingReady $a)
  $vpn = [bool]($b -and $b.status -eq 'Up' -and (RoutesOn $b))
  $hotspot = [bool]($c -and $c.status -eq 'Up')
  $neighbors = @()
  if ($hotspot) {
    $neighbors = @(Get-NetNeighbor -InterfaceIndex $c.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.State -in @('Reachable','Stale','Delay','Probe') -and $_.IPAddress -notmatch '^(224\.|239\.|255\.|0\.)' -and $_.LinkLayerAddress -notmatch '^00-00-00-00-00-00$' } |
      Select-Object -Unique IPAddress,LinkLayerAddress,State)
  }
  $diagnostics = @()
  $faults = @()
  if (-not $a) { $diagnostics += 'Choose the incoming internet adapter.' }
  elseif (-not $internet) { $diagnostics += 'Incoming adapter is down or has no usable IPv4 address. This does not prove internet reachability.' }
  if (-not $b) { $diagnostics += 'Choose the VPN TUN adapter.' }
  elseif (-not $vpn) { $diagnostics += 'VPN adapter is down or has no default/split-default IPv4 routes.' }
  if (-not $c) { $diagnostics += 'Turn on Windows Mobile hotspot, then choose Wi-Fi Direct.' }
  elseif (-not $hotspot) { $diagnostics += 'Wi-Fi Direct adapter is not Up. Enable Mobile hotspot.' }
  if ($b -and $c -and -not $ics) { $diagnostics += 'ICS is not mapped from VPN to Wi-Fi Direct.' }
  if (-not $internet) { $faults += @{code='internet';title='Входящий интернет';action='Проверьте USB-модем или Wi-Fi, затем выберите входящий интерфейс.'} }
  if (-not $vpn) { $faults += @{code='vpn';title='VPN TUN';action='Подключите VPN в режиме TUN и проверьте маршруты.'} }
  if (-not $hotspot) { $faults += @{code='hotspot';title='Точка доступа';action='Включите мобильный хот-спот Windows, затем обновите интерфейсы.'} }
  if ($vpn -and $hotspot -and -not $ics) { $faults += @{code='ics';title='Общий доступ ICS';action='Проверьте выбор B и C, затем нажмите «Настроить ICS».'} }
  if ($internet -and $vpn -and $hotspot -and $ics) { $diagnostics += 'Local network configuration looks ready. Verify VPN externally on each client.' }
  $traffic = @{ internet=(TrafficSample $a); vpn=(TrafficSample $b); hotspot=(TrafficSample $c) }
  return @{
    keepAwake = [bool]$script:keepAwake
    clientReport = $script:clientReport
    publicIp = $script:lastIpProbe
    clientPage = $(if ($script:clientListener -and $script:clientListener.IsListening) { 'http://'+$script:clientIp+':18782/' } else { $null })
    faults = $faults
    traffic = $traffic
    timestamp = (Get-Date).ToString('HH:mm:ss')
    adapters = $all; selection = $script:selection
    states = @{ internet=$internet; vpn=$vpn; hotspot=$hotspot; ics=[bool]$ics; clientObserved=($neighbors.Count -gt 0); clientVpnVerified=$false }
    observedClientCount = [int]$neighbors.Count
    countIsEstimate = $true
    clients = @($neighbors | ForEach-Object { @{ip=$_.IPAddress; state=[string]$_.State} })
    diagnostics = $diagnostics
    note = 'Observed IPv4 neighbors are NOT a reliable count of currently connected devices. Client VPN is not verifiable from this PC.'
  }
}
function Configure {
  $all = @(Adapters)
  $a = Chosen $all 'input'; $b = Chosen $all 'vpn'; $c = Chosen $all 'hotspot'
  if (-not $a -or -not $b -or -not $c) { throw 'Select all three adapters first.' }
  if (@(@($a.id,$b.id,$c.id) | Select-Object -Unique).Count -ne 3) { throw 'All three adapters must be different.' }
  if (-not $b.vpnCandidate -or -not $c.hotspotCandidate) { throw 'VPN must be a TUN/TAP adapter and hotspot must be Wi-Fi Direct.' }
  if ($b.status -ne 'Up' -or $c.status -ne 'Up' -or -not (RoutesOn $b)) { throw 'VPN TUN and hotspot must be active; VPN needs IPv4 routes.' }
  $roles = @(Roles)
  if ((@($roles | Where-Object { $_.id -eq $b.id -and $_.shared -and $_.kind -eq 0 }).Count -gt 0) -and
      (@($roles | Where-Object { $_.id -eq $c.id -and $_.shared -and $_.kind -eq 1 }).Count -gt 0)) {
    return 'ICS already configured correctly; no changes made.'
  }
  $snapshot = @($roles | Where-Object shared | ForEach-Object { @{ id=$_.id; kind=$_.kind } })
  try {
    $svc = Get-Service SharedAccess -ErrorAction Stop
    if ($svc.Status -ne 'Running') { Start-Service SharedAccess -ErrorAction Stop }
    foreach ($entry in @(Roles | Where-Object shared)) { $entry.config.DisableSharing() }
    $roles = @(Roles)
    $source = @($roles | Where-Object { $_.id -eq $b.id })[0]
    $target = @($roles | Where-Object { $_.id -eq $c.id })[0]
    if (-not $source -or -not $target) { throw 'Windows ICS cannot find the selected adapters.' }
    $source.config.EnableSharing(0)
    $target = @(Roles | Where-Object { $_.id -eq $c.id })[0]
    $target.config.EnableSharing(1)
    $check = @(Roles)
    if (-not ((@($check | Where-Object { $_.id -eq $b.id -and $_.shared -and $_.kind -eq 0 }).Count -gt 0) -and
               (@($check | Where-Object { $_.id -eq $c.id -and $_.shared -and $_.kind -eq 1 }).Count -gt 0))) {
      throw 'Windows did not retain the new ICS configuration.'
    }
    Log 'ICS configured: VPN -> Wi-Fi Direct'
    return 'ICS configured: VPN -> Wi-Fi Direct'
  } catch {
    $problem = $_.Exception.Message
    Log ('ICS error: ' + $problem)
    try {
      foreach ($entry in @(Roles | Where-Object shared)) { $entry.config.DisableSharing() }
      foreach ($old in $snapshot) {
        $entry = @(Roles | Where-Object { $_.id -eq $old.id })[0]
        if ($entry) { $entry.config.EnableSharing([int]$old.kind) }
      }
    } catch { Log ('Rollback failed: ' + $_.Exception.Message) }
    throw $problem
  }
}
function SaveSelection($data) {
  $all = @(Adapters)
  foreach ($key in @('input','vpn','hotspot')) {
    $id = [string]$data.$key
    if ($id -and -not @($all | Where-Object id -eq $id).Count) { throw ('Unknown adapter: ' + $key) }
    $script:selection[$key] = $id
  }
  $folder = Split-Path $script:configPath -Parent
  if (-not (Test-Path $folder)) { [void](New-Item -ItemType Directory -Path $folder -Force) }
  $script:selection | ConvertTo-Json | Set-Content -LiteralPath $script:configPath -Encoding UTF8
  return 'Adapter selection saved.'
}
function Json($value) { return ConvertTo-Json -InputObject $value -Depth 8 -Compress }
function Respond($context,[int]$status,[string]$body,[string]$type) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($body)
  $context.Response.StatusCode = $status
  $context.Response.ContentType = $type
  $context.Response.ContentEncoding = [Text.Encoding]::UTF8
  $context.Response.Headers['Cache-Control'] = 'no-store'
  $context.Response.Headers['X-Content-Type-Options'] = 'nosniff'
  $context.Response.ContentLength64 = $bytes.Length
  $context.Response.OutputStream.Write($bytes,0,$bytes.Length)
  $context.Response.Close()
}
$script:html = @'
<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Share — Network Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#090e1b;--card:#121b2d;--line:#273449;--muted:#96a7bf;--text:#edf4ff;--green:#42e2a0;--amber:#ffc56b;--red:#ff7389;--blue:#7aabff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 70% -15%,#1d3156,transparent 55%),var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1160px;margin:auto;padding:30px 22px 55px}header{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:26px}h1{margin:0;font-size:28px;letter-spacing:-.8px}h2{margin:0 0 17px;font-size:17px}p{margin:5px 0;color:var(--muted)}.eyebrow{font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--green);font-weight:700}.badge{padding:8px 12px;border:1px solid var(--line);border-radius:30px;color:var(--muted);white-space:nowrap}.layout{display:grid;grid-template-columns:1.5fr 1fr;gap:18px}.card{background:linear-gradient(150deg,#152138,#111a2c);border:1px solid #2a3850;border-radius:20px;padding:23px;box-shadow:0 16px 40px #0002}.wide{grid-column:1/-1}.path{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:0;align-items:start;padding:22px 0 12px}.stage{position:relative;text-align:center;min-width:0}.stage:not(:last-child):after{content:"";position:absolute;height:3px;top:22px;left:calc(50% + 23px);right:calc(-50% + 23px);background:var(--line);z-index:0}.stage.ok:not(:last-child):after{background:linear-gradient(90deg,var(--green),var(--line))}.dot{width:46px;height:46px;border-radius:50%;border:2px solid #46546b;background:#1b2940;margin:0 auto 13px;display:grid;place-items:center;font-size:19px;position:relative;z-index:1}.ok .dot{border-color:var(--green);background:#143d37;box-shadow:0 0 24px #42e2a033}.bad .dot{border-color:var(--red);background:#3d2434}.unknown .dot{border-color:var(--amber)}.stage strong{font-size:13px;display:block}.stage small{display:block;font-size:11px;color:var(--muted);padding:4px}.ok small{color:var(--green)}.bad small{color:var(--red)}.unknown small{color:var(--amber)}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}.metric{background:#0b1425;border:1px solid var(--line);border-radius:14px;padding:14px}.metric b{font-size:26px;display:block}.metric span{font-size:12px;color:var(--muted)}label{font-size:12px;color:#b7c7df;display:block;margin:13px 0 6px}select{width:100%;padding:12px;border-radius:10px;border:1px solid #40506a;background:#0b1425;color:var(--text);font-size:13px;min-width:0}button{border:0;border-radius:10px;padding:11px 15px;background:#263a55;color:white;font-weight:700;cursor:pointer}button:hover{filter:brightness(1.2)}button.primary{background:var(--green);color:#08231b}.buttons{display:flex;flex-wrap:wrap;gap:9px;margin-top:18px}.hint{background:#0c182a;border:1px solid var(--line);padding:13px;border-radius:12px;margin-top:14px;color:#bac9dd;font-size:13px}.alert{border-left:3px solid var(--amber);padding:9px 12px;margin:10px 0;background:#202334;border-radius:5px;color:#e3e9f5}.good{border-left-color:var(--green)}pre{white-space:pre-wrap;word-break:break-word;background:#080f1d;padding:14px;border-radius:12px;color:#b9cbe4;max-height:190px;overflow:auto}.steps{padding-left:20px;color:#c8d7ec}.steps li{margin:9px 0}a{color:#8dbaff}footer{color:#7c8ba2;font-size:12px;margin-top:20px}@media(max-width:850px){.layout{grid-template-columns:1fr}.path{grid-template-columns:repeat(3,1fr);row-gap:25px}.stage:nth-child(3):after{display:none}}@media(max-width:450px){.path{grid-template-columns:repeat(2,1fr)}.stage:nth-child(2):after,.stage:nth-child(4):after{display:none}.stage:nth-child(3):after{display:block}.metrics{grid-template-columns:1fr 1fr}}
</style></head><body><main>
<header><div><div class="eyebrow">Windows 11 · Local dashboard</div><h1>VPN Share <span style="color:var(--green)">●</span></h1><p>Наглядный маршрут интернета через VPN и точку доступа</p></div><div class="badge" id="clock">Подключение…</div></header>
<div class="layout">
<section class="card wide"><h2>Маршрут подключения</h2><div class="path" id="path"></div><div class="metrics"><div class="metric"><b id="count">—</b><span>Наблюдаемых устройств*</span></div><div class="metric"><b id="ready">—</b><span>Локальных этапов готово</span></div><div class="metric"><b id="time">—</b><span>Последняя проверка</span></div></div><div class="hint">* Число определяется по IPv4-соседям в таблице Windows. Это <b>оценка, а не точное число подключённых клиентов</b>. Последний этап «VPN на устройстве» нельзя подтвердить с ноутбука: проверьте IP, DNS и IPv6 на Quest 3 или другом клиенте.</div></section>
<section class="card"><h2>Выбор интерфейсов</h2><label for="input">01 · Входящий интернет — USB или Wi-Fi</label><select id="input"></select><label for="vpn">02 · VPN / TUN — источник ICS</label><select id="vpn"></select><label for="hotspot">03 · Wi-Fi Direct — получатель ICS</label><select id="hotspot"></select><div class="buttons"><button id="detect">Найти автоматически</button><button id="save">Сохранить выбор</button><button id="configure" class="primary">Настроить ICS</button><button id="refresh">Обновить</button></div><div class="hint">Кнопка «Настроить ICS» меняет системный общий доступ. Если уже есть другая настройка ICS, приложение попросит подтверждение.</div></section>
<section class="card wide"><h2>Скорость передачи по трём участкам</h2><div class="metrics" id="speeds"><div class="metric">Загрузка…</div></div><div class="hint">Это текущая нагрузка на сетевые интерфейсы Windows (получено / отправлено, Мбит/с), <b>не</b> максимальная скорость интернета. Входящий канал, VPN и Wi-Fi Direct могут учитывать один и тот же трафик, поэтому значения не складываются. Первая выборка после запуска не содержит скорости.</div></section><section class="card"><h2>Диагностика</h2><div id="faults"></div><div id="alerts"></div><h2 style="margin-top:24px">Подключённые IP (наблюдаемые)</h2><div id="clients" class="hint">Нет данных</div><div class="buttons"><button id="settings">Настройки хот-спота</button><button id="connections">Сетевые подключения</button></div></section>
<section class="card wide"><h2>Проверка внешнего IP и устройства</h2><div class="metrics"><div class="metric"><b id="publicIp" style="font-size:20px">—</b><span>Публичный IP ноутбука (по маршруту ОС)</span></div><div class="metric"><b id="clientPageStatus" style="font-size:16px">Выключена</b><span>Страница проверки Quest 3</span></div><div class="metric"><b id="clientPageAddress" style="font-size:14px;word-break:break-word">—</b><span>Адрес страницы на Quest</span></div></div><div class="buttons"><button id="checkIp">Проверить внешний IP</button><button id="enableClient">Включить страницу Quest</button><button id="disableClient">Выключить страницу</button></div><div class="hint">Проверка IP выполняет HTTPS-запрос к api.ipify.org. Страница Quest открывается <b>только после нажатия кнопки</b> на IP хот-спота, порт 18782, и не содержит административных функций. Если Windows Firewall блокирует порт, потребуется отдельное правило только для локального интерфейса хот-спота. Никакие правила автоматически не меняются. Сравнение IP и проверка DNS/IPv6 выполняются вручную.</div></section><section class="card wide"><h2>Сравнение IP ноутбука и клиента</h2><div id="comparison" class="hint">Запустите проверку IP на ноутбуке и в браузере Quest 3.</div><div class="hint">Совпадение IP — только косвенный признак общего выхода. Несовпадение также не всегда означает ошибку (например, разные IPv4/IPv6 маршруты или VPN-политики). Результат клиента считается актуальным только 2 минуты.</div></section><section class="card wide"><h2>Фоновая раздача и блокировка экрана</h2><div class="metrics"><div class="metric"><b id="awakeStatus" style="font-size:18px">Выключено</b><span>Предотвращение автоматического сна</span></div><div class="metric"><b style="font-size:18px">Win + L</b><span>Блокировка Windows без завершения работы</span></div><div class="metric"><b style="font-size:18px">Экран можно выключить</b><span>Система остаётся активной</span></div></div><div class="buttons"><button id="awakeOn" class="primary">Включить фоновую раздачу</button><button id="awakeOff">Выключить режим</button></div><div class="hint">При включении Windows получает запрос не переходить в <b>автоматический сон из-за бездействия</b>. Блокировка Win + L продолжит работать. Режим не предотвращает ручной сон, гибернацию, действия при закрытии крышки или принудительный сон по политике питания. Для ноутбука с закрытой крышкой отдельно настройте действие крышки в Windows и обеспечьте охлаждение. Режим действует только пока запущен VPN Share; он не запускает VPN автоматически и не восстанавливает отключённый хот-спот.</div></section><section class="card wide"><h2>Три теста реальной скорости — ручной режим</h2><p>Откройте один и тот же сервис измерения в каждом режиме и внесите результаты. Это не счётчики интерфейсов. Приложение не отключает VPN и не меняет маршруты автоматически.</p><div class="metrics" id="speedTests"></div><div class="buttons"><button id="exportTests">Экспорт результатов CSV</button><button id="clearTests">Сбросить результаты</button></div><div class="hint">1. Без VPN: вручную отключите VPN, если это безопасно, и измерьте на ноутбуке. 2. Через VPN: включите VPN и измерьте на ноутбуке. 3. На Quest: подключитесь к хот-споту, откройте тест в браузере Quest и перенесите значения. Рекомендуемый внешний тест: <a href="https://speed.cloudflare.com/" target="_blank" rel="noopener noreferrer">Cloudflare Speed Test</a>. Каждый тест может расходовать значительный объём мобильного трафика. Результаты — ручной ввод, а не автоматическая телеметрия.</div></section><section class="card wide"><h2>История скоростей</h2><p>Последние 5 минут, входящий поток ↓ каждого интерфейса. График строится локально в браузере.</p><div style="overflow:auto"><svg id="history" viewBox="0 0 900 220" style="width:100%;min-width:440px;background:#0a1324;border:1px solid var(--line);border-radius:12px" aria-label="График истории скорости"></svg></div><div class="buttons"><button id="clearHistory">Очистить график</button><button id="exportHistory">Экспорт CSV</button></div><div class="hint">История хранится только в текущей вкладке и не отправляется в облако. При закрытии вкладки она исчезает.</div></section><section class="card wide"><h2>Как включить ICS</h2><ol class="steps"><li>Подключите интернет к ноутбуку по USB или Wi-Fi. Запустите Happ / Hub VPN в режиме <b>TUN</b>.</li><li>Откройте <b>Параметры Windows → Сеть и Интернет → Мобильный хот-спот</b> и включите раздачу по Wi-Fi.</li><li>Выберите выше входящий адаптер, VPN TUN и Microsoft Wi-Fi Direct. Нажмите <b>Сохранить выбор</b>, затем <b>Настроить ICS</b>.</li><li>Если автоматическая настройка не работает: откройте <b>Сетевые подключения</b> → правой кнопкой по VPN TUN → <b>Свойства → Доступ</b> → разрешите общий доступ → выберите <b>Wi-Fi Direct</b> → ОК.</li><li>Подключите Quest 3 к хот-споту и проверьте внешний IP на <a href="https://2ip.ru" target="_blank" rel="noopener">2ip.ru</a>. Дополнительно проверьте DNS и IPv6. Зеленые этапы означают только локальные проверки.</li></ol><div class="hint">Для ручного открытия окна адаптеров: <b>Win + R → ncpa.cpl</b>. Для хот-спота: <b>Win + I → Сеть и Интернет → Мобильный хот-спот</b>.</div><h2 style="margin-top:20px">Журнал</h2><pre id="log">Запуск…</pre></section>
</div><footer>VPN Share · локальный веб-интерфейс доступен только на 127.0.0.1 · Без облака и внешнего сервера · MIT</footer></main>
<script>
const token='__TOKEN__'; let last=null, loading=false, history=[]; const $=id=>document.getElementById(id);
const stages=[['internet','Интернет','Входящий канал','⇩'],['vpn','VPN TUN','Маршруты VPN','◆'],['ics','ICS','Общий доступ','↗'],['hotspot','Wi-Fi','Точка доступа','◉'],['clientObserved','Устройства','Обнаружение','▣'],['clientVpnVerified','VPN клиента','Не проверено','?']];
function addLog(s){$('log').textContent=new Date().toLocaleTimeString()+' · '+s+'\n'+$('log').textContent.slice(0,4000)}
async function api(path,body){const opts={headers:{'X-VPN-Share-Token':token}};if(body!==undefined){opts.method='POST';opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body)}const r=await fetch(path,opts);const data=await r.json();if(!r.ok)throw Error(data.error||'HTTP '+r.status);return data}
function updateSelectors(d){for(const key of ['input','vpn','hotspot']){const el=$(key);const current=el.value||d.selection[key]||'';const candidates=d.adapters.filter(a=>key==='input'?true:key==='vpn'?a.vpnCandidate:a.hotspotCandidate);el.replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent='— Выберите адаптер —';el.append(empty);for(const a of candidates){const o=document.createElement('option');o.value=a.id;o.textContent=a.name+' · '+a.description+' ['+a.status+']';el.append(o)}el.value=candidates.some(a=>a.id===current)?current:''}}


const speedModes=[['direct','Без VPN'],['vpn','Через VPN'],['quest','Quest 3 / раздача']];
let speedResults={};
function renderSpeedTests(){
  const root=$('speedTests');root.replaceChildren();
  for(const [key,title] of speedModes){
    const card=document.createElement('div');card.className='metric';
    const heading=document.createElement('b');heading.textContent=title;heading.style.fontSize='16px';card.append(heading);
    const row={};
    for(const [field,label] of [['down','Загрузка ↓ Мбит/с'],['up','Отдача ↑ Мбит/с'],['ping','Ping мс']]){
      const l=document.createElement('label');l.textContent=label;
      const inp=document.createElement('input');inp.type='number';inp.min='0';inp.max='100000';inp.step='0.01';inp.placeholder='—';inp.style.cssText='width:100%;padding:9px;background:#0b1425;color:white;border:1px solid #40506a;border-radius:8px';
      inp.value=speedResults[key]?.[field]??'';row[field]=inp;card.append(l,inp);
    }
    const save=document.createElement('button');save.textContent='Сохранить измерение';save.style.marginTop='12px';
    save.onclick=()=>{
      const data={at:new Date().toISOString()};
      for(const field of ['down','up','ping']){const raw=row[field].value.trim();if(!raw||!Number.isFinite(Number(raw))||Number(raw)<0||Number(raw)>100000){addLog('Введите корректное значение '+field+' для '+title);return}data[field]=Number(raw)}
      speedResults[key]=data;renderSpeedTests();addLog('Измерение сохранено: '+title)
    };
    card.append(save);
    if(speedResults[key]){const time=document.createElement('div');time.textContent='Сохранено: '+new Date(speedResults[key].at).toLocaleTimeString();time.style.marginTop='8px';card.append(time)}
    root.append(card);
  }
}
$('clearTests').onclick=()=>{if(!confirm('Очистить все три результата?'))return;speedResults={};renderSpeedTests()};
$('exportTests').onclick=()=>{
  const rows=['mode,download_mbps,upload_mbps,ping_ms,measured_at',...speedModes.filter(([key])=>speedResults[key]).map(([key])=>{const r=speedResults[key];return [key,r.down,r.up,r.ping,r.at].join(',')})];
  const blob=new Blob([rows.join('\r\n')],{type:'text/csv;charset=utf-8'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='vpn-share-speedtests.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
};
renderSpeedTests();

function renderHistory(){
  const svg=$('history');svg.replaceChildren();const ns='http://www.w3.org/2000/svg';
  function node(tag,attrs,text){const e=document.createElementNS(ns,tag);for(const [k,v] of Object.entries(attrs))e.setAttribute(k,v);if(text!==undefined)e.textContent=text;svg.append(e);return e}
  const max=Math.max(1,...history.flatMap(h=>['internet','vpn','hotspot'].map(k=>h[k]??0)));
  for(let i=0;i<=4;i++){const y=180-i*40;node('line',{x1:46,y1:y,x2:884,y2:y,stroke:'#26354d','stroke-width':1});node('text',{x:5,y:y+4,fill:'#9caec5','font-size':11},(max*i/4).toFixed(1))}
  const colors={internet:'#55aaff',vpn:'#42e2a0',hotspot:'#ffc56b'};
  for(const [key,color] of Object.entries(colors)){
    const valid=history.map((h,i)=>({i,v:h[key]})).filter(p=>p.v!==null);
    const points=valid.map(p=>(46+p.i/Math.max(1,history.length-1)*838).toFixed(1)+','+(180-p.v/max*160).toFixed(1)).join(' ');
    if(points)node('polyline',{points,fill:'none',stroke:color,'stroke-width':2,'stroke-linecap':'round','stroke-linejoin':'round'});
  }
  node('text',{x:52,y:208,fill:'#55aaff','font-size':12},'● Интернет');
  node('text',{x:185,y:208,fill:'#42e2a0','font-size':12},'● VPN TUN');
  node('text',{x:310,y:208,fill:'#ffc56b','font-size':12},'● Wi-Fi Direct');
  node('text',{x:738,y:208,fill:'#96a7bf','font-size':11},'Мбит/с ↓');
}
function addHistory(d){
  const row={time:new Date().toISOString()};
  for(const key of ['internet','vpn','hotspot'])row[key]=d.traffic?.[key]?.available?d.traffic[key].rxMbps:null;
  history.push(row);if(history.length>60)history.shift();renderHistory();
}
$('clearHistory').onclick=()=>{history=[];renderHistory();addLog('История скоростей очищена')};
$('exportHistory').onclick=()=>{
  const lines=['time,internet_rx_mbps,vpn_rx_mbps,hotspot_rx_mbps',...history.map(h=>[h.time,...['internet','vpn','hotspot'].map(k=>h[k]??'')].join(','))];
  const blob=new Blob([lines.join('\r\n')],{type:'text/csv;charset=utf-8'});
  const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='vpn-share-traffic.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
};

function render(d){last=d;$('clock').textContent='● Обновлено '+d.timestamp;$('awakeStatus').textContent=d.keepAwake?'Включено':'Выключено';$('publicIp').textContent=d.publicIp?.ip||'Не проверен';$('clientPageStatus').textContent=d.clientPage?'Активна':'Выключена';$('clientPageAddress').textContent=d.clientPage||'—';const report=d.clientReport;const age=report?(Date.now()-Date.parse(report.receivedAt))/1000:Infinity;const fresh=age>=0&&age<120;const host=d.publicIp?.ip;$('comparison').textContent=!fresh?'Нет свежего отчёта от Quest 3.':!host?'Quest сообщил IP '+report.ip+'. Сначала проверьте IP ноутбука.':'Ноутбук: '+host+' · Quest: '+report.ip+' · '+(host===report.ip?'IP совпадают. Это НЕ доказательство отсутствия утечек.':'IP отличаются. Проверьте VPN и маршруты.')+' · '+report.time;$('time').textContent=d.timestamp;$('count').textContent=d.observedClientCount+' ≈';const good=['internet','vpn','hotspot','ics','clientObserved'].filter(k=>d.states[k]).length;$('ready').textContent=good+' / 5';$('path').innerHTML=stages.map(([key,title,sub,ico],i)=>{const ok=d.states[key],unknown=key==='clientVpnVerified';return '<div class="stage '+(unknown?'unknown':ok?'ok':'bad')+'"><div class="dot">'+ico+'</div><strong>'+title+'</strong><small>'+(unknown?'Не подтверждено':ok?'● '+sub:'○ Нет сигнала')+'</small></div>'}).join('');$('faults').replaceChildren();for(const f of d.faults||[]){const div=document.createElement('div');div.className='alert';div.textContent=f.title+': '+f.action;$('faults').append(div)}$('alerts').replaceChildren();for(const m of d.diagnostics){const div=document.createElement('div');div.className='alert'+(m.startsWith('Local network')?' good':'');div.textContent=m;$('alerts').append(div)}const names=[['internet','Входящий интернет'],['vpn','VPN TUN'],['hotspot','Раздача Wi-Fi Direct']];$('speeds').replaceChildren();for(const [key,title] of names){const x=d.traffic?.[key];const div=document.createElement('div');div.className='metric';const h=document.createElement('b');h.textContent=x?.available?(x.rxMbps.toFixed(2)+' ↓ / '+x.txMbps.toFixed(2)+' ↑'):'—';h.style.fontSize='18px';const sub=document.createElement('span');sub.textContent=title+' · Мбит/с';div.append(h,sub);$('speeds').append(div)}$('clients').textContent=d.clients.length?d.clients.map(c=>c.ip+' · '+c.state).join(' · '):'Устройства пока не обнаружены';}
async function refresh(reselect=false){if(loading)return;loading=true;try{const d=await api('/api/status');if(reselect||!last)updateSelectors(d);render(d);addHistory(d)}catch(e){$('clock').textContent='Ошибка связи';addLog(e.message)}finally{loading=false}}
$('refresh').onclick=()=>refresh(true);
$('awakeOn').onclick=async()=>{try{const d=await api('/api/power',{enabled:true});addLog(d.message);await refresh()}catch(e){addLog('Питание: '+e.message)}};
$('awakeOff').onclick=async()=>{try{const d=await api('/api/power',{enabled:false});addLog(d.message);await refresh()}catch(e){addLog('Питание: '+e.message)}};

$('checkIp').onclick=async()=>{try{const d=await api('/api/public-ip',{});addLog('Внешний IP: '+(d.ip||d.note));await refresh()}catch(e){addLog('IP: '+e.message)}};
$('enableClient').onclick=async()=>{if(!confirm('Открыть только страницу диагностики на IP хот-спота? Доступ к ней могут получить устройства в этой сети.'))return;try{const d=await api('/api/client-start',{});addLog('Адрес для Quest: '+d.url);await refresh()}catch(e){addLog('Страница Quest: '+e.message)}};
$('disableClient').onclick=async()=>{try{await api('/api/client-stop',{});addLog('Страница Quest выключена');await refresh()}catch(e){addLog(e.message)}};

$('detect').onclick=async()=>{try{const p=await api('/api/suggest');for(const k of ['input','vpn','hotspot']){if(p[k])$(k).value=p[k]}addLog(p.ambiguous.length?'Автопоиск: '+p.ambiguous.join(' '):'Все три интерфейса определены. Проверьте выбор и нажмите «Сохранить выбор».')}catch(e){addLog('Автопоиск: '+e.message)}};
$('save').onclick=async()=>{try{const data=await api('/api/select',{input:$('input').value,vpn:$('vpn').value,hotspot:$('hotspot').value});addLog(data.message);await refresh()}catch(e){addLog('Ошибка: '+e.message)}};
$('configure').onclick=async()=>{if(!confirm('Настроить Windows ICS: VPN → Wi-Fi Direct? Существующий общий доступ может быть изменён.'))return;try{const data=await api('/api/configure',{});addLog(data.message);await refresh()}catch(e){addLog('ICS: '+e.message)}};
$('settings').onclick=async()=>{try{addLog((await api('/api/open-hotspot',{})).message)}catch(e){addLog(e.message)}};
$('connections').onclick=async()=>{try{addLog((await api('/api/open-connections',{})).message)}catch(e){addLog(e.message)}};
refresh(true);setInterval(()=>refresh(false),5000);
</script></body></html>
'@
$script:html = $script:html.Replace('__TOKEN__',$script:token)
$listener = New-Object Net.HttpListener
$port = $null
foreach ($candidate in 18761..18780) {
  try {
    $listener.Prefixes.Clear()
    $listener.Prefixes.Add(('http://127.0.0.1:{0}/' -f $candidate))
    $listener.Start()
    $port = $candidate
    break
  } catch { try { $listener.Stop() } catch {} }
}
if (-not $port) { throw 'Could not bind a localhost port (18761-18780).' }
$url = ('http://127.0.0.1:{0}/' -f $port)
Log ('Dashboard: ' + $url)
if ($PortFile) {
  [IO.File]::WriteAllText($PortFile,[string]$port,(New-Object Text.UTF8Encoding($false)))
}
if (-not $NoBrowser) { Start-Process $url }
try {
  $mainPending = $null
  $clientPending = $null
  while ($listener.IsListening) {
    RefreshKeepAwake
    if (-not $mainPending) { $mainPending = $listener.GetContextAsync() }
    if ($script:clientListener -and $script:clientListener.IsListening -and -not $clientPending) {
      $clientPending = $script:clientListener.GetContextAsync()
    }
    $tasks = @($mainPending)
    if ($clientPending) { $tasks += $clientPending }
    [void][Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$tasks,500)
    if ($clientPending -and $clientPending.IsCompleted) {
      try {
        if (-not $clientPending.IsFaulted -and -not $clientPending.IsCanceled) {
          $remote = $clientPending.Result
          if ($remote.Request.HttpMethod -eq 'GET' -and $remote.Request.Url.AbsolutePath -eq '/') { ClientResponse $remote }
          elseif ($remote.Request.HttpMethod -eq 'POST' -and $remote.Request.Url.AbsolutePath -eq '/report') { ClientReport $remote }
          else { Respond $remote 404 'Not found' 'text/plain; charset=utf-8' }
        }
      } catch { Log ('Client page error: '+$_.Exception.Message) }
      $clientPending = $null
    }
    if (-not $mainPending.IsCompleted) { continue }
    try { $ctx = $mainPending.Result } catch { Log ('Dashboard listener error: '+$_.Exception.Message); break }
    $mainPending = $null
    try {
      if (-not [Net.IPAddress]::IsLoopback($ctx.Request.RemoteEndPoint.Address)) {
        Respond $ctx 403 (Json @{error='Local connections only'}) 'application/json; charset=utf-8'
        continue
      }
      $path = $ctx.Request.Url.AbsolutePath
      if ($ctx.Request.HttpMethod -eq 'GET' -and $path -eq '/') {
        Respond $ctx 200 $script:html 'text/html; charset=utf-8'
        continue
      }
      if ($ctx.Request.Headers['X-VPN-Share-Token'] -ne $script:token) {
        Respond $ctx 403 (Json @{error='Invalid session token'}) 'application/json; charset=utf-8'
        continue
      }
      if ($ctx.Request.HttpMethod -eq 'GET' -and $path -eq '/api/suggest') {
        Respond $ctx 200 (Json (AutoSuggest @(Adapters))) 'application/json; charset=utf-8'
        continue
      }
      if ($ctx.Request.HttpMethod -eq 'GET' -and $path -eq '/api/status') {
        Respond $ctx 200 (Json (BuildStatus)) 'application/json; charset=utf-8'
        continue
      }
      if ($ctx.Request.HttpMethod -eq 'POST' -and $path -in @('/api/select','/api/configure','/api/open-hotspot','/api/open-connections','/api/public-ip','/api/client-start','/api/client-stop','/api/power')) {
        if ($ctx.Request.ContentLength64 -gt 8192) { throw 'Request too large.' }
        $body = ''
        if ($ctx.Request.HasEntityBody) {
          $reader = New-Object IO.StreamReader($ctx.Request.InputStream,[Text.Encoding]::UTF8)
          $body = $reader.ReadToEnd()
          $reader.Dispose()
        }
        if ($path -eq '/api/power') {
          $power = $body | ConvertFrom-Json
          if ($null -eq $power.enabled -or $power.enabled -isnot [bool]) { throw 'Expected boolean enabled.' }
          SetKeepAwake ([bool]$power.enabled)
          Respond $ctx 200 (Json @{message=$(if ($script:keepAwake) {'Фоновая раздача включена.'} else {'Фоновая раздача выключена.'}); enabled=$script:keepAwake}) 'application/json; charset=utf-8'
          continue
        }
        if ($path -eq '/api/public-ip') {
          $script:lastIpProbe = PublicIpProbe
          $script:lastIpProbeAt = Get-Date
          Respond $ctx 200 (Json $script:lastIpProbe) 'application/json; charset=utf-8'
          continue
        }
        if ($path -eq '/api/client-start') {
          $clientUrl = StartClientListener
          Respond $ctx 200 (Json @{url=$clientUrl}) 'application/json; charset=utf-8'
          continue
        }
        if ($path -eq '/api/client-stop') {
          StopClientListener
          Respond $ctx 200 (Json @{message='Client page stopped'}) 'application/json; charset=utf-8'
          continue
        }
        if ($path -eq '/api/select') { $message = SaveSelection ($body | ConvertFrom-Json) }
        elseif ($path -eq '/api/configure') { $message = Configure }
        elseif ($path -eq '/api/open-hotspot') { Start-Process 'ms-settings:network-mobilehotspot'; $message='Opened Mobile hotspot settings.' }
        else { Start-Process 'ncpa.cpl'; $message='Opened Network connections.' }
        Respond $ctx 200 (Json @{message=$message}) 'application/json; charset=utf-8'
        continue
      }
      Respond $ctx 404 (Json @{error='Not found'}) 'application/json; charset=utf-8'
    } catch {
      $message = $_.Exception.Message
      Log ('Request error: ' + $message)
      try { Respond $ctx 500 (Json @{error=$message}) 'application/json; charset=utf-8' } catch {}
    }
  }
} finally { try { SetKeepAwake $false } catch {}; StopClientListener; $listener.Stop(); $listener.Close() }
