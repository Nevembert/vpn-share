#requires -Version 5.1
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
function RoutesOn($adapter) {
  if (-not $adapter) { return $false }
  return @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') }).Count -gt 0
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
  $internet = [bool]($a -and $a.status -eq 'Up' -and (RoutesOn $a))
  $vpn = [bool]($b -and $b.status -eq 'Up' -and (RoutesOn $b))
  $hotspot = [bool]($c -and $c.status -eq 'Up')
  $neighbors = @()
  if ($hotspot) {
    $neighbors = @(Get-NetNeighbor -InterfaceIndex $c.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.State -in @('Reachable','Stale','Delay','Probe') -and $_.IPAddress -notmatch '^(224\.|239\.|255\.|0\.)' -and $_.LinkLayerAddress -notmatch '^00-00-00-00-00-00$' } |
      Select-Object -Unique IPAddress,LinkLayerAddress,State)
  }
  $diagnostics = @()
  if (-not $a) { $diagnostics += 'Choose the incoming internet adapter.' }
  elseif (-not $internet) { $diagnostics += 'Incoming adapter has no active IPv4 default route.' }
  if (-not $b) { $diagnostics += 'Choose the VPN TUN adapter.' }
  elseif (-not $vpn) { $diagnostics += 'VPN adapter is down or has no default/split-default IPv4 routes.' }
  if (-not $c) { $diagnostics += 'Turn on Windows Mobile hotspot, then choose Wi-Fi Direct.' }
  elseif (-not $hotspot) { $diagnostics += 'Wi-Fi Direct adapter is not Up. Enable Mobile hotspot.' }
  if ($b -and $c -and -not $ics) { $diagnostics += 'ICS is not mapped from VPN to Wi-Fi Direct.' }
  if ($internet -and $vpn -and $hotspot -and $ics) { $diagnostics += 'Local network configuration looks ready. Verify VPN externally on each client.' }
  return @{
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
<section class="card"><h2>Выбор интерфейсов</h2><label for="input">01 · Входящий интернет — USB или Wi-Fi</label><select id="input"></select><label for="vpn">02 · VPN / TUN — источник ICS</label><select id="vpn"></select><label for="hotspot">03 · Wi-Fi Direct — получатель ICS</label><select id="hotspot"></select><div class="buttons"><button id="save">Сохранить выбор</button><button id="configure" class="primary">Настроить ICS</button><button id="refresh">Обновить</button></div><div class="hint">Кнопка «Настроить ICS» меняет системный общий доступ. Если уже есть другая настройка ICS, приложение попросит подтверждение.</div></section>
<section class="card"><h2>Диагностика</h2><div id="alerts"></div><h2 style="margin-top:24px">Подключённые IP (наблюдаемые)</h2><div id="clients" class="hint">Нет данных</div><div class="buttons"><button id="settings">Настройки хот-спота</button><button id="connections">Сетевые подключения</button></div></section>
<section class="card wide"><h2>Как включить ICS</h2><ol class="steps"><li>Подключите интернет к ноутбуку по USB или Wi-Fi. Запустите Happ / Hub VPN в режиме <b>TUN</b>.</li><li>Откройте <b>Параметры Windows → Сеть и Интернет → Мобильный хот-спот</b> и включите раздачу по Wi-Fi.</li><li>Выберите выше входящий адаптер, VPN TUN и Microsoft Wi-Fi Direct. Нажмите <b>Сохранить выбор</b>, затем <b>Настроить ICS</b>.</li><li>Если автоматическая настройка не работает: откройте <b>Сетевые подключения</b> → правой кнопкой по VPN TUN → <b>Свойства → Доступ</b> → разрешите общий доступ → выберите <b>Wi-Fi Direct</b> → ОК.</li><li>Подключите Quest 3 к хот-споту и проверьте внешний IP на <a href="https://2ip.ru" target="_blank" rel="noopener">2ip.ru</a>. Дополнительно проверьте DNS и IPv6. Зеленые этапы означают только локальные проверки.</li></ol><div class="hint">Для ручного открытия окна адаптеров: <b>Win + R → ncpa.cpl</b>. Для хот-спота: <b>Win + I → Сеть и Интернет → Мобильный хот-спот</b>.</div><h2 style="margin-top:20px">Журнал</h2><pre id="log">Запуск…</pre></section>
</div><footer>VPN Share · локальный веб-интерфейс доступен только на 127.0.0.1 · Без облака и внешнего сервера · MIT</footer></main>
<script>
const token='__TOKEN__'; let last=null, loading=false; const $=id=>document.getElementById(id);
const stages=[['internet','Интернет','Входящий канал','⇩'],['vpn','VPN TUN','Маршруты VPN','◆'],['hotspot','Wi-Fi','Точка доступа','◉'],['ics','ICS','Общий доступ','↗'],['clientObserved','Устройства','Обнаружение','▣'],['clientVpnVerified','VPN клиента','Не проверено','?']];
function addLog(s){$('log').textContent=new Date().toLocaleTimeString()+' · '+s+'\n'+$('log').textContent.slice(0,4000)}
async function api(path,body){const opts={headers:{'X-VPN-Share-Token':token}};if(body!==undefined){opts.method='POST';opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body)}const r=await fetch(path,opts);const data=await r.json();if(!r.ok)throw Error(data.error||'HTTP '+r.status);return data}
function updateSelectors(d){for(const key of ['input','vpn','hotspot']){const el=$(key);const current=el.value||d.selection[key]||'';const candidates=d.adapters.filter(a=>key==='input'?true:key==='vpn'?a.vpnCandidate:a.hotspotCandidate);el.replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent='— Выберите адаптер —';el.append(empty);for(const a of candidates){const o=document.createElement('option');o.value=a.id;o.textContent=a.name+' · '+a.description+' ['+a.status+']';el.append(o)}el.value=candidates.some(a=>a.id===current)?current:''}}
function render(d){last=d;$('clock').textContent='● Обновлено '+d.timestamp;$('time').textContent=d.timestamp;$('count').textContent=d.observedClientCount+' ≈';const good=['internet','vpn','hotspot','ics','clientObserved'].filter(k=>d.states[k]).length;$('ready').textContent=good+' / 5';$('path').innerHTML=stages.map(([key,title,sub,ico],i)=>{const ok=d.states[key],unknown=key==='clientVpnVerified';return '<div class="stage '+(unknown?'unknown':ok?'ok':'bad')+'"><div class="dot">'+ico+'</div><strong>'+title+'</strong><small>'+(unknown?'Не подтверждено':ok?'● '+sub:'○ Нет сигнала')+'</small></div>'}).join('');$('alerts').replaceChildren();for(const m of d.diagnostics){const div=document.createElement('div');div.className='alert'+(m.startsWith('Local network')?' good':'');div.textContent=m;$('alerts').append(div)}$('clients').textContent=d.clients.length?d.clients.map(c=>c.ip+' · '+c.state).join(' · '):'Устройства пока не обнаружены';}
async function refresh(reselect=false){if(loading)return;loading=true;try{const d=await api('/api/status');if(reselect||!last)updateSelectors(d);render(d)}catch(e){$('clock').textContent='Ошибка связи';addLog(e.message)}finally{loading=false}}
$('refresh').onclick=()=>refresh(true);
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
Start-Process $url
try {
  while ($listener.IsListening) {
    $ctx = $listener.GetContext()
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
      if ($ctx.Request.HttpMethod -eq 'GET' -and $path -eq '/api/status') {
        Respond $ctx 200 (Json (BuildStatus)) 'application/json; charset=utf-8'
        continue
      }
      if ($ctx.Request.HttpMethod -eq 'POST' -and $path -in @('/api/select','/api/configure','/api/open-hotspot','/api/open-connections')) {
        if ($ctx.Request.ContentLength64 -gt 8192) { throw 'Request too large.' }
        $body = ''
        if ($ctx.Request.HasEntityBody) {
          $reader = New-Object IO.StreamReader($ctx.Request.InputStream,[Text.Encoding]::UTF8)
          $body = $reader.ReadToEnd()
          $reader.Dispose()
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
} finally { $listener.Stop(); $listener.Close() }
