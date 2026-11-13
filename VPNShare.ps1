#requires -Version 5.1
# VPN Share - Windows 11 Mobile Hotspot / VPN ICS utility
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -STA -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"')
    exit
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$script:log = Join-Path $PSScriptRoot 'vpn-share.log'
$script:inputs = @(); $script:vpns = @(); $script:hotspots = @()
function Say([string]$message) {
    $line = ('{0:HH:mm:ss} {1}' -f (Get-Date), $message)
    $script:output.AppendText($line + [Environment]::NewLine)
    try { Add-Content -LiteralPath $script:log -Value $line -Encoding UTF8 } catch {}
}
function Id($guid) { return ([string]$guid).Trim('{}').ToLowerInvariant() }
function Sharing {
    $manager = New-Object -ComObject HNetCfg.HNetShare
    $rows = @()
    foreach ($connection in @($manager.EnumEveryConnection())) {
        $props = $manager.NetConnectionProps($connection)
        $config = $manager.INetSharingConfigurationForINetConnection($connection)
        $kind = -1
        if ($config.SharingEnabled) { $kind = [int]$config.SharingConnectionType }
        $rows += [pscustomobject]@{ Name = [string]$props.Name; Guid = (Id $props.Guid); Device = [string]$props.DeviceName; Config = $config; Shared = [bool]$config.SharingEnabled; Kind = $kind }
    }
    return $rows
}
function Pick($combo, $items) {
    if ($combo.SelectedIndex -lt 0 -or $combo.SelectedIndex -ge $items.Count) { return $null }
    return $items[$combo.SelectedIndex]
}
function Refresh-List {
    $old = @((Pick $script:inputBox $script:inputs), (Pick $script:vpnBox $script:vpns), (Pick $script:hotBox $script:hotspots))
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object InterfaceGuid)
    $script:inputs = @($adapters | Sort-Object Name)
    $script:vpns = @($adapters | Where-Object { ($_.Name + ' ' + $_.InterfaceDescription) -match 'tun|tap|vpn|wintun|wireguard|happ|hub|sockstunnel|openvpn|amnezia|hiddify' } | Sort-Object Name)
    $script:hotspots = @($adapters | Where-Object { $_.InterfaceDescription -match 'Wi-Fi Direct Virtual Adapter' } | Sort-Object Name)
    $boxes = @($script:inputBox, $script:vpnBox, $script:hotBox)
    $sets = @($script:inputs, $script:vpns, $script:hotspots)
    for ($j=0; $j -lt 3; $j++) {
        $boxes[$j].Items.Clear()
        $index = -1
        for ($i=0; $i -lt $sets[$j].Count; $i++) {
            $a = $sets[$j][$i]
            [void]$boxes[$j].Items.Add(('[{0}] {1} - {2}' -f $a.Status, $a.Name, $a.InterfaceDescription))
            if ($old[$j] -and (Id $old[$j].InterfaceGuid) -eq (Id $a.InterfaceGuid)) { $index = $i }
            if ($index -lt 0 -and $a.Status -eq 'Up' -and ($j -ne 0 -or $a.InterfaceDescription -notmatch 'Virtual|Tunnel|Miniport')) { $index = $i }
        }
        if ($index -ge 0) { $boxes[$j].SelectedIndex = $index }
    }
    Say ('Adapters: internet={0}, VPN={1}, hotspot={2}' -f $script:inputs.Count, $script:vpns.Count, $script:hotspots.Count)
}
function Plan {
    $inputAdapter = Pick $script:inputBox $script:inputs
    $vpn = Pick $script:vpnBox $script:vpns
    $hotspot = Pick $script:hotBox $script:hotspots
    if (-not $inputAdapter -or -not $vpn -or -not $hotspot) { throw 'Select all three adapters. Turn on TUN and Mobile hotspot, then refresh.' }
    if ((@((Id $inputAdapter.InterfaceGuid), (Id $vpn.InterfaceGuid), (Id $hotspot.InterfaceGuid)) | Select-Object -Unique).Count -ne 3) { throw 'Internet, VPN and hotspot adapters must be different.' }
    if ($vpn.Status -ne 'Up' -or $hotspot.Status -ne 'Up') { throw 'VPN and Wi-Fi Direct adapters must be Up.' }
    $routes = @(Get-NetRoute -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') })
    if ($routes.Count -eq 0) { throw 'No default or split-default IPv4 route found on VPN. Check VPN TUN mode.' }
    return [pscustomobject]@{ Input=$inputAdapter; VPN=$vpn; Hotspot=$hotspot }
}
function Current-Role($rows,$guid,$kind) {
    return @($rows | Where-Object { $_.Guid -eq (Id $guid) -and $_.Shared -and $_.Kind -eq $kind }).Count -gt 0
}
function Check-Plan {
    $p = Plan
    Say ('Path: {0} -> {1} -> {2}' -f $p.Input.Name,$p.VPN.Name,$p.Hotspot.Name)
    $rows = @(Sharing)
    if ((Current-Role $rows $p.VPN.InterfaceGuid 0) -and (Current-Role $rows $p.Hotspot.InterfaceGuid 1)) {
        Say 'ICS already matches VPN -> Wi-Fi Direct. No changes needed.'
    } else { Say 'ICS does not match yet. Click Configure ICS.' }
    $ip = @(Get-NetIPAddress -InterfaceIndex $p.Hotspot.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
    if ($ip.Count) { Say ('Hotspot IPv4: ' + ($ip.IPAddress -join ', ')) }
    Say 'Client-side IP/DNS/IPv6 leak checks are still required.'
}
function Configure-ICS {
    $p = Plan
    $rows = @(Sharing)
    if ((Current-Role $rows $p.VPN.InterfaceGuid 0) -and (Current-Role $rows $p.Hotspot.InterfaceGuid 1)) {
        Say 'ICS already configured correctly. Skipping.'; return
    }
    $other = @($rows | Where-Object Shared)
    if ($other.Count -gt 0) {
        $answer = [Windows.Forms.MessageBox]::Show('Existing ICS sharing will be changed. Continue?', 'VPN Share', 'YesNo', 'Warning')
        if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }
    }
    $snapshot = @($other | ForEach-Object { [pscustomobject]@{ Guid=$_.Guid; Kind=$_.Kind } })
    try {
        $svc = Get-Service SharedAccess
        if ($svc.Status -ne 'Running') { Start-Service SharedAccess }
        foreach ($entry in @(Sharing | Where-Object Shared)) { $entry.Config.DisableSharing() }
        $rows = @(Sharing)
        $source = @($rows | Where-Object { $_.Guid -eq (Id $p.VPN.InterfaceGuid) }) | Select-Object -First 1
        $target = @($rows | Where-Object { $_.Guid -eq (Id $p.Hotspot.InterfaceGuid) }) | Select-Object -First 1
        if (-not $source -or -not $target) { throw 'ICS COM API cannot find selected adapters.' }
        $source.Config.EnableSharing(0)
        $rows = @(Sharing)
        (@($rows | Where-Object { $_.Guid -eq (Id $p.Hotspot.InterfaceGuid) }) | Select-Object -First 1).Config.EnableSharing(1)
        $rows = @(Sharing)
        if (-not ((Current-Role $rows $p.VPN.InterfaceGuid 0) -and (Current-Role $rows $p.Hotspot.InterfaceGuid 1))) { throw 'ICS roles not saved.' }
        Say 'ICS configured: VPN (public) -> hotspot (private).'
    } catch {
        $errorMessage = $_.Exception.Message
        Say ('ICS error: ' + $errorMessage + '. Attempting rollback.')
        try {
            foreach ($entry in @(Sharing | Where-Object Shared)) { $entry.Config.DisableSharing() }
            foreach ($saved in $snapshot) {
                $entry = @(Sharing | Where-Object { $_.Guid -eq $saved.Guid }) | Select-Object -First 1
                if ($entry) { $entry.Config.EnableSharing([int]$saved.Kind) }
            }
        } catch { Say ('Rollback error: ' + $_.Exception.Message) }
        throw $errorMessage
    }
}
function Diagnose {
    $path = Join-Path ([Environment]::GetFolderPath('Desktop')) ('VPN-Share-Diagnostics-{0:yyyyMMdd-HHmmss}.txt' -f (Get-Date))
    $lines = @('VPN Share diagnostics',('Date: ' + (Get-Date)), '=== Adapters ===')
    $lines += (Get-NetAdapter -IncludeHidden | Format-Table Name,InterfaceDescription,Status,ifIndex -AutoSize | Out-String -Width 180)
    $lines += '=== ICS ==='
    $lines += (Sharing | Select-Object Name,Device,Shared,Kind | Format-Table -AutoSize | Out-String -Width 180)
    $lines += '=== IPv4 routes ==='
    $lines += (Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') } | Format-Table -AutoSize | Out-String -Width 180)
    $lines | Out-File -LiteralPath $path -Encoding UTF8
    Say ('Diagnostics saved: ' + $path)
}
$form = New-Object Windows.Forms.Form
$form.Text = 'VPN Share | Windows 11 | v1.0'
$form.Size = New-Object Drawing.Size(870,680)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object Drawing.Font('Segoe UI',10)
function LabelAt($text,$y) {
    $label = New-Object Windows.Forms.Label
    $label.Text=$text; $label.Location=New-Object Drawing.Point(20,$y)
    $label.Size=New-Object Drawing.Size(810,28); $form.Controls.Add($label)
}
function ComboAt($y) {
    $combo = New-Object Windows.Forms.ComboBox
    $combo.DropDownStyle='DropDownList'
    $combo.Location=New-Object Drawing.Point(20,$y)
    $combo.Size=New-Object Drawing.Size(810,28)
    $form.Controls.Add($combo)
    return $combo
}
function ButtonAt($text,$x,$y,$w,$action) {
    $button = New-Object Windows.Forms.Button
    $button.Text=$text; $button.Location=New-Object Drawing.Point($x,$y)
    $button.Size=New-Object Drawing.Size($w,36)
    $button.Add_Click({ try { & $action } catch { Say ('ERROR: ' + $_.Exception.Message); [void][Windows.Forms.MessageBox]::Show($_.Exception.Message,'VPN Share','OK','Error') } }.GetNewClosure())
    $form.Controls.Add($button)
}
LabelAt 'Internet (USB tethering or Wi-Fi) -> VPN TUN -> Windows Mobile Hotspot' 18
ButtonAt 'Windows hotspot settings' 20 52 230 { Start-Process 'ms-settings:network-mobilehotspot' }
ButtonAt 'Network connections' 270 52 190 { Start-Process ncpa.cpl }
ButtonAt 'Refresh adapters' 480 52 170 { Refresh-List }
LabelAt 'A. Incoming internet (not the ICS source)' 105
$script:inputBox=ComboAt 135
LabelAt 'B. VPN TUN adapter (ICS public/source)' 180
$script:vpnBox=ComboAt 210
LabelAt 'C. Microsoft Wi-Fi Direct Virtual Adapter (ICS private/destination)' 255
$script:hotBox=ComboAt 285
ButtonAt 'Check configuration' 20 330 195 { Check-Plan }
ButtonAt 'Configure ICS' 230 330 195 { Configure-ICS }
ButtonAt 'Save diagnostics' 440 330 195 { Diagnose }
LabelAt 'Log (contains local adapter names; review before sharing):' 385
$script:output=New-Object Windows.Forms.TextBox
$script:output.Location=New-Object Drawing.Point(20,420)
$script:output.Size=New-Object Drawing.Size(810,175)
$script:output.Multiline=$true; $script:output.ReadOnly=$true; $script:output.ScrollBars='Vertical'
$form.Controls.Add($script:output)
LabelAt 'Warning: test external IP, DNS, IPv6 and VPN-off behavior on the connected device.' 603
try { Refresh-List } catch { Say ('Startup error: ' + $_.Exception.Message) }
[void]$form.ShowDialog()
