## VPN Share 2.0.0 preview 4 — Windows desktop

**Download:** `VPNShare-v2.0.0-preview.4-win-x64.zip` in Assets. Extract it and launch **VPNShare.exe** (not Start.cmd).

**New in preview 4:** per-client IPv4 packet throughput using optional Npcap on the selected Wi-Fi Direct interface. Shows RX/TX Mbps and cumulative transferred bytes per observed IP. Install [Npcap](https://npcap.com/#download) with **WinPcap API-compatible mode**, then restart the app. Captures only IP headers/lengths; no payloads are stored. Excludes IPv6 and local-to-local traffic. Requires real-device verification; no claim of full coverage.\n\n**Previously:** opt-in, conservative ICS auto-recovery (30-second checks, no takeover of third-party sharing, 3-error cutoff). This is NOT a VPN kill switch.\n\n**Previously:** automatically discover hotspot clients by IP/MAC from Windows IPv4 neighbor table, auto-select a recently reachable client, or choose from a dropdown. Client activity is a reachability hint, **not** a per-IP throughput measurement. The displayed Wi-Fi Direct speed remains the total interface throughput.\n\n**What's new:** native Windows desktop window with embedded WebView2 dashboard, hidden PowerShell backend, automatic local port discovery, background mode via tray, restart, error journal and copyable diagnostics. PowerShell script is embedded in the executable and extracted with UTF-8 BOM on startup.

**Requirements:** Windows 11 x64, Microsoft Edge WebView2 Runtime, administrator permission for ICS. Includes .NET 8 runtime (self-contained). VPN and Mobile Hotspot need to be set up separately.

**Important:** this is an unsigned **preview**. Compilation and static checks are automated in GitHub Actions; this release **has not yet been validated on a real Windows 11 + Quest 3 setup**. True Windows sleep disables normal VPN sharing; use Win+L and optionally enable idle sleep prevention.

**Logs:** `%LOCALAPPDATA%\VPNShare\logs`. Open the **Диагностика** tab after startup errors. The process remains running after closing the window (system tray); choose **Выход** to stop it.
