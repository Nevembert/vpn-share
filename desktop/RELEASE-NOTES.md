## VPN Share 2.0.0 preview 1 — Windows desktop

**Download:** `VPNShare-v2.0.0-preview.1-win-x64.zip` in Assets. Extract it and launch **VPNShare.exe** (not Start.cmd).

**What's new:** native Windows desktop window with embedded WebView2 dashboard, hidden PowerShell backend, automatic local port discovery, background mode via tray, restart, error journal and copyable diagnostics. PowerShell script is embedded in the executable and extracted with UTF-8 BOM on startup.

**Requirements:** Windows 11 x64, Microsoft Edge WebView2 Runtime, administrator permission for ICS. Includes .NET 8 runtime (self-contained). VPN and Mobile Hotspot need to be set up separately.

**Important:** this is an unsigned **preview**. Compilation and static checks are automated in GitHub Actions; this release **has not yet been validated on a real Windows 11 + Quest 3 setup**. True Windows sleep disables normal VPN sharing; use Win+L and optionally enable idle sleep prevention.

**Logs:** `%LOCALAPPDATA%\VPNShare\logs`. Open the **Диагностика** tab after startup errors. The process remains running after closing the window (system tray); choose **Выход** to stop it.
