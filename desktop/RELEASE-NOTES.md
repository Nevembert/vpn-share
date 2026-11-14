# VPN Share 2.0.0 preview 7

- Simplified dashboard: Overview, Devices and Tools sections.
- New native Settings tab: opt-in Windows logon startup through an elevated interactive Scheduled Task.
- Opt-in automatic ICS setup/recovery when saved VPN and Wi-Fi Direct adapters become active, checked every 30 seconds; no automatic Windows hotspot or VPN activation.
- Preferences stored locally under %LOCALAPPDATA%/VPNShare/preferences.json.
- No kill switch; hotspot recovery remains experimental and will not override unrelated ICS assignments.
- Built-in Windows PktMon fallback retained.
