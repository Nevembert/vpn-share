# VPN Share

Windows 11 utility for sharing a VPN connection through Mobile Hotspot (Windows ICS).

**Traffic path:** USB tethering or Wi-Fi → Windows 11 → VPN TUN adapter (e.g. Happ) → Wi-Fi Direct hotspot → client devices.

## Quick start

1. Connect Windows to the internet using a phone's USB tethering or a Wi-Fi network.
2. Connect the VPN client and enable its TUN mode.
3. Enable Windows 11 **Settings → Network & internet → Mobile hotspot**.
4. Run `Start.cmd` as administrator from the application package.
5. Choose the incoming internet adapter, the VPN/TUN adapter, and the Microsoft Wi-Fi Direct Virtual Adapter for the hotspot.
6. Check the configuration and configure ICS if necessary.
7. Verify external IP, DNS, and IPv6 from a device connected to the hotspot.

**Caution:** ICS configuration is system-dependent. A successful configuration does not guarantee all traffic passes through the VPN. Test for leaks. This project is provided as-is.

## Status

The source code and launch scripts are being prepared for upload. The repository currently contains documentation only; it is **not yet a complete downloadable application**.
