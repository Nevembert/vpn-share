# VPN Share Android — alpha scaffold

Native Kotlin + Jetpack Compose app, independent of the Windows desktop build.

## Modes
- **Without root**: observes Android network validation, VPN transport, and explains Android tethering restrictions. Does **not** claim to forward VPN traffic.
- **Root (experimental)**: opt-in UI mode and possible su binary detection only. It only executes an explicit user-triggered, read-only `su -c id` probe with a 3-second timeout; it does not otherwise use su, change firewall/NAT, or modify routing. Full root sharing requires device-specific interface detection, backup/rollback, IPv4/IPv6 leak controls, and real-device validation.

## Build
Install Android Studio with JDK 17 and Android SDK 35, open the `android/` directory and build the `app` module. A Gradle wrapper is not checked in yet; use Android Studio's installed Gradle or generate a wrapper locally.

No extra software is installed on hotspot clients. Android network checks run locally.

## Roadmap
1. Root capability probe with explicit consent and command timeout (implemented; requires device validation).
2. Read-only interface, route, DNS, tethering and NAT inventory (OEM dependent).
3. Safe, transactional root forwarding with rollback, VPN disconnect fail-closed behavior and IPv6 policy.
4. Per-client counters and verified APK release pipeline.
