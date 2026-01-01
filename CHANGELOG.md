# Changelog

## 1.0.1

* Fixed false positive VPN detection on Xiaomi/Redmi and Vivo devices
  - Removed rmnet_data and ccmni from VPN interface detection (standard mobile data interfaces)
* Fixed false positive root detection on MIUI and FunTouch OS devices
  - Removed /data/adb/modules from Magisk check (can exist without root)
  - Fixed checkRWSystem() to use precise mount line parsing

## 1.0.0

* Initial release
* Play Integrity API support (Android)
* App Attest support (iOS)
* Root/Jailbreak detection
* Emulator/Simulator detection
* Anti-debugging protection
* Hooking framework detection (Frida, Xposed, Substrate)
* App signature verification
* SSL Certificate Pinning
* String encryption utilities
* SecurityGate widget
* Native C security layer (Android)
