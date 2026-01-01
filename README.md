# App Fortress

Production-grade multi-layer security for Flutter applications.

[![pub package](https://img.shields.io/pub/v/app_fortress.svg)](https://pub.dev/packages/app_fortress)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

| Feature | Description | Android | iOS |
|---------|-------------|---------|-----|
| **Attestation** | Play Integrity API / App Attest | ✅ | ✅ |
| **Root/Jailbreak Detection** | Multi-layer detection (Magisk, KernelSU, Cydia, etc.) | ✅ | ✅ |
| **Emulator Detection** | Simulator/Emulator detection with scoring | ✅ | ✅ |
| **Debugger Detection** | Anti-debugging (JDWP, ptrace, LLDB) | ✅ | ✅ |
| **Hooking Detection** | Frida, Xposed, LSPosed, Substrate | ✅ | ✅ |
| **Proxy Detection** | HTTP proxy & MITM tool detection | ✅ | ✅ |
| **VPN Detection** | VPN connection detection | ✅ | ✅ |
| **Signature Verification** | App tampering detection | ✅ | ✅ |
| **Native Security** | C/C++ security layer | ✅ | - |

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Platform Setup](#platform-setup)
- [API Reference](#api-reference)
- [Security Features](#security-features)
- [Examples](#examples)

---

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  app_fortress: ^1.0.0
```

Then run:
```bash
flutter pub get
```

---

## Quick Start

### Basic Setup

```dart
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:app_fortress/app_fortress.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Configure App Fortress
  await AppFortress.configure(
    cloudProjectNumber: 123456789, // Your Google Cloud Project Number
    config: kDebugMode
        ? SecurityConfig.development()  // Permissive for testing
        : SecurityConfig.production(    // Strict for release
            expectedSignatures: ['YOUR_SHA256_SIGNATURE'],
          ),
  );

  runApp(const MyApp());
}
```

### Using SecurityGate Widget

The easiest way to protect your app:

```dart
class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: SecurityGate(
        // Called when security check fails (blocking threats detected)
        onSecurityCheckFailed: (status) {
          print('Threats: ${status.threats}');
        },
        // Called when security check passes
        onSecurityCheckPassed: (status) {
          print('Security OK');
        },
        // Custom loading widget (optional)
        loadingWidget: const CircularProgressIndicator(),
        // Your app content
        child: const HomePage(),
      ),
    );
  }
}
```

### Manual Security Check

For more control over security handling:

```dart
Future<void> checkSecurity() async {
  final status = await AppFortress.runSecurityCheck();

  if (status.isSecure) {
    // All clear - proceed with app
    navigateToHome();
  } else {
    // Handle threats
    for (final threat in status.threats) {
      print('${threat.code}: ${threat.message} (blocking: ${threat.isBlocking})');
    }

    if (status.shouldBlock) {
      showBlockedScreen();
    }
  }
}
```

---

## Configuration

### SecurityConfig

`SecurityConfig` controls which security checks block the app vs. just warn.

#### Development Configuration (Permissive)

For development and testing - all checks pass, nothing blocks:

```dart
await AppFortress.configure(
  config: SecurityConfig.development(),
);
```

This is equivalent to:
```dart
SecurityConfig(
  allowRootedDevices: true,    // Don't block rooted devices
  allowEmulators: true,        // Don't block emulators
  allowDebugMode: true,        // Don't block debug builds
  blockOnHooking: false,       // Don't block Frida/Xposed
  blockOnDebugger: false,      // Don't block debugger
  blockOnProxy: false,         // Don't block proxy
  blockOnVpn: false,           // Don't block VPN
)
```

#### Production Configuration (Strict)

For release builds - maximum security:

```dart
await AppFortress.configure(
  config: SecurityConfig.production(
    expectedSignatures: ['YOUR_SHA256_SIGNATURE'],
    blockOnProxy: true,   // Block MITM attacks
    blockOnVpn: false,    // Allow VPN (optional)
  ),
);
```

This is equivalent to:
```dart
SecurityConfig(
  expectedSignatures: ['...'],
  allowRootedDevices: false,   // Block rooted devices
  allowEmulators: false,       // Block emulators
  allowDebugMode: false,       // Block debug builds
  blockOnHooking: true,        // Block Frida/Xposed
  blockOnDebugger: true,       // Block debugger
  blockOnProxy: true,          // Block proxy/MITM
  blockOnVpn: false,           // Allow VPN
)
```

#### Custom Configuration

Mix and match settings:

```dart
await AppFortress.configure(
  config: SecurityConfig(
    expectedSignatures: ['YOUR_SHA256'],
    allowRootedDevices: false,
    allowEmulators: true,      // Allow emulators for QA
    allowDebugMode: false,
    blockOnHooking: true,
    blockOnDebugger: true,
    blockOnProxy: true,
    blockOnVpn: false,
  ),
);
```

### Configuration Options Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `expectedSignatures` | `List<String>` | `[]` | SHA-256 fingerprints of valid app signatures |
| `allowRootedDevices` | `bool` | `false` | If `true`, rooted/jailbroken devices won't block |
| `allowEmulators` | `bool` | `false` | If `true`, emulators/simulators won't block |
| `allowDebugMode` | `bool` | `false` | If `true`, debug builds won't block |
| `blockOnHooking` | `bool` | `true` | If `true`, Frida/Xposed detection blocks |
| `blockOnDebugger` | `bool` | `true` | If `true`, debugger attachment blocks |
| `blockOnProxy` | `bool` | `true` | If `true`, HTTP proxy detection blocks |
| `blockOnVpn` | `bool` | `false` | If `true`, VPN connection blocks |

---

## Platform Setup

### Android Setup

#### 1. AndroidManifest.xml (Auto-included)

The plugin automatically adds required permissions. No manual changes needed.

#### 2. Play Integrity API Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create or select your project
3. Enable **Play Integrity API**
4. Get your **Cloud Project Number** (NOT Project ID)
5. Link your app in [Google Play Console](https://play.google.com/console)

```dart
await AppFortress.configure(
  cloudProjectNumber: 123456789, // Your Cloud Project Number
);
```

#### 3. Get Your App Signature

For release builds:
```bash
keytool -list -v -keystore your-release.keystore | grep SHA256
```

For debug builds:
```bash
keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android | grep SHA256
```

Remove colons from the output and use in config:
```dart
SecurityConfig.production(
  expectedSignatures: ['A1B2C3D4E5F6...'], // SHA-256 without colons
)
```

#### 4. ProGuard Rules

Add to `android/app/proguard-rules.pro`:
```proguard
# App Fortress
-keep class com.app.fortress.** { *; }
-keep class com.google.android.play.core.integrity.** { *; }
```

### iOS Setup

#### 1. Info.plist Configuration

Add to `ios/Runner/Info.plist` for proxy and jailbreak app detection:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
    <!-- Jailbreak detection -->
    <string>cydia</string>
    <string>sileo</string>
    <string>zbra</string>
    <string>filza</string>
    <!-- Proxy/MITM tool detection -->
    <string>charles</string>
    <string>proxyman</string>
    <string>httpcatcher</string>
    <string>surge</string>
    <string>quantumult</string>
    <string>shadowrocket</string>
    <string>potatso</string>
    <string>loon</string>
    <string>stash</string>
    <string>thor</string>
</array>
```

#### 2. App Attest Setup

1. In [Apple Developer Portal](https://developer.apple.com), enable App Attest for your App ID
2. In Xcode: **Signing & Capabilities** → **+ Capability** → **App Attest**

#### 3. Minimum iOS Version

iOS 14.0+ is required for App Attest. Set in `ios/Podfile`:
```ruby
platform :ios, '14.0'
```

---

## API Reference

### Core Methods

#### `AppFortress.configure()`

Initialize the plugin with your settings:

```dart
await AppFortress.configure(
  cloudProjectNumber: 123456789,  // Required for Android attestation
  config: SecurityConfig(...),     // Optional security configuration
);
```

#### `AppFortress.runSecurityCheck()`

Run a comprehensive security check:

```dart
final status = await AppFortress.runSecurityCheck();

print(status.isSecure);    // true if no blocking threats
print(status.shouldBlock); // true if any blocking threat detected
print(status.threats);     // List<SecurityThreat>
```

#### `AppFortress.quickSecurityCheck()`

Run a faster security check (no attestation):

```dart
final status = await AppFortress.quickSecurityCheck();
```

### Individual Checks

```dart
// Root/Jailbreak detection
final isRooted = await AppFortress.isRooted();

// Emulator/Simulator detection
final isEmulator = await AppFortress.isEmulator();

// Debugger detection
final isDebugger = await AppFortress.isDebuggerAttached();

// Hooking framework detection (Frida, Xposed, etc.)
final isHooked = await AppFortress.isHookingDetected();

// HTTP Proxy detection
final isProxy = await AppFortress.isProxyEnabled();

// VPN detection
final isVpn = await AppFortress.isVpnActive();
```

### Attestation

```dart
// Request attestation token
final result = await AppFortress.requestAttestation(
  nonce: 'server-generated-nonce',
);

print(result.token);    // Send to your server for verification
print(result.platform); // 'android' or 'ios'
```

### Device Info

```dart
final info = await AppFortress.getDeviceSecurityInfo();

print(info.platform);           // 'android' or 'ios'
print(info.model);              // Device model
print(info.osVersion);          // OS version
print(info.appVersion);         // App version
print(info.isRooted);           // Root/jailbreak status
print(info.isEmulator);         // Emulator status
print(info.isDebuggerAttached); // Debugger status
print(info.isHookingDetected);  // Hooking status
print(info.isProxyEnabled);     // Proxy status
print(info.isVpnActive);        // VPN status
print(info.signatureSha256);    // App signature (Android)
print(info.installSource);      // Install source
```

### Signature Verification

```dart
final isValid = await AppFortress.verifySignature(
  expectedSignatures: ['YOUR_SHA256_SIGNATURE'],
);
```

---

## Security Features

### Root/Jailbreak Detection

Detects rooted Android devices and jailbroken iOS devices through multiple layers:

**Android:**
- su binary locations
- Magisk, KernelSU detection
- Root management apps
- System partition checks
- Native checks

**iOS:**
- Cydia, Sileo, Zebra apps
- Jailbreak file paths
- Symbolic link checks
- Fork ability test
- Dynamic library inspection

### Emulator Detection

**Android:** Uses scoring-based detection to minimize false positives:
- Build properties (HARDWARE, PRODUCT, MODEL)
- QEMU detection
- Hardware files
- Native checks

**iOS:** Compile-time simulator detection.

### Debugger Detection

**Android:**
- `Debug.isDebuggerConnected()`
- JDWP thread detection
- TracerPid check
- Native ptrace detection

**iOS:**
- sysctl P_TRACED flag
- Exception ports check

### Hooking Detection

Detects runtime manipulation frameworks:

**Android:**
- Frida (ports 27042/27043, /proc/maps)
- Xposed Framework
- LSPosed
- Magisk Hide
- Substrate

**iOS:**
- Frida port check
- Suspicious dylibs (frida, cycript, ssl_kill)
- Substrate detection

### Proxy Detection

Detects HTTP proxies that could intercept traffic:

**Android:**
- System proxy settings
- WiFi proxy configuration
- Known proxy apps (Charles, Burp, etc.)
- MITM tools

**iOS:**
- CFNetwork proxy settings
- Known proxy apps via URL schemes (Charles, Proxyman, etc.)

### VPN Detection

**Android:**
- NetworkCapabilities TRANSPORT_VPN
- Network interface names (tun, tap, ppp)
- Route table analysis

**iOS:**
- Network interface enumeration (utun, ppp, ipsec)
- Proxy settings scoped interfaces

---

## Examples

### Complete Example

```dart
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:app_fortress/app_fortress.dart';

class AppSecurityConfig {
  static const int cloudProjectNumber = 123456789;
  static const List<String> expectedSignatures = [
    'A1B2C3D4E5F6...',
  ];
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await AppFortress.configure(
    cloudProjectNumber: AppSecurityConfig.cloudProjectNumber,
    config: kDebugMode
        ? SecurityConfig.development()
        : SecurityConfig.production(
            expectedSignatures: AppSecurityConfig.expectedSignatures,
            blockOnProxy: true,
            blockOnVpn: false,
          ),
  );

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: SecurityGate(
        onSecurityCheckFailed: (status) {
          debugPrint('Security threats: ${status.threats}');
        },
        onSecurityCheckPassed: (status) {
          debugPrint('Security check passed');
        },
        child: const HomePage(),
      ),
    );
  }
}
```

### Custom Security Screen

```dart
SecurityGate(
  blockedWidget: (status) => Scaffold(
    body: Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.security, size: 64, color: Colors.red),
          const Text('Security Alert'),
          ...status.threats.map((t) => Text(t.message)),
        ],
      ),
    ),
  ),
  child: const HomePage(),
)
```

### Server-Side Attestation Flow

```dart
Future<void> secureApiCall() async {
  // 1. Get nonce from your server
  final nonce = await api.getNonce();

  // 2. Request attestation
  final attestation = await AppFortress.requestAttestation(nonce: nonce);

  // 3. Send token to your server for verification
  final response = await api.verifyAndGetData(
    attestationToken: attestation.token,
  );

  // 4. Use verified data
  processData(response);
}
```

---

## Threat Codes

| Code | Severity | Description |
|------|----------|-------------|
| `ROOT_DETECTED` / `JAILBREAK_DETECTED` | High | Device is rooted/jailbroken |
| `EMULATOR_DETECTED` / `SIMULATOR_DETECTED` | Medium | Running on emulator |
| `DEBUGGER_DETECTED` | Critical | Debugger is attached |
| `HOOKING_DETECTED` | Critical | Frida/Xposed detected |
| `PROXY_DETECTED` | High | HTTP proxy configured |
| `VPN_DETECTED` | Medium | VPN is active |
| `DEBUGGABLE_BUILD` | Low | App is debug build |
| `SIGNATURE_INVALID` | Critical | App signature mismatch |

---

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please read our contributing guidelines.

## Support

- [Report bugs](https://github.com/girija870/app_fortress/issues)
- [Request features](https://github.com/girija870/app_fortress/issues)
- [Documentation](https://github.com/girija870/app_fortress#readme)
# app_fortress
