import 'dart:async';

import 'app_fortress_platform_interface.dart';
import 'models/attestation_result.dart';
import 'models/device_security_info.dart';
import 'models/security_config.dart';
import 'models/security_status.dart';
import 'models/security_threat.dart';

/// Main entry point for App Fortress security features
///
/// Example:
/// ```dart
/// // Configure (call once at app start)
/// await AppFortress.configure(cloudProjectNumber: 123456789);
///
/// // Check security
/// final status = await AppFortress.runSecurityCheck();
/// if (!status.isSecure) {
///   // Handle security threat
/// }
///
/// // Get attestation token for server verification
/// final attestation = await AppFortress.requestAttestation(nonce: 'server-nonce');
/// ```
class AppFortress {
  AppFortress._();

  static AppFortressPlatform get _platform => AppFortressPlatform.instance;

  /// Current security configuration
  static SecurityConfig _config = const SecurityConfig();

  /// Get current config (for testing/debugging)
  static SecurityConfig get currentConfig => _config;

  /// Configure the plugin with your settings
  ///
  /// [cloudProjectNumber] - Google Cloud project number for Play Integrity (Android)
  /// [config] - Additional security configuration
  static Future<bool> configure({
    int? cloudProjectNumber,
    SecurityConfig? config,
  }) {
    // Store config for use in security checks
    _config = config ?? const SecurityConfig();

    return _platform.configure(
      cloudProjectNumber: cloudProjectNumber,
      config: config,
    );
  }

  /// Get platform version string
  static Future<String?> getPlatformVersion() {
    return _platform.getPlatformVersion();
  }

  /// Request attestation token from platform
  ///
  /// [nonce] - Server-generated nonce for replay protection
  /// Returns attestation token to send to your server for verification
  static Future<AttestationResult> requestAttestation({
    required String nonce,
  }) {
    return _platform.requestAttestation(nonce: nonce);
  }

  /// Get comprehensive device security information
  static Future<DeviceSecurityInfo> getDeviceSecurityInfo() {
    return _platform.getDeviceSecurityInfo();
  }

  /// Check if device is rooted (Android) or jailbroken (iOS)
  static Future<bool> isRooted() {
    return _platform.isRooted();
  }

  /// Check if running on emulator (Android) or simulator (iOS)
  static Future<bool> isEmulator() {
    return _platform.isEmulator();
  }

  /// Check if a debugger is attached
  static Future<bool> isDebuggerAttached() {
    return _platform.isDebuggerAttached();
  }

  /// Check if hooking framework (Frida, Xposed, etc.) is detected
  static Future<bool> isHookingDetected() {
    return _platform.isHookingDetected();
  }

  /// Verify app signature against expected values
  ///
  /// [expectedSignatures] - List of SHA-256 fingerprints (without colons)
  static Future<bool> verifySignature({
    required List<String> expectedSignatures,
  }) {
    return _platform.verifySignature(expectedSignatures: expectedSignatures);
  }

  /// Check if HTTP proxy is enabled on the device
  ///
  /// Returns true if a proxy is configured (potential MITM attack)
  static Future<bool> isProxyEnabled() {
    return _platform.isProxyEnabled();
  }

  /// Check if VPN connection is active
  ///
  /// Returns true if VPN is active
  static Future<bool> isVpnActive() {
    return _platform.isVpnActive();
  }

  /// Quick security check (faster, less comprehensive)
  ///
  /// Checks root, emulator, debugger, hooking, proxy, and VPN
  /// Uses the configured [SecurityConfig] to determine blocking behavior
  static Future<SecurityStatus> quickSecurityCheck() async {
    final results = await Future.wait([
      isRooted(),
      isEmulator(),
      isDebuggerAttached(),
      isHookingDetected(),
      isProxyEnabled(),
      isVpnActive(),
    ]);

    final threats = <SecurityThreat>[];

    // Root detection - blocked unless allowRootedDevices is true
    if (results[0]) {
      threats.add(SecurityThreat(
        code: ThreatCodes.rootDetected,
        severity: ThreatSeverity.high,
        message: 'Device root access detected',
        isBlocking: !_config.allowRootedDevices,
      ));
    }

    // Emulator detection - blocked unless allowEmulators is true
    if (results[1]) {
      threats.add(SecurityThreat(
        code: ThreatCodes.emulatorDetected,
        severity: ThreatSeverity.medium,
        message: 'Running on emulator/simulator',
        isBlocking: !_config.allowEmulators,
      ));
    }

    // Debugger detection - blocked if blockOnDebugger is true
    if (results[2]) {
      threats.add(SecurityThreat(
        code: ThreatCodes.debuggerDetected,
        severity: ThreatSeverity.critical,
        message: 'Debugger attached to process',
        isBlocking: _config.blockOnDebugger,
      ));
    }

    // Hooking detection - blocked if blockOnHooking is true
    if (results[3]) {
      threats.add(SecurityThreat(
        code: ThreatCodes.hookingDetected,
        severity: ThreatSeverity.critical,
        message: 'Hooking framework detected',
        isBlocking: _config.blockOnHooking,
      ));
    }

    // Proxy detection - blocked if blockOnProxy is true
    if (results[4]) {
      threats.add(SecurityThreat(
        code: ThreatCodes.proxyDetected,
        severity: ThreatSeverity.high,
        message: 'HTTP proxy is configured (potential MITM)',
        isBlocking: _config.blockOnProxy,
      ));
    }

    // VPN detection - blocked if blockOnVpn is true
    if (results[5]) {
      threats.add(SecurityThreat(
        code: ThreatCodes.vpnDetected,
        severity: ThreatSeverity.medium,
        message: 'VPN connection is active',
        isBlocking: _config.blockOnVpn,
      ));
    }

    return SecurityStatus(
      isSecure: !threats.any((t) => t.isBlocking),
      threats: threats,
      timestamp: DateTime.now(),
    );
  }

  /// Run comprehensive security check with config-aware blocking
  ///
  /// Returns [SecurityStatus] with threats filtered by config settings
  static Future<SecurityStatus> runSecurityCheck() async {
    final status = await _platform.runSecurityCheck();

    // Apply config to modify blocking behavior
    final adjustedThreats = status.threats.map((threat) {
      bool isBlocking = threat.isBlocking;

      // Adjust blocking based on config
      switch (threat.code) {
        case ThreatCodes.rootDetected:
        case 'ROOT':
          isBlocking = !_config.allowRootedDevices;
          break;
        case ThreatCodes.emulatorDetected:
        case 'EMULATOR':
          isBlocking = !_config.allowEmulators;
          break;
        case ThreatCodes.debuggerDetected:
        case 'DEBUGGER':
          isBlocking = _config.blockOnDebugger;
          break;
        case ThreatCodes.hookingDetected:
        case 'HOOKING':
          isBlocking = _config.blockOnHooking;
          break;
        case ThreatCodes.proxyDetected:
        case 'PROXY':
          isBlocking = _config.blockOnProxy;
          break;
        case ThreatCodes.vpnDetected:
        case 'VPN':
          isBlocking = _config.blockOnVpn;
          break;
        case ThreatCodes.debugBuild:
        case 'DEBUGGABLE':
        case 'DEBUGGABLE_BUILD':
          isBlocking = !_config.allowDebugMode;
          break;
      }

      return SecurityThreat(
        code: threat.code,
        severity: threat.severity,
        message: threat.message,
        isBlocking: isBlocking,
      );
    }).toList();

    return SecurityStatus(
      isSecure: !adjustedThreats.any((t) => t.isBlocking),
      threats: adjustedThreats,
      timestamp: status.timestamp,
    );
  }
}
