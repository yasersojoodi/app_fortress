import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'app_fortress_method_channel.dart';
import 'models/attestation_result.dart';
import 'models/device_security_info.dart';
import 'models/security_config.dart';
import 'models/security_status.dart';

/// Platform interface for App Fortress
abstract class AppFortressPlatform extends PlatformInterface {
  AppFortressPlatform() : super(token: _token);

  static final Object _token = Object();

  static AppFortressPlatform _instance = MethodChannelAppFortress();

  /// The default instance of [AppFortressPlatform] to use.
  static AppFortressPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [AppFortressPlatform].
  static set instance(AppFortressPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  /// Configure the plugin
  Future<bool> configure({
    int? cloudProjectNumber,
    SecurityConfig? config,
  }) {
    throw UnimplementedError('configure() has not been implemented.');
  }

  /// Get platform version
  Future<String?> getPlatformVersion() {
    throw UnimplementedError('getPlatformVersion() has not been implemented.');
  }

  /// Request attestation token
  Future<AttestationResult> requestAttestation({required String nonce}) {
    throw UnimplementedError('requestAttestation() has not been implemented.');
  }

  /// Get device security info
  Future<DeviceSecurityInfo> getDeviceSecurityInfo() {
    throw UnimplementedError(
        'getDeviceSecurityInfo() has not been implemented.');
  }

  /// Check if rooted/jailbroken
  Future<bool> isRooted() {
    throw UnimplementedError('isRooted() has not been implemented.');
  }

  /// Check if emulator/simulator
  Future<bool> isEmulator() {
    throw UnimplementedError('isEmulator() has not been implemented.');
  }

  /// Check if debugger attached
  Future<bool> isDebuggerAttached() {
    throw UnimplementedError('isDebuggerAttached() has not been implemented.');
  }

  /// Check if hooking detected
  Future<bool> isHookingDetected() {
    throw UnimplementedError('isHookingDetected() has not been implemented.');
  }

  /// Verify signature
  Future<bool> verifySignature({required List<String> expectedSignatures}) {
    throw UnimplementedError('verifySignature() has not been implemented.');
  }

  /// Run full security check
  Future<SecurityStatus> runSecurityCheck() {
    throw UnimplementedError('runSecurityCheck() has not been implemented.');
  }

  /// Check if HTTP proxy is enabled
  Future<bool> isProxyEnabled() {
    throw UnimplementedError('isProxyEnabled() has not been implemented.');
  }

  /// Check if VPN is active
  Future<bool> isVpnActive() {
    throw UnimplementedError('isVpnActive() has not been implemented.');
  }
}
