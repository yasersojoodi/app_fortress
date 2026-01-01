import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'app_fortress_platform_interface.dart';
import 'models/attestation_result.dart';
import 'models/device_security_info.dart';
import 'models/security_config.dart';
import 'models/security_status.dart';
import 'models/security_threat.dart';

/// Method channel implementation of AppFortressPlatform
class MethodChannelAppFortress extends AppFortressPlatform {
  @visibleForTesting
  final methodChannel = const MethodChannel('com.app.fortress/security');

  @override
  Future<bool> configure({
    int? cloudProjectNumber,
    SecurityConfig? config,
  }) async {
    final result = await methodChannel.invokeMethod<bool>('configure', {
      'cloudProjectNumber': cloudProjectNumber,
    });
    return result ?? false;
  }

  @override
  Future<String?> getPlatformVersion() async {
    return methodChannel.invokeMethod<String>('getPlatformVersion');
  }

  @override
  Future<AttestationResult> requestAttestation({required String nonce}) async {
    try {
      final result = await methodChannel.invokeMethod<Map<dynamic, dynamic>>(
        'requestAttestation',
        {'nonce': nonce},
      );

      if (result == null) {
        throw PlatformException(
          code: 'NULL_RESULT',
          message: 'No attestation result returned',
        );
      }

      return AttestationResult.fromMap(Map<String, dynamic>.from(result));
    } on PlatformException catch (e) {
      throw AttestationException(
        code: e.code,
        message: e.message ?? 'Attestation failed',
      );
    }
  }

  @override
  Future<DeviceSecurityInfo> getDeviceSecurityInfo() async {
    final result = await methodChannel.invokeMethod<Map<dynamic, dynamic>>(
      'getDeviceSecurityInfo',
    );

    if (result == null) {
      throw PlatformException(
        code: 'NULL_RESULT',
        message: 'No device info returned',
      );
    }

    return DeviceSecurityInfo.fromMap(Map<String, dynamic>.from(result));
  }

  @override
  Future<bool> isRooted() async {
    return await methodChannel.invokeMethod<bool>('isRooted') ?? false;
  }

  @override
  Future<bool> isEmulator() async {
    return await methodChannel.invokeMethod<bool>('isEmulator') ?? false;
  }

  @override
  Future<bool> isDebuggerAttached() async {
    return await methodChannel.invokeMethod<bool>('isDebuggerAttached') ??
        false;
  }

  @override
  Future<bool> isHookingDetected() async {
    return await methodChannel.invokeMethod<bool>('isHookingDetected') ?? false;
  }

  @override
  Future<bool> verifySignature(
      {required List<String> expectedSignatures}) async {
    return await methodChannel.invokeMethod<bool>(
          'verifySignature',
          {'expectedSignatures': expectedSignatures},
        ) ??
        false;
  }

  @override
  Future<bool> isProxyEnabled() async {
    return await methodChannel.invokeMethod<bool>('isProxyEnabled') ?? false;
  }

  @override
  Future<bool> isVpnActive() async {
    return await methodChannel.invokeMethod<bool>('isVpnActive') ?? false;
  }

  @override
  Future<SecurityStatus> runSecurityCheck() async {
    final result = await methodChannel.invokeMethod<Map<dynamic, dynamic>>(
      'runFullSecurityCheck',
    );

    if (result == null) {
      return SecurityStatus(
        isSecure: false,
        threats: [
          const SecurityThreat(
            code: 'CHECK_FAILED',
            severity: ThreatSeverity.high,
            message: 'Security check failed',
            isBlocking: true,
          ),
        ],
        timestamp: DateTime.now(),
      );
    }

    final map = Map<String, dynamic>.from(result);
    final threatsList = (map['threats'] as List? ?? [])
        .map((t) => SecurityThreat.fromMap(Map<String, dynamic>.from(t)))
        .toList();

    return SecurityStatus(
      isSecure: map['isSecure'] as bool? ?? false,
      threats: threatsList,
      timestamp: DateTime.fromMillisecondsSinceEpoch(
        map['timestamp'] as int? ?? DateTime.now().millisecondsSinceEpoch,
      ),
    );
  }
}

/// Exception thrown when attestation fails
class AttestationException implements Exception {
  final String code;
  final String message;

  const AttestationException({
    required this.code,
    required this.message,
  });

  @override
  String toString() => 'AttestationException[$code]: $message';
}
