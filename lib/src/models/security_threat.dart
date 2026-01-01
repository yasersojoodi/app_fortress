/// Severity levels for security threats
enum ThreatSeverity {
  low,
  medium,
  high,
  critical,
}

/// Represents a detected security threat
class SecurityThreat {
  /// Unique threat code
  final String code;

  /// Severity level
  final ThreatSeverity severity;

  /// Human-readable message
  final String message;

  /// Whether this threat should block the app
  final bool isBlocking;

  /// Additional context
  final Map<String, dynamic>? context;

  const SecurityThreat({
    required this.code,
    required this.severity,
    required this.message,
    required this.isBlocking,
    this.context,
  });

  factory SecurityThreat.fromMap(Map<String, dynamic> map) {
    return SecurityThreat(
      code: map['code'] as String? ?? 'UNKNOWN',
      severity: _parseSeverity(map['severity']),
      message: map['message'] as String? ?? 'Unknown threat',
      isBlocking:
          map['blocking'] as bool? ?? map['isBlocking'] as bool? ?? false,
      context: map['context'] as Map<String, dynamic>?,
    );
  }

  static ThreatSeverity _parseSeverity(dynamic value) {
    if (value is ThreatSeverity) return value;
    if (value is String) {
      return ThreatSeverity.values.firstWhere(
        (s) => s.name.toLowerCase() == value.toLowerCase(),
        orElse: () => ThreatSeverity.medium,
      );
    }
    return ThreatSeverity.medium;
  }

  Map<String, dynamic> toMap() {
    return {
      'code': code,
      'severity': severity.name,
      'message': message,
      'isBlocking': isBlocking,
      if (context != null) 'context': context,
    };
  }

  @override
  String toString() =>
      'SecurityThreat($code, ${severity.name}, blocking: $isBlocking)';
}

// Common threat codes
abstract class ThreatCodes {
  static const String rootDetected = 'ROOT_DETECTED';
  static const String jailbreakDetected = 'JAILBREAK_DETECTED';
  static const String emulatorDetected = 'EMULATOR_DETECTED';
  static const String simulatorDetected = 'SIMULATOR_DETECTED';
  static const String debuggerDetected = 'DEBUGGER_DETECTED';
  static const String hookingDetected = 'HOOKING_DETECTED';
  static const String signatureMismatch = 'SIGNATURE_MISMATCH';
  static const String attestationFailed = 'ATTESTATION_FAILED';
  static const String debugBuild = 'DEBUG_BUILD';
  static const String proxyDetected = 'PROXY_DETECTED';
  static const String vpnDetected = 'VPN_DETECTED';
  static const String untrustedInstallSource = 'UNTRUSTED_INSTALL_SOURCE';
}
