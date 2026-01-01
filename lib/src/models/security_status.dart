import 'security_threat.dart';

/// Overall security status of the device/app
class SecurityStatus {
  /// Whether the environment is considered secure
  final bool isSecure;

  /// List of detected security threats
  final List<SecurityThreat> threats;

  /// Timestamp of the security check
  final DateTime timestamp;

  const SecurityStatus({
    required this.isSecure,
    required this.threats,
    required this.timestamp,
  });

  /// Whether the app should be blocked from running
  bool get shouldBlock => threats.any((t) => t.isBlocking);

  /// Whether a warning should be shown
  bool get shouldWarn => threats.any(
      (t) => !t.isBlocking && t.severity.index >= ThreatSeverity.medium.index);

  /// Get blocking threats
  List<SecurityThreat> get blockingThreats =>
      threats.where((t) => t.isBlocking).toList();

  /// Get highest severity threat
  SecurityThreat? get highestThreat {
    if (threats.isEmpty) return null;
    return threats
        .reduce((a, b) => a.severity.index > b.severity.index ? a : b);
  }

  factory SecurityStatus.fromMap(Map<String, dynamic> map) {
    return SecurityStatus(
      isSecure: map['isSecure'] as bool? ?? false,
      threats: (map['threats'] as List? ?? [])
          .map((t) => SecurityThreat.fromMap(Map<String, dynamic>.from(t)))
          .toList(),
      timestamp: DateTime.fromMillisecondsSinceEpoch(
        map['timestamp'] as int? ?? DateTime.now().millisecondsSinceEpoch,
      ),
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'isSecure': isSecure,
      'threats': threats.map((t) => t.toMap()).toList(),
      'timestamp': timestamp.millisecondsSinceEpoch,
    };
  }

  @override
  String toString() =>
      'SecurityStatus(isSecure: $isSecure, threats: ${threats.length})';
}
