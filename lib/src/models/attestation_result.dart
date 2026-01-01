/// Result from platform attestation (Play Integrity / App Attest)
class AttestationResult {
  /// Attestation token to send to your server
  final String token;

  /// Platform (android/ios)
  final String platform;

  /// Key ID (iOS only)
  final String? keyId;

  /// Timestamp
  final DateTime timestamp;

  /// Additional metadata
  final Map<String, dynamic> metadata;

  const AttestationResult({
    required this.token,
    required this.platform,
    this.keyId,
    required this.timestamp,
    this.metadata = const {},
  });

  factory AttestationResult.fromMap(Map<String, dynamic> map) {
    return AttestationResult(
      token: map['token'] as String,
      platform: map['platform'] as String? ?? 'unknown',
      keyId: map['keyId'] as String?,
      timestamp: DateTime.fromMillisecondsSinceEpoch(
        map['timestamp'] as int? ?? DateTime.now().millisecondsSinceEpoch,
      ),
      metadata: Map<String, dynamic>.from(map['metadata'] as Map? ?? {}),
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'token': token,
      'platform': platform,
      'keyId': keyId,
      'timestamp': timestamp.millisecondsSinceEpoch,
      'metadata': metadata,
    };
  }

  @override
  String toString() =>
      'AttestationResult(platform: $platform, hasToken: ${token.isNotEmpty})';
}
