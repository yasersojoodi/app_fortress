import 'security_threat.dart';

/// Comprehensive device security information
class DeviceSecurityInfo {
  final String platform;
  final String? model;
  final String? manufacturer;
  final String? osVersion;
  final int? sdkVersion;
  final String? appVersion;
  final int? appVersionCode;
  final String? packageName;
  final bool isRooted;
  final bool isEmulator;
  final bool isDebuggerAttached;
  final bool isHookingDetected;
  final bool isDebuggable;
  final bool isProxyEnabled;
  final bool isVpnActive;
  final String? installSource;
  final String? signatureSha256;
  final List<SecurityThreat> threats;
  final DateTime timestamp;

  const DeviceSecurityInfo({
    required this.platform,
    this.model,
    this.manufacturer,
    this.osVersion,
    this.sdkVersion,
    this.appVersion,
    this.appVersionCode,
    this.packageName,
    this.isRooted = false,
    this.isEmulator = false,
    this.isDebuggerAttached = false,
    this.isHookingDetected = false,
    this.isDebuggable = false,
    this.isProxyEnabled = false,
    this.isVpnActive = false,
    this.installSource,
    this.signatureSha256,
    this.threats = const [],
    required this.timestamp,
  });

  /// Check if any security concern is present
  bool get hasSecurityConcerns =>
      isRooted ||
      isEmulator ||
      isDebuggerAttached ||
      isHookingDetected ||
      isProxyEnabled;

  /// Check if installed from official store
  bool get isOfficialInstall =>
      installSource == 'com.android.vending' ||
      installSource == 'appstore' ||
      installSource == 'testflight';

  factory DeviceSecurityInfo.fromMap(Map<String, dynamic> map) {
    return DeviceSecurityInfo(
      platform: map['platform'] as String? ?? 'unknown',
      model: map['model'] as String?,
      manufacturer: map['manufacturer'] as String?,
      osVersion: map['osVersion'] as String?,
      sdkVersion: map['sdkVersion'] as int?,
      appVersion: map['appVersion'] as String?,
      appVersionCode: map['appVersionCode'] as int?,
      packageName: map['packageName'] as String?,
      isRooted: map['isRooted'] as bool? ?? false,
      isEmulator: map['isEmulator'] as bool? ?? false,
      isDebuggerAttached: map['isDebuggerAttached'] as bool? ?? false,
      isHookingDetected: map['isHookingDetected'] as bool? ?? false,
      isDebuggable: map['isDebuggable'] as bool? ?? false,
      isProxyEnabled: map['isProxyEnabled'] as bool? ?? false,
      isVpnActive: map['isVpnActive'] as bool? ?? false,
      installSource: map['installSource'] as String?,
      signatureSha256: map['signatureSha256'] as String?,
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
      'platform': platform,
      'model': model,
      'manufacturer': manufacturer,
      'osVersion': osVersion,
      'sdkVersion': sdkVersion,
      'appVersion': appVersion,
      'appVersionCode': appVersionCode,
      'packageName': packageName,
      'isRooted': isRooted,
      'isEmulator': isEmulator,
      'isDebuggerAttached': isDebuggerAttached,
      'isHookingDetected': isHookingDetected,
      'isDebuggable': isDebuggable,
      'isProxyEnabled': isProxyEnabled,
      'isVpnActive': isVpnActive,
      'installSource': installSource,
      'signatureSha256': signatureSha256,
      'threats': threats.map((t) => t.toMap()).toList(),
      'timestamp': timestamp.millisecondsSinceEpoch,
    };
  }

  @override
  String toString() =>
      'DeviceSecurityInfo(platform: $platform, hasIssues: $hasSecurityConcerns)';
}
