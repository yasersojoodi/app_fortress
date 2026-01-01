/// Configuration for App Fortress security features
///
/// Use [SecurityConfig.development] for debug/testing builds (permissive).
/// Use [SecurityConfig.production] for release builds (strict security).
class SecurityConfig {
  /// Expected app signatures (SHA-256, no colons)
  final List<String> expectedSignatures;

  /// Allow app to run on rooted/jailbroken devices
  final bool allowRootedDevices;

  /// Allow app to run on emulators/simulators
  final bool allowEmulators;

  /// Allow app to run in debug mode
  final bool allowDebugMode;

  /// Block app if hooking framework is detected (Frida, Xposed, etc.)
  final bool blockOnHooking;

  /// Block app if debugger is attached
  final bool blockOnDebugger;

  /// Block app if proxy is detected
  final bool blockOnProxy;

  /// Block app if VPN is active
  final bool blockOnVpn;

  const SecurityConfig({
    this.expectedSignatures = const [],
    this.allowRootedDevices = false,
    this.allowEmulators = false,
    this.allowDebugMode = false,
    this.blockOnHooking = true,
    this.blockOnDebugger = true,
    this.blockOnProxy = true,
    this.blockOnVpn = false,
  });

  /// Development configuration - permissive for testing
  /// Pass custom [SecurityConfig] to override specific settings
  factory SecurityConfig.development([SecurityConfig? customConfig]) {
    return customConfig ??
        const SecurityConfig(
          allowRootedDevices: true,
          allowEmulators: true,
          allowDebugMode: true,
          blockOnHooking: false,
          blockOnDebugger: false,
          blockOnProxy: false,
          blockOnVpn: false,
        );
  }

  /// Production configuration - strict security enforcement
  /// [expectedSignatures] - Your app's release signing certificate SHA-256 fingerprints
  factory SecurityConfig.production({
    required List<String> expectedSignatures,
    bool blockOnProxy = true,
    bool blockOnVpn = false,
  }) {
    return SecurityConfig(
      expectedSignatures: expectedSignatures,
      allowRootedDevices: false, // Block rooted devices
      allowEmulators: false, // Block emulators
      allowDebugMode: false, // Block debug builds
      blockOnHooking: true, // Block Frida/Xposed
      blockOnDebugger: true, // Block debugger attachment
      blockOnProxy: blockOnProxy, // Block proxy/MITM tools
      blockOnVpn: blockOnVpn, // Optional: block VPN
    );
  }

  SecurityConfig copyWith({
    List<String>? expectedSignatures,
    bool? allowRootedDevices,
    bool? allowEmulators,
    bool? allowDebugMode,
    bool? blockOnHooking,
    bool? blockOnDebugger,
    bool? blockOnProxy,
    bool? blockOnVpn,
  }) {
    return SecurityConfig(
      expectedSignatures: expectedSignatures ?? this.expectedSignatures,
      allowRootedDevices: allowRootedDevices ?? this.allowRootedDevices,
      allowEmulators: allowEmulators ?? this.allowEmulators,
      allowDebugMode: allowDebugMode ?? this.allowDebugMode,
      blockOnHooking: blockOnHooking ?? this.blockOnHooking,
      blockOnDebugger: blockOnDebugger ?? this.blockOnDebugger,
      blockOnProxy: blockOnProxy ?? this.blockOnProxy,
      blockOnVpn: blockOnVpn ?? this.blockOnVpn,
    );
  }

  @override
  String toString() {
    return 'SecurityConfig('
        'allowRootedDevices: $allowRootedDevices, '
        'allowEmulators: $allowEmulators, '
        'allowDebugMode: $allowDebugMode, '
        'blockOnHooking: $blockOnHooking, '
        'blockOnDebugger: $blockOnDebugger, '
        'blockOnProxy: $blockOnProxy, '
        'blockOnVpn: $blockOnVpn)';
  }
}
