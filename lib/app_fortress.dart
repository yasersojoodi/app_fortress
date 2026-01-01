/// App Fortress - Production-grade multi-layer app security for Flutter
///
/// Features:
/// - 🛡️ Play Integrity API (Android) & App Attest (iOS)
/// - 🔐 SSL Certificate Pinning
/// - 🚫 Root/Jailbreak Detection
/// - 🔍 Emulator/Simulator Detection
/// - 🐛 Anti-Debugging Protection
/// - 🪝 Hooking Framework Detection (Frida, Xposed)
/// - 🔑 String Encryption
/// - 📱 Signature Verification
///
/// Quick Start:
/// ```dart
/// import 'package:app_fortress/app_fortress.dart';
///
/// void main() async {
///   WidgetsFlutterBinding.ensureInitialized();
///
///   // Configure the plugin
///   await AppFortress.configure(
///     cloudProjectNumber: 123456789, // Android Play Integrity
///   );
///
///   // Run security check
///   final status = await AppFortress.runSecurityCheck();
///
///   if (status.isSecure) {
///     runApp(MyApp());
///   } else {
///     runApp(SecurityBlockedApp(threats: status.threats));
///   }
/// }
/// ```
library;

// Main API
export 'src/app_fortress.dart';
export 'src/app_fortress_platform_interface.dart';
export 'src/app_fortress_method_channel.dart';

// Models
export 'src/models/security_status.dart';
export 'src/models/security_threat.dart';
export 'src/models/device_security_info.dart';
export 'src/models/attestation_result.dart';
export 'src/models/security_config.dart';

// Protection
export 'src/protection/ssl_pinning.dart';
export 'src/protection/string_encryption.dart';

// Widgets
export 'src/widgets/security_gate.dart';
