import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:app_fortress/app_fortress.dart';

// =============================================================================
// CONFIGURATION - Update these values for your production app
// =============================================================================

class AppSecurityConfig {
  // Google Cloud Project Number (for Play Integrity API)
  // Get from: Google Cloud Console > Project Settings
  static const int cloudProjectNumber = 123456789;

  // Your app's release signing certificate SHA-256 fingerprint
  // Get with: keytool -list -v -keystore your-release.keystore
  // Or from Google Play Console > App Integrity
  static const List<String> expectedSignatures = [
    // Add your release signature here (remove colons)
    // Example: 'A1B2C3D4E5F6...'
  ];
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Configure App Fortress
  // Development: permissive settings for testing
  // Production: strict security (blocks rooted, emulator, debugger, hooking, proxy)
  await AppFortress.configure(
    cloudProjectNumber: AppSecurityConfig.cloudProjectNumber,
    config: kDebugMode
        ? SecurityConfig.development() // Permissive for testing
        : SecurityConfig.production(
            expectedSignatures: AppSecurityConfig.expectedSignatures,
            blockOnProxy: true, // Block proxy/MITM tools
            blockOnVpn: false, // Allow VPN (optional)
          ),
  );

  runApp(const MyApp());
}

// =============================================================================
// APP WITH SECURITY GATE
// =============================================================================

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'App Fortress Demo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: SecurityGate(
        onSecurityCheckFailed: (status) {
          debugPrint('Security threats detected: ${status.threats}');
        },
        onSecurityCheckPassed: (status) {
          debugPrint('Security check passed');
        },
        loadingWidget: const _LoadingScreen(),
        child: const HomePage(),
      ),
    );
  }
}

class _LoadingScreen extends StatelessWidget {
  const _LoadingScreen();

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 16),
            Text('Verifying security...'),
          ],
        ),
      ),
    );
  }
}

// =============================================================================
// HOME PAGE - SECURITY DASHBOARD
// =============================================================================

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  SecurityStatus? _status;
  DeviceSecurityInfo? _deviceInfo;
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    _runSecurityCheck();
  }

  Future<void> _runSecurityCheck() async {
    setState(() => _isLoading = true);
    try {
      final status = await AppFortress.runSecurityCheck();
      final info = await AppFortress.getDeviceSecurityInfo();
      setState(() {
        _status = status;
        _deviceInfo = info;
      });
    } finally {
      setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('App Fortress'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _runSecurityCheck,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : RefreshIndicator(
              onRefresh: _runSecurityCheck,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _buildStatusCard(),
                  const SizedBox(height: 16),
                  _buildSecurityChecksCard(),
                  const SizedBox(height: 16),
                  _buildDeviceInfoCard(),
                  const SizedBox(height: 16),
                  _buildActionsCard(),
                ],
              ),
            ),
    );
  }

  Widget _buildStatusCard() {
    final isSecure = _status?.isSecure ?? false;
    return Card(
      color: isSecure ? Colors.green[50] : Colors.red[50],
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          children: [
            Icon(
              isSecure ? Icons.verified_user : Icons.gpp_bad,
              size: 48,
              color: isSecure ? Colors.green : Colors.red,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    isSecure ? 'SECURE' : 'THREATS DETECTED',
                    style: TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                      color: isSecure ? Colors.green[800] : Colors.red[800],
                    ),
                  ),
                  Text(
                    isSecure
                        ? 'No security issues found'
                        : '${_status?.threats.length ?? 0} issue(s) detected',
                    style: TextStyle(
                      color: isSecure ? Colors.green[600] : Colors.red[600],
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSecurityChecksCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.security, color: Colors.indigo),
                SizedBox(width: 8),
                Text(
                  'Security Checks',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const Divider(),
            _buildCheckItem('Root/Jailbreak', _deviceInfo?.isRooted ?? false),
            _buildCheckItem('Emulator', _deviceInfo?.isEmulator ?? false),
            _buildCheckItem(
                'Debugger', _deviceInfo?.isDebuggerAttached ?? false),
            _buildCheckItem('Hooking', _deviceInfo?.isHookingDetected ?? false),
            _buildCheckItem('Debug Build', _deviceInfo?.isDebuggable ?? false),
            _buildCheckItem(
                'Proxy Enabled', _deviceInfo?.isProxyEnabled ?? false),
            _buildCheckItem('VPN Active', _deviceInfo?.isVpnActive ?? false),
          ],
        ),
      ),
    );
  }

  Widget _buildCheckItem(String label, bool detected) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        children: [
          Icon(
            detected ? Icons.warning_amber : Icons.check_circle,
            color: detected ? Colors.orange : Colors.green,
            size: 20,
          ),
          const SizedBox(width: 12),
          Expanded(child: Text(label)),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: detected ? Colors.orange[100] : Colors.green[100],
              borderRadius: BorderRadius.circular(12),
            ),
            child: Text(
              detected ? 'DETECTED' : 'OK',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.bold,
                color: detected ? Colors.orange[800] : Colors.green[800],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDeviceInfoCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.phone_android, color: Colors.indigo),
                SizedBox(width: 8),
                Text(
                  'Device Info',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const Divider(),
            _buildInfoRow('Platform', _deviceInfo?.platform ?? '-'),
            _buildInfoRow('Model', _deviceInfo?.model ?? '-'),
            _buildInfoRow('OS Version', _deviceInfo?.osVersion ?? '-'),
            _buildInfoRow('App Version', _deviceInfo?.appVersion ?? '-'),
            _buildInfoRow('Install Source', _deviceInfo?.installSource ?? '-'),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(color: Colors.grey)),
          Flexible(
            child: Text(
              value,
              textAlign: TextAlign.end,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildActionsCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.touch_app, color: Colors.indigo),
                SizedBox(width: 8),
                Text(
                  'Actions',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const Divider(),
            const SizedBox(height: 8),
            _buildActionButton(
              'Request Attestation',
              Icons.verified,
              Colors.green,
              _requestAttestation,
            ),
            const SizedBox(height: 8),
            _buildActionButton(
              'Verify Signature',
              Icons.fingerprint,
              Colors.orange,
              _verifySignature,
            ),
            const SizedBox(height: 8),
            _buildActionButton(
              'Quick Security Check',
              Icons.flash_on,
              Colors.blue,
              _quickCheck,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildActionButton(
    String label,
    IconData icon,
    Color color,
    VoidCallback onPressed,
  ) {
    return SizedBox(
      width: double.infinity,
      child: ElevatedButton.icon(
        onPressed: onPressed,
        icon: Icon(icon),
        label: Text(label),
        style: ElevatedButton.styleFrom(
          backgroundColor: color,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(vertical: 12),
        ),
      ),
    );
  }

  Future<void> _requestAttestation() async {
    setState(() => _isLoading = true);
    try {
      final nonce =
          'nonce-${DateTime.now().millisecondsSinceEpoch}-wafeesrgrrewraewagfafwaf';
      final result = await AppFortress.requestAttestation(nonce: nonce);
      if (!mounted) return;
      _showResultDialog(
        'Attestation Success',
        'Token received (${result.token.length} chars)\n\nSend this to your server for verification.',
        true,
      );
    } on AttestationException catch (e) {
      if (!mounted) return;
      _showResultDialog('Attestation Failed', e.message, false);
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _verifySignature() async {
    setState(() => _isLoading = true);
    try {
      final isValid = await AppFortress.verifySignature(
        expectedSignatures: AppSecurityConfig.expectedSignatures,
      );
      if (!mounted) return;
      _showResultDialog(
        isValid ? 'Signature Valid' : 'Signature Invalid',
        isValid
            ? 'App signature matches expected value.'
            : 'WARNING: App may have been tampered with!',
        isValid,
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _quickCheck() async {
    setState(() => _isLoading = true);
    try {
      final status = await AppFortress.quickSecurityCheck();
      if (!mounted) return;
      _showResultDialog(
        status.isSecure ? 'Secure' : 'Issues Found',
        status.isSecure
            ? 'Quick check passed!'
            : 'Threats: ${status.threats.map((t) => t.code).join(', ')}',
        status.isSecure,
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }

  void _showResultDialog(String title, String message, bool success) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Row(
          children: [
            Icon(
              success ? Icons.check_circle : Icons.error,
              color: success ? Colors.green : Colors.red,
            ),
            const SizedBox(width: 8),
            Expanded(child: Text(title)),
          ],
        ),
        content: Text(message),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }
}
