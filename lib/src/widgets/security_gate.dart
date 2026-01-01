import 'package:flutter/material.dart';

import '../app_fortress.dart';
import '../models/security_status.dart';

/// Widget that gates app access based on security verification
///
/// Example:
/// ```dart
/// void main() async {
///   WidgetsFlutterBinding.ensureInitialized();
///   await AppFortress.configure(cloudProjectNumber: 123456789);
///
///   runApp(
///     SecurityGate(
///       child: MyApp(),
///       onSecurityCheckFailed: (status) {
///         print('Security failed: ${status.threats}');
///       },
///     ),
///   );
/// }
/// ```
class SecurityGate extends StatefulWidget {
  /// Child widget to show when security passes
  final Widget child;

  /// Custom loading widget
  final Widget? loadingWidget;

  /// Custom blocked widget
  final Widget Function(BuildContext, SecurityStatus)? blockedBuilder;

  /// Custom warning widget
  final Widget Function(BuildContext, SecurityStatus, VoidCallback)?
      warningBuilder;

  /// Callback when security check fails
  final void Function(SecurityStatus)? onSecurityCheckFailed;

  /// Callback when security check passes
  final void Function(SecurityStatus)? onSecurityCheckPassed;

  /// Whether to use quick check only
  final bool quickCheckOnly;

  const SecurityGate({
    super.key,
    required this.child,
    this.loadingWidget,
    this.blockedBuilder,
    this.warningBuilder,
    this.onSecurityCheckFailed,
    this.onSecurityCheckPassed,
    this.quickCheckOnly = false,
  });

  @override
  State<SecurityGate> createState() => _SecurityGateState();
}

class _SecurityGateState extends State<SecurityGate> {
  SecurityStatus? _status;
  bool _isLoading = true;
  bool _warningDismissed = false;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _runSecurityCheck();
  }

  Future<void> _runSecurityCheck() async {
    try {
      setState(() {
        _isLoading = true;
        _error = null;
      });

      final status = widget.quickCheckOnly
          ? await AppFortress.quickSecurityCheck()
          : await AppFortress.runSecurityCheck();

      if (mounted) {
        setState(() {
          _status = status;
          _isLoading = false;
        });

        if (status.isSecure) {
          widget.onSecurityCheckPassed?.call(status);
        } else {
          widget.onSecurityCheckFailed?.call(status);
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e;
          _isLoading = false;
        });
      }
    }
  }

  void _dismissWarning() {
    setState(() => _warningDismissed = true);
  }

  void _retry() {
    _warningDismissed = false;
    _runSecurityCheck();
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return widget.loadingWidget ?? const _DefaultLoadingWidget();
    }

    if (_error != null) {
      return _DefaultErrorWidget(error: _error!, onRetry: _retry);
    }

    final status = _status;
    if (status == null) {
      return const _DefaultLoadingWidget();
    }

    if (status.shouldBlock) {
      return widget.blockedBuilder?.call(context, status) ??
          _DefaultBlockedWidget(status: status);
    }

    if (status.shouldWarn && !_warningDismissed) {
      return widget.warningBuilder?.call(context, status, _dismissWarning) ??
          _DefaultWarningWidget(status: status, onContinue: _dismissWarning);
    }

    return widget.child;
  }
}

class _DefaultLoadingWidget extends StatelessWidget {
  const _DefaultLoadingWidget();

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        body: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(
                  width: 48,
                  height: 48,
                  child: CircularProgressIndicator(strokeWidth: 3)),
              SizedBox(height: 24),
              Text('Verifying security...',
                  style: TextStyle(fontSize: 16, color: Colors.grey)),
            ],
          ),
        ),
      ),
    );
  }
}

class _DefaultBlockedWidget extends StatelessWidget {
  final SecurityStatus status;
  const _DefaultBlockedWidget({required this.status});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        body: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.shield_outlined, size: 80, color: Colors.red),
                const SizedBox(height: 24),
                const Text('Security Check Failed',
                    style:
                        TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
                const SizedBox(height: 16),
                Text(
                  status.highestThreat?.message ??
                      'Security concerns detected.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 16, color: Colors.grey[600]),
                ),
                const SizedBox(height: 32),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.red[50],
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('Detected Issues:',
                          style: TextStyle(
                              fontWeight: FontWeight.bold, color: Colors.red)),
                      const SizedBox(height: 8),
                      ...status.blockingThreats.map((t) => Padding(
                            padding: const EdgeInsets.only(bottom: 4),
                            child: Row(children: [
                              const Icon(Icons.error_outline,
                                  size: 16, color: Colors.red),
                              const SizedBox(width: 8),
                              Expanded(child: Text(t.message)),
                            ]),
                          )),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _DefaultWarningWidget extends StatelessWidget {
  final SecurityStatus status;
  final VoidCallback onContinue;
  const _DefaultWarningWidget({required this.status, required this.onContinue});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        body: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.warning_amber_rounded,
                    size: 80, color: Colors.orange),
                const SizedBox(height: 24),
                const Text('Security Warning',
                    style:
                        TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
                const SizedBox(height: 16),
                Text(
                  'Some security concerns detected. You may continue with limited functionality.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 16, color: Colors.grey[600]),
                ),
                const SizedBox(height: 32),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: onContinue,
                    style: ElevatedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 16)),
                    child: const Text('Continue Anyway'),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _DefaultErrorWidget extends StatelessWidget {
  final Object error;
  final VoidCallback onRetry;
  const _DefaultErrorWidget({required this.error, required this.onRetry});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        body: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.error_outline, size: 80, color: Colors.grey),
                const SizedBox(height: 24),
                const Text('Verification Error',
                    style:
                        TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
                const SizedBox(height: 16),
                Text('Unable to verify security. Please try again.',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 16, color: Colors.grey[600])),
                const SizedBox(height: 32),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: onRetry,
                    style: ElevatedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 16)),
                    child: const Text('Retry'),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
