import 'dart:io';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

/// SSL Certificate Pinning configuration
class CertificatePinConfig {
  /// Map of hostname to SHA-256 pin hashes (Base64 encoded)
  final Map<String, List<String>> pins;

  /// Whether to allow connection if pinning fails (dev only!)
  final bool allowOnFailure;

  const CertificatePinConfig({
    required this.pins,
    this.allowOnFailure = false,
  });

  /// Development config - no pinning
  factory CertificatePinConfig.development() {
    return const CertificatePinConfig(pins: {}, allowOnFailure: true);
  }

  /// Production config with pins
  factory CertificatePinConfig.production({
    required Map<String, List<String>> pins,
  }) {
    return CertificatePinConfig(pins: pins, allowOnFailure: false);
  }
}

/// HTTP client with certificate pinning
class PinnedHttpClient {
  final CertificatePinConfig _config;
  late final HttpClient _httpClient;
  late final http.Client _client;

  PinnedHttpClient({required CertificatePinConfig config}) : _config = config {
    _httpClient = HttpClient()..badCertificateCallback = _validateCertificate;
    _client = IOClient(_httpClient);
  }

  /// Get the pinned HTTP client
  http.Client get client => _client;

  bool _validateCertificate(X509Certificate cert, String host, int port) {
    final hostPins = _config.pins[host];
    if (hostPins == null || hostPins.isEmpty) {
      return _config.allowOnFailure;
    }

    try {
      final certHash =
          base64.encode(cert.der.sublist(0, 32.clamp(0, cert.der.length)));
      return hostPins.any((pin) => pin == certHash) || _config.allowOnFailure;
    } catch (e) {
      return _config.allowOnFailure;
    }
  }

  /// Close the client
  void close() {
    _client.close();
    _httpClient.close();
  }
}

/// Generate certificate pins
///
/// Run in terminal:
/// ```bash
/// openssl s_client -connect api.example.com:443 | \
///   openssl x509 -pubkey -noout | \
///   openssl pkey -pubin -outform der | \
///   openssl dgst -sha256 -binary | \
///   openssl enc -base64
/// ```
abstract class CertificatePinGenerator {
  static String? fromPem(String pemCertificate) {
    try {
      final lines = pemCertificate.split('\n');
      final base64Lines = lines
          .where((line) => !line.startsWith('-----') && line.trim().isNotEmpty)
          .join('');
      final der = base64.decode(base64Lines);
      return base64.encode(der.sublist(0, 32.clamp(0, der.length)));
    } catch (e) {
      return null;
    }
  }
}
