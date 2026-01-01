import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/// Encrypted string utilities to prevent static analysis
///
/// Usage:
/// ```dart
/// // Generate encrypted value at build time
/// final encrypted = EncryptedString.encrypt('my-api-key', 'secret-key');
///
/// // Decrypt at runtime
/// final apiKey = EncryptedString.decode(encrypted, 'secret-key');
/// ```
class EncryptedString {
  EncryptedString._();

  /// Encrypt a string (use at build time)
  static String encrypt(String plaintext, String key) {
    final keyBytes = _deriveKey(key);
    final plaintextBytes = utf8.encode(plaintext);

    final random = Random.secure();
    final iv = Uint8List.fromList(
      List.generate(16, (_) => random.nextInt(256)),
    );

    final encrypted = _xorEncrypt(plaintextBytes, keyBytes, iv);

    final combined = Uint8List(iv.length + encrypted.length);
    combined.setRange(0, iv.length, iv);
    combined.setRange(iv.length, combined.length, encrypted);

    return base64.encode(combined);
  }

  /// Decrypt a string (use at runtime)
  static String decode(String encrypted, String key) {
    try {
      final keyBytes = _deriveKey(key);
      final combined = base64.decode(encrypted);

      final iv = combined.sublist(0, 16);
      final encryptedData = combined.sublist(16);

      final decrypted = _xorEncrypt(encryptedData, keyBytes, iv);
      return utf8.decode(decrypted);
    } catch (e) {
      throw FormatException('Failed to decrypt: $e');
    }
  }

  static Uint8List _deriveKey(String key) {
    final keyBytes = utf8.encode(key);
    final derived = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      derived[i] = keyBytes[i % keyBytes.length] ^ (i * 17);
    }
    return derived;
  }

  static Uint8List _xorEncrypt(List<int> data, Uint8List key, Uint8List iv) {
    final result = Uint8List(data.length);
    var keyStream = Uint8List.fromList(iv);

    for (var i = 0; i < data.length; i++) {
      if (i > 0 && i % 16 == 0) {
        keyStream = _updateKeyStream(keyStream, key);
      }
      result[i] = data[i] ^ keyStream[i % 16] ^ key[i % key.length];
    }
    return result;
  }

  static Uint8List _updateKeyStream(Uint8List current, Uint8List key) {
    final next = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      next[i] = current[i] ^ key[i % key.length] ^ (i + 1);
    }
    return next;
  }
}

/// Obfuscated string that decrypts on first access
class ObfuscatedString {
  final String _encrypted;
  final String Function() _keyProvider;
  String? _cached;

  ObfuscatedString(this._encrypted, this._keyProvider);

  /// Get decrypted value (cached)
  String get value {
    _cached ??= EncryptedString.decode(_encrypted, _keyProvider());
    return _cached!;
  }

  /// Clear cached value
  void clear() => _cached = null;

  @override
  String toString() => '[OBFUSCATED]';
}

/// Secure string that clears itself
class SecureString {
  List<int>? _data;

  SecureString(String value) {
    _data = utf8.encode(value);
  }

  String get value {
    if (_data == null) throw StateError('SecureString cleared');
    return utf8.decode(_data!);
  }

  bool get isAvailable => _data != null;

  void clear() {
    if (_data != null) {
      for (var i = 0; i < _data!.length; i++) {
        _data![i] = 0;
      }
      _data = null;
    }
  }

  @override
  String toString() => '[SECURE]';
}
