# Changelog

## 0.1.0

Initial release.

- Android: encrypted key-value storage via `AndroidKeyStore` (AES-256-GCM),
  no biometric enrollment required.
- Desktop: intentionally unsupported — returns a clear error rather than a
  silent fallback.
- iOS: not implemented yet.
