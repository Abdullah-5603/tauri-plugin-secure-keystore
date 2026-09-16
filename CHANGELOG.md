# Changelog

## 0.0.1

First stable release. Same API surface and storage behavior as
`0.0.1-beta.1`, plus iOS support:

- **iOS: encrypted key-value storage via the Keychain**
  (`kSecClassGenericPassword`, items namespaced by bundle identifier), using
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — readable without a
  biometric/passcode prompt and never synced to iCloud, matching the
  Android backend's "no biometric enrollment required" trade-off.
- Docs: expanded README with concrete use cases, a Rust-side usage example,
  and a full accounting of how each platform backend stores data.
- No breaking changes to the Android backend or the JS/Rust API.

## 0.0.1-beta.1

Initial release.

- Android: encrypted key-value storage via `AndroidKeyStore` (AES-256-GCM),
  no biometric enrollment required.
- Desktop: not implemented yet — returns a clear error rather than a
  silent fallback.
- iOS: not implemented yet.
