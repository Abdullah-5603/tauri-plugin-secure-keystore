# Changelog

## 0.0.2

- **Desktop: encrypted key-value storage via the OS credential store**
  (Keychain Services on macOS, Credential Manager on Windows, Secret
  Service on Linux), using the [`keyring`](https://crates.io/crates/keyring)
  crate. Items are namespaced by the app's `identifier`
  (`<identifier>.secure_keystore` as the credential service). `getItem` on
  an absent key resolves to `null`, matching Android/iOS — no more
  `UnsupportedPlatform` error on desktop.
- No breaking changes to the Android/iOS backends or the JS/Rust API.

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
