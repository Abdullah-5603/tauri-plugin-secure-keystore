# Changelog

## 0.0.3-beta.1

- **Optional per-item lock.** `setItem`/`getItem`/`deleteItem` accept a new
  `requireAuth` option (`"os"` or `"password"`); omitting it keeps the
  existing silent, no-prompt behavior exactly as before — this is
  opt-in, not a behavior change for existing callers.
  - `requireAuth: "os"` gates the item behind the platform's own
    device-authentication prompt — Android `BiometricPrompt` (biometric,
    with PIN/pattern/password as the OS's built-in fallback) or the iOS
    Face ID / Touch ID / passcode sheet. Mobile only; rejected with a clear
    `UnsupportedPlatform` error on desktop.
  - `requireAuth: "password"` gates the item behind an app-managed
    password/PIN/pattern string (a PIN or pattern is just a string from
    your own UI — there's no separate code path), via envelope encryption
    with an Argon2id-derived key. Works on every platform, including
    desktop.
- New commands/JS functions to manage the app-level password:
  `setLockPassword`, `changeLockPassword`, `removeLockPassword`,
  `unlockWithPassword`, `lock`, `lockStatus`.
- New `Error` variants: `Locked`, `NoLockPasswordSet`,
  `LockPasswordAlreadySet`, `WeakPassword`, `AuthFailed`,
  `TooManyAttempts`, `UnsupportedPlatform`, `ReservedKey`.
- Hardening on the password/PIN/pattern lock: Argon2id params read from
  stored metadata are bounds-checked before use (a tampered blob can't turn
  `unlockWithPassword` into a memory/CPU DoS); `unlockWithPassword`/
  `changeLockPassword`/`removeLockPassword` share an exponential-backoff
  rate limiter on wrong guesses; key material is wrapped in `Zeroizing`
  end-to-end; `setLockPassword`/`changeLockPassword`/`removeLockPassword`/
  `unlockWithPassword` are serialized against each other to remove a
  check-then-write race.
- No breaking changes: the JS API's new `requireAuth` option is optional on
  all three existing functions, and the Rust `SecureKeystoreExt` trait is
  unchanged.

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
