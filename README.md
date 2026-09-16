# tauri-plugin-secure-keystore

Encrypted key-value storage for Tauri 2 apps, backed by the
**Android Keystore** and **iOS Keychain** (desktop planned — see [Status](#status)).
No biometric enrollment required — it works on every device, not just the
ones with Face ID / fingerprint / screen-lock set up.

## Use cases

Reach for this plugin whenever your app needs to persist a **secret** on a
mobile device *silently* — read on app launch, no user interaction — rather
than a value that's fine to keep in plain `localStorage` or an unencrypted
file:

- **Session / refresh tokens** — keep a user logged in across app restarts
  without storing the token in plaintext on disk.
- **API keys and client secrets** shipped or fetched at runtime, that would
  be a real problem if pulled off a rooted/jailbroken device via a file
  backup.
- **Locally cached credentials** for offline-first apps (e.g. a hashed PIN
  or an encryption key for a local database) that must survive app restarts
  without prompting the user every time.
- **Device-bound secrets** you deliberately do **not** want synced across a
  user's devices (iOS items are `ThisDeviceOnly`; Android keys are
  per-device Keystore material) — e.g. a per-install device identifier used
  for attestation.

If your app *should* require a biometric prompt before a secret is
readable, this plugin's trade-off is the wrong one for you — see
[Why this exists](#why-this-exists) for an alternative.

## Why this exists

Two other options were evaluated first and both fell short:

- A plugin claiming Android + iOS + desktop support via `keyring-core`
  turned out to be effectively unpublished — its `Cargo.toml` declares a
  version that was never actually released to crates.io (the crate name is
  taken by an unrelated, desktop-only plugin from a different author), and
  its own README's npm install instructions point at that other author's
  package. Real source code, not a usable dependency.
- A legitimately published, actively maintained plugin
  (`@impierce/tauri-plugin-keystore`) does wrap Android Keystore + iOS
  Keychain correctly, but **requires biometrics already enrolled on the
  device and fails otherwise**, with no PIN/pattern-only fallback — a real
  gap for apps that need to work on any device, not just ones with
  biometrics set up.

This plugin picks a different trade-off: on Android, the Keystore-backed AES
key is created **without** `setUserAuthenticationRequired(true)`; on iOS,
items are stored with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
rather than a `SecAccessControl` that requires biometrics. Both backends are
still hardware-backed where the platform supports it and never leave the
device — a compromised app process can't extract the raw key material on
Android, and iOS Keychain items are marked device-only (no iCloud sync) —
but neither requires biometric enrollment or gates reads behind a biometric
prompt. If you need the stronger "requires biometrics to decrypt" guarantee,
this plugin is not that; look at `@impierce/tauri-plugin-keystore` instead.

## Status

- ✅ Android — implemented, Keystore-backed AES-256-GCM.
- ✅ iOS — implemented, Keychain-backed (`kSecClassGenericPassword`).
- 🚧 Desktop — not implemented yet (see [`src/desktop.rs`](src/desktop.rs)).
  Every command currently returns a clear error rather than a silent,
  insecure fallback. Until a desktop-appropriate backend lands, pair this
  with something like `tauri-plugin-stronghold` if your app also targets
  desktop.

## Install

`src-tauri/Cargo.toml`:

```toml
[dependencies]
tauri-plugin-secure-keystore = "0.0.1"
```

```bash
npm install tauri-plugin-secure-keystore
# or: pnpm add / yarn add / bun add
```

`src-tauri/src/lib.rs`:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_secure_keystore::init())
    // ...
```

`src-tauri/capabilities/default.json`:

```json
{
  "permissions": ["secure-keystore:default"]
}
```

## Usage

### From the frontend (TypeScript)

```ts
import { setItem, getItem, deleteItem } from "tauri-plugin-secure-keystore";

// After a successful login, persist the session token silently — no
// biometric prompt, works even without a screen lock enrolled.
await setItem("session_token", token);

// On app launch, restore it without asking the user to log in again.
const sessionToken = await getItem("session_token"); // string | null
if (sessionToken) {
  // already authenticated
}

// On logout, wipe it.
await deleteItem("session_token");
```

`getItem` resolves to `null` (not an error) when nothing is stored for that
key — checking `sessionToken === null` is how you detect "no logged-in
session" on a fresh install.

### From Rust

The same store is reachable from Rust commands via `SecureKeystoreExt`,
useful when you want to read/write a secret without a round-trip through
the webview:

```rust
use tauri_plugin_secure_keystore::SecureKeystoreExt;

#[tauri::command]
async fn restore_session(app: tauri::AppHandle) -> Result<Option<String>, String> {
    app.secure_keystore()
        .get_item(tauri_plugin_secure_keystore::ItemKey {
            key: "session_token".into(),
        })
        .map(|res| res.value)
        .map_err(|e| e.to_string())
}
```

## How it works

### Android

- A single AES-256-GCM key is generated inside `AndroidKeyStore` on first
  use, aliased per-app (`<your.package.name>.secure_keystore_key`) so
  multiple apps on one device never collide.
- Each `setItem` call encrypts the value and stores the ciphertext + IV in
  a `SharedPreferences` file, also namespaced per-app.
- The key itself never leaves the Keystore; only the `Cipher` API is used
  to encrypt/decrypt through it.

### iOS

- Each item is stored as its own `kSecClassGenericPassword` Keychain entry,
  with `kSecAttrService` set to the app's bundle identifier (so multiple
  apps never collide) and `kSecAttrAccount` set to the item's key.
- Items use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: readable
  without a biometric/passcode prompt once the device has been unlocked
  once since boot, and never synced to iCloud or any other device.

## License

MIT OR Apache-2.0, matching the rest of the Tauri plugin ecosystem.
