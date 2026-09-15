# tauri-plugin-mobile-keystore

Encrypted key-value storage for Tauri 2 mobile apps, backed by the
**Android Keystore** (iOS Keychain planned — see [Status](#status)).

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

This plugin picks a different trade-off: the Keystore-backed AES key is
created **without** `setUserAuthenticationRequired(true)`. The key is still
hardware-backed and non-exportable — a compromised app process can't
extract the raw key material — but it doesn't require biometric enrollment
or gate reads behind a biometric prompt. If you need the stronger
"requires biometrics to decrypt" guarantee, this plugin is not that; look
at `@impierce/tauri-plugin-keystore` instead.

## Status

- ✅ Android — implemented, Keystore-backed AES-256-GCM.
- 🚧 iOS — not implemented yet. `src/mobile.rs` only registers the Android
  plugin; adding iOS means an `ios/` Swift package plus wiring
  `api.register_ios_plugin(...)`. Contributions welcome.
- ❌ Desktop — not supported, on purpose (see [`src/desktop.rs`](src/desktop.rs)).
  Every command returns a clear error rather than a silent, insecure
  fallback. Pair this with a desktop-appropriate store (e.g.
  `tauri-plugin-stronghold`) if your app also targets desktop.

## Install

`src-tauri/Cargo.toml`:

```toml
[dependencies]
tauri-plugin-mobile-keystore = "0.1"
```

```bash
npm install tauri-plugin-mobile-keystore-api
# or: pnpm add / yarn add / bun add
```

`src-tauri/src/lib.rs`:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_mobile_keystore::init())
    // ...
```

`src-tauri/capabilities/default.json`:

```json
{
  "permissions": ["mobile-keystore:default"]
}
```

## Usage

```ts
import { setItem, getItem, deleteItem } from "tauri-plugin-mobile-keystore-api";

await setItem("session_token", token);
const stored = await getItem("session_token"); // string | null
await deleteItem("session_token");
```

## How it works (Android)

- A single AES-256-GCM key is generated inside `AndroidKeyStore` on first
  use, aliased per-app (`<your.package.name>.mobile_keystore_key`) so
  multiple apps on one device never collide.
- Each `setItem` call encrypts the value and stores the ciphertext + IV in
  a `SharedPreferences` file, also namespaced per-app.
- The key itself never leaves the Keystore; only the `Cipher` API is used
  to encrypt/decrypt through it.

## License

MIT OR Apache-2.0, matching the rest of the Tauri plugin ecosystem.
