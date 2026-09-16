# tauri-plugin-secure-keystore

[![npm downloads](https://img.shields.io/npm/dt/tauri-plugin-secure-keystore?label=npm%20downloads)](https://www.npmjs.com/package/tauri-plugin-secure-keystore)
[![crates.io downloads](https://img.shields.io/crates/d/tauri-plugin-secure-keystore?label=crates.io%20downloads)](https://crates.io/crates/tauri-plugin-secure-keystore)
[![jsr downloads](https://jsr.io/badges/@abdullah/tauri-plugin-secure-keystore/total-downloads)](https://jsr.io/@abdullah/tauri-plugin-secure-keystore)

Encrypted key-value storage for Tauri 2 apps, backed by the
**Android Keystore**, **iOS Keychain**, and — on desktop — the OS credential
store (**macOS Keychain Services**, **Windows Credential Manager**,
**Linux Secret Service**). No biometric enrollment required by default — it
works on every device, not just the ones with Face ID / fingerprint /
screen-lock set up.

Need a prompt in front of a *specific* secret instead? An **optional,
per-item lock** lets you require a PIN, password, pattern, or the device's
own biometrics before that item is readable — see
[Locking an item](#locking-an-item). Nothing is locked unless you ask for
it; every existing `setItem`/`getItem` call keeps working exactly as before.

## Use cases

Reach for this plugin whenever your app needs to persist a **secret**
*silently* — read on app launch, no user interaction — rather than a value
that's fine to keep in plain `localStorage` or an unencrypted file:

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
  per-device Keystore material; desktop entries live in that machine's own
  credential store) — e.g. a per-install device identifier used for
  attestation.
- **Cross-platform apps** that need the same `setItem`/`getItem`/`deleteItem`
  calls to do the right thing on mobile *and* desktop, without branching on
  `platform()` in your own code.

And when a secret is high-value enough that a silent read isn't good
enough — a stored crypto wallet key, a "view my saved cards" screen, an
admin-mode toggle — reach for `requireAuth`:

- **"Unlock the app" flows**, e.g. a password-manager-style app that shows a
  PIN pad on launch and only decrypts the vault after it's entered
  correctly — see the [password/PIN/pattern guide](#guide-app-managed-password-pin-or-pattern-lock).
- **"Confirm it's really you" moments** before a sensitive action —
  revealing a seed phrase, approving a payment, changing security
  settings — using the device's own Face ID / Touch ID / PIN prompt, see
  the [OS biometric guide](#guide-os-biometric--device-credential-lock-mobile-only).
- **Defense in depth for a subset of your data**: most of an app's secrets
  (session tokens, cached credentials) stay silently readable for a smooth
  UX, while a few high-value items (a recovery phrase, a legal-document
  signing key) get the extra lock — both live in the same store, the choice
  is per item.

If your app *should* require a biometric prompt before **every** secret is
readable, and can't tolerate the `"password"` fallback this plugin offers,
[Why this exists](#why-this-exists) links to an alternative built for
exactly that.

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

This plugin picks a different trade-off by default, across every platform
it supports: on Android, the Keystore-backed AES key used for plain
`setItem`/`getItem` calls is created **without**
`setUserAuthenticationRequired(true)`; on iOS, plain items are stored with
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` rather than a
`SecAccessControl` that requires biometrics; on desktop, items go straight
into the OS credential store with no OS-password re-prompt attached. None
of that requires biometric enrollment or gates reads behind a prompt.

Unlike `@impierce/tauri-plugin-keystore`, though, that's a *default*, not
the only mode: pass `requireAuth: "os"` on a specific `setItem`/`getItem`
call and this plugin will gate that item behind the same kind of native
biometric/device-credential prompt — see
[Locking an item](#locking-an-item). The difference is that it's opt-in and
per-item, and on top of that this plugin also offers `requireAuth:
"password"`, an app-managed PIN/password/pattern lock that works even on
desktop, where there's no OS biometric prompt to hook into at all.

## Status

- ✅ Android — implemented, Keystore-backed AES-256-GCM. Optional
  `requireAuth: "os"` via `BiometricPrompt`; optional `requireAuth:
  "password"` via the cross-platform app-managed lock.
- ✅ iOS — implemented, Keychain-backed (`kSecClassGenericPassword`).
  Optional `requireAuth: "os"` via a `.userPresence` access control;
  optional `requireAuth: "password"`.
- ✅ Desktop — implemented via [`keyring`](https://crates.io/crates/keyring),
  backed by Keychain Services (macOS), Credential Manager (Windows), and
  the Secret Service (Linux — GNOME Keyring / KWallet). `requireAuth: "os"`
  is **not** available (no per-item OS prompt exists on desktop) and
  returns a clear error; `requireAuth: "password"` works normally.

## Install

`src-tauri/Cargo.toml`:

```toml
[dependencies]
tauri-plugin-secure-keystore = "0.0.3-beta.1"
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

`secure-keystore:default` covers every command this plugin exposes,
including the lock-management ones below. See
[`permissions/autogenerated/reference.md`](permissions/autogenerated/reference.md)
if you want to allow/deny individual commands instead.

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

The lock-management functions (below) are also available directly from
Rust as free functions — `tauri_plugin_secure_keystore::set_lock_password`,
`unlock_with_password`, `lock_keystore`, `lock_status`,
`change_lock_password`, `remove_lock_password` — each taking `&AppHandle<R>`
as the first argument, for apps that manage the lock from native code
instead of the webview.

## Locking an item

Every one of `setItem`, `getItem`, and `deleteItem` accepts an optional
second argument, `{ requireAuth }`:

```ts
type AuthMethod = "os" | "password";
```

| | `requireAuth: "os"` | `requireAuth: "password"` |
|---|---|---|
| What gates it | The platform's own device-authentication prompt | A password/PIN/pattern string your app collects |
| Covers | Biometric, **with PIN/pattern/password as the OS's built-in fallback** | PIN, password, or pattern — your UI decides which |
| Platforms | Mobile only (Android, iOS) | Every platform, including desktop |
| Re-auth needed | Every single call | Once per app session, via `unlockWithPassword` |
| Setup required | None — device must have *something* enrolled | Call `setLockPassword` once |

**Important:** `requireAuth` is part of *where* an item is stored, not just
a read-time check — an item set with `requireAuth: "os"` lives separately
from a plain item of the same key name (and from a `requireAuth:
"password"` item of the same key name). Use the same `requireAuth` value
for `setItem`, `getItem`, and `deleteItem` on a given key.

Both mechanisms are independent — pick whichever fits a given item, or use
both across different items in the same app. Neither is required: call
`setItem`/`getItem` without `requireAuth` at all, as before, and nothing
changes.

**A note on what `requireAuth: "os"` does and doesn't hide:** whether a
given key *exists* is revealed without authentication — `getItem(key, {
requireAuth: "os" })` on a key nobody ever set resolves straight to `null`
with no prompt shown, because there's nothing there for the OS to gate
access to. On iOS this is inherent to how Keychain access control works
(a query matching nothing can't trigger a `SecAccessControl` prompt) and
isn't something this plugin can change. Only the item's *value* is behind
the prompt. (`requireAuth: "password"` doesn't have this gap: `getItem`
checks the password session is unlocked *before* looking the key up, so a
locked store can't be probed for which keys exist.)

### Guide: OS biometric / device-credential lock (mobile only)

Use this when you want the OS's own Face ID / Touch ID / fingerprint sheet
(with PIN/pattern/password as its built-in fallback) in front of one
specific item. There's no separate setup step — just pass the option:

```ts
import { setItem, getItem } from "tauri-plugin-secure-keystore";

// Storing a seed phrase behind a biometric/device-credential prompt.
async function saveRecoveryPhrase(phrase: string) {
  await setItem("wallet_recovery_phrase", phrase, { requireAuth: "os" });
}

// Reading it back always re-prompts — there is no "unlock once" session
// for this method, unlike requireAuth: "password" below. That's
// intentional: it's the strictest guarantee this plugin offers.
async function revealRecoveryPhrase(): Promise<string | null> {
  try {
    return await getItem("wallet_recovery_phrase", { requireAuth: "os" });
  } catch (err) {
    // User canceled, failed authentication, or no biometric/device
    // credential is enrolled at all on this device.
    console.error("Could not authenticate:", err);
    return null;
  }
}
```

On desktop, both calls reject immediately with an `UnsupportedPlatform`
error — there's no OS-level per-item prompt to hook into there. If your app
runs on desktop too, either skip `requireAuth: "os"` there and use
`requireAuth: "password"` instead, or branch on
[`platform()`](https://v2.tauri.app/reference/javascript/os/#platform) from
`@tauri-apps/plugin-os`.

### Guide: app-managed password, PIN, or pattern lock

Use this for a password-manager-style "enter your PIN to unlock the app"
flow, or anywhere you want the *same* lock UX on desktop as on mobile. A
4-digit PIN, a drawn pattern serialized to a string (e.g. `"0-3-6-7-8"`),
and a full password are all just strings to this API — there's no separate
PIN or pattern mode, your UI decides which one the user is entering.

**1. First run: let the user set their PIN/password/pattern.**

```ts
import { setLockPassword } from "tauri-plugin-secure-keystore";

async function onCreatePin(pin: string) {
  await setLockPassword(pin); // e.g. "4821", or a full passphrase
  // The session is now unlocked — requireAuth: "password" items are
  // usable immediately, no separate unlock call needed right after this.
}
```

**2. Every later launch: ask for it again and unlock.**

```ts
import { unlockWithPassword, lockStatus } from "tauri-plugin-secure-keystore";

async function onAppStart() {
  const { hasLockPassword } = await lockStatus();
  if (!hasLockPassword) return; // user never set one up — nothing to do

  // Show your own PIN pad / password field, then:
  async function onPinEntered(pin: string) {
    try {
      await unlockWithPassword(pin);
      // proceed into the app
    } catch {
      // wrong PIN — ask again
    }
  }
}
```

**3. Store and read items behind it, same as any other item:**

```ts
import { setItem, getItem } from "tauri-plugin-secure-keystore";

await setItem("db_encryption_key", key, { requireAuth: "password" });

// Later, in the same session (after unlockWithPassword succeeded):
const key = await getItem("db_encryption_key", { requireAuth: "password" });
// Throws a "locked" error instead if unlockWithPassword hasn't been
// called yet this session — catch it and show the PIN pad again.
```

**4. Locking, changing, or removing the PIN/password:**

```ts
import { lock, changeLockPassword, removeLockPassword } from "tauri-plugin-secure-keystore";

await lock(); // e.g. on app backgrounding, or a manual "lock" button —
               // clears the in-memory session; requireAuth: "password"
               // calls fail until unlockWithPassword runs again

await changeLockPassword(oldPin, newPin); // requires the current one

// Deletes the lock entirely. Any items you stored with
// requireAuth: "password" become permanently unreadable — read and
// re-save anything you need to keep (without requireAuth) first.
await removeLockPassword(currentPin);
```

The session (the unwrapped key `unlockWithPassword` produces) lives only in
memory for the lifetime of the process — nothing is cached to disk, so
every app restart needs a fresh `unlockWithPassword` call, even if the OS
itself never asked the user to re-authenticate.

## How it works

### Android

- A single AES-256-GCM key is generated inside `AndroidKeyStore` on first
  use, aliased per-app (`<your.package.name>.secure_keystore_key`) so
  multiple apps on one device never collide.
- Each plain `setItem` call encrypts the value and stores the ciphertext +
  IV in a `SharedPreferences` file, also namespaced per-app.
- The key itself never leaves the Keystore; only the `Cipher` API is used
  to encrypt/decrypt through it.
- `requireAuth: "os"` items use a **second** Keystore key
  (`<your.package.name>.secure_keystore_auth_key`), created with
  `setUserAuthenticationRequired(true)` — Android itself refuses to unlock
  this key without a fresh `BiometricPrompt` authentication, not just this
  plugin's own logic. On Android 11+ (API 30+), that prompt accepts either
  a class-3 biometric or the device's PIN/pattern/password as a built-in
  fallback (`BIOMETRIC_STRONG | DEVICE_CREDENTIAL`); on older Android, it
  falls back to biometric-only. These items live in their own
  `SharedPreferences` file, entirely separate from plain items.

### iOS

- Each plain item is stored as its own `kSecClassGenericPassword` Keychain
  entry, with `kSecAttrService` set to the app's bundle identifier (so
  multiple apps never collide) and `kSecAttrAccount` set to the item's key.
- Plain items use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`:
  readable without a biometric/passcode prompt once the device has been
  unlocked once since boot, and never synced to iCloud or any other device.
- `requireAuth: "os"` items are stored under a separate `kSecAttrService`
  (`<bundle-id>.secure_keystore_auth`) with a `SecAccessControl` using the
  `.userPresence` flag — iOS itself shows the Face ID / Touch ID / passcode
  sheet when such an item is read, before this plugin's code ever sees the
  data. Writing a `.userPresence`-protected item does not itself require
  authentication on iOS (only reading does) — that's an iOS Keychain
  behavior, not a choice this plugin makes.

### Desktop

- Each plain item is its own credential in the OS-native store, addressed
  by a `service` string (`<your.app.identifier>.secure_keystore`, from
  `tauri.conf.json`'s `identifier`) and a `username` equal to the item's
  key — so, as on mobile, multiple apps on one machine never collide.
- The concrete store is chosen per-OS by the [`keyring`](https://crates.io/crates/keyring)
  crate at build time: Keychain Services on macOS, Credential Manager on
  Windows, and the Secret Service D-Bus API on Linux (works with both
  GNOME Keyring and KWallet).
- `getItem` on a key that was never set (or was deleted) resolves to `null`
  rather than raising — same contract as Android/iOS.
- `requireAuth: "os"` always fails with `UnsupportedPlatform` on desktop —
  there is no OS-level per-item authentication gate on any of the three
  desktop credential stores to hook into. Use `requireAuth: "password"`.

### The app-managed password/PIN/pattern lock (`requireAuth: "password"`)

This mechanism is implemented once, in Rust, on top of the platform
backends above — it works identically on all four platforms.

1. `setLockPassword(password)` generates a random 256-bit **data key**, and
   wraps ("envelope encryption") it with a key derived from `password` via
   **Argon2id** (19 MiB memory, 2 iterations, 1 thread — the OWASP-2024
   minimum recommendation) and a random 16-byte salt. The wrapped data key,
   salt, nonce, and Argon2 parameters are stored as one JSON blob under a
   reserved item key, through the *same* per-platform backend as everything
   else — so it still benefits from Android Keystore / iOS Keychain /
   OS-credential-store protection underneath.
2. The unwrapped data key is kept **only in process memory**
   (`unlockWithPassword` populates it; `lock()` or a process restart clears
   it) — it is never written to disk itself.
3. Each `setItem(key, value, { requireAuth: "password" })` call encrypts
   `value` with the in-memory data key using AES-256-GCM and a fresh random
   96-bit nonce, then stores that ciphertext through the normal backend
   `setItem` path — so a `requireAuth: "password"` item is encrypted
   *twice*: once by this layer, once by whatever the platform backend
   already does to it.
4. Changing the password (`changeLockPassword`) only re-wraps the 32-byte
   data key under the new password-derived key — it does not touch, or
   need to re-encrypt, any stored items.

**What this does and doesn't protect against:** the password/PIN/pattern
never leaves your process (there's no server round-trip, no plaintext
storage of it anywhere), and Argon2id makes offline guessing against a
stolen `LockMeta` blob deliberately slow. `unlockWithPassword`,
`changeLockPassword`, and `removeLockPassword` also share an in-memory,
exponential-backoff rate limiter — after 3 free attempts, each further
wrong guess forces a growing delay (capped at 30s) before the next attempt
is accepted, specifically because a short PIN (e.g. 10,000 four-digit
combinations) would otherwise be guessable in reasonable time even through
Argon2id's per-guess cost alone. That counter resets on process restart, so
it's a throttle, not a lockout — it does **not** protect against a
compromised or debugged instance of *your own running app* reading its own
process memory, which no in-app lock can. Treat it as a UX gate and a
defense against casual disk/backup extraction and rapid online guessing,
not as a defense against a fully compromised device.

## Errors

| Error | When |
|---|---|
| `Locked` | `requireAuth: "password"` used before `unlockWithPassword`/`setLockPassword` this session |
| `NoLockPasswordSet` | `unlockWithPassword`/`changeLockPassword`/`removeLockPassword` called before any `setLockPassword` |
| `LockPasswordAlreadySet` | `setLockPassword` called again without removing the existing one first |
| `WeakPassword` | An empty string passed as a password/PIN/pattern |
| `AuthFailed` | Wrong password/PIN/pattern passed to `unlockWithPassword`/`changeLockPassword`/`removeLockPassword` |
| `TooManyAttempts` | Rate-limited after repeated wrong guesses — wait and retry (see [the lock section](#the-app-managed-passwordpinpattern-lock-requireauth-password)) |
| `UnsupportedPlatform` | `requireAuth: "os"` used on desktop |
| `ReservedKey` | An item key collides with the plugin's own internal storage key |

## License

MIT OR Apache-2.0, matching the rest of the Tauri plugin ecosystem.
