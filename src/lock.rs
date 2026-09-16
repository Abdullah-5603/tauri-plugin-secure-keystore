//! App-managed password/PIN/pattern lock.
//!
//! This is deliberately independent of the platform backends (desktop.rs /
//! mobile.rs): it works by encrypting item values with a random 256-bit data
//! key *before* handing them to the normal `set_item`/`get_item` backend
//! calls, so the ciphertext gets a second, password-derived layer on top of
//! whatever protection the OS store already provides. The data key itself is
//! wrapped ("envelope encryption") with a key derived from the app's chosen
//! password via Argon2id, so changing the password only re-wraps a 32-byte
//! key rather than re-encrypting every item.
//!
//! The unwrapped data key lives only in process memory (`LockState`), never
//! written to disk — a fresh `unlockWithPassword` call is required after
//! every process restart. Since a PIN or a drawn pattern is just a string
//! from the app's own UI, this same password path is what backs the PIN and
//! pattern use cases described in the README — there is no separate PIN or
//! pattern code path.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, Runtime};
use zeroize::Zeroizing;

use crate::models::{ItemKey, SetItemRequest};
use crate::{Error, Result, SecureKeystoreExt};

/// Reserved backend key holding the wrapped data key. Rejected if an app
/// tries to use it as an item key via `set_item`/`get_item`/`delete_item`.
pub(crate) const LOCK_META_KEY: &str = "__secure_keystore_lock_meta__";

// OWASP-recommended minimums for Argon2id (2024 cheat sheet: m=19 MiB, t=2, p=1).
const ARGON2_M_COST: u32 = 19 * 1024;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

// `LockMeta` stores its own Argon2 params for forward compatibility (so a
// future release can raise the defaults without breaking existing stored
// locks) — but that means a tampered or corrupted `LockMeta` blob is
// untrusted input. Bound the params we'll actually run Argon2id with, so a
// malicious blob (e.g. a huge m_cost) can't turn `unlockWithPassword` into
// a memory-exhaustion / hang DoS. Generous enough for any reasonable future
// tuning, far below anything that would allocate an unreasonable amount of
// memory or block for an unreasonable amount of time.
const ARGON2_M_COST_MAX: u32 = 256 * 1024; // 256 MiB
const ARGON2_T_COST_MAX: u32 = 10;
const ARGON2_P_COST_MAX: u32 = 4;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

// Rate-limit password/PIN/pattern guesses against `unlockWithPassword` /
// `changeLockPassword` / `removeLockPassword`. Argon2id alone isn't enough
// protection for a short PIN (e.g. 10,000 4-digit combinations) against a
// local attacker able to call these repeatedly without any backoff.
const BACKOFF_FREE_ATTEMPTS: u32 = 3;
const BACKOFF_BASE: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

struct AttemptState {
    failures: u32,
    last_failure: Instant,
}

#[derive(Default)]
pub struct LockState {
    session_key: Mutex<Option<Zeroizing<[u8; KEY_LEN]>>>,
    attempts: Mutex<Option<AttemptState>>,
    /// Serializes `setLockPassword`/`changeLockPassword`/
    /// `removeLockPassword`/`unlockWithPassword` against each other, so a
    /// concurrent pair of calls can't race on the check-then-write of the
    /// stored `LockMeta` blob.
    config_lock: Mutex<()>,
}

#[derive(Serialize, Deserialize)]
struct LockMeta {
    salt: String,
    nonce: String,
    wrapped_key: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

fn derive_kek(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params =
        Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN)).map_err(|_| Error::AuthFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, out.as_mut_slice())
        .map_err(|_| Error::AuthFailed)?;
    Ok(out)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Wraps `data_key` under a key derived from `password` (fresh random salt
/// and nonce). Pure function, no I/O — kept separate from
/// [`wrap_and_store`] so the crypto itself is directly unit-testable.
fn wrap_key(password: &str, data_key: &[u8; KEY_LEN]) -> Result<LockMeta> {
    if password.is_empty() {
        return Err(Error::WeakPassword);
    }
    let salt = random_bytes::<SALT_LEN>();
    let kek = derive_kek(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;
    let cipher = Aes256Gcm::new_from_slice(kek.as_slice()).map_err(|_| Error::AuthFailed)?;
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let wrapped = cipher
        .encrypt(nonce, data_key.as_slice())
        .map_err(|_| Error::AuthFailed)?;

    Ok(LockMeta {
        salt: B64.encode(salt),
        nonce: B64.encode(nonce_bytes),
        wrapped_key: B64.encode(wrapped),
        m_cost: ARGON2_M_COST,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
    })
}

/// Reverses [`wrap_key`]: verifies `password` against `meta` and returns the
/// unwrapped data key. Pure function, no I/O.
fn unwrap_key(meta: &LockMeta, password: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if meta.m_cost > ARGON2_M_COST_MAX
        || meta.t_cost > ARGON2_T_COST_MAX
        || meta.p_cost > ARGON2_P_COST_MAX
        || meta.p_cost == 0
    {
        // A `LockMeta` we ourselves wrote never has params outside these
        // bounds — this only trips on a corrupted or tampered blob, so
        // treat it the same as a wrong password rather than a distinct
        // error that would confirm the blob was tampered with.
        return Err(Error::AuthFailed);
    }

    let salt = B64.decode(&meta.salt).map_err(|_| Error::AuthFailed)?;
    let nonce_bytes = B64.decode(&meta.nonce).map_err(|_| Error::AuthFailed)?;
    let wrapped = B64.decode(&meta.wrapped_key).map_err(|_| Error::AuthFailed)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(Error::AuthFailed);
    }

    let kek = derive_kek(password, &salt, meta.m_cost, meta.t_cost, meta.p_cost)?;
    let cipher = Aes256Gcm::new_from_slice(kek.as_slice()).map_err(|_| Error::AuthFailed)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let data_key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        cipher
            .decrypt(nonce, wrapped.as_slice())
            .map_err(|_| Error::AuthFailed)?,
    );
    if data_key_bytes.len() != KEY_LEN {
        return Err(Error::AuthFailed);
    }
    let mut data_key = Zeroizing::new([0u8; KEY_LEN]);
    data_key.copy_from_slice(&data_key_bytes);
    Ok(data_key)
}

/// Encrypts `plaintext` under `key` with a fresh random nonce, returning
/// `base64(nonce || ciphertext)`. Pure function, no I/O.
fn encrypt_bytes(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| Error::AuthFailed)?;
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::AuthFailed)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(B64.encode(out))
}

/// Reverses [`encrypt_bytes`]. Pure function, no I/O.
fn decrypt_bytes(key: &[u8; KEY_LEN], blob_b64: &str) -> Result<String> {
    let raw = B64.decode(blob_b64).map_err(|_| Error::AuthFailed)?;
    if raw.len() < NONCE_LEN {
        return Err(Error::AuthFailed);
    }
    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| Error::AuthFailed)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::AuthFailed)?;
    String::from_utf8(plaintext).map_err(|_| Error::AuthFailed)
}

fn load_meta<R: Runtime>(app: &AppHandle<R>) -> Result<Option<LockMeta>> {
    let raw = app
        .secure_keystore()
        .get_item(ItemKey {
            key: LOCK_META_KEY.into(),
        })?
        .value;
    match raw {
        None => Ok(None),
        Some(json) => serde_json::from_str(&json).map(Some).map_err(|_| Error::AuthFailed),
    }
}

fn check_backoff<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<LockState>();
    let guard = state.attempts.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(a) = guard.as_ref() {
        if a.failures > BACKOFF_FREE_ATTEMPTS {
            let shift = (a.failures - BACKOFF_FREE_ATTEMPTS).min(8);
            let wait = (BACKOFF_BASE * (1u32 << shift)).min(BACKOFF_MAX);
            if a.last_failure.elapsed() < wait {
                return Err(Error::TooManyAttempts);
            }
        }
    }
    Ok(())
}

fn record_failure<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<LockState>();
    let mut guard = state.attempts.lock().unwrap_or_else(|e| e.into_inner());
    let failures = guard.as_ref().map_or(0, |a| a.failures) + 1;
    *guard = Some(AttemptState {
        failures,
        last_failure: Instant::now(),
    });
}

fn record_success<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<LockState>();
    let mut guard = state.attempts.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// Verifies `password` against the stored metadata and returns the
/// unwrapped data key, without touching the in-memory session. Rate-limited
/// via [`check_backoff`] — every caller of this (unlock, change, remove)
/// shares the same failure counter.
fn unwrap_data_key<R: Runtime>(
    app: &AppHandle<R>,
    password: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    check_backoff(app)?;
    let meta = load_meta(app)?.ok_or(Error::NoLockPasswordSet)?;
    match unwrap_key(&meta, password) {
        Ok(key) => {
            record_success(app);
            Ok(key)
        }
        Err(err) => {
            if matches!(err, Error::AuthFailed) {
                record_failure(app);
            }
            Err(err)
        }
    }
}

fn wrap_and_store<R: Runtime>(
    app: &AppHandle<R>,
    password: &str,
    data_key: &[u8; KEY_LEN],
) -> Result<()> {
    let meta = wrap_key(password, data_key)?;
    let meta_json = serde_json::to_string(&meta).map_err(|_| Error::AuthFailed)?;
    app.secure_keystore().set_item(SetItemRequest {
        key: LOCK_META_KEY.into(),
        value: meta_json,
    })
}

fn set_session<R: Runtime>(app: &AppHandle<R>, data_key: Zeroizing<[u8; KEY_LEN]>) {
    let state = app.state::<LockState>();
    let mut guard = state.session_key.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(data_key);
}

pub fn set_lock_password<R: Runtime>(app: &AppHandle<R>, password: &str) -> Result<()> {
    let state = app.state::<LockState>();
    let _guard = state.config_lock.lock().unwrap_or_else(|e| e.into_inner());
    if load_meta(app)?.is_some() {
        return Err(Error::LockPasswordAlreadySet);
    }
    let data_key = Zeroizing::new(random_bytes::<KEY_LEN>());
    wrap_and_store(app, password, &data_key)?;
    // Auto-unlock: the app just proved it knows the password by setting it.
    set_session(app, data_key);
    Ok(())
}

pub fn change_lock_password<R: Runtime>(
    app: &AppHandle<R>,
    old_password: &str,
    new_password: &str,
) -> Result<()> {
    let state = app.state::<LockState>();
    let _guard = state.config_lock.lock().unwrap_or_else(|e| e.into_inner());
    let data_key = unwrap_data_key(app, old_password)?;
    wrap_and_store(app, new_password, &data_key)?;
    set_session(app, data_key);
    Ok(())
}

pub fn remove_lock_password<R: Runtime>(app: &AppHandle<R>, password: &str) -> Result<()> {
    let state = app.state::<LockState>();
    let _config_guard = state.config_lock.lock().unwrap_or_else(|e| e.into_inner());
    // Verify the caller actually knows the password before destroying the
    // wrapped key — this is a destructive action (see the README note on
    // `requireAuth: "password"` items becoming permanently unreadable).
    unwrap_data_key(app, password)?;
    app.secure_keystore().delete_item(ItemKey {
        key: LOCK_META_KEY.into(),
    })?;
    let mut session_guard = state.session_key.lock().unwrap_or_else(|e| e.into_inner());
    *session_guard = None;
    Ok(())
}

pub fn unlock_with_password<R: Runtime>(app: &AppHandle<R>, password: &str) -> Result<()> {
    let state = app.state::<LockState>();
    let _guard = state.config_lock.lock().unwrap_or_else(|e| e.into_inner());
    let data_key = unwrap_data_key(app, password)?;
    set_session(app, data_key);
    Ok(())
}

pub fn lock<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<LockState>();
    let mut guard = state.session_key.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

pub fn lock_status<R: Runtime>(app: &AppHandle<R>) -> Result<crate::models::LockStatusResponse> {
    let state = app.state::<LockState>();
    let unlocked = state
        .session_key
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some();
    Ok(crate::models::LockStatusResponse {
        has_lock_password: load_meta(app)?.is_some(),
        unlocked,
    })
}

/// Returns `Error::Locked` unless a password session is currently active.
/// Callers should check this *before* looking up whether a
/// `requireAuth: "password"` item exists, so a locked keystore doesn't leak
/// key-existence through "Locked" vs "not found" — see
/// [`decrypt_with_session`]'s caller in `commands.rs`.
pub fn require_unlocked<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<LockState>();
    let guard = state.session_key.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        Ok(())
    } else {
        Err(Error::Locked)
    }
}

/// Encrypts `plaintext` with the current session's data key. Returns
/// `Error::Locked` if `unlockWithPassword`/`setLockPassword` hasn't been
/// called yet (or `lock()` was called since).
pub fn encrypt_with_session<R: Runtime>(app: &AppHandle<R>, plaintext: &[u8]) -> Result<String> {
    let state = app.state::<LockState>();
    let guard = state.session_key.lock().unwrap_or_else(|e| e.into_inner());
    let key = guard.as_ref().ok_or(Error::Locked)?;
    encrypt_bytes(key, plaintext)
}

pub fn decrypt_with_session<R: Runtime>(app: &AppHandle<R>, blob_b64: &str) -> Result<String> {
    let state = app.state::<LockState>();
    let guard = state.session_key.lock().unwrap_or_else(|e| e.into_inner());
    let key = guard.as_ref().ok_or(Error::Locked)?;
    decrypt_bytes(key, blob_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let data_key = random_bytes::<KEY_LEN>();
        let meta = wrap_key("correct horse battery staple", &data_key).unwrap();
        let recovered = unwrap_key(&meta, "correct horse battery staple").unwrap();
        assert_eq!(&*recovered, &data_key);
    }

    #[test]
    fn wrap_rejects_empty_password() {
        let data_key = random_bytes::<KEY_LEN>();
        assert!(matches!(wrap_key("", &data_key), Err(Error::WeakPassword)));
    }

    #[test]
    fn unwrap_rejects_wrong_password() {
        let data_key = random_bytes::<KEY_LEN>();
        let meta = wrap_key("right password", &data_key).unwrap();
        assert!(matches!(
            unwrap_key(&meta, "wrong password"),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn unwrap_rejects_a_pin_style_password_against_a_different_pin() {
        // A 4-digit PIN is just a short password string from this module's
        // point of view — exercise that path explicitly.
        let data_key = random_bytes::<KEY_LEN>();
        let meta = wrap_key("4821", &data_key).unwrap();
        assert!(unwrap_key(&meta, "4821").is_ok());
        assert!(matches!(
            unwrap_key(&meta, "1248"),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn wrap_uses_a_fresh_salt_and_nonce_every_call() {
        let data_key = random_bytes::<KEY_LEN>();
        let a = wrap_key("same password", &data_key).unwrap();
        let b = wrap_key("same password", &data_key).unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.wrapped_key, b.wrapped_key);
    }

    #[test]
    fn tampered_wrapped_key_is_rejected() {
        let data_key = random_bytes::<KEY_LEN>();
        let mut meta = wrap_key("password", &data_key).unwrap();
        let mut wrapped = B64.decode(&meta.wrapped_key).unwrap();
        wrapped[0] ^= 0xFF;
        meta.wrapped_key = B64.encode(wrapped);
        assert!(matches!(
            unwrap_key(&meta, "password"),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn item_encrypt_decrypt_roundtrip() {
        let key = random_bytes::<KEY_LEN>();
        let blob = encrypt_bytes(&key, b"secret value").unwrap();
        let plain = decrypt_bytes(&key, &blob).unwrap();
        assert_eq!(plain, "secret value");
    }

    #[test]
    fn item_decrypt_with_wrong_key_fails() {
        let key1 = random_bytes::<KEY_LEN>();
        let key2 = random_bytes::<KEY_LEN>();
        let blob = encrypt_bytes(&key1, b"secret value").unwrap();
        assert!(decrypt_bytes(&key2, &blob).is_err());
    }

    #[test]
    fn item_encrypt_nonce_differs_across_calls() {
        let key = random_bytes::<KEY_LEN>();
        let a = encrypt_bytes(&key, b"same plaintext").unwrap();
        let b = encrypt_bytes(&key, b"same plaintext").unwrap();
        // Same plaintext, same key, but a random nonce each time means the
        // ciphertext blobs must differ — otherwise nonce reuse would leak
        // that two stored items share a value.
        assert_ne!(a, b);
    }

    #[test]
    fn item_decrypt_rejects_truncated_blob() {
        let key = random_bytes::<KEY_LEN>();
        assert!(decrypt_bytes(&key, "").is_err());
        assert!(decrypt_bytes(&key, &B64.encode([0u8; 4])).is_err());
    }

    #[test]
    fn item_decrypt_rejects_garbage_base64() {
        let key = random_bytes::<KEY_LEN>();
        assert!(decrypt_bytes(&key, "not valid base64!!").is_err());
    }

    #[test]
    fn unwrap_rejects_absurd_argon2_params() {
        // A tampered/corrupted LockMeta claiming a huge m_cost must be
        // rejected before ever running Argon2id with it, or a malicious
        // blob could turn unlockWithPassword into a memory/CPU DoS.
        let data_key = random_bytes::<KEY_LEN>();
        let mut meta = wrap_key("password", &data_key).unwrap();
        meta.m_cost = u32::MAX;
        assert!(matches!(
            unwrap_key(&meta, "password"),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn unwrap_rejects_zero_parallelism() {
        let data_key = random_bytes::<KEY_LEN>();
        let mut meta = wrap_key("password", &data_key).unwrap();
        meta.p_cost = 0;
        assert!(matches!(
            unwrap_key(&meta, "password"),
            Err(Error::AuthFailed)
        ));
    }
}
