use serde::{Deserialize, Serialize};

/// How access to an item is gated, chosen per-item by the app at
/// `setItem`/`getItem` time. `None` (the default, omitting the option
/// entirely) keeps today's behavior: no prompt, no password, silent
/// read/write.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AuthMethod {
    /// Gate the item behind the OS's own device-authentication prompt:
    /// Android `BiometricPrompt` (biometric, with PIN/pattern/password as a
    /// built-in fallback), or the iOS Face ID / Touch ID / passcode sheet.
    /// Mobile only — rejected on desktop, where no such OS prompt exists.
    Os,
    /// Gate the item behind an app-managed password/PIN/pattern string, set
    /// via `setLockPassword` and unlocked via `unlockWithPassword`. Works on
    /// every platform, including desktop.
    Password,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemKey {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetItemRequest {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetItemResponse {
    pub value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockStatusResponse {
    /// Whether `setLockPassword` has been called (a lock password exists).
    pub has_lock_password: bool,
    /// Whether the password session is currently unlocked in memory. Always
    /// `false` right after process start, even if `has_lock_password` is
    /// `true` — `unlockWithPassword` must be called again each launch.
    pub unlocked: bool,
}
