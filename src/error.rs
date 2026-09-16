use serde::{ser::Serializer, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[cfg(mobile)]
    #[error(transparent)]
    PluginInvoke(#[from] tauri::plugin::mobile::PluginInvokeError),
    #[cfg(desktop)]
    #[error(transparent)]
    Keyring(#[from] keyring::Error),

    #[error("the key \"{0}\" is reserved for internal use by this plugin")]
    ReservedKey(String),
    #[error("requireAuth: \"os\" is not supported on this platform")]
    UnsupportedPlatform,
    #[error("the keystore is locked; call unlockWithPassword() first")]
    Locked,
    #[error("no lock password has been set; call setLockPassword() first")]
    NoLockPasswordSet,
    #[error("a lock password is already set; call changeLockPassword() to change it")]
    LockPasswordAlreadySet,
    #[error("password must not be empty")]
    WeakPassword,
    #[error("incorrect password")]
    AuthFailed,
    #[error("too many failed attempts; wait before trying again")]
    TooManyAttempts,
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}
