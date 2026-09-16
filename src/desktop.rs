use keyring::Entry;
use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<SecureKeystore<R>> {
    Ok(SecureKeystore { app: app.clone() })
}

/// Encrypted key-value storage backed by the OS credential store: Keychain
/// Services on macOS, Credential Manager on Windows, and the Secret Service
/// (GNOME Keyring / KWallet) on Linux. Items are namespaced by the app's own
/// identifier as the credential `service`, so multiple apps on one machine
/// never collide — the same trade-off as the Android/iOS backends: no
/// biometric or OS-password prompt gates reads.
pub struct SecureKeystore<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> SecureKeystore<R> {
    fn entry(&self, key: &str) -> crate::Result<Entry> {
        let service = format!("{}.secure_keystore", self.app.config().identifier);
        Ok(Entry::new(&service, key)?)
    }

    pub fn set_item(&self, payload: SetItemRequest) -> crate::Result<()> {
        self.entry(&payload.key)?.set_password(&payload.value)?;
        Ok(())
    }

    pub fn get_item(&self, payload: ItemKey) -> crate::Result<GetItemResponse> {
        match self.entry(&payload.key)?.get_password() {
            Ok(value) => Ok(GetItemResponse { value: Some(value) }),
            // No entry stored for this key — resolve to `None`, not an error,
            // matching the Android/iOS backends.
            Err(keyring::Error::NoEntry) => Ok(GetItemResponse { value: None }),
            Err(err) => Err(err.into()),
        }
    }

    pub fn delete_item(&self, payload: ItemKey) -> crate::Result<()> {
        match self.entry(&payload.key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}
