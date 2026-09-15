use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

/// This plugin exists specifically for the mobile Keystore/Keychain APIs —
/// there is no desktop backend, and deliberately no silent fallback (an
/// in-memory or plaintext-file stand-in would be actively misleading: code
/// that appears to persist a secret on desktop but doesn't, or does so
/// insecurely, is worse than a clear error at the call site). If your app
/// also runs on desktop, pair this with a desktop-appropriate secret store
/// (e.g. `tauri-plugin-stronghold`) and pick the backend per-target.
pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<MobileKeystore<R>> {
    Ok(MobileKeystore { _app: app.clone() })
}

pub struct MobileKeystore<R: Runtime> {
    _app: AppHandle<R>,
}

impl<R: Runtime> MobileKeystore<R> {
    pub fn set_item(&self, _payload: SetItemRequest) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub fn get_item(&self, _payload: ItemKey) -> crate::Result<GetItemResponse> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub fn delete_item(&self, _payload: ItemKey) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }
}
