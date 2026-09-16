use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

/// Desktop backend not implemented yet (tracked for a future release —
/// see the README). Deliberately no silent fallback in the meantime: an
/// in-memory or plaintext-file stand-in would be actively misleading, code
/// that appears to persist a secret on desktop but doesn't, or does so
/// insecurely, is worse than a clear error at the call site. Until this
/// lands, pair the plugin with a desktop-appropriate secret store (e.g.
/// `tauri-plugin-stronghold`) and pick the backend per-target.
pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<SecureKeystore<R>> {
    Ok(SecureKeystore { _app: app.clone() })
}

pub struct SecureKeystore<R: Runtime> {
    _app: AppHandle<R>,
}

impl<R: Runtime> SecureKeystore<R> {
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
