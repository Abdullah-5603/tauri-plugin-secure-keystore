use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

const PLUGIN_IDENTIFIER: &str = "io.github.abdullah5603.mobilekeystore";

// iOS (Keychain) isn't implemented yet — Android ships first. Add an
// `ios/` Swift package + `api.register_ios_plugin(...)` call here when
// that lands; until then this file only handles Android, and `#[cfg(mobile)]`
// callers on iOS will fail to link (tracked as a known gap, see README).
pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<MobileKeystore<R>> {
    let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "MobileKeystorePlugin")?;

    Ok(MobileKeystore(handle))
}

/// Access to the encrypted key-value store, backed by the Android Keystore
/// (iOS Keychain is not wired up yet — see the README).
pub struct MobileKeystore<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> MobileKeystore<R> {
    pub fn set_item(&self, payload: SetItemRequest) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("setItem", payload)
            .map_err(Into::into)
    }

    pub fn get_item(&self, payload: ItemKey) -> crate::Result<GetItemResponse> {
        self.0
            .run_mobile_plugin("getItem", payload)
            .map_err(Into::into)
    }

    pub fn delete_item(&self, payload: ItemKey) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("deleteItem", payload)
            .map_err(Into::into)
    }
}
