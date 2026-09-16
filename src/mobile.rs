use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "io.github.abdullah5603.securekeystore";

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_secure_keystore);

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<SecureKeystore<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "SecureKeystorePlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_secure_keystore)?;

    Ok(SecureKeystore(handle))
}

/// Access to the encrypted key-value store, backed by the Android Keystore
/// or the iOS Keychain.
pub struct SecureKeystore<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> SecureKeystore<R> {
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
