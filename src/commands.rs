use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::Result;
use crate::SecureKeystoreExt;

#[command]
pub(crate) async fn set_item<R: Runtime>(
    app: AppHandle<R>,
    key: String,
    value: String,
) -> Result<()> {
    app.secure_keystore().set_item(SetItemRequest { key, value })
}

#[command]
pub(crate) async fn get_item<R: Runtime>(
    app: AppHandle<R>,
    key: String,
) -> Result<GetItemResponse> {
    app.secure_keystore().get_item(ItemKey { key })
}

#[command]
pub(crate) async fn delete_item<R: Runtime>(app: AppHandle<R>, key: String) -> Result<()> {
    app.secure_keystore().delete_item(ItemKey { key })
}
