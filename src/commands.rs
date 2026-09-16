use tauri::{command, AppHandle, Runtime};
use zeroize::Zeroizing;

use crate::lock as lockmod;
use crate::models::*;
use crate::Error;
use crate::Result;
use crate::SecureKeystoreExt;

fn check_reserved(key: &str) -> Result<()> {
    if key == lockmod::LOCK_META_KEY {
        return Err(Error::ReservedKey(key.to_string()));
    }
    Ok(())
}

#[command]
pub(crate) async fn set_item<R: Runtime>(
    app: AppHandle<R>,
    key: String,
    value: String,
    require_auth: Option<AuthMethod>,
) -> Result<()> {
    check_reserved(&key)?;
    match require_auth {
        None => app.secure_keystore().set_item(SetItemRequest { key, value }),
        Some(AuthMethod::Os) => app.secure_keystore().set_item_os(SetItemRequest { key, value }),
        Some(AuthMethod::Password) => {
            let encrypted = lockmod::encrypt_with_session(&app, value.as_bytes())?;
            app.secure_keystore().set_item(SetItemRequest {
                key,
                value: encrypted,
            })
        }
    }
}

#[command]
pub(crate) async fn get_item<R: Runtime>(
    app: AppHandle<R>,
    key: String,
    require_auth: Option<AuthMethod>,
) -> Result<GetItemResponse> {
    check_reserved(&key)?;
    match require_auth {
        None => app.secure_keystore().get_item(ItemKey { key }),
        Some(AuthMethod::Os) => app.secure_keystore().get_item_os(ItemKey { key }),
        Some(AuthMethod::Password) => {
            // Check the session is unlocked *before* looking the key up, so
            // a locked keystore can't be probed for which keys exist by
            // comparing a "Locked" error against a "null" result.
            lockmod::require_unlocked(&app)?;
            let raw = app.secure_keystore().get_item(ItemKey { key })?;
            match raw.value {
                None => Ok(GetItemResponse { value: None }),
                Some(v) => Ok(GetItemResponse {
                    value: Some(lockmod::decrypt_with_session(&app, &v)?),
                }),
            }
        }
    }
}

#[command]
pub(crate) async fn delete_item<R: Runtime>(
    app: AppHandle<R>,
    key: String,
    require_auth: Option<AuthMethod>,
) -> Result<()> {
    check_reserved(&key)?;
    match require_auth {
        // Password-tagged items live at the same underlying storage slot as
        // plain items (only their value is pre-encrypted), so the plain
        // delete path already covers them.
        Some(AuthMethod::Os) => app.secure_keystore().delete_item_os(ItemKey { key }),
        Some(AuthMethod::Password) | None => app.secure_keystore().delete_item(ItemKey { key }),
    }
}

#[command]
pub(crate) async fn set_lock_password<R: Runtime>(
    app: AppHandle<R>,
    password: String,
) -> Result<()> {
    let password = Zeroizing::new(password);
    lockmod::set_lock_password(&app, &password)
}

#[command]
pub(crate) async fn change_lock_password<R: Runtime>(
    app: AppHandle<R>,
    old_password: String,
    new_password: String,
) -> Result<()> {
    let old_password = Zeroizing::new(old_password);
    let new_password = Zeroizing::new(new_password);
    lockmod::change_lock_password(&app, &old_password, &new_password)
}

#[command]
pub(crate) async fn remove_lock_password<R: Runtime>(
    app: AppHandle<R>,
    password: String,
) -> Result<()> {
    let password = Zeroizing::new(password);
    lockmod::remove_lock_password(&app, &password)
}

#[command]
pub(crate) async fn unlock_with_password<R: Runtime>(
    app: AppHandle<R>,
    password: String,
) -> Result<()> {
    let password = Zeroizing::new(password);
    lockmod::unlock_with_password(&app, &password)
}

#[command]
pub(crate) async fn lock_keystore<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    lockmod::lock(&app);
    Ok(())
}

#[command]
pub(crate) async fn lock_status<R: Runtime>(app: AppHandle<R>) -> Result<LockStatusResponse> {
    lockmod::lock_status(&app)
}
