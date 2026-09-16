use tauri::{
    plugin::{Builder, TauriPlugin},
    AppHandle, Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod lock;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::SecureKeystore;
#[cfg(mobile)]
use mobile::SecureKeystore;

/// Extension trait, accessible via `app_handle.secure_keystore()`.
pub trait SecureKeystoreExt<R: Runtime> {
    fn secure_keystore(&self) -> &SecureKeystore<R>;
}

impl<R: Runtime, T: Manager<R>> SecureKeystoreExt<R> for T {
    fn secure_keystore(&self) -> &SecureKeystore<R> {
        self.state::<SecureKeystore<R>>().inner()
    }
}

/// Sets the app-managed lock password (used for `requireAuth: "password"`
/// items on any platform, including desktop). Errors if a password is
/// already set — use [`change_lock_password`] to change it.
pub fn set_lock_password<R: Runtime>(app: &AppHandle<R>, password: &str) -> Result<()> {
    lock::set_lock_password(app, password)
}

/// Changes the lock password, re-wrapping the existing data key so
/// previously stored `requireAuth: "password"` items stay readable.
pub fn change_lock_password<R: Runtime>(
    app: &AppHandle<R>,
    old_password: &str,
    new_password: &str,
) -> Result<()> {
    lock::change_lock_password(app, old_password, new_password)
}

/// Removes the lock password. Any items previously stored with
/// `requireAuth: "password"` become permanently unreadable.
pub fn remove_lock_password<R: Runtime>(app: &AppHandle<R>, password: &str) -> Result<()> {
    lock::remove_lock_password(app, password)
}

/// Verifies `password` and, on success, keeps the derived key in memory for
/// the rest of the process's lifetime (or until [`lock`] is called), so
/// subsequent `requireAuth: "password"` calls don't need it passed again.
pub fn unlock_with_password<R: Runtime>(app: &AppHandle<R>, password: &str) -> Result<()> {
    lock::unlock_with_password(app, password)
}

/// Drops the in-memory password session. Subsequent `requireAuth:
/// "password"` calls fail with [`Error::Locked`] until
/// [`unlock_with_password`] is called again.
pub fn lock_keystore<R: Runtime>(app: &AppHandle<R>) {
    lock::lock(app)
}

/// Whether a lock password has been set, and whether the password session
/// is currently unlocked.
pub fn lock_status<R: Runtime>(app: &AppHandle<R>) -> Result<LockStatusResponse> {
    lock::lock_status(app)
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("secure-keystore")
        .invoke_handler(tauri::generate_handler![
            commands::set_item,
            commands::get_item,
            commands::delete_item,
            commands::set_lock_password,
            commands::change_lock_password,
            commands::remove_lock_password,
            commands::unlock_with_password,
            commands::lock_keystore,
            commands::lock_status
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let secure_keystore = mobile::init(app, api)?;
            #[cfg(desktop)]
            let secure_keystore = desktop::init(app, api)?;

            app.manage(secure_keystore);
            app.manage(lock::LockState::default());
            Ok(())
        })
        .build()
}
