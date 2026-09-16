use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
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

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("secure-keystore")
        .invoke_handler(tauri::generate_handler![
            commands::set_item,
            commands::get_item,
            commands::delete_item
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let secure_keystore = mobile::init(app, api)?;
            #[cfg(desktop)]
            let secure_keystore = desktop::init(app, api)?;

            app.manage(secure_keystore);
            Ok(())
        })
        .build()
}
