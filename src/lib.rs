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
use desktop::MobileKeystore;
#[cfg(mobile)]
use mobile::MobileKeystore;

/// Extension trait, accessible via `app_handle.mobile_keystore()`.
pub trait MobileKeystoreExt<R: Runtime> {
    fn mobile_keystore(&self) -> &MobileKeystore<R>;
}

impl<R: Runtime, T: Manager<R>> MobileKeystoreExt<R> for T {
    fn mobile_keystore(&self) -> &MobileKeystore<R> {
        self.state::<MobileKeystore<R>>().inner()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("mobile-keystore")
        .invoke_handler(tauri::generate_handler![
            commands::set_item,
            commands::get_item,
            commands::delete_item
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let mobile_keystore = mobile::init(app, api)?;
            #[cfg(desktop)]
            let mobile_keystore = desktop::init(app, api)?;

            app.manage(mobile_keystore);
            Ok(())
        })
        .build()
}
