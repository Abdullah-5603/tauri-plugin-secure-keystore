const COMMANDS: &[&str] = &[
    "set_item",
    "get_item",
    "delete_item",
    "set_lock_password",
    "change_lock_password",
    "remove_lock_password",
    "unlock_with_password",
    "lock_keystore",
    "lock_status",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
