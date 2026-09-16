const COMMANDS: &[&str] = &["set_item", "get_item", "delete_item"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
