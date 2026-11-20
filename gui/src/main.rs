// The GUI is the emulator's own /_ui page in a native window; start the emulator first.
// ponytail: window URL is fixed to the default bind; read ROCALCLOUD_URL when people run on other ports.
fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("failed to start rocalcloud GUI");
}
