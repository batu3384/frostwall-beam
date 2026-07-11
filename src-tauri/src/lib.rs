// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
pub mod commands;
pub mod config;
pub mod crypto;
pub mod discovery;
pub mod internet;
pub mod liveness;
pub mod pairing;
pub mod protocol;
pub mod session;
pub mod transfer;
pub mod transport;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::generate_code,
            commands::host_start,
            commands::host_start_internet,
            commands::discover_peers,
            commands::join_peer,
            commands::join_internet,
            commands::send_files,
            commands::cancel_transfer,
            commands::current_liveness_code,
            commands::disconnect,
            commands::respond_incoming_transfer,
            commands::get_config,
            commands::set_download_dir,
            commands::set_device_name,
            commands::set_mailbox_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
