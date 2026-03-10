pub mod error;
pub mod state;
pub mod commands;
pub mod tests;

use state::AppState;
use tauri::{Manager, Listener, Emitter};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = AppState::new();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::parse_invite,
            commands::create_room,
            commands::join_room,
            commands::get_room_snapshot,
            commands::confirm_peer_verified,
            commands::trust_new_server_identity,
            commands::reset_server_pin,
            commands::send_message,
            commands::leave_room,
            commands::frontend_ready
        ])
        .setup(|app| {
            // Register deep link handler directly in Tauri setup
            // Wait: tauri_plugin_deep_link handles registering the OS URI scheme.
            // When a blindwire:// link is opened, we either queue it or emit to UI.
            
            let handle = app.handle().clone();
            
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            {
                // Note: Actual API for tauri-plugin-deep-link v2 might vary, typically:
                // `app.deep_link().on_open(...)`
                // I will add a placeholder for deep link event handling that safely queues using app state.
                
                app.listen("deep-link://new-url", move |event: tauri::Event| {
                    let uri = event.payload();
                    let state = handle.state::<AppState>();
                    if state.ui_ready.load(std::sync::atomic::Ordering::SeqCst) {
                        let _ = handle.emit("blindwire-deep-link", uri);
                    } else {
                        // Queue it for when frontend starts
                        let state_clone = state.inner();
                        let uri_owned = uri.to_string();
                        tauri::async_runtime::block_on(async {
                            *state_clone.pending_deep_link.lock().await = Some(uri_owned);
                        });
                    }
                });
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
