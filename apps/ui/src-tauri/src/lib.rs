//! Tauri shell: the Rust side owns the named pipe; React talks to it through `invoke` and events.

mod bridge;

use serde_json::Value;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State};
use tokio::sync::{mpsc, oneshot};

struct Link(mpsc::Sender<bridge::Rpc>);

#[tauri::command]
async fn rpc(link: State<'_, Link>, method: String, params: Option<Value>) -> Result<Value, String> {
    if !bridge::is_allowed(&method) {
        return Err("method_not_allowed".into());
    }
    let (reply, wait) = oneshot::channel();
    let call = bridge::Rpc {
        method,
        params: params.unwrap_or_else(|| Value::Object(serde_json::Map::new())),
        reply,
    };
    link.0
        .send(call)
        .await
        .map_err(|_| "service_unavailable".to_string())?;
    wait.await.map_err(|_| "service_unavailable".to_string())?
}

const TRAY_ID: &str = "main";

fn show_main(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

fn tray_menu(app: &AppHandle, open: &str, quit: &str) -> tauri::Result<Menu<tauri::Wry>> {
    let open = MenuItem::with_id(app, "open", open, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", quit, true, None::<&str>)?;
    Menu::with_items(app, &[&open, &quit])
}

/// The tray menu text lives in the frontend's i18n tables; React pushes it here on language change.
#[tauri::command]
fn set_tray_labels(app: AppHandle, open: String, quit: String) -> Result<(), String> {
    let menu = tray_menu(&app, &open, &quit).map_err(|e| e.to_string())?;
    let tray = app.tray_by_id(TRAY_ID).ok_or("tray_missing")?;
    tray.set_menu(Some(menu)).map_err(|e| e.to_string())
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let mut tray = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&tray_menu(app, "Open", "Quit")?)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app).map(|_| ())
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let (tx, rx) = mpsc::channel(32);
            app.manage(Link(tx));
            build_tray(app.handle())?;
            tauri::async_runtime::spawn(bridge::run(app.handle().clone(), rx));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![rpc, set_tray_labels])
        .run(tauri::generate_context!())
        .expect("failed to start Vigil UI");
}
