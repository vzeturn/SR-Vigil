//! Tauri shell: the Rust side owns the named pipe; React talks to it through `invoke` and events.

mod bridge;
mod popup;

use serde_json::Value;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot};

struct Link(mpsc::Sender<bridge::Rpc>);

#[tauri::command]
async fn rpc(
    link: State<'_, Link>,
    method: String,
    params: Option<Value>,
) -> Result<Value, String> {
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

const TRAY_MODES: [&str; 3] = ["observe", "learning", "enforce"];

/// Tray labels keyed by menu id (`open`, `quit`, `panic`, `mode_<name>`, `pending`).
type Labels = std::collections::HashMap<String, String>;

fn tray_menu(app: &AppHandle, labels: &Labels) -> tauri::Result<Menu<tauri::Wry>> {
    let text = |k: &str| labels.get(k).cloned().unwrap_or_else(|| k.to_owned());
    let item = |id: &str| MenuItem::with_id(app, id, text(id), true, None::<&str>);
    let modes = Submenu::with_id(app, "modes", text("modes"), true)?;
    for m in TRAY_MODES {
        modes.append(&item(&format!("mode_{m}"))?)?;
    }
    let version = MenuItem::new(
        app,
        format!("Vigil {}", env!("CARGO_PKG_VERSION")),
        false,
        None::<&str>,
    )?;
    let autostart = CheckMenuItem::with_id(
        app,
        "autostart",
        text("autostart"),
        true,
        autostart_enabled(),
        None::<&str>,
    )?;
    let sep = || PredefinedMenuItem::separator(app);
    Menu::with_items(
        app,
        &[
            &version,
            &sep()?,
            &item("open")?,
            &item("pending")?,
            &item("audit")?,
            &item("settings")?,
            &sep()?,
            &modes,
            &item("panic")?,
            &sep()?,
            &autostart,
            &item("quit")?,
        ],
    )
}

const RUN_KEY: &str = r"HKCUSoftwareMicrosoftWindowsCurrentVersionRun";
const RUN_VALUE: &str = "Vigil";

fn reg(args: &[&str]) -> bool {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("reg")
        .args(args)
        .creation_flags(0x0800_0000)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Start-with-Windows is a per-user Run value (no admin needed).
fn autostart_enabled() -> bool {
    reg(&["query", RUN_KEY, "/v", RUN_VALUE])
}

fn set_autostart(on: bool) -> bool {
    if !on {
        return reg(&["delete", RUN_KEY, "/v", RUN_VALUE, "/f"]);
    }
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let value = format!("\"{}\" --background", exe.display());
    reg(&[
        "add", RUN_KEY, "/v", RUN_VALUE, "/t", "REG_SZ", "/d", &value, "/f",
    ])
}

/// Bring the window forward and ask the UI to switch page.
fn open_page(app: &AppHandle, page: &str) {
    show_main(app);
    let _ = app.emit("vigil://navigate", page);
}

fn default_labels() -> Labels {
    [
        ("open", "Open"),
        ("quit", "Quit"),
        ("pending", "Pending"),
        ("modes", "Mode"),
        ("panic", "Panic"),
        ("audit", "Audit log"),
        ("settings", "Settings"),
        ("autostart", "Start with Windows"),
        ("mode_observe", "Observe"),
        ("mode_learning", "Learning"),
        ("mode_enforce", "Enforce"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

/// The tray menu text lives in the frontend's i18n tables; React pushes it here on language change.
#[tauri::command]
fn set_tray_labels(app: AppHandle, labels: Labels) -> Result<(), String> {
    let mut all = default_labels();
    all.extend(labels);
    let menu = tray_menu(&app, &all).map_err(|e| e.to_string())?;
    let tray = app.tray_by_id(TRAY_ID).ok_or("tray_missing")?;
    tray.set_menu(Some(menu)).map_err(|e| e.to_string())
}

/// One-click "enable protection": installs the service through a single UAC prompt. The UI itself
/// stays unelevated. The path comes from our own install folder and travels in an environment
/// variable, never interpolated into the PowerShell text.
#[tauri::command]
async fn enable_protection() -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const NO_WINDOW: u32 = 0x0800_0000;
    let ctl = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name("vigilctl.exe");
    if !ctl.is_file() {
        return Err("vigilctl_missing".into());
    }
    let status = tauri::async_runtime::spawn_blocking(move || {
        std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$p = Start-Process -FilePath $env:VIGIL_CTL -ArgumentList 'service','install' -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode",
        ])
        .env("VIGIL_CTL", &ctl)
        .creation_flags(NO_WINDOW)
        .status()
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("elevation_declined".into())
    }
}

/// Show the number of pending decisions in the tray tooltip.
#[tauri::command]
fn set_tray_pending(app: AppHandle, tooltip: String) -> Result<(), String> {
    let tray = app.tray_by_id(TRAY_ID).ok_or("tray_missing")?;
    tray.set_tooltip(Some(tooltip)).map_err(|e| e.to_string())
}

/// Fire-and-forget admin call from a tray click; failures surface in the main window's banners.
fn tray_rpc(app: &AppHandle, method: &str, params: Value) {
    let tx = app.state::<Link>().0.clone();
    let method = method.to_owned();
    tauri::async_runtime::spawn(async move {
        let (reply, wait) = oneshot::channel();
        if tx
            .send(bridge::Rpc {
                method,
                params,
                reply,
            })
            .await
            .is_ok()
        {
            let _ = wait.await;
        }
    });
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let mut tray = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&tray_menu(app, &default_labels())?)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "quit" => app.exit(0),
            "pending" => open_page(app, "pending"),
            "audit" => open_page(app, "audit"),
            "settings" => open_page(app, "settings"),
            "autostart" => {
                let _ = set_autostart(!autostart_enabled());
            }
            id => {
                if let Some(mode) = id.strip_prefix("mode_") {
                    tray_rpc(app, "mode.set", serde_json::json!({ "mode": mode }));
                }
            }
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
            app.manage(popup::Gate::default());
            build_tray(app.handle())?;
            // Autostart passes `--background`: stay in the tray; a manual launch opens the window.
            if !std::env::args().any(|a| a == "--background") {
                show_main(app.handle());
            }
            tauri::async_runtime::spawn(bridge::run(app.handle().clone(), rx));
            Ok(())
        })
        // Closing the main window keeps Vigil running in the tray; "Quit" in the tray menu exits.
        .on_window_event(|w, e| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = e {
                if w.label() == "main" {
                    api.prevent_close();
                    let _ = w.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            rpc,
            set_tray_labels,
            set_tray_pending,
            enable_protection
        ])
        .run(tauri::generate_context!())
        .expect("failed to start Vigil UI");
}
