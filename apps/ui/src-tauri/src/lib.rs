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

/// Get a window, building it from `tauri.conf.json` on first use. Windows are created lazily and
/// destroyed when dismissed, so a tray-resident Vigil holds no WebView (hundreds of MB) at all.
pub(crate) fn window(app: &AppHandle, label: &str) -> Option<tauri::WebviewWindow> {
    if let Some(w) = app.get_webview_window(label) {
        return Some(w);
    }
    let cfg = app
        .config()
        .app
        .windows
        .iter()
        .find(|c| c.label == label)?
        .clone();
    tauri::WebviewWindowBuilder::from_config(app, &cfg)
        .ok()?
        .build()
        .ok()
}

/// Show the main window; returns `true` when it had to be created (its page is not ready yet).
fn show_main(app: &AppHandle) -> bool {
    let created = app.get_webview_window("main").is_none();
    if let Some(win) = window(app, "main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
    created
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
    let fresh = show_main(app);
    let (app, page) = (app.clone(), page.to_owned());
    tauri::async_runtime::spawn(async move {
        if fresh {
            // A new WebView needs a moment to attach its listeners.
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        }
        let _ = app.emit("vigil://navigate", page);
    });
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

/// Read-only survey of reclaimable junk: `[{id, files, bytes}]`.
#[tauri::command]
async fn junk_scan() -> Result<Value, String> {
    let cats = tauri::async_runtime::spawn_blocking(vigil_win::junk::scan)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Value::Array(
        cats.iter()
            .map(|c| serde_json::json!({ "id": c.id, "files": c.files, "bytes": c.bytes }))
            .collect(),
    ))
}

/// Delete the categories the user ticked and confirmed; returns bytes freed.
#[tauri::command]
async fn junk_clean(ids: Vec<String>) -> Result<u64, String> {
    tauri::async_runtime::spawn_blocking(move || vigil_win::junk::clean(&ids))
        .await
        .map_err(|e| e.to_string())
}

/// Insight payload for a (possibly partial) scan: counts, posture score, score histogram, the
/// most common reasons, and every non-safe process.
fn scan_payload(scan: &vigil_win::scan::Scan) -> Value {
    let name = vigil_win::scan::verdict_name;
    let count = |v: &str| scan.rows.iter().filter(|r| name(r.eval.verdict) == v).count();
    let (safe, unknown, malicious) = (count("safe"), count("unknown"), count("malicious"));
    let total = scan.rows.len().max(1);
    // Posture: share of trusted processes (unknown counts half), minus 30 per malicious one.
    let weighted = (safe * 2 + unknown) * 50 / total;
    let posture = weighted.saturating_sub(malicious * 30).min(100);
    let mut buckets = [0usize; 4];
    for r in &scan.rows {
        let i = match r.eval.score {
            0..=29 => 0,
            30..=49 => 1,
            50..=79 => 2,
            _ => 3,
        };
        buckets[i] += 1;
    }
    let mut reasons: std::collections::HashMap<String, (String, String, &str, usize)> =
        Default::default();
    let findings: Vec<Value> = scan
        .rows
        .iter()
        .filter(|r| name(r.eval.verdict) != "safe")
        .map(|r| {
            let why = scan.reasons(r);
            for w in &why {
                reasons
                    .entry(w.id.clone())
                    .or_insert((w.name.clone(), w.description.clone(), w.kind, 0))
                    .3 += 1;
            }
            serde_json::json!({
                "pid": r.pid, "name": r.name, "image": r.image,
                "start": r.start_time.map(|t| t.to_string()),
                "score": r.eval.score, "verdict": name(r.eval.verdict),
                "spoof": r.spoof().name(),
                "known": r.known().map(|(label, what)| serde_json::json!({"label": label, "what": what})),
                "advice": r.advice().name(), "impact": r.impact(),
                "ramMb": r.ram_bytes / (1024 * 1024), "cpu": r.cpu_percent, "threads": r.threads,
                "identity": {
                    "signature": format!("{:?}", r.signer.state),
                    "publisher": r.signer.org,
                    "chain": r.signer.chain_names,
                    "msRoot": r.signer.ms_root, "osSigned": r.signer.os_signed,
                    "company": r.version.company, "product": r.version.product,
                    "original": r.version.original_filename,
                },
                "reasons": why.iter().map(|w| serde_json::json!({
                    "id": w.id, "name": w.name, "kind": w.kind,
                    "description": w.description, "delta": w.delta
                })).collect::<Vec<_>>(),
            })
        })
        .take(200)
        .collect();
    let mut top: Vec<_> = reasons.into_iter().collect();
    top.sort_by(|a, b| b.1.3.cmp(&a.1.3).then(a.0.cmp(&b.0)));
    serde_json::json!({
        "safe": safe, "unknown": unknown, "malicious": malicious,
        "total": scan.rows.len(), "skipped": scan.skipped, "posture": posture,
        "buckets": buckets,
        "topReasons": top.iter().take(6).map(|(id, (name, d, kind, n))| serde_json::json!({
            "id": id, "name": name, "kind": kind, "description": d, "count": n
        })).collect::<Vec<_>>(),
        "findings": findings,
    })
}

/// Service-less, unelevated survey of running processes for the watching-only view. Partial
/// results stream as `vigil://scan` events (`{done, total, scan}`) while it runs.
#[tauri::command]
async fn local_scan(app: AppHandle) -> Result<Value, String> {
    let scan = tauri::async_runtime::spawn_blocking(move || {
        vigil_win::scan::run_with(|partial, done, total| {
            let _ = app.emit(
                "vigil://scan",
                serde_json::json!({ "done": done, "total": total, "scan": scan_payload(partial) }),
            );
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    Ok(scan_payload(&scan))
}

/// Terminate one non-safe process the user picked in the watching-only view. The target is
/// re-classified first: it must still be the same instance, not in the never-kill set and not safe.
#[tauri::command]
async fn local_kill(pid: u32, start: String, image: String) -> Result<String, String> {
    let start: u64 = start.parse().map_err(|_| "bad_start".to_owned())?;
    tauri::async_runtime::spawn_blocking(move || {
        let scan = vigil_win::scan::run()?;
        let row = scan
            .rows
            .iter()
            .find(|r| r.pid == pid && r.start_time == Some(start) && r.image == image)
            .ok_or("gone")?;
        if row.eval.never_kill {
            return Err("protected_target".to_owned());
        }
        if vigil_win::scan::verdict_name(row.eval.verdict) == "safe" {
            return Err("now_safe".to_owned());
        }
        Ok(match vigil_win::kill::terminate(pid, start) {
            vigil_win::kill::Outcome::Terminated => "terminated",
            vigil_win::kill::Outcome::Gone => "gone",
            vigil_win::kill::Outcome::AccessDenied => "access_denied",
            vigil_win::kill::Outcome::Failed => "failed",
        }
        .to_owned())
    })
    .await
    .map_err(|e| e.to_string())?
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
            "open" => drop(show_main(app)),
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
        .invoke_handler(tauri::generate_handler![
            rpc,
            local_kill,
            set_tray_labels,
            set_tray_pending,
            enable_protection,
            junk_scan,
            junk_clean,
            local_scan
        ])
        .build(tauri::generate_context!())
        .expect("failed to start Vigil UI")
        // Closing the last window destroys its WebView but keeps Vigil in the tray; only the tray's
        // "Quit" (an explicit exit code) ends the process.
        .run(|_, event| {
            if let tauri::RunEvent::ExitRequested { code: None, api, .. } = event {
                api.prevent_exit();
            }
        });
}
