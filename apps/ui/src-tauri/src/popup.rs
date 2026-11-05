//! Approval popup: shown (never focused) when the service queues a pending decision.
//! At most one appearance per `MIN_GAP`; the rest wait in the queue the popup itself renders.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager, PhysicalPosition};
use tauri_plugin_notification::NotificationExt;

/// Native Windows toast; failures (notifications disabled by the user) are not errors.
pub fn toast(app: &AppHandle, title: &str, body: &str) {
    let _ = app.notification().builder().title(title).body(body).show();
}

const MIN_GAP: Duration = Duration::from_secs(5);
const MARGIN: i32 = 16;
const WIDTH: f64 = 440.0;

#[derive(Default)]
pub struct Gate {
    last_shown: Mutex<Option<Instant>>,
    scheduled: AtomicBool,
}

/// A pending item arrived: show the popup now, or after the rate-limit window elapses.
pub fn on_pending(app: &AppHandle) {
    let gate = app.state::<Gate>();
    let wait = gate
        .last_shown
        .lock()
        .ok()
        .and_then(|last| *last)
        .map_or(Duration::ZERO, |t| MIN_GAP.saturating_sub(t.elapsed()));
    if wait.is_zero() {
        show(app);
    } else if !gate.scheduled.swap(true, Ordering::AcqRel) {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(wait).await;
            app.state::<Gate>()
                .scheduled
                .store(false, Ordering::Release);
            show(&app);
        });
    }
}

pub fn show(app: &AppHandle) {
    let Some(win) = crate::window(app, "popup") else {
        return;
    };
    if win.is_visible().unwrap_or(false) {
        return;
    }
    anchor(&win);
    // `show` only: the popup must never take focus from what the user is doing.
    let _ = win.show();
    if let Ok(mut last) = app.state::<Gate>().last_shown.lock() {
        *last = Some(Instant::now());
    }
}

/// Bottom-right of the primary work area, so a resized popup keeps its corner.
fn anchor(win: &tauri::WebviewWindow) {
    if let (Ok(Some(mon)), Ok(size)) = (win.primary_monitor(), win.outer_size()) {
        let area = mon.work_area();
        let (w, h) = (
            i32::try_from(size.width).unwrap_or(0),
            i32::try_from(size.height).unwrap_or(0),
        );
        let right = area.position.x + i32::try_from(area.size.width).unwrap_or(0);
        let bottom = area.position.y + i32::try_from(area.size.height).unwrap_or(0);
        let _ = win.set_position(PhysicalPosition::new(
            right - w - MARGIN,
            bottom - h - MARGIN,
        ));
    }
}

/// The popup page reports its content height (CSS px); the window shrinks to fit instead of
/// reserving a fixed 420 px of screen.
#[tauri::command]
pub fn fit_popup(app: AppHandle, height: f64) {
    let Some(win) = app.get_webview_window("popup") else {
        return;
    };
    let (width, h) = (WIDTH, height.clamp(96.0, 560.0));
    // Same height again (shadow/DPI rounding): skip, or the resize observer feeds back into itself.
    if win.inner_size().is_ok_and(|s| {
        let k = win.scale_factor().unwrap_or(1.0);
        (f64::from(s.height) / k - h).abs() < 2.0 && (f64::from(s.width) / k - width).abs() < 2.0
    }) {
        return;
    }
    let _ = win.set_size(tauri::LogicalSize::new(width, h));
    anchor(&win);
}
