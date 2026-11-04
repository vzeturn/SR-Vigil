//! Approval popup: shown (never focused) when the service queues a pending decision.
//! At most one appearance per `MIN_GAP`; the rest wait in the queue the popup itself renders.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager, PhysicalPosition};

const MIN_GAP: Duration = Duration::from_secs(5);
const MARGIN: i32 = 16;

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

fn show(app: &AppHandle) {
    let Some(win) = crate::window(app, "popup") else {
        return;
    };
    if win.is_visible().unwrap_or(false) {
        return;
    }
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
    // `show` only: the popup must never take focus from what the user is doing.
    let _ = win.show();
    if let Ok(mut last) = app.state::<Gate>().last_shown.lock() {
        *last = Some(Instant::now());
    }
}
