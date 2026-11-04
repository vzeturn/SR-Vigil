//! Tauri shell: the Rust side owns the named pipe; React talks to it through `invoke` and events.

mod bridge;

use serde_json::Value;
use tauri::{Manager, State};
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

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let (tx, rx) = mpsc::channel(32);
            app.manage(Link(tx));
            tauri::async_runtime::spawn(bridge::run(app.handle().clone(), rx));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![rpc])
        .run(tauri::generate_context!())
        .expect("failed to start Vigil UI");
}
