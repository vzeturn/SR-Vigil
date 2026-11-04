//! Owns the control pipe. The webview never sees it: it receives snapshots as events and
//! sends allow-listed calls through the `rpc` command.

use std::time::Duration;

use serde_json::{Value, json};
use tauri::{AppHandle, Emitter};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::{mpsc, oneshot};
use vigil_ipc::PIPE_NAME;
use vigil_ipc::client::{CallError, Client};

const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);
const BACKOFF_MIN: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(5);
const PAGE: u64 = 1000;
const MAX_PAGES: usize = 20;

/// Methods the UI may call. Everything else is refused here, before reaching the service.
const ALLOWED: &[&str] = &[
    "status.get",
    "mode.set",
    "rule.list",
    "trust.list",
    "settings.get",
    "settings.set",
];

pub struct Rpc {
    pub method: String,
    pub params: Value,
    pub reply: oneshot::Sender<Result<Value, String>>,
}

pub fn is_allowed(method: &str) -> bool {
    ALLOWED.contains(&method)
}

pub async fn run(app: AppHandle, mut rx: mpsc::Receiver<Rpc>) {
    let mut backoff = BACKOFF_MIN;
    loop {
        if let Ok(pipe) = ClientOptions::new().open(PIPE_NAME) {
            let mut client = Client::new(pipe);
            if let Err(e) = session(&app, &mut client, &mut rx).await {
                tracing::warn!(error = %e, "service link lost");
            }
            backoff = BACKOFF_MIN;
        }
        let _ = app.emit("vigil://link", json!({"up": false}));
        // Calls made while the service is down fail fast instead of piling up.
        while let Ok(rpc) = rx.try_recv() {
            let _ = rpc.reply.send(Err("service_unavailable".into()));
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

async fn session(
    app: &AppHandle,
    client: &mut Client<NamedPipeClient>,
    rx: &mut mpsc::Receiver<Rpc>,
) -> Result<(), CallError> {
    let hello = client
        .call(
            "hello",
            json!({"client": "vigil-ui", "client_version": env!("CARGO_PKG_VERSION"),
                   "protocol": vigil_ipc::PROTOCOL}),
        )
        .await?;
    let _ = app.emit("vigil://link", json!({"up": true, "role": hello["role"]}));
    let mut tick = tokio::time::interval(SNAPSHOT_EVERY);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let snap = snapshot(client).await?;
                let _ = app.emit("vigil://snapshot", snap);
                client.notifications.clear();
            }
            Some(rpc) = rx.recv() => match client.call(&rpc.method, rpc.params).await {
                Ok(v) => { let _ = rpc.reply.send(Ok(v)); }
                Err(CallError::Rpc(e)) => { let _ = rpc.reply.send(Err(e.message)); }
                Err(e) => { let _ = rpc.reply.send(Err(e.to_string())); return Err(e); }
            },
        }
    }
}

async fn snapshot(client: &mut Client<NamedPipeClient>) -> Result<Value, CallError> {
    let status = client.call("status.get", json!({})).await?;
    let processes = collect(client, "process.list").await?;
    let connections = collect(client, "connection.list").await?;
    Ok(json!({"status": status, "processes": processes, "connections": connections}))
}

async fn collect(client: &mut Client<NamedPipeClient>, method: &str) -> Result<Vec<Value>, CallError> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut params = json!({"limit": PAGE});
        if let Some(c) = &cursor {
            params["cursor"] = json!(c);
        }
        let mut page = client.call(method, params).await?;
        if let Some(Value::Array(v)) = page.get_mut("items").map(Value::take) {
            items.extend(v);
        }
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    Ok(items)
}
