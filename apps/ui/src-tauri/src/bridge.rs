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
    "pending.list",
    "decision.submit",
    "decision.list",
    "decision.revoke",
    "decision.exception",
    "reopen.answer",
    "launcher.answer",
    "threat.list",
    "threat.answer",
    "audit.query",
    "enforcement.panic",
    "purge.start",
    "purge.stop",
    "purge.status",
    "dns.status",
    "protection.set",
    "process.get",
    "process.modules",
    "process.kill",
    "persistence.scan",
    "persistence.apply",
    "ai.activity",
    "ai.config.get",
    "ai.config.set",
    "ai.preview",
    "ai.test",
    "ai.explain",
    "audit.export",
    "decision.export",
    "decision.import",
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
    let role = hello["role"].clone();
    let _ = client
        .call("subscribe", json!({"topics": ["pending", "ai", "enforcement"]}))
        .await;
    let mut tick = tokio::time::interval(SNAPSHOT_EVERY);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let snap = snapshot(client).await?;
                // Re-announced every tick so a window created after the first event still learns the role.
                let _ = app.emit("vigil://link", json!({"up": true, "role": role}));
                let _ = app.emit("vigil://snapshot", snap);
                forward_pending(app, client);
            }
            Some(rpc) = rx.recv() => match client.call(&rpc.method, rpc.params).await {
                Ok(v) => { let _ = rpc.reply.send(Ok(v)); }
                Err(CallError::Rpc(e)) => { let _ = rpc.reply.send(Err(e.message)); }
                Err(e) => { let _ = rpc.reply.send(Err(e.to_string())); return Err(e); }
            },
        }
    }
}

/// Queued service notifications: `pending_created` (popup + toast + UI refresh) and the daily AI digest.
fn forward_pending(app: &AppHandle, client: &mut Client<NamedPipeClient>) {
    let mut created = false;
    for n in client.notifications.drain(..) {
        let params = n.params.unwrap_or(Value::Null);
        match n.method.as_str() {
            "event.pending_created" => {
                // Popup/toast only for an established incident; other items wait in the Pending list.
                created |= params["alert"].as_bool().unwrap_or(false);
                let _ = app.emit("vigil://pending", params);
            }
            "event.reopen_prompt" => {
                // The service already rate-limits these, and the process is frozen until answered.
                let _ = app.emit("vigil://reopen", params);
                crate::popup::show(app);
            }
            "event.launcher_prompt" => {
                let _ = app.emit("vigil://launcher", params);
                crate::popup::show(app);
            }
            "event.threat_detected" => {
                // The service asks once per program per run; nothing goes to the AI until answered.
                let _ = app.emit("vigil://threat", params);
                crate::popup::show(app);
            }
            "event.ai_digest" => {
                let g = |k: &str| params[k].as_u64().unwrap_or(0);
                let body = format!(
                    "In the last 24 h the AI assessed {} programs, made {} decisions on its own and left {} to you. About {} tokens, roughly ${:.2}.",
                    g("assessed"),
                    g("allowed") + g("blocked") + g("killed"),
                    g("left_to_user"),
                    g("tokens_in") + g("tokens_out"),
                    params["cost_usd"].as_f64().unwrap_or(0.0),
                );
                crate::popup::toast(app, "Vigil AI daily summary", &body);
                let _ = app.emit("vigil://ai-digest", params);
            }
            _ => {}
        }
    }
    if created {
        crate::popup::on_pending(app);
    }
}

async fn snapshot(client: &mut Client<NamedPipeClient>) -> Result<Value, CallError> {
    let status = client.call("status.get", json!({})).await?;
    let processes = collect(client, "process.list").await?;
    let connections = collect(client, "connection.list").await?;
    Ok(json!({"status": status, "processes": processes, "connections": connections}))
}

async fn collect(
    client: &mut Client<NamedPipeClient>,
    method: &str,
) -> Result<Vec<Value>, CallError> {
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
