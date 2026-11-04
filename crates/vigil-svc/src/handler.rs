//! JSON-RPC method dispatch for one client connection.

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use vigil_ipc::proto::{INVALID_PARAMS, INVALID_STATE, Role, RpcError};
use vigil_ipc::server::{Handler, serve};

use crate::events::{TOPICS, forward};
use crate::state::{SERVICE_VERSION, Shared};

/// Per-connection handler: shared service state plus this client's topic subscriptions.
pub struct ConnHandler {
    shared: Arc<Shared>,
    topics: Arc<Mutex<HashSet<String>>>,
}

fn invalid(msg: &str) -> RpcError {
    RpcError::new(INVALID_PARAMS, msg)
}

fn topic_list(params: &Value) -> Result<Vec<String>, RpcError> {
    let arr = params
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("topics must be an array"))?;
    arr.iter()
        .map(|t| {
            t.as_str()
                .filter(|t| TOPICS.contains(t))
                .map(str::to_string)
                .ok_or_else(|| invalid("unknown topic"))
        })
        .collect()
}

impl ConnHandler {
    fn dispatch(&self, role: Role, method: &str, params: &Value) -> Result<Value, RpcError> {
        let s = &self.shared;
        match method {
            "hello" => {
                if params.get("protocol").and_then(Value::as_u64)
                    != Some(u64::from(vigil_ipc::PROTOCOL))
                {
                    return Err(invalid("unsupported protocol version"));
                }
                let (mode, health) = s.mode_and_health();
                Ok(json!({
                    "protocol": vigil_ipc::PROTOCOL, "service_version": SERVICE_VERSION,
                    "role": if role == Role::Admin { "admin" } else { "viewer" },
                    "mode": mode, "health": health,
                }))
            }
            "status.get" => Ok(s.status()),
            "mode.set" => s.set_mode(
                params
                    .get("mode")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("mode is required"))?,
                params
                    .get("override_learning_minimum")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
            "enforcement.panic" => Ok(s.panic_now("user")),
            "process.list" => s.list_processes(params),
            "process.get" => s.get_process(
                params
                    .get("pid")
                    .and_then(Value::as_u64)
                    .and_then(|p| u32::try_from(p).ok())
                    .ok_or_else(|| invalid("pid is required"))?,
                params
                    .get("start_time")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("start_time is required"))?,
            ),
            "process.kill" => s.kill_process(params, "user"),
            "persistence.scan" => {
                s.persistence_scan(params.get("target_image_path").and_then(Value::as_str))
            }
            "persistence.apply" => s.persistence_apply(params, "user"),
            "connection.list" => s.list_connections(params),
            "rule.list" => Ok(s.rules()),
            "trust.list" => Ok(s.trust()),
            "pending.list" => s.list_pending(),
            "decision.list" => s.list_decisions(),
            "decision.submit" => s.submit_decision(params),
            "decision.revoke" => s.revoke_decision(params),
            "audit.query" => s.audit_query(params),
            "settings.get" => Ok(s.settings()),
            "settings.set" => s.update_settings(
                params
                    .get("settings")
                    .ok_or_else(|| invalid("settings is required"))?,
            ),
            "ai.config.get" => Ok(s.ai_config_get()),
            "ai.config.set" => s.ai_config_set(params, "user"),
            "ai.preview" => s.ai_preview(params),
            "subscribe" => {
                let add = topic_list(params)?;
                let mut t = self.topics.lock().unwrap_or_else(PoisonError::into_inner);
                t.extend(add);
                Ok(json!({ "subscribed": t.iter().collect::<Vec<_>>() }))
            }
            "unsubscribe" => {
                let drop_topics = topic_list(params)?;
                let mut t = self.topics.lock().unwrap_or_else(PoisonError::into_inner);
                for d in drop_topics {
                    t.remove(&d);
                }
                Ok(json!({}))
            }
            other => Err(RpcError::new(
                INVALID_STATE,
                format!("{other} is not available in this release"),
            )),
        }
    }
}

impl Handler for ConnHandler {
    fn call(
        &self,
        role: Role,
        method: &str,
        params: Value,
    ) -> impl Future<Output = Result<Value, RpcError>> + Send {
        let shared = Arc::clone(&self.shared);
        let method = method.to_string();
        let sync = match method.as_str() {
            "ai.test" | "ai.explain" => None,
            _ => Some(self.dispatch(role, &method, &params)),
        };
        async move {
            match (sync, method.as_str()) {
                (Some(r), _) => r,
                (None, "ai.test") => Ok(shared.ai_test().await),
                (None, _) => shared.ai_explain(&params).await,
            }
        }
    }
}

/// Serve one authenticated client until it disconnects.
pub async fn handle_connection<S>(stream: S, role: Role, shared: Arc<Shared>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let topics = Arc::new(Mutex::new(HashSet::new()));
    let (out, inbox) = tokio::sync::mpsc::unbounded_channel();
    let forwarder = tokio::spawn(forward(shared.subscribe_bus(), Arc::clone(&topics), out));
    let handler = ConnHandler { shared, topics };
    let result = serve(stream, role, &handler, inbox).await;
    forwarder.abort();
    result
}
