//! Service host: data directory, state construction and the named-pipe accept loop.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use serde_json::{Map, Value, json};
use vigil_core::rules::RuleStore;
use vigil_ipc::PIPE_NAME;
use vigil_ipc::proto::Role;
use vigil_win::pipe::{client_is_elevated, create_instance};

use crate::handler::handle_connection;
use crate::state::{Options, Shared, now};

const DEFAULT_RULES: &str = include_str!("../../../rules/default.toml");
const PUBLISHERS: &str = include_str!("../../../rules/publishers.toml");
const RULE_KEYS: [&str; 11] = [
    "id",
    "name",
    "kind",
    "description",
    "when",
    "score",
    "cap",
    "verdict",
    "terminal",
    "exclusive_group",
    "priority",
];

/// `%ProgramData%\Vigil` when writable (service), else `%LOCALAPPDATA%\Vigil` (unelevated dev run).
fn data_dir() -> anyhow::Result<PathBuf> {
    let candidates = ["PROGRAMDATA", "LOCALAPPDATA"]
        .iter()
        .filter_map(std::env::var_os)
        .map(|b| PathBuf::from(b).join("Vigil"));
    for dir in candidates {
        if std::fs::create_dir_all(&dir).is_ok()
            && std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("vigil.db"))
                .is_ok()
        {
            return Ok(dir);
        }
    }
    anyhow::bail!("no writable data directory")
}

fn toml_to_json(src: &str) -> anyhow::Result<Value> {
    Ok(serde_json::to_value(toml::from_str::<toml::Value>(src)?)?)
}

fn builtin_rules() -> anyhow::Result<Value> {
    let doc = toml_to_json(DEFAULT_RULES)?;
    let rules = doc["rule"].as_array().cloned().unwrap_or_default();
    Ok(Value::Array(
        rules
            .into_iter()
            .map(|r| {
                let mut out: Map<String, Value> = r
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(k, _)| RULE_KEYS.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                out.insert("source".into(), json!("builtin"));
                Value::Object(out)
            })
            .collect(),
    ))
}

fn builtin_trust() -> anyhow::Result<Vec<Value>> {
    let ts = now();
    let doc = toml_to_json(PUBLISHERS)?;
    Ok(doc["publisher"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| {
            json!({
                "id": p["id"], "subject_org": p["subject_org"], "thumbprint": "",
                "source": "builtin", "note": p["note"].as_str(), "created_at": ts,
            })
        })
        .collect())
}

/// Build the shared state from the on-disk store and embedded rules.
pub fn build_state() -> anyhow::Result<(Arc<Shared>, Arc<vigil_core::rules::RulePack>)> {
    let dir = data_dir()?;
    let mut conn = vigil_store::open(&dir.join("vigil.db")).context("open database")?;
    vigil_store::migrate(&mut conn).context("migrate database")?;
    let pack = RuleStore::from_embedded()?.active();
    let shared = Shared::new(Options {
        store: Some(conn),
        rules: builtin_rules()?,
        trust: builtin_trust()?,
        rule_pack_version: pack.meta.rule_pack_version.clone(),
    });
    tracing::info!(dir = %dir.display(), "data directory ready");
    Ok((Arc::new(shared), pack))
}

/// Accept clients forever. The first instance claims the pipe name (squat protection).
pub async fn serve_pipe(shared: Arc<Shared>) -> anyhow::Result<()> {
    let mut server = create_instance(PIPE_NAME, true).context("create control pipe")?;
    loop {
        server.connect().await.context("pipe connect")?;
        let next = create_instance(PIPE_NAME, false).context("create next pipe instance")?;
        let stream = std::mem::replace(&mut server, next);
        let role = if client_is_elevated(&stream).unwrap_or(false) {
            Role::Admin
        } else {
            Role::Viewer
        };
        let sh = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, role, sh).await {
                tracing::debug!(error = %e, "client connection ended");
            }
        });
    }
}
