//! `vigilctl status`: ask the running service for its state over the control pipe.

use anyhow::Context as _;
use serde_json::{Value, json};
use tokio::net::windows::named_pipe::ClientOptions;
use vigil_ipc::PIPE_NAME;
use vigil_ipc::client::Client;

pub fn run(json: bool) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(query(json))
}

async fn query(json_out: bool) -> anyhow::Result<()> {
    let pipe = ClientOptions::new()
        .open(PIPE_NAME)
        .context("VigilSvc is not running (start it with `vigilctl service start`, or run `vigil-svc --console`)")?;
    let mut c = Client::new(pipe);
    let hello = c
        .call(
            "hello",
            json!({"client": "vigilctl", "client_version": env!("CARGO_PKG_VERSION"),
                   "protocol": vigil_ipc::PROTOCOL}),
        )
        .await
        .map_err(|e| anyhow::anyhow!("hello failed: {e:?}"))?;
    let status = c
        .call("status.get", json!({}))
        .await
        .map_err(|e| anyhow::anyhow!("status.get failed: {e:?}"))?;
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"hello": hello, "status": status}))?
        );
        return Ok(());
    }
    let s = |v: &Value, k: &str| v[k].as_str().unwrap_or("?").to_string();
    println!(
        "VigilSvc {}  mode={}  health={}  role={}  rules={}",
        s(&status, "service_version"),
        s(&status, "mode"),
        s(&status, "health"),
        s(&hello, "role"),
        s(&status, "rule_pack_version"),
    );
    let n = |k: &str| status["counts"][k].as_u64().unwrap_or(0);
    println!(
        "{} safe, {} unknown, {} malicious, {} pending",
        n("safe"),
        n("unknown"),
        n("malicious"),
        n("pending")
    );
    Ok(())
}
