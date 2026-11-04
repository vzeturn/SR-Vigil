//! `vigilctl panic` and `vigilctl mode`: admin-only enforcement controls (run from an elevated shell).

use anyhow::Context as _;
use serde_json::{Value, json};
use tokio::net::windows::named_pipe::ClientOptions;
use vigil_ipc::PIPE_NAME;
use vigil_ipc::client::Client;

pub fn panic() -> anyhow::Result<()> {
    call("enforcement.panic", json!({}))
}

pub fn mode(mode: &str, override_minimum: bool) -> anyhow::Result<()> {
    call(
        "mode.set",
        json!({"mode": mode, "override_learning_minimum": override_minimum}),
    )
}

fn call(method: &'static str, params: Value) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let pipe = ClientOptions::new()
                .open(PIPE_NAME)
                .context("VigilSvc is not running")?;
            let mut c = Client::new(pipe);
            c.call(
                "hello",
                json!({"client": "vigilctl", "client_version": env!("CARGO_PKG_VERSION"),
                       "protocol": vigil_ipc::PROTOCOL}),
            )
            .await
            .map_err(|e| anyhow::anyhow!("hello failed: {e:?}"))?;
            let s = c
                .call(method, params)
                .await
                .map_err(|e| anyhow::anyhow!("{method} failed: {e:?} (needs an elevated shell)"))?;
            println!(
                "mode={}  filters_armed={}",
                s["mode"].as_str().unwrap_or("?"),
                s["filters_armed"].as_bool().unwrap_or(false)
            );
            Ok(())
        })
}
