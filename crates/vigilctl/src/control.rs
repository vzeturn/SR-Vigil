//! `vigilctl panic` and `vigilctl mode`: admin-only enforcement controls (run from an elevated shell).

use anyhow::Context as _;
use serde_json::{Value, json};
use tokio::net::windows::named_pipe::ClientOptions;
use vigil_ipc::PIPE_NAME;
use vigil_ipc::client::Client;

pub fn panic() -> anyhow::Result<()> {
    print_mode(&call("enforcement.panic", json!({}))?);
    Ok(())
}

/// `vigilctl kill`: terminate one process and keep it from coming back.
pub fn kill(pid: u32, start_time: &str, tree: bool) -> anyhow::Result<()> {
    let r = call(
        "process.kill",
        json!({"pid": pid, "start_time": start_time, "tree": tree}),
    )?;
    print_action(&r)
}

/// `vigilctl persistence scan`: list autostart entries (optionally for one image).
pub fn persistence_scan(image: Option<&str>) -> anyhow::Result<()> {
    let r = call("persistence.scan", json!({"target_image_path": image}))?;
    for f in r["findings"].as_array().into_iter().flatten() {
        println!(
            "{:>4}  {:<16} {:<9} {}",
            f["id"].as_str().unwrap_or("?"),
            f["kind"].as_str().unwrap_or("?"),
            f["status"].as_str().unwrap_or("?"),
            f["location"].as_str().unwrap_or("?")
        );
    }
    Ok(())
}

/// `vigilctl persistence apply`: disable, restore or delete one scanned entry.
pub fn persistence_apply(item_id: &str, action: &str) -> anyhow::Result<()> {
    print_action(&call(
        "persistence.apply",
        json!({"item_id": item_id, "action": action}),
    )?)
}

fn print_action(r: &Value) -> anyhow::Result<()> {
    let detail = r["detail"].as_str().unwrap_or("");
    if r["ok"].as_bool().unwrap_or(false) {
        println!("ok  {detail}");
        Ok(())
    } else {
        anyhow::bail!("{}: {detail}", r["error_code"].as_str().unwrap_or("failed"))
    }
}

pub fn mode(mode: &str, override_minimum: bool) -> anyhow::Result<()> {
    print_mode(&call(
        "mode.set",
        json!({"mode": mode, "override_learning_minimum": override_minimum}),
    )?);
    Ok(())
}

/// `vigilctl ai`: print the advisor settings (never the key); `--mode` changes the mode first.
pub fn ai(mode: Option<&str>, escalate_below: Option<f64>) -> anyhow::Result<()> {
    let mut set = serde_json::Map::new();
    if let Some(m) = mode {
        set.insert("mode".into(), json!(m));
    }
    if let Some(e) = escalate_below {
        set.insert("escalate_below".into(), json!(e));
    }
    let c = if set.is_empty() {
        call("ai.config.get", json!({}))?
    } else {
        call("ai.config.set", Value::Object(set))?
    };
    for k in [
        "enabled",
        "mode",
        "source",
        "model",
        "auto_threshold",
        "escalate_below",
        "auto_kill",
        "calls_today",
        "daily_call_budget",
    ] {
        println!("{k}={}", c[k]);
    }
    Ok(())
}

/// `vigilctl decisions`: list active decisions; `--revoke` lifts one (and any respawn block it made).
pub fn decisions(revoke: Option<&str>, except: Option<&str>) -> anyhow::Result<()> {
    if let Some(id) = revoke {
        call("decision.revoke", json!({ "decision_id": id }))?;
        println!("revoked decision {id}");
    }
    if let Some(id) = except {
        call("decision.exception", json!({ "decision_id": id }))?;
        println!("lifted decision {id} and allowed the program");
    }
    let list = call("decision.list", json!({}))?;
    for d in list["items"].as_array().into_iter().flatten() {
        println!(
            "{} {} {} {} identity={} by={} {} score={} kills={}",
            d["id"].as_str().unwrap_or("?"),
            d["action"].as_str().unwrap_or("?"),
            d["scope"].as_str().unwrap_or("?"),
            d["apply_to"].as_str().unwrap_or("?"),
            d["identity_id"].as_str().unwrap_or("?"),
            d["by"].as_str().unwrap_or("?"),
            d["identity"]["path"].as_str().unwrap_or("?"),
            d["evaluation"]["score"],
            d["respawn_kills"],
        );
    }
    Ok(())
}

/// `vigilctl purge`: run one lockdown method and print the report.
pub fn purge(method: &'static str, params: Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(&call(method, params)?)?);
    Ok(())
}

/// `vigilctl allow`: a forever allow for one file, bound to the verified hash.
pub fn allow(path: &str, sha256: &str, source: &str) -> anyhow::Result<()> {
    let list = call(
        "process.list",
        json!({ "filter": { "text": path }, "limit": 1000 }),
    )?;
    let proc = list["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| {
            p["path"]
                .as_str()
                .is_some_and(|x| x.eq_ignore_ascii_case(path))
        })
        .ok_or_else(|| anyhow::anyhow!("{path} is not running; start it once so Vigil sees it"))?;
    let seen = call(
        "process.get",
        json!({ "pid": proc["pid"], "start_time": proc["start_time"] }),
    )?;
    anyhow::ensure!(
        seen["identity"]["sha256"]
            .as_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(sha256)),
        "the file Vigil sees has a different SHA-256 than the one you verified"
    );
    call(
        "decision.submit",
        json!({
            "identity_id": proc["identity_id"], "action": "allow", "scope": "forever",
            "apply_to": "file", "note": format!("hash verified against {source}"),
        }),
    )?;
    println!("allowed {path}");
    Ok(())
}

fn print_mode(s: &Value) {
    println!(
        "mode={}  filters_armed={}",
        s["mode"].as_str().unwrap_or("?"),
        s["filters_armed"].as_bool().unwrap_or(false)
    );
}

fn call(method: &'static str, params: Value) -> anyhow::Result<Value> {
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
            Ok(s)
        })
}
