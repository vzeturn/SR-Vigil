//! Contract gates against `schemas/ipc.schema.json`, plus an end-to-end role test.

use serde_json::{Value, json};
use vigil_ipc::client::{CallError, Client};
use vigil_ipc::proto::{
    ERROR_CODES, METHODS, Notification, Request, Response, Role, RpcError, UNAUTHORIZED,
};
use vigil_ipc::server::{Handler, serve};

fn schema() -> Value {
    serde_json::from_str(include_str!("../../../schemas/ipc.schema.json")).unwrap()
}

#[test]
fn method_roles_match_the_schema() {
    let s = schema();
    let methods = s["x-methods"].as_object().unwrap();
    assert_eq!(methods.len(), METHODS.len());
    for (name, role) in METHODS {
        let want = methods[name]["role"].as_str().unwrap();
        let have = if role == Role::Admin {
            "admin"
        } else {
            "viewer"
        };
        assert_eq!(have, want, "{name}");
    }
}

#[test]
fn error_codes_match_the_schema() {
    let s = schema();
    let codes = s["x-error-codes"].as_object().unwrap();
    assert_eq!(codes.len(), ERROR_CODES.len());
    for (code, name) in ERROR_CODES {
        assert_eq!(codes[&code.to_string()], name);
    }
}

#[test]
fn protocol_constants_match_the_schema() {
    let s = schema();
    assert_eq!(s["x-protocol"], vigil_ipc::PROTOCOL);
    assert_eq!(s["x-max-frame-bytes"], vigil_ipc::frame::MAX_FRAME);
}

fn validate(def: &str, v: &Value) {
    let mut root = schema();
    let defs = root["$defs"].clone();
    let v_schema = json!({ "$ref": format!("#/$defs/{def}"), "$defs": defs });
    root = v_schema;
    jsonschema::validator_for(&root)
        .unwrap()
        .validate(v)
        .unwrap_or_else(|e| panic!("{def}: {e}"));
}

#[test]
fn envelopes_validate_against_the_schema() {
    let req = Request {
        jsonrpc: "2.0".into(),
        id: json!(1),
        method: "hello".into(),
        params: Some(json!({})),
    };
    validate("Request", &serde_json::to_value(req).unwrap());
    let err = Response::err(json!(1), RpcError::new(UNAUTHORIZED, "no"));
    validate("Response", &serde_json::to_value(err).unwrap());
    let ok = Response::ok(json!(2), json!({}));
    validate("Response", &serde_json::to_value(ok).unwrap());
}

struct Echo;

impl Handler for Echo {
    #[allow(clippy::unused_async_trait_impl)]
    async fn call(&self, role: Role, method: &str, _p: Value) -> Result<Value, RpcError> {
        Ok(json!({ "method": method, "admin": role == Role::Admin }))
    }
}

fn session(
    role: Role,
) -> (
    Client<tokio::io::DuplexStream>,
    tokio::sync::mpsc::UnboundedSender<Notification>,
) {
    let (a, b) = tokio::io::duplex(8192);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let _ = serve(b, role, &Echo, rx).await;
    });
    (Client::new(a), tx)
}

#[tokio::test]
async fn viewer_is_denied_admin_methods_over_the_wire() {
    let (mut c, _tx) = session(Role::Viewer);
    assert!(c.call("process.list", json!({})).await.is_ok());
    match c.call("process.kill", json!({"pid": 1})).await {
        Err(CallError::Rpc(e)) => assert_eq!(e.code, UNAUTHORIZED),
        other => panic!("expected -32001, got {other:?}"),
    }
}

#[tokio::test]
async fn admin_reaches_the_handler_and_notifications_are_queued() {
    let (mut c, tx) = session(Role::Admin);
    tx.send(Notification {
        jsonrpc: "2.0".into(),
        method: "event.health".into(),
        params: Some(json!({"state": "healthy"})),
    })
    .unwrap();
    let r = c
        .call("mode.set", json!({"mode": "observe"}))
        .await
        .unwrap();
    assert_eq!(r["admin"], true);
}
