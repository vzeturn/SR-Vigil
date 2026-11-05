//! Every implemented method's result and every emitted event validate against the IPC schema.

use std::sync::Arc;

use serde_json::{Value, json};
use vigil_ipc::client::Client;
use vigil_ipc::proto::Role;
use vigil_store::repo::{Executable, NewEvaluation, insert_evaluation, upsert_executable};
use vigil_svc::handler::handle_connection;
use vigil_svc::state::{ConnRow, Options, ProcRow, Shared};

fn schema() -> Value {
    serde_json::from_str(include_str!("../../../schemas/ipc.schema.json")).unwrap()
}

fn validate(part: &Value, what: &str, v: &Value) {
    let wrapped = json!({ "allOf": [part], "$defs": schema()["$defs"] });
    jsonschema::validator_for(&wrapped)
        .unwrap()
        .validate(v)
        .unwrap_or_else(|e| panic!("{what}: {e}\n{v}"));
}

fn shared() -> Arc<Shared> {
    let s = Shared::new(Options {
        store: Some(vigil_store::open_in_memory().unwrap()),
        rules: json!([{"id": "SIG-001", "name": "n", "kind": "signal", "when": {}, "source": "builtin"}]),
        trust: vec![
            json!({"id": "ms", "subject_org": "Microsoft", "thumbprint": "",
                           "source": "builtin", "note": null, "created_at": "2026-01-01T00:00:00Z"}),
        ],
        rule_pack_version: "1.0.0".into(),
        network_critical: Vec::new(),
        never_kill: Vec::new(),
    });
    s.put_process(ProcRow {
        pid: 4242,
        start_time: "2026-01-01T00:00:00Z".into(),
        ppid: 1,
        name: "a.exe".into(),
        path: Some(r"C:\a.exe".into()),
        parent_path: None,
        identity_id: None,
        verdict: None,
        score: None,
        freshness: None,
        origin: None,
    });
    let id = s
        .with_store(|c| {
            let exe = Executable {
                sha256: "a".repeat(64),
                path: r"C:\a.exe".into(),
                signer_thumbprint: None,
                publisher: None,
                company: None,
                product: None,
                original_filename: None,
                signature_status: "unsigned".into(),
            };
            let id = upsert_executable(c, &exe, "2026-01-01T00:00:00Z").unwrap();
            let ev = NewEvaluation {
                score: 90,
                verdict: "safe".into(),
                hard_rule: None,
                signals_json: r#"[{"id":"SIG-001","name":"n","delta":45}]"#.into(),
                rule_pack_version: "1.0.0".into(),
                source: "rules".into(),
            };
            insert_evaluation(c, id, &ev, "2026-01-01T00:00:00Z").unwrap();
            id
        })
        .unwrap();
    s.apply_evaluation(r"C:\a.exe", None, &id.to_string(), "safe", 90, None);
    s.sync_connections(vec![ConnRow {
        id: "c1".into(),
        pid: 4242,
        direction: "outbound",
        local_addr: "10.0.0.2".into(),
        local_port: 50000,
        remote_addr: Some("1.1.1.1".into()),
        remote_port: Some(443),
        state: "established",
        verdict: Some("safe".into()),
        first_seen: "2026-01-01T00:00:00Z".into(),
        last_seen: "2026-01-01T00:00:00Z".into(),
    }]);
    Arc::new(s)
}

#[tokio::test]
async fn implemented_method_results_match_the_schema() {
    let s = schema();
    let (a, b) = tokio::io::duplex(1 << 16);
    tokio::spawn(handle_connection(b, Role::Admin, shared()));
    let mut c = Client::new(a);
    let calls: [(&str, Value); 15] = [
        (
            "hello",
            json!({"client": "t", "client_version": "1", "protocol": 1}),
        ),
        ("status.get", json!({})),
        ("process.list", json!({})),
        (
            "process.get",
            json!({"pid": 4242, "start_time": "2026-01-01T00:00:00Z"}),
        ),
        (
            "process.modules",
            json!({"pid": 4242, "start_time": "2026-01-01T00:00:00Z"}),
        ),
        ("connection.list", json!({"limit": 5})),
        ("rule.list", json!({})),
        ("trust.list", json!({})),
        ("pending.list", json!({})),
        ("decision.list", json!({})),
        ("audit.query", json!({})),
        ("settings.get", json!({})),
        ("mode.set", json!({"mode": "learning"})),
        ("subscribe", json!({"topics": ["processes", "health"]})),
        ("unsubscribe", json!({"topics": ["health"]})),
    ];
    for (method, params) in calls {
        validate(&s["x-methods"][method]["params"], method, &params);
        let res = c
            .call(method, params)
            .await
            .unwrap_or_else(|e| panic!("{method}: {e:?}"));
        validate(&s["x-methods"][method]["result"], method, &res);
    }
}

#[tokio::test]
async fn emitted_events_match_the_schema() {
    let s = schema();
    let sh = shared();
    let mut bus = sh.subscribe_bus();
    sh.put_process(ProcRow {
        pid: 1,
        start_time: "2026-01-01T00:00:00Z".into(),
        ppid: 0,
        name: "b.exe".into(),
        path: None,
        parent_path: None,
        identity_id: None,
        verdict: None,
        score: None,
        freshness: None,
        origin: None,
    });
    validate(
        &s["x-events"]["event.reopen_prompt"],
        "event.reopen_prompt",
        &json!({"pid": 7, "start_time": "t7", "path": "C:/a.exe", "answer_within_secs": 60, "decision": null}),
    );
    sh.remove_process(1, "2026-01-01T00:00:00Z");
    sh.sync_connections(vec![]);
    sh.set_mode("learning", false).unwrap();
    sh.set_health("degraded", Some("x"));
    let mut seen = std::collections::BTreeSet::new();
    while let Ok(e) = bus.try_recv() {
        validate(&s["x-events"][e.method], e.method, &e.params);
        seen.insert(e.method);
    }
    for m in [
        "event.process_started",
        "event.process_exited",
        "event.connection_closed",
        "event.enforcement_changed",
        "event.health",
    ] {
        assert!(seen.contains(m), "{m} not emitted: {seen:?}");
    }
}

#[tokio::test]
async fn decision_flow_matches_the_schema_and_is_audited() {
    use vigil_store::decisions::{DestClass, NewPending, create_pending};
    let s = schema();
    let shared = shared();
    shared
        .with_store(|c| {
            let p = NewPending {
                executable_id: 1,
                dest_class: DestClass::Public,
                dest_addr: "8.8.8.8".into(),
                dest_port: 443,
                dns_name: None,
            };
            create_pending(c, &p, time::OffsetDateTime::now_utc()).unwrap();
        })
        .unwrap();
    let (a, b) = tokio::io::duplex(1 << 16);
    tokio::spawn(handle_connection(b, Role::Admin, shared));
    let mut c = Client::new(a);

    let list = c.call("pending.list", json!({})).await.unwrap();
    validate(
        &s["x-methods"]["pending.list"]["result"],
        "pending.list",
        &list,
    );
    let pid = list["items"][0]["id"]
        .as_str()
        .expect("one pending item")
        .to_owned();

    let params = json!({"pending_id": pid, "action": "allow", "scope": "1h", "apply_to": "file"});
    validate(
        &s["x-methods"]["decision.submit"]["params"],
        "decision.submit",
        &params,
    );
    let res = c.call("decision.submit", params).await.unwrap();
    validate(
        &s["x-methods"]["decision.submit"]["result"],
        "decision.submit",
        &res,
    );

    let after = c.call("pending.list", json!({})).await.unwrap();
    assert_eq!(
        after["items"].as_array().unwrap().len(),
        0,
        "pending resolved"
    );
    let audit = c.call("audit.query", json!({})).await.unwrap();
    validate(
        &s["x-methods"]["audit.query"]["result"],
        "audit.query",
        &audit,
    );
    assert_eq!(audit["chain_ok"], true);
    assert_eq!(audit["items"][0]["kind"], "decision");

    let id = res["decision"]["id"].clone();
    let listed = c.call("decision.list", json!({})).await.unwrap();
    validate(
        &s["x-methods"]["decision.list"]["result"],
        "decision.list",
        &listed,
    );
    assert!(listed["items"][0]["respawn_kills"].is_u64());
    let exc = c
        .call("decision.exception", json!({"decision_id": id}))
        .await
        .unwrap();
    validate(
        &s["x-methods"]["decision.exception"]["result"],
        "decision.exception",
        &exc,
    );
    assert_eq!(exc["decision"]["action"], "allow");
    let id = exc["decision"]["id"].clone();
    c.call("decision.revoke", json!({"decision_id": id}))
        .await
        .unwrap();
    let kinds: Vec<String> = c.call("audit.query", json!({})).await.unwrap()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        kinds,
        [
            "decision",
            "decision_revoked",
            "decision",
            "decision_revoked"
        ]
    );
}
