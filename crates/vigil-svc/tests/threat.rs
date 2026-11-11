//! Beaconing is detected from connection metadata alone; nothing about it reaches the advisor
//! until the user agrees (`docs/24`).

use serde_json::{Value, json};
use vigil_store::repo::{Executable, NewEvaluation, insert_evaluation, upsert_executable};
use vigil_svc::state::{ConnRow, Options, ProcRow, Shared};

const PATH: &str = r"C:\Users\a\AppData\Roaming\upd.exe";
const MINUTE: u64 = 60_000;

fn setup(verdict: &str) -> (Shared, i64) {
    let s = Shared::new(Options {
        store: Some(vigil_store::open_in_memory().unwrap()),
        rules: json!([]),
        trust: vec![],
        rule_pack_version: "1".into(),
        network_critical: vec![],
        never_kill: vec![],
    });
    let id = s
        .with_store(|c| {
            let exe = Executable {
                sha256: "b".repeat(64),
                path: PATH.into(),
                signer_thumbprint: None,
                publisher: None,
                company: None,
                product: None,
                original_filename: None,
                signature_status: "unsigned".into(),
            };
            let id = upsert_executable(c, &exe, "2026-01-01T00:00:00Z").unwrap();
            let ev = NewEvaluation {
                score: 40,
                verdict: verdict.into(),
                hard_rule: None,
                signals_json: "[]".into(),
                rule_pack_version: "1".into(),
                source: "rules".into(),
            };
            insert_evaluation(c, id, &ev, "2026-01-01T00:00:00Z").unwrap();
            id
        })
        .unwrap();
    s.put_process(ProcRow {
        pid: 9,
        start_time: "t9".into(),
        ppid: 0,
        name: "upd.exe".into(),
        path: Some(PATH.into()),
        parent_path: None,
        identity_id: Some(id.to_string()),
        verdict: Some(verdict.into()),
        score: Some(40),
        freshness: None,
        tab: false,
        origin: None,
    });
    (s, id)
}

fn conn(n: u64, remote: &str) -> ConnRow {
    ConnRow {
        id: format!("9:{n}:{remote}"),
        pid: 9,
        direction: "outbound",
        local_addr: "192.168.1.5".into(),
        local_port: u16::try_from(50_000 + n).unwrap(),
        remote_addr: Some(remote.into()),
        remote_port: Some(443),
        state: "established",
        verdict: None,
        dns_name: None,
        reputation: None,
        first_seen: String::new(),
        last_seen: String::new(),
    }
}

/// One new connection to `remote` every minute, `n` times.
fn call_home(s: &Shared, remote: &str, n: u64) {
    for i in 0..n {
        s.track_beacons_at(&[conn(i, remote)], 1_000_000 + i * MINUTE);
    }
}

fn threats(s: &Shared) -> Vec<Value> {
    s.threat_list()["threats"].as_array().unwrap().clone()
}

fn shares_beaconing(s: &Shared, id: i64) -> bool {
    let p = s
        .ai_preview(&json!({ "identity_id": id.to_string() }))
        .unwrap();
    p["payload"]["behaviour"]["beaconing"] == json!(true)
}

#[tokio::test]
async fn beaconing_asks_once_and_shares_nothing_before_consent() {
    let (s, id) = setup("unknown");
    let mut bus = s.subscribe_bus();
    call_home(&s, "203.0.113.9", 8);

    assert!(s.is_beaconing(PATH));
    assert_eq!(s.take_rejudge_paths(), vec![PATH.to_string()]);
    let list = threats(&s);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["dest_ip"], "203.0.113.9");
    assert_eq!(list[0]["interval_secs"], 60);
    let prompts = std::iter::from_fn(|| bus.try_recv().ok())
        .filter(|e| e.method == "event.threat_detected")
        .count();
    assert_eq!(prompts, 1);
    assert!(!shares_beaconing(&s, id), "nothing shared before consent");

    let threat_id = list[0]["threat_id"].as_str().unwrap().to_owned();
    // AI is off in this setup: the consent is recorded, the prompt stays so the user can block.
    let err = s
        .threat_answer(&json!({ "threat_id": threat_id, "action": "analyze" }))
        .await
        .unwrap_err();
    assert_eq!(err.message, "off");
    assert!(shares_beaconing(&s, id), "consent shares the pattern");
    assert_eq!(threats(&s).len(), 1);

    s.threat_answer(&json!({ "threat_id": threat_id, "action": "block" }))
        .await
        .unwrap();
    assert_eq!(threats(&s), Vec::<Value>::new());
    assert!(!s.user_allows(id));
    assert!(
        s.threat_answer(&json!({ "threat_id": threat_id, "action": "dismiss" }))
            .await
            .is_err()
    );
}

#[test]
fn local_traffic_and_safe_programs_raise_no_prompt() {
    let (s, _) = setup("unknown");
    call_home(&s, "192.168.1.1", 8);
    assert!(!s.is_beaconing(PATH));

    let (s, _) = setup("safe");
    call_home(&s, "203.0.113.9", 8);
    assert!(s.is_beaconing(PATH), "still scored (BEH-002)");
    assert_eq!(threats(&s), Vec::<Value>::new());
}

#[test]
fn etw_connects_count_short_flows_and_replace_the_poll() {
    let (s, _) = setup("unknown");
    let dest: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    s.use_etw_connects(true);
    // The poll never saw these (each lasted less than its interval); ETW reports every one.
    for i in 0..5 {
        s.track_connect_at(9, dest, 443, 1_000_000 + i * MINUTE);
    }
    // While ETW feeds the tracker, a polled row of the same flow is not counted again.
    s.track_beacons_at(&[conn(99, "203.0.113.9")], 1_000_000 + 5 * MINUTE - 1);
    assert!(
        !s.is_beaconing(PATH),
        "5 connects, the polled duplicate ignored"
    );
    s.track_connect_at(9, dest, 443, 1_000_000 + 5 * MINUTE);
    assert!(s.is_beaconing(PATH));

    // Private destinations and unknown processes are ignored as before.
    let (s, _) = setup("unknown");
    s.use_etw_connects(true);
    for i in 0..8 {
        s.track_connect_at(9, "10.0.0.7".parse().unwrap(), 443, 1_000_000 + i * MINUTE);
        s.track_connect_at(4242, dest, 443, 1_000_000 + i * MINUTE);
    }
    assert!(!s.is_beaconing(PATH));
}
