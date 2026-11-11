//! Offline destination reputation in the service (`docs/15 §4`): DNS answers name connections,
//! findings re-judge the program once, and the Connections page gets a chip.

use std::net::IpAddr;

use serde_json::json;
use vigil_svc::state::{ConnRow, Options, ProcRow, Shared};

const PATH: &str = r"C:\Users\a\AppData\Roaming\upd.exe";
/// Past the warm-up in which a missing DNS answer proves nothing.
const WATCHED: u64 = 11 * 60_000;

fn setup() -> Shared {
    let s = Shared::new(Options {
        store: Some(vigil_store::open_in_memory().unwrap()),
        rules: json!([]),
        trust: vec![],
        rule_pack_version: "1".into(),
        network_critical: vec![],
        never_kill: vec![],
    });
    s.put_process(ProcRow {
        pid: 9,
        start_time: "t9".into(),
        ppid: 0,
        name: "upd.exe".into(),
        path: Some(PATH.into()),
        parent_path: None,
        identity_id: None,
        verdict: Some("unknown".into()),
        score: Some(50),
        freshness: None,
        tab: false,
        origin: None,
    });
    s
}

fn ip(a: &str) -> IpAddr {
    a.parse().unwrap()
}

#[test]
fn listed_name_marks_the_program_bad_once() {
    let s = setup();
    s.note_dns_at(9, "a.wicar.org", &[ip("203.0.113.7")], 0);
    let (name, chip) = s.assess_destination_at(9, "203.0.113.7", 443, 1000);
    assert_eq!(name.as_deref(), Some("a.wicar.org"));
    assert_eq!(chip, Some("bad"));
    let seen = s.net_seen(PATH);
    assert!(seen.bad && seen.public_outbound && !seen.no_dns);
    assert_eq!(s.take_rejudge_paths(), vec![PATH.to_string()]);
    s.assess_destination_at(9, "203.0.113.7", 443, 2000);
    assert!(
        s.take_rejudge_paths().is_empty(),
        "same finding re-judges once"
    );
}

#[test]
fn raw_ip_counts_only_once_dns_has_been_watched() {
    let s = setup();
    s.note_dns_at(1, "example.com", &[ip("93.184.216.34")], 0);
    assert_eq!(
        s.assess_destination_at(9, "198.51.100.4", 443, 1000).1,
        None
    );
    assert!(!s.net_seen(PATH).no_dns);
    assert_eq!(
        s.assess_destination_at(9, "198.51.100.4", 443, WATCHED).1,
        Some("risky")
    );
    assert!(s.net_seen(PATH).no_dns);
}

#[test]
fn local_destinations_are_not_assessed() {
    let s = setup();
    assert_eq!(
        s.assess_destination_at(9, "192.168.1.10", 4444, WATCHED),
        (None, None)
    );
    assert!(!s.net_seen(PATH).public_outbound);
}

#[test]
fn polled_connections_carry_name_and_chip() {
    let s = setup();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let now = u64::try_from(now.as_millis()).unwrap();
    s.note_dns_at(9, "xjwqkvbnzhpqrt.com", &[ip("203.0.113.9")], now);
    s.sync_connections(vec![ConnRow {
        id: "c1".into(),
        pid: 9,
        direction: "outbound",
        local_addr: "10.0.0.2".into(),
        local_port: 50000,
        remote_addr: Some("203.0.113.9".into()),
        remote_port: Some(443),
        state: "established",
        verdict: None,
        dns_name: None,
        reputation: None,
        first_seen: "t".into(),
        last_seen: "t".into(),
    }]);
    let rows = s.list_connections(&json!({})).unwrap();
    let c = &rows["items"][0];
    assert_eq!(c["dns_name"], "xjwqkvbnzhpqrt.com");
    assert_eq!(c["reputation"], "risky");
    assert!(s.net_seen(PATH).generated_name);
}

#[test]
fn an_upload_to_a_public_address_marks_the_program_once() {
    let s = setup();
    s.note_upload(9, ip("192.168.1.20"), 900_000_000, 0);
    assert!(
        !s.net_seen(PATH).unusual_upload,
        "a NAS backup is not counted"
    );
    s.note_upload(9, ip("::ffff:203.0.113.7"), 60_000_000, 1_000);
    assert!(s.net_seen(PATH).unusual_upload);
    assert_eq!(s.take_rejudge_paths(), vec![PATH.to_string()]);
    s.note_upload(9, ip("203.0.113.8"), 60_000_000, 1_000);
    assert!(s.take_rejudge_paths().is_empty(), "re-judged once");
}
