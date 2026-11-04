//! FR-018: decisions round-trip through TOML, hostile documents are rejected or skipped, and
//! the CSV audit export neutralises formula injection.

use serde_json::json;
use vigil_store::repo::{Executable, upsert_executable};
use vigil_svc::state::{Options, Shared};

fn shared() -> Shared {
    Shared::new(Options {
        store: Some(vigil_store::open_in_memory().unwrap()),
        rules: json!([]),
        trust: vec![],
        rule_pack_version: "1".into(),
        network_critical: vec![],
        never_kill: vec![],
    })
}

fn with_decision(s: &Shared, path: &str, sha: &str) {
    let id = s
        .with_store(|c| {
            upsert_executable(
                c,
                &Executable {
                    sha256: sha.into(),
                    path: path.into(),
                    signer_thumbprint: None,
                    publisher: None,
                    company: None,
                    product: None,
                    original_filename: None,
                    signature_status: "unsigned".into(),
                },
                "2026-01-01T00:00:00Z",
            )
            .unwrap()
        })
        .unwrap();
    s.submit_decision(&json!({
        "action": "allow", "scope": "forever", "apply_to": "file",
        "identity_id": id.to_string(), "note": "=HYPERLINK(\"x\")"
    }))
    .unwrap();
}

#[test]
fn decisions_round_trip_and_duplicates_are_skipped() {
    let a = shared();
    with_decision(&a, r"C:\tools\x.exe", &"a".repeat(64));
    let exported = a.decisions_export().unwrap();
    assert_eq!(exported["count"], 1);
    let content = exported["content"].as_str().unwrap();

    let b = shared();
    let r = b
        .decisions_import(&json!({"content": content}), "user")
        .unwrap();
    assert_eq!(
        (r["imported"].as_u64(), r["skipped"].as_u64()),
        (Some(1), Some(0))
    );
    assert_eq!(
        b.list_decisions().unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let again = b
        .decisions_import(&json!({"content": content}), "user")
        .unwrap();
    assert_eq!(
        (again["imported"].as_u64(), again["skipped"].as_u64()),
        (Some(0), Some(1))
    );
}

#[test]
fn hostile_documents_are_rejected_or_skipped() {
    let s = shared();
    assert!(
        s.decisions_import(&json!({"content": "not toml ["}), "user")
            .is_err()
    );
    assert!(
        s.decisions_import(&json!({"content": "version = 9"}), "user")
            .is_err()
    );
    assert!(
        s.decisions_import(&json!({"content": "x".repeat((1 << 20) + 1)}), "user")
            .is_err()
    );
    let doc = format!(
        "version = 1\n[[decision]]\nsha256 = \"zz\"\npath = 'C:/a.exe'\nsignature_status = \"unsigned\"\naction = \"allow\"\nscope = \"forever\"\napply_to = \"file\"\n\n[[decision]]\nsha256 = \"{}\"\npath = 'C:/b.exe'\nsignature_status = \"unsigned\"\naction = \"allow\"\nscope = \"once\"\napply_to = \"file\"\n",
        "b".repeat(64)
    );
    let r = s
        .decisions_import(&json!({"content": doc}), "user")
        .unwrap();
    assert_eq!(
        (r["imported"].as_u64(), r["skipped"].as_u64()),
        (Some(0), Some(2))
    );
}

#[test]
fn csv_export_neutralises_formulas() {
    let s = shared();
    with_decision(&s, r"C:\tools\x.exe", &"a".repeat(64));
    let r = s.audit_export(&json!({"format": "csv"})).unwrap();
    let csv = r["content"].as_str().unwrap();
    assert!(csv.starts_with("seq,ts,actor,kind"));
    assert!(r["count"].as_u64().unwrap() >= 1);
    assert!(!csv.split("\r\n").any(|l| l.contains(",\"=")), "{csv}");
    assert!(s.audit_export(&json!({"format": "xml"})).is_err());
}
