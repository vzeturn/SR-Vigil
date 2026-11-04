//! Gate: the shared endpoint's prompt/schema (`proxy/src/spec.json`) must equal what the client
//! would send directly. Regenerate with `VIGIL_WRITE_SPEC=1 cargo test -p vigil-ai --test proxy_spec`.

use std::path::PathBuf;

fn spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proxy/src/spec.json")
}

#[test]
fn proxy_spec_matches_client() {
    let want = vigil_ai::proxy_spec();
    if std::env::var_os("VIGIL_WRITE_SPEC").is_some() {
        let text = serde_json::to_string_pretty(&want).expect("serialize");
        std::fs::write(spec_path(), format!("{text}\n")).expect("write spec");
    }
    let have: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(spec_path()).expect("read spec"))
            .expect("parse spec");
    assert_eq!(have, want, "proxy/src/spec.json is stale; regenerate it");
}

#[test]
fn template_has_single_payload_slot() {
    let t = vigil_ai::proxy_spec()["user_template"]
        .as_str()
        .expect("template")
        .to_string();
    assert_eq!(t.matches("{payload}").count(), 1);
    assert!(t.starts_with("<untrusted_telemetry>"));
}
