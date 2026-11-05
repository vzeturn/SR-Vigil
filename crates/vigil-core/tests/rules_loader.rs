//! Loader behaviour: strict validation, `rules.d` overrides, fail closed to the previous pack.

use std::fs;

use vigil_core::rules::{EMBEDDED_DEFAULT, RuleError, RulePack, RuleStore};

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vigil-rules-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

const GOOD_OVERRIDE: &str = r#"
[[rule]]
id = "SIG-011"
name = "unsigned_other"
kind = "signal"
description = "Unsigned elsewhere, stricter"
when = { signature = "unsigned" }
score = -9
"#;

#[test]
fn embedded_default_is_valid() {
    let store = RuleStore::from_embedded().unwrap();
    assert_eq!(store.active().meta.rule_pack_version, "1.0.0");
}

#[test]
fn override_replaces_by_id_and_appends_new_rules() {
    let base = RulePack::parse("d", EMBEDDED_DEFAULT).unwrap();
    let extra = format!(
        "{GOOD_OVERRIDE}\n[[rule]]\nid = \"X-900\"\nname = \"custom\"\nkind = \"signal\"\ndescription = \"d\"\nwhen = {{ lolbin = true }}\nscore = -1\n"
    );
    let merged = base.with_override("o.toml", &extra).unwrap();
    assert_eq!(merged.rule("SIG-011").unwrap().score, Some(-9));
    assert!(merged.rule("X-900").is_some());
    assert_eq!(merged.rules.len(), base.rules.len() + 1);
}

#[test]
fn unknown_predicate_key_is_rejected() {
    let bad = GOOD_OVERRIDE.replace("signature = \"unsigned\"", "bogus_key = true");
    let base = RulePack::parse("d", EMBEDDED_DEFAULT).unwrap();
    assert!(matches!(
        base.with_override("o.toml", &bad),
        Err(RuleError::Parse { .. })
    ));
}

#[test]
fn structural_errors_are_rejected() {
    let base = RulePack::parse("d", EMBEDDED_DEFAULT).unwrap();
    let cases = [
        // terminal without verdict
        (
            "[[rule]]\nid=\"Z-1\"\nname=\"n\"\nkind=\"signal\"\ndescription=\"d\"\nwhen={ lolbin = true }\nscore=-1\nterminal=true\n",
            "terminal",
        ),
        // exclusive_group without priority
        (
            "[[rule]]\nid=\"Z-2\"\nname=\"n\"\nkind=\"signal\"\ndescription=\"d\"\nwhen={ lolbin = true }\nscore=-1\nexclusive_group=\"g\"\n",
            "priority",
        ),
        // unknown kind
        (
            "[[rule]]\nid=\"Z-3\"\nname=\"n\"\nkind=\"weird\"\ndescription=\"d\"\nwhen={ lolbin = true }\n",
            "unknown variant",
        ),
        // protected rule
        (
            "[[rule]]\nid=\"SG-001\"\nname=\"n\"\nkind=\"guard\"\ndescription=\"d\"\nwhen={ never_kill_set = true }\nguard=\"x\"\n",
            "protected",
        ),
        // kind change
        (
            "[[rule]]\nid=\"HR-001\"\nname=\"n\"\nkind=\"signal\"\ndescription=\"d\"\nwhen={ lolbin = true }\nscore=-1\n",
            "kind",
        ),
        // hard rule that would force safe
        (
            "[[rule]]\nid=\"HR-050\"\nname=\"n\"\nkind=\"hard_rule\"\ndescription=\"d\"\nwhen={ lolbin = true }\nverdict=\"safe\"\nterminal=true\n",
            "malicious",
        ),
    ];
    for (text, expect) in cases {
        let err = base.with_override("o.toml", text).unwrap_err().to_string();
        assert!(err.contains(expect), "expected {expect:?} in {err:?}");
    }
}

#[test]
fn thresholds_must_equal_consts() {
    let tampered = EMBEDDED_DEFAULT.replace("safe_min          = 80", "safe_min          = 60");
    assert!(RulePack::parse("t", &tampered).is_err());
}

#[test]
fn missing_override_dir_means_defaults() {
    let store = RuleStore::from_embedded().unwrap();
    let dir = scratch("missing").join("nope");
    assert_eq!(store.reload(&dir).unwrap().rules.len(), 38);
}

#[test]
fn invalid_override_keeps_previous_pack() {
    let store = RuleStore::from_embedded().unwrap();
    let dir = scratch("failclosed");
    fs::write(dir.join("10-good.toml"), GOOD_OVERRIDE).unwrap();
    store.reload(&dir).unwrap();
    assert_eq!(store.active().rule("SIG-011").unwrap().score, Some(-9));

    fs::write(dir.join("20-bad.toml"), "[[rule]]\nid = \"Q\"\nbogus = 1\n").unwrap();
    assert!(store.reload(&dir).is_err());
    let active = store.active();
    assert_eq!(
        active.rule("SIG-011").unwrap().score,
        Some(-9),
        "previous pack stays active"
    );
    assert!(active.rule("Q").is_none());
}
