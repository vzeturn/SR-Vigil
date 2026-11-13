//! Signed remote rule packs (`docs/03 §8.1`): `{kid, payload, sig}` signed with the project keys in
//! `rules/catalogue_keys.toml`. The payload is `{v, type: "rulepack", issued, pack}` where `pack`
//! is override TOML that may only add score-lowering signals ([`RulePack::with_remote`]). The
//! `type` tag keeps a catalogue snapshot from ever being read as a rule pack and vice versa.

use serde::Deserialize;

use super::{EMBEDDED_DEFAULT, RuleError, RulePack};
use crate::analysis::catalogue;

const FORMAT: u32 = 1;
const TYPE: &str = "rulepack";

/// A verified remote pack, already checked against the embedded defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePack {
    /// ISO-8601 UTC issue time (orders correctly as text).
    pub issued: String,
    /// Override TOML (`[[rule]]` entries only).
    pub text: String,
}

/// Why a remote pack was refused.
#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error(transparent)]
    Envelope(#[from] catalogue::Error),
    #[error("payload is not a rule pack")]
    Malformed,
    #[error("unsupported rule pack format")]
    UnsupportedFormat,
    #[error("rule pack is older than the one in use")]
    Rollback,
    #[error(transparent)]
    Rule(#[from] RuleError),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    v: u32,
    #[serde(rename = "type")]
    kind: String,
    issued: String,
    pack: String,
}

/// `2026-11-13T00:00:00Z` or with milliseconds: digits and `-:.TZ` only, so it is safe in a
/// version string and compares correctly as text.
fn plain_time(s: &str) -> bool {
    (20..=24).contains(&s.len())
        && s.ends_with('Z')
        && s.as_bytes()[10] == b'T'
        && s.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | '.' | 'T' | 'Z'))
}

fn from_payload(text: &str) -> Result<RemotePack, RemoteError> {
    let p: Payload = serde_json::from_str(text).map_err(|_| RemoteError::Malformed)?;
    if p.kind != TYPE || !plain_time(&p.issued) {
        return Err(RemoteError::Malformed);
    }
    if p.v != FORMAT {
        return Err(RemoteError::UnsupportedFormat);
    }
    let base = RulePack::parse("embedded:default.toml", EMBEDDED_DEFAULT)?;
    base.with_remote("remote", &p.issued, &p.pack)?;
    Ok(RemotePack {
        issued: p.issued,
        text: p.pack,
    })
}

/// Verify a downloaded or cached rule pack. `current` is the issue time of the pack in use; an
/// older one is refused so a replayed download cannot undo a newer pack.
///
/// # Errors
/// See [`RemoteError`]; on any error nothing from the bytes may be used.
pub fn verify(bytes: &[u8], current: Option<&str>) -> Result<RemotePack, RemoteError> {
    check_issue(from_payload(&catalogue::open(bytes)?)?, current)
}

fn check_issue(pack: RemotePack, current: Option<&str>) -> Result<RemotePack, RemoteError> {
    if current.is_some_and(|c| pack.issued.as_str() < c) {
        return Err(RemoteError::Rollback);
    }
    Ok(pack)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(pack: &str) -> String {
        serde_json::json!({"v": 1, "type": "rulepack", "issued": "2026-11-13T00:00:00Z", "pack": pack})
            .to_string()
    }

    const ADD: &str = r#"
[[rule]]
id = "RMT-001"
name = "remote_test"
kind = "signal"
description = "Test signal from a remote pack."
when = { lolbin = true, dest_public = true }
score = -10
"#;

    #[test]
    fn a_new_lowering_signal_is_accepted_and_tags_the_version() {
        let p = from_payload(&payload(ADD)).unwrap();
        let base = RulePack::parse("d", EMBEDDED_DEFAULT).unwrap();
        let merged = base.with_remote("remote", &p.issued, &p.text).unwrap();
        assert!(merged.rule("RMT-001").is_some());
        assert!(
            merged
                .meta
                .rule_pack_version
                .ends_with("+remote.2026-11-13T00:00:00Z")
        );
    }

    #[test]
    fn anything_that_could_raise_trust_or_condemn_is_refused() {
        for bad in [
            ADD.replace("score = -10", "score = 5"),
            ADD.replace("score = -10\n", ""),
            ADD.replace(
                "kind = \"signal\"",
                "kind = \"hard_rule\"\nverdict = \"malicious\"\nterminal = true",
            )
            .replace("score = -10\n", ""),
            ADD.replace("RMT-001", "SIG-011"),
            ADD.replace(
                "score = -10",
                "score = -10\nexclusive_group = \"g\"\npriority = 9",
            ),
        ] {
            assert!(
                matches!(from_payload(&payload(&bad)), Err(RemoteError::Rule(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn wrong_type_time_or_format_is_refused() {
        let mut v: serde_json::Value = serde_json::from_str(&payload(ADD)).unwrap();
        v["type"] = "catalogue".into();
        assert!(matches!(
            from_payload(&v.to_string()),
            Err(RemoteError::Malformed)
        ));
        v["type"] = "rulepack".into();
        v["issued"] = "2026-11-13 00:00:00; x".into();
        assert!(matches!(
            from_payload(&v.to_string()),
            Err(RemoteError::Malformed)
        ));
        v["issued"] = "2026-11-13T00:00:00Z".into();
        v["v"] = 2.into();
        assert!(matches!(
            from_payload(&v.to_string()),
            Err(RemoteError::UnsupportedFormat)
        ));
        let catalogue = r#"{"v":1,"issued":"2026-11-04T00:00:00.000Z","products":{}}"#;
        assert!(matches!(
            from_payload(catalogue),
            Err(RemoteError::Malformed)
        ));
    }

    #[test]
    fn unsigned_bytes_and_rollbacks_are_refused() {
        let env = serde_json::json!({"kid": "k1", "payload": payload(ADD), "sig": "AAAA"});
        assert!(matches!(
            verify(env.to_string().as_bytes(), None),
            Err(RemoteError::Envelope(catalogue::Error::BadSignature))
        ));
        let pack = from_payload(&payload(ADD)).unwrap();
        assert!(check_issue(pack.clone(), Some("2026-11-12T00:00:00Z")).is_ok());
        assert!(check_issue(pack.clone(), Some("2026-11-13T00:00:00Z")).is_ok());
        assert!(matches!(
            check_issue(pack, Some("2026-11-14T00:00:00Z")),
            Err(RemoteError::Rollback)
        ));
        assert!(plain_time("2026-11-13T00:00:00.000Z"));
    }
}
