//! Signed version catalogue (`docs/16`): verify a snapshot and hold the release data it carries.
//!
//! A snapshot is `{kid, payload, sig}`; `sig` is Ed25519 over the exact UTF-8 bytes of `payload`,
//! made by a key listed in `rules/catalogue_keys.toml`. Nothing is applied unless the signature,
//! the format version and the issue time all check out.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

const KEYS: &str = include_str!("../../../../rules/catalogue_keys.toml");
const FORMAT: u32 = 1;

/// Release data for one product, all optional.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Release {
    pub latest: Option<String>,
    pub min_supported: Option<String>,
    pub vulnerable_below: Option<String>,
    /// Vendor download page; shown only when [`safe_link`] accepts it.
    pub download_page: Option<String>,
    /// `winget` package id, for the later user-approved update flow (`docs/16 §6`).
    pub winget_id: Option<String>,
    /// Installer SHA-256 values the vendor published for `latest` (one per architecture).
    #[serde(default)]
    pub installer_sha256: Vec<String>,
    /// ISO date the vendor ends support for this product line, when announced.
    pub end_of_support: Option<String>,
}

/// `url` when it is fit to hand to the shell as a vendor page: `https://`, a plain host name
/// (letters, digits, dots, hyphens, optional port), at most 300 characters, and no spaces,
/// control characters, quotes, backslashes or credentials.
#[must_use]
pub fn safe_link(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (host, name) = (&rest[..host_end], rest[..host_end].split(':').next()?);
    let host_ok = !name.is_empty()
        && name.contains('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && host[name.len()..]
            .strip_prefix(':')
            .is_none_or(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    let text_ok = url.len() <= 300
        && url.chars().all(|c| {
            c.is_ascii_graphic()
                && !matches!(c, '"' | '\\' | '<' | '>' | '`' | '^' | '{' | '}' | '|')
        });
    (host_ok && text_ok).then_some(url)
}

/// Why a snapshot was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("snapshot is not valid JSON")]
    Malformed,
    #[error("unknown signing key")]
    UnknownKey,
    #[error("signature does not verify")]
    BadSignature,
    #[error("unsupported snapshot format")]
    UnsupportedFormat,
    #[error("snapshot is older than the one in use")]
    Rollback,
}

#[derive(Deserialize)]
struct Envelope {
    kid: String,
    payload: String,
    sig: String,
}

#[derive(Deserialize)]
struct Payload {
    v: u32,
    issued: String,
    products: HashMap<String, Release>,
}

#[derive(Deserialize)]
struct KeyFile {
    key: Vec<KeyEntry>,
}

#[derive(Deserialize)]
struct KeyEntry {
    kid: String,
    public: String,
}

/// A verified snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// ISO-8601 UTC issue time (compared as text, which orders correctly for that format).
    pub issued: String,
    pub products: HashMap<String, Release>,
}

fn verifying_key(kid: &str) -> Option<VerifyingKey> {
    let file: KeyFile = toml::from_str(KEYS).ok()?;
    let entry = file.key.iter().find(|k| k.kid == kid)?;
    let raw: [u8; 32] = STANDARD.decode(&entry.public).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&raw).ok()
}

/// The payload text of a `{kid, payload, sig}` envelope whose signature verifies under `key_for`.
pub(crate) fn open_with(
    bytes: &[u8],
    key_for: impl Fn(&str) -> Option<VerifyingKey>,
) -> Result<String, Error> {
    let env: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
    let key = key_for(&env.kid).ok_or(Error::UnknownKey)?;
    let sig_bytes: [u8; 64] = STANDARD
        .decode(&env.sig)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::BadSignature)?;
    key.verify(env.payload.as_bytes(), &Signature::from_bytes(&sig_bytes))
        .map_err(|_| Error::BadSignature)?;
    Ok(env.payload)
}

/// [`open_with`] against the embedded project keys (also used for signed rule packs).
pub(crate) fn open(bytes: &[u8]) -> Result<String, Error> {
    open_with(bytes, verifying_key)
}

fn verify_with(
    bytes: &[u8],
    key_for: impl Fn(&str) -> Option<VerifyingKey>,
) -> Result<Snapshot, Error> {
    let text = open_with(bytes, key_for)?;
    let payload: Payload = serde_json::from_str(&text).map_err(|_| Error::Malformed)?;
    if payload.v != FORMAT {
        return Err(Error::UnsupportedFormat);
    }
    Ok(Snapshot {
        issued: payload.issued,
        products: payload.products,
    })
}

/// Verify a downloaded or cached snapshot against the embedded public keys.
///
/// # Errors
/// See [`Error`]; on any error nothing from the snapshot may be used.
pub fn verify(bytes: &[u8]) -> Result<Snapshot, Error> {
    verify_with(bytes, verifying_key)
}

fn applied() -> &'static RwLock<Option<Snapshot>> {
    static APPLIED: OnceLock<RwLock<Option<Snapshot>>> = OnceLock::new();
    APPLIED.get_or_init(|| RwLock::new(None))
}

/// Make `snapshot` the release data in use. An older snapshot than the current one is refused so a
/// replayed stale download cannot undo a newer one.
///
/// # Errors
/// [`Error::Rollback`] when `snapshot` was issued before the one already applied.
pub fn apply(snapshot: Snapshot) -> Result<(), Error> {
    let mut slot = applied()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if slot
        .as_ref()
        .is_some_and(|cur| snapshot.issued < cur.issued)
    {
        return Err(Error::Rollback);
    }
    *slot = Some(snapshot);
    Ok(())
}

/// Release data for the catalogue label `label` from the applied snapshot, if any.
#[must_use]
pub fn release(label: &str) -> Option<Release> {
    applied()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|s| s.products.get(label).cloned())
}

/// Issue time of the snapshot in use.
#[must_use]
pub fn issued() -> Option<String> {
    applied()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(|s| s.issued.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn envelope(payload: &str, key: &SigningKey) -> Vec<u8> {
        let sig = STANDARD.encode(key.sign(payload.as_bytes()).to_bytes());
        serde_json::json!({"kid": "t", "payload": payload, "sig": sig})
            .to_string()
            .into_bytes()
    }

    fn lookup(kid: &str) -> Option<VerifyingKey> {
        (kid == "t").then(|| signing_key().verifying_key())
    }

    const PAYLOAD: &str =
        r#"{"v":1,"issued":"2026-11-04T00:00:00.000Z","products":{"Git":{"latest":"2.56.0"}}}"#;

    #[test]
    fn embedded_keys_parse() {
        let file: KeyFile = toml::from_str(KEYS).unwrap();
        assert!(!file.key.is_empty());
        assert!(file.key.iter().all(|k| verifying_key(&k.kid).is_some()));
    }

    #[test]
    fn valid_snapshot_verifies() {
        let s = verify_with(&envelope(PAYLOAD, &signing_key()), lookup).unwrap();
        assert_eq!(s.products["Git"].latest.as_deref(), Some("2.56.0"));
    }

    #[test]
    fn tampered_payload_unknown_key_and_bad_format_are_refused() {
        let good = envelope(PAYLOAD, &signing_key());
        let mut env: serde_json::Value = serde_json::from_slice(&good).unwrap();
        env["payload"] = PAYLOAD.replace("2.56.0", "9.9.9").into();
        assert_eq!(
            verify_with(env.to_string().as_bytes(), lookup),
            Err(Error::BadSignature)
        );
        assert_eq!(verify_with(&good, |_| None), Err(Error::UnknownKey));
        assert_eq!(verify_with(b"nope", lookup), Err(Error::Malformed));
        let v2 = envelope(&PAYLOAD.replace("\"v\":1", "\"v\":2"), &signing_key());
        assert_eq!(verify_with(&v2, lookup), Err(Error::UnsupportedFormat));
    }

    #[test]
    fn only_plain_https_vendor_links_are_accepted() {
        for ok in [
            "https://www.videolan.org/vlc/",
            "https://git-scm.com/download/win?x=1#top",
            "https://example.com:8443/a",
        ] {
            assert_eq!(safe_link(ok), Some(ok), "{ok}");
        }
        for bad in [
            "http://www.videolan.org/",
            "file:///C:/Windows/System32/calc.exe",
            "https://user:pw@example.com/",
            "https://example.com/a b",
            "https://example.com/\"x",
            "https://example.com/a\\b",
            "https://localhost/",
            "https://exa_mple.com/",
            "https://example.com:/",
            "https:///path",
            "javascript:alert(1)",
        ] {
            assert_eq!(safe_link(bad), None, "{bad}");
        }
        assert_eq!(
            safe_link(&format!("https://a.com/{}", "x".repeat(300))),
            None
        );
    }

    #[test]
    fn extra_release_fields_are_read_and_optional() {
        let payload = r#"{"v":1,"issued":"2026-11-04T00:00:00.000Z","products":{"VLC":{"latest":"3.0.21","winget_id":"VideoLAN.VLC","download_page":"https://www.videolan.org/vlc/","installer_sha256":["ab"],"end_of_support":"2030-01-01"},"Git":{}}}"#;
        let s = verify_with(&envelope(payload, &signing_key()), lookup).unwrap();
        assert_eq!(s.products["VLC"].winget_id.as_deref(), Some("VideoLAN.VLC"));
        assert_eq!(s.products["VLC"].installer_sha256, vec!["ab".to_string()]);
        assert_eq!(
            s.products["VLC"].end_of_support.as_deref(),
            Some("2030-01-01")
        );
        assert_eq!(s.products["Git"], Release::default());
    }

    #[test]
    fn apply_refuses_older_snapshots() {
        let snap = |issued: &str| Snapshot {
            issued: issued.into(),
            products: HashMap::new(),
        };
        apply(snap("2026-11-05T00:00:00.000Z")).unwrap();
        assert_eq!(
            apply(snap("2026-11-01T00:00:00.000Z")),
            Err(Error::Rollback)
        );
        apply(snap("2026-11-06T00:00:00.000Z")).unwrap();
    }
}
