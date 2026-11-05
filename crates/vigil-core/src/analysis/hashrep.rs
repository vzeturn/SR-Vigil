//! Known-good file hashes (`docs/20 §5`): results of the CIRCL hashlookup service, which indexes the
//! NIST NSRL and vendor package hashes. Only a SHA-256 ever leaves the machine; the answer is a
//! pure yes/no filled by the service and read while scoring.

use std::collections::HashSet;
use std::sync::{PoisonError, RwLock};

static KNOWN: RwLock<Option<HashSet<String>>> = RwLock::new(None);

/// Remember that `sha256` is a known-good hash.
pub fn mark_known(sha256: &str) {
    KNOWN
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(HashSet::new)
        .insert(sha256.to_ascii_lowercase());
}

/// Whether `sha256` was reported as a known-good hash.
#[must_use]
pub fn is_known(sha256: &str) -> bool {
    KNOWN
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .is_some_and(|s| s.contains(&sha256.to_ascii_lowercase()))
}

/// Whether any hash is known, so callers can skip hashing files when the set is empty.
#[must_use]
pub fn any() -> bool {
    KNOWN
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .is_some_and(|s| !s.is_empty())
}

/// Whether a CIRCL hashlookup answer says the file is trusted (`hashlookup:trust` of 50 or more).
/// The answer is untrusted JSON: only that one number is read.
#[must_use]
pub fn circl_trusts(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["hashlookup:trust"].as_i64())
        .is_some_and(|t| t >= 50)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_trust_score_of_fifty_or_more_counts() {
        assert!(circl_trusts(
            r#"{"FileName":"a.exe","hashlookup:trust":75}"#
        ));
        assert!(circl_trusts(r#"{"hashlookup:trust":50}"#));
        for no in [
            r#"{"hashlookup:trust":49}"#,
            r#"{"message":"Non existing SHA-256"}"#,
            r#"{"hashlookup:trust":"99"}"#,
            "not json",
            "",
        ] {
            assert!(!circl_trusts(no), "{no}");
        }
    }

    #[test]
    fn marked_hashes_are_found_regardless_of_case() {
        mark_known("ABCDEF0123");
        assert!(is_known("abcdef0123"));
        assert!(!is_known("ffff"));
    }
}
