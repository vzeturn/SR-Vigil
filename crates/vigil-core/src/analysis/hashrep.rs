//! Known-good file hashes (`docs/20 §5`): results of the CIRCL hashlookup service, which indexes the
//! NIST NSRL and vendor package hashes. Only a SHA-256 ever leaves the machine; the answer is a
//! pure yes/no filled by the service and read while scoring.
//!
//! The same holds for the optional keyed services: `VirusTotal` detection counts and
//! `MalwareBazaar` sample listings.

use std::collections::{HashMap, HashSet};
use std::sync::{PoisonError, RwLock};

static KNOWN: RwLock<Option<HashSet<String>>> = RwLock::new(None);
static MALWARE: RwLock<Option<HashSet<String>>> = RwLock::new(None);
static VT: RwLock<Option<HashMap<String, VtReport>>> = RwLock::new(None);

/// What `VirusTotal` knows about a file: engines flagging it and when it was first submitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VtReport {
    pub detections: u32,
    /// Unix seconds of the first submission.
    pub first_seen: i64,
}

impl VtReport {
    /// Whole days between the first submission and `now` (Unix seconds); 0 for a future date.
    #[must_use]
    pub fn first_seen_days(&self, now: i64) -> u32 {
        u32::try_from((now - self.first_seen).max(0) / 86_400).unwrap_or(u32::MAX)
    }
}

/// Remember `VirusTotal`'s answer for `sha256`.
pub fn record_vt(sha256: &str, report: VtReport) {
    VT.write()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert(sha256.to_ascii_lowercase(), report);
}

/// `VirusTotal`'s answer for `sha256`, if one was recorded.
#[must_use]
pub fn vt_of(sha256: &str) -> Option<VtReport> {
    VT.read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .and_then(|m| m.get(&sha256.to_ascii_lowercase()).copied())
}

/// Remember that `sha256` is a malware sample listed by `MalwareBazaar`.
pub fn mark_malware(sha256: &str) {
    MALWARE
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(HashSet::new)
        .insert(sha256.to_ascii_lowercase());
}

/// Whether `sha256` is a listed malware sample.
#[must_use]
pub fn is_malware(sha256: &str) -> bool {
    MALWARE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .is_some_and(|s| s.contains(&sha256.to_ascii_lowercase()))
}

/// Whether any keyed-service answer is held, so callers can skip hashing when there is none.
#[must_use]
pub fn any_keyed() -> bool {
    let has = |n: Option<usize>| n.is_some_and(|n| n > 0);
    has(MALWARE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map(HashSet::len))
        || has(VT
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(HashMap::len))
}

/// Parse a `VirusTotal` v3 file report. The answer is untrusted JSON: only the malicious-engine
/// count and the first submission date are read; anything else malformed yields `None`.
#[must_use]
pub fn vt_parse(body: &str) -> Option<VtReport> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let a = &v["data"]["attributes"];
    Some(VtReport {
        detections: u32::try_from(a["last_analysis_stats"]["malicious"].as_u64()?).ok()?,
        first_seen: a["first_submission_date"].as_i64()?,
    })
}

/// Whether a `MalwareBazaar` `get_info` answer lists the hash as a sample.
#[must_use]
pub fn bazaar_lists(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body).is_ok_and(|v| {
        v["query_status"] == "ok" && v["data"].as_array().is_some_and(|d| !d.is_empty())
    })
}

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
    fn virustotal_reports_read_only_the_count_and_first_date() {
        let body = r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":7,"harmless":60},
            "first_submission_date":1700000000,"names":["x.exe"]}}}"#;
        let r = vt_parse(body).unwrap();
        assert_eq!(
            r,
            VtReport {
                detections: 7,
                first_seen: 1_700_000_000
            }
        );
        assert_eq!(r.first_seen_days(1_700_000_000 + 30 * 86_400), 30);
        assert_eq!(r.first_seen_days(0), 0);
        for bad in [
            r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":"7"},"first_submission_date":1}}}"#,
            r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":-1},"first_submission_date":1}}}"#,
            r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":1}}}}"#,
            r#"{"error":{"code":"NotFoundError"}}"#,
            "not json",
        ] {
            assert_eq!(vt_parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn bazaar_lists_only_an_ok_answer_with_samples() {
        assert!(bazaar_lists(
            r#"{"query_status":"ok","data":[{"sha256_hash":"ab"}]}"#
        ));
        for no in [
            r#"{"query_status":"hash_not_found"}"#,
            r#"{"query_status":"ok","data":[]}"#,
            r#"{"query_status":"illegal_hash"}"#,
            "",
        ] {
            assert!(!bazaar_lists(no), "{no}");
        }
    }

    #[test]
    fn keyed_answers_are_found_regardless_of_case() {
        mark_malware("DEAD01");
        record_vt(
            "BEEF02",
            VtReport {
                detections: 3,
                first_seen: 0,
            },
        );
        assert!(is_malware("dead01") && !is_malware("beef02"));
        assert_eq!(vt_of("beef02").map(|r| r.detections), Some(3));
        assert!(any_keyed());
    }

    #[test]
    fn marked_hashes_are_found_regardless_of_case() {
        mark_known("ABCDEF0123");
        assert!(is_known("abcdef0123"));
        assert!(!is_known("ffff"));
    }
}
