//! Offline destination reputation (`docs/15 §4`): bundled bad hosts, risky ports and TLDs, and a
//! machine-generated-name heuristic, from the embedded `rules/reputation.toml`. No network.

use std::sync::OnceLock;

use serde::Deserialize;

const SOURCE: &str = include_str!("../../../../rules/reputation.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    bad: Bad,
    risky: Risky,
    dga: Dga,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bad {
    domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Risky {
    ports: Vec<u16>,
    tlds: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dga {
    min_label_len: usize,
    min_entropy: f64,
    max_vowel_ratio: f64,
    min_digits: usize,
}

fn data() -> &'static File {
    static F: OnceLock<File> = OnceLock::new();
    F.get_or_init(|| toml::from_str(SOURCE).expect("rules/reputation.toml is validated by tests"))
}

/// What the offline layer says about one public destination.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct DestAssessment {
    /// NET-001: the name is on the bundled list (callers also OR in the URL-filter feeds).
    pub bad: bool,
    /// NET-002: the registrable label looks algorithmically generated.
    pub generated_name: bool,
    /// BEH-003: no DNS answer for this address was seen for the program.
    pub no_dns: bool,
    /// BEH-004: risky port or TLD.
    pub risky_port_or_tld: bool,
}

impl DestAssessment {
    /// `"bad"`, `"risky"` or `None`, for the Connections page chip.
    #[must_use]
    pub fn label(&self) -> Option<&'static str> {
        if self.bad {
            Some("bad")
        } else if self.generated_name || self.no_dns || self.risky_port_or_tld {
            Some("risky")
        } else {
            None
        }
    }
}

/// Assess a public destination. `name` is the DNS name the program resolved to reach it;
/// `dns_known` is false when no DNS feed is running (then a missing name proves nothing).
#[must_use]
pub fn assess(name: Option<&str>, port: u16, dns_known: bool) -> DestAssessment {
    let f = data();
    let name = name.map(|n| n.trim_end_matches('.').to_ascii_lowercase());
    let name = name.as_deref().filter(|n| !n.is_empty());
    let tld = name.and_then(|n| n.rsplit('.').next());
    DestAssessment {
        bad: name.is_some_and(|n| f.bad.domains.iter().any(|d| covers(d, n))),
        generated_name: name.is_some_and(looks_generated),
        no_dns: dns_known && name.is_none(),
        risky_port_or_tld: f.risky.ports.contains(&port)
            || tld.is_some_and(|t| f.risky.tlds.iter().any(|r| r == t)),
    }
}

/// `domain` equals `name` or is one of its parents.
fn covers(domain: &str, name: &str) -> bool {
    name == domain
        || name
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// Second-level labels that are part of a public suffix (`bbc.co.uk` → `bbc`).
const SUFFIX_LABELS: [&str; 7] = ["co", "com", "net", "org", "gov", "edu", "ac"];

/// The label a registrant chose: the one left of the TLD, skipping a `co.uk`-style suffix.
fn registrable_label(name: &str) -> Option<&str> {
    let mut labels = name.rsplit('.').skip(1);
    let first = labels.next()?;
    match labels.next() {
        Some(next) if SUFFIX_LABELS.contains(&first) => Some(next),
        _ => Some(first),
    }
}

/// Shannon entropy in bits per character.
#[allow(clippy::cast_precision_loss)]
fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[usize::from(b)] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

/// NET-002 heuristic: long, high-entropy, and vowel-poor or digit-mixed. IDN (`xn--`) labels are
/// skipped because their encoding is high-entropy by construction.
#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn looks_generated(name: &str) -> bool {
    let d = &data().dga;
    let Some(label) = registrable_label(name) else {
        return false;
    };
    if label.len() < d.min_label_len || label.starts_with("xn--") {
        return false;
    }
    let letters = label.bytes().filter(u8::is_ascii_alphabetic).count();
    let digits = label.bytes().filter(u8::is_ascii_digit).count();
    let vowels = label.bytes().filter(|b| b"aeiou".contains(b)).count();
    let vowel_poor = letters > 0 && (vowels as f64 / letters as f64) <= d.max_vowel_ratio;
    let digit_mixed = digits >= d.min_digits && letters >= d.min_digits;
    entropy(label) >= d.min_entropy && (vowel_poor || digit_mixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_file_parses() {
        let f = data();
        assert!(!f.bad.domains.is_empty() && !f.risky.tlds.is_empty());
    }

    #[test]
    fn listed_hosts_and_their_subdomains_are_bad() {
        assert!(assess(Some("testsafebrowsing.appspot.com"), 443, true).bad);
        assert!(assess(Some("A.WICAR.ORG."), 443, true).bad);
        assert!(!assess(Some("notwicar.org"), 443, true).bad);
        assert!(!assess(Some("appspot.com"), 443, true).bad);
    }

    #[test]
    fn generated_names_are_flagged_and_real_ones_are_not() {
        for dga in [
            "xjwqkvbnzhpqrt.com",
            "q8z3k1v9x7m2p4.net",
            "cdn.kd93jf8a2lq7zm.xyz",
        ] {
            assert!(looks_generated(dga), "{dga}");
        }
        for real in [
            "stackoverflow.com",
            "msftconnecttest.com",
            "googleusercontent.com",
            "login.microsoftonline.com",
            "news.bbc.co.uk",
            "xn--bcher-kva.example",
            "d1a2b3c4d5e6f7.cloudfront.net",
        ] {
            assert!(!looks_generated(real), "{real}");
        }
    }

    #[test]
    fn missing_name_counts_only_when_dns_is_watched() {
        assert!(assess(None, 443, true).no_dns);
        assert!(!assess(None, 443, false).no_dns);
    }

    #[test]
    fn risky_port_or_tld() {
        assert!(assess(Some("shop.example.top"), 443, true).risky_port_or_tld);
        assert!(assess(Some("example.com"), 4444, true).risky_port_or_tld);
        assert!(!assess(Some("example.com"), 443, true).risky_port_or_tld);
    }

    #[test]
    fn chip_label_ranks_bad_above_risky() {
        assert_eq!(assess(Some("wicar.org"), 4444, true).label(), Some("bad"));
        assert_eq!(assess(None, 443, true).label(), Some("risky"));
        assert_eq!(assess(Some("example.com"), 443, true).label(), None);
    }
}
