//! Typosquat detection and publisher-metadata comparison (`docs/03 §5.3-5.4`).

/// Map look-alike characters (Cyrillic/Greek homoglyphs, digits) to a Latin skeleton.
fn skeleton_char(c: char) -> char {
    match c {
        '0' | 'о' | 'ο' => 'o',
        '1' | 'i' | 'і' | 'ι' | '|' => 'l',
        'а' | 'α' => 'a',
        'е' => 'e',
        'р' => 'p',
        'с' => 'c',
        'х' => 'x',
        'у' => 'y',
        'ѕ' | '5' => 's',
        'ν' => 'v',
        other => other,
    }
}

/// Lower-cased skeleton of `s` with `rn`→`m` and `vv`→`w` folded.
#[must_use]
pub fn skeleton(s: &str) -> String {
    let mapped: String = s.to_lowercase().chars().map(skeleton_char).collect();
    mapped.replace("rn", "m").replace("vv", "w")
}

/// Levenshtein distance over `char`s.
#[must_use]
pub fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != *cb);
            cur.push(sub.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

fn stem(name: &str) -> String {
    let n = name.to_lowercase();
    n.strip_suffix(".exe").unwrap_or(&n).to_string()
}

/// True when `name` imitates (but is not) one of the `canonical` image names.
///
/// Distance ≤ 2 applies only to canonical stems of 5+ characters to keep short names quiet;
/// an equal skeleton applies to any length.
#[must_use]
pub fn is_typosquat(name: &str, canonical: &[String]) -> bool {
    let s = stem(name);
    let stems: Vec<String> = canonical.iter().map(|c| stem(c)).collect();
    if stems.contains(&s) {
        return false;
    }
    let sk = skeleton(&s);
    stems
        .iter()
        .any(|c| (sk == skeleton(c)) || (c.chars().count() >= 5 && levenshtein(&s, c) <= 2))
}

const LEGAL_SUFFIXES: [&str; 12] = [
    "corporation",
    "corp",
    "incorporated",
    "inc",
    "limited",
    "ltd",
    "llc",
    "gmbh",
    "co",
    "company",
    "sa",
    "plc",
];

/// Normalise an organisation name: lower-case, drop punctuation and legal suffixes.
#[must_use]
pub fn normalize_org(s: &str) -> String {
    let cleaned: String = s
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    cleaned
        .split_whitespace()
        .filter(|w| !LEGAL_SUFFIXES.contains(w))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Result of comparing `VersionInfo` against the signer organisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompanyCheck {
    pub matches: bool,
    pub conflicts: bool,
}

/// Compare `CompanyName` with the signer organisation. Empty company ⇒ neither matches nor conflicts.
#[must_use]
pub fn compare_company(company: &str, signer_org: &str) -> CompanyCheck {
    let (c, s) = (normalize_org(company), normalize_org(signer_org));
    if c.is_empty() || s.is_empty() {
        return CompanyCheck::default();
    }
    // Third-party drivers and helpers signed through the Windows Hardware Compatibility program carry
    // Microsoft's publisher name by design; the vendor's own CompanyName is expected.
    if s.starts_with("microsoft windows hardware") {
        return CompanyCheck::default();
    }
    // Same leading brand word ("intel r" vs "intel") means the same vendor.
    let brand = |x: &str| {
        x.split(' ')
            .next()
            .filter(|w| w.len() >= 4)
            .map(str::to_owned)
    };
    let loosely = c == s
        || c.contains(&s)
        || s.contains(&c)
        || brand(&c).is_some_and(|w| brand(&s).as_deref() == Some(w.as_str()));
    CompanyCheck {
        matches: loosely,
        conflicts: !loosely,
    }
}

/// True when any `VersionInfo` text claims one of the pinned publishers' names or aliases.
#[must_use]
pub fn claims_publisher(metadata: &[&str], names: &[String]) -> bool {
    let names: Vec<String> = names.iter().map(|n| normalize_org(n)).collect();
    metadata.iter().map(|m| normalize_org(m)).any(|m| {
        !m.is_empty()
            && names
                .iter()
                .any(|n| !n.is_empty() && (m == *n || m.starts_with(&format!("{n} "))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon() -> Vec<String> {
        ["svchost.exe", "lsass.exe", "explorer.exe", "csrss.exe"]
            .map(String::from)
            .to_vec()
    }

    #[test]
    fn flags_lookalikes_not_exact_names() {
        let c = canon();
        assert!(is_typosquat("svch0st.exe", &c));
        assert!(is_typosquat("svchost1.exe", &c));
        assert!(is_typosquat("expl0rer.exe", &c));
        assert!(is_typosquat("svсhost.exe", &c), "cyrillic с");
        assert!(is_typosquat("lssas.exe", &c));
        assert!(!is_typosquat("SVCHOST.EXE", &c));
        assert!(!is_typosquat("notepad.exe", &c));
    }

    #[test]
    fn short_names_only_match_by_skeleton() {
        let c = vec!["dwm.exe".to_string()];
        assert!(!is_typosquat("dwx.exe", &c));
        assert!(is_typosquat("dvvm.exe", &c));
    }

    #[test]
    fn company_comparison() {
        assert!(compare_company("Microsoft Corporation", "Microsoft Corporation").matches);
        assert!(compare_company("Google", "Google LLC").matches);
        assert!(compare_company("Acme Tools", "Microsoft Corporation").conflicts);
        assert!(compare_company("Intel(R) Corporation", "Intel Corp.").matches);
        assert!(compare_company("Polycom Inc.", "Polycom, Inc. Systems").matches);
        assert!(compare_company("Microsoft Tools", "Microsoft Corporation").matches);
        assert_eq!(
            compare_company(
                "Intel Corporation",
                "Microsoft Windows Hardware Compatibility Publisher"
            ),
            CompanyCheck::default()
        );
        assert_eq!(compare_company("", "Acme"), CompanyCheck::default());
    }

    #[test]
    fn publisher_claims() {
        let names = vec!["Microsoft Corporation".to_string(), "Microsoft".to_string()];
        assert!(claims_publisher(&["Microsoft Corporation"], &names));
        assert!(claims_publisher(&["Microsoft Windows"], &names));
        assert!(!claims_publisher(&["Microsoftware Ltd"], &names));
        assert!(!claims_publisher(&[""], &names));
    }
}
