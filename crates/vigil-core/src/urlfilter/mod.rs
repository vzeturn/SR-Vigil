//! Domain filtering (`docs/23`): blocklist matching and the DNS wire format the local sinkhole needs.
//! Pure logic, no I/O. Every name is untrusted text: it is validated before it becomes a map key and is
//! never interpolated into anything.

pub mod dns;

use std::collections::HashMap;

/// What a blocklist says about a domain. One bit each so a domain can sit in several lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Malware = 1,
    Phishing = 2,
    Adult = 4,
    Ads = 8,
}

impl Category {
    pub const ALL: [Self; 4] = [Self::Malware, Self::Phishing, Self::Adult, Self::Ads];

    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Malware => "malware",
            Self::Phishing => "phishing",
            Self::Adult => "adult",
            Self::Ads => "ads",
        }
    }

    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.id() == id)
    }
}

/// Lowercase, strip one trailing dot, and accept only plausible host names (letters, digits, `-`, `_`,
/// dots; at least two labels; RFC length limits). Anything else is dropped rather than guessed at.
#[must_use]
pub fn normalize(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = (3..=253).contains(&name.len())
        && name.contains('.')
        && name.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    ok.then_some(name)
}

/// Domains named by a hosts-format list (`0.0.0.0 example.com`); loopback names are skipped.
pub fn parse_hosts(text: &str) -> impl Iterator<Item = String> + '_ {
    text.lines().flat_map(|line| {
        let line = line.split('#').next().unwrap_or("");
        let mut parts = line.split_whitespace();
        let ip_like = parts
            .next()
            .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok());
        parts
            .filter(move |_| ip_like)
            .filter(|n| {
                !matches!(
                    *n,
                    "localhost" | "localhost.localdomain" | "local" | "broadcasthost"
                )
            })
            .filter_map(normalize)
            .collect::<Vec<_>>()
    })
}

/// Domains named by a plain list, one per line (`#` and `!` start comments; `||x^` adblock style is accepted).
pub fn parse_domains(text: &str) -> impl Iterator<Item = String> + '_ {
    text.lines().filter_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            return None;
        }
        normalize(line.trim_start_matches("||").trim_end_matches('^'))
    })
}

/// Names a list can never block, so a poisoned or careless feed cannot cut off OS updates, the signed
/// catalogue, the advisor, the feeds themselves or code hosting (`docs/23 §4`).
pub const PROTECTED: [&str; 14] = [
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "live.com",
    "msftconnecttest.com",
    "anthropic.com",
    "github.com",
    "githubusercontent.com",
    "workers.dev",
    "circl.lu",
    "abuse.ch",
    "phishing.army",
    "digicert.com",
    "signpath.io",
];

/// The merged, in-memory blocklist plus the user's exceptions.
#[derive(Debug, Default, Clone)]
pub struct Blocklist {
    domains: HashMap<Box<str>, u8>,
    allowed: Vec<String>,
}

impl Blocklist {
    pub fn extend(&mut self, domains: impl IntoIterator<Item = String>, category: Category) {
        for d in domains {
            *self.domains.entry(d.into()).or_insert(0) |= category as u8;
        }
    }

    /// A user exception: the domain and all its subdomains are never blocked.
    pub fn set_allowed(&mut self, allowed: impl IntoIterator<Item = String>) {
        self.allowed = allowed.into_iter().filter_map(|d| normalize(&d)).collect();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// The first enabled category listing `name` or any parent domain; `None` = let it through.
    #[must_use]
    pub fn check(&self, name: &str, enabled: &[Category]) -> Option<Category> {
        let name = normalize(name)?;
        let covered = |d: &str| name == d || name.ends_with(&format!(".{d}"));
        if self.allowed.iter().any(|a| covered(a)) || PROTECTED.iter().any(|p| covered(p)) {
            return None;
        }
        let mask = enabled.iter().fold(0u8, |m, c| m | *c as u8);
        let mut rest = name.as_str();
        loop {
            if let Some(bits) = self.domains.get(rest)
                && let Some(c) = Category::ALL
                    .into_iter()
                    .find(|c| bits & mask & *c as u8 != 0)
            {
                return Some(c);
            }
            match rest.split_once('.') {
                Some((_, parent)) if parent.contains('.') => rest = parent,
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> Blocklist {
        let mut b = Blocklist::default();
        b.extend(
            parse_hosts(
                "# c\n127.0.0.1 localhost\n0.0.0.0 evil.example a.test # x\nnot-an-ip x.test\n",
            ),
            Category::Malware,
        );
        b.extend(
            parse_domains("! c\n||ads.example^\nporn.example\n"),
            Category::Ads,
        );
        b
    }

    #[test]
    fn hosts_and_domain_lists_parse_and_garbage_is_dropped() {
        let b = list();
        assert_eq!(b.len(), 4);
        assert_eq!(normalize("bad name.com"), None);
        assert_eq!(normalize("localhost"), None);
        assert_eq!(normalize("Ex-Ample.COM."), Some("ex-ample.com".into()));
    }

    #[test]
    fn subdomains_match_but_siblings_and_tlds_do_not() {
        let b = list();
        let all = Category::ALL;
        assert_eq!(b.check("cdn.evil.example", &all), Some(Category::Malware));
        assert_eq!(b.check("evil.example", &all), Some(Category::Malware));
        assert_eq!(b.check("notevil.example", &all), None);
        assert_eq!(b.check("example", &all), None);
    }

    #[test]
    fn disabled_categories_and_user_exceptions_let_it_through() {
        let mut b = list();
        assert_eq!(b.check("ads.example", &[Category::Malware]), None);
        assert_eq!(
            b.check("ads.example", &[Category::Ads]),
            Some(Category::Ads)
        );
        b.set_allowed(["evil.example".to_string()]);
        assert_eq!(b.check("x.evil.example", &Category::ALL), None);
        b.extend(["update.microsoft.com".to_string()], Category::Malware);
        assert_eq!(b.check("update.microsoft.com", &Category::ALL), None);
    }
}
