//! Offline destination reputation in the service (`docs/15 §4`): remember which DNS name each
//! program resolved to reach an address (ETW DNS-Client, names only, no packets), assess every
//! public outbound connection, and feed NET-001/NET-002/BEH-001/003/004 back into the verdict.

use std::collections::HashMap;
use std::net::IpAddr;

use serde_json::json;
use vigil_core::analysis::reputation::{self, DestAssessment};
use vigil_core::audit::AuditKind;
use vigil_core::observe::NetSeen;

use crate::state::Shared;
use crate::threat::{is_public, now_ms};

/// A DNS answer is used for this long after it was seen.
const NAME_TTL_MS: u64 = 10 * 60 * 1000;
/// Bounded memory: past this many answers, stale ones are dropped (all of them if none are).
const MAX_NAMES: usize = 16_384;

/// Lives in [`Shared`].
#[derive(Default)]
pub(crate) struct DestRep {
    /// (pid, address) → (name, seen at ms).
    names: HashMap<(u32, IpAddr), (String, u64)>,
    /// Lower-cased image path → findings this run.
    seen: HashMap<String, NetSeen>,
    /// When the DNS feed delivered its first answer; a missing name proves nothing before
    /// [`NAME_TTL_MS`] has passed (earlier answers were cached before Vigil watched).
    dns_since: Option<u64>,
}

impl DestRep {
    fn remember(&mut self, pid: u32, name: &str, addrs: &[IpAddr], at_ms: u64) {
        self.dns_since.get_or_insert(at_ms);
        if self.names.len() + addrs.len() > MAX_NAMES {
            self.names
                .retain(|_, (_, t)| at_ms.saturating_sub(*t) < NAME_TTL_MS);
            if self.names.len() + addrs.len() > MAX_NAMES {
                self.names.clear();
            }
        }
        for a in addrs {
            self.names
                .insert((pid, canonical(*a)), (name.to_owned(), at_ms));
        }
    }

    /// The name `pid` resolved for `ip`, else any program's (a shared resolver answered it).
    fn name_for(&self, pid: u32, ip: IpAddr, at_ms: u64) -> Option<String> {
        let fresh =
            |(n, t): &(String, u64)| (at_ms.saturating_sub(*t) < NAME_TTL_MS).then(|| n.clone());
        self.names.get(&(pid, ip)).and_then(fresh).or_else(|| {
            self.names
                .iter()
                .filter(|((_, a), _)| *a == ip)
                .find_map(|(_, v)| fresh(v))
        })
    }

    fn dns_watched(&self, at_ms: u64) -> bool {
        self.dns_since
            .is_some_and(|s| at_ms.saturating_sub(s) >= NAME_TTL_MS)
    }
}

/// `::ffff:1.2.3.4` → `1.2.3.4`, so IPv4 answers match IPv4 connects.
fn canonical(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(a, IpAddr::V4),
        IpAddr::V4(_) => a,
    }
}

fn lock(m: &std::sync::Mutex<DestRep>) -> std::sync::MutexGuard<'_, DestRep> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Shared {
    /// A DNS answer from ETW: `pid` resolved `name` to `addrs`.
    pub(crate) fn note_dns(&self, pid: u32, name: &str, addrs: &[IpAddr]) {
        self.note_dns_at(pid, name, addrs, now_ms());
    }

    /// [`Self::note_dns`] with an explicit clock (milliseconds since the Unix epoch).
    pub fn note_dns_at(&self, pid: u32, name: &str, addrs: &[IpAddr], at_ms: u64) {
        lock(&self.destrep).remember(pid, name, addrs, at_ms);
    }

    /// Assess one outbound connection. Returns the DNS name and chip label for the Connections
    /// page; a new finding re-evaluates the program and writes an audit row.
    pub(crate) fn assess_destination(
        &self,
        pid: u32,
        ip: &str,
        port: u16,
    ) -> (Option<String>, Option<&'static str>) {
        self.assess_destination_at(pid, ip, port, now_ms())
    }

    /// [`Self::assess_destination`] with an explicit clock.
    pub fn assess_destination_at(
        &self,
        pid: u32,
        ip: &str,
        port: u16,
        at_ms: u64,
    ) -> (Option<String>, Option<&'static str>) {
        let Some(addr) = ip.parse::<IpAddr>().ok().map(canonical) else {
            return (None, None);
        };
        if !is_public(&addr.to_string()) {
            return (None, None);
        }
        let (name, watched) = {
            let g = lock(&self.destrep);
            (g.name_for(pid, addr, at_ms), g.dns_watched(at_ms))
        };
        let mut a = reputation::assess(name.as_deref(), port, watched);
        a.bad |= name.as_deref().is_some_and(crate::dnsfilter::listed_bad);
        if let Some(path) = self.row_by_pid(pid).and_then(|r| r.path) {
            self.absorb_destination(&path, a, name.as_deref(), (ip, port));
        }
        (name, a.label())
    }

    fn absorb_destination(
        &self,
        path: &str,
        a: DestAssessment,
        name: Option<&str>,
        (ip, port): (&str, u16),
    ) {
        let added = lock(&self.destrep)
            .seen
            .entry(path.to_ascii_lowercase())
            .or_default()
            .absorb(&a);
        if !added {
            return;
        }
        self.queue_rejudge(path);
        let signals: Vec<&str> = [
            (a.bad, "NET-001"),
            (a.generated_name, "NET-002"),
            (a.no_dns, "BEH-003"),
            (a.risky_port_or_tld, "BEH-004"),
        ]
        .into_iter()
        .filter_map(|(on, id)| on.then_some(id))
        .collect();
        if !signals.is_empty() {
            self.audit(
                "service",
                AuditKind::Verdict,
                Some(path),
                &json!({ "signals": signals, "dest_ip": ip, "dest_port": port, "dns_name": name }),
            );
        }
    }

    /// Network findings for `path` this run (feeds the rule engine on re-evaluation).
    #[must_use]
    pub fn net_seen(&self, path: &str) -> NetSeen {
        lock(&self.destrep)
            .seen
            .get(&path.to_ascii_lowercase())
            .copied()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_v6_answers_match_v4_connects() {
        let mut d = DestRep::default();
        d.remember(
            7,
            "example.com",
            &["::ffff:93.184.216.34".parse().unwrap()],
            1000,
        );
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(d.name_for(7, ip, 2000).as_deref(), Some("example.com"));
        assert_eq!(d.name_for(9, ip, 2000).as_deref(), Some("example.com"));
        assert_eq!(d.name_for(7, ip, 1000 + NAME_TTL_MS), None);
    }

    #[test]
    fn missing_names_count_only_after_a_full_ttl_of_watching() {
        let mut d = DestRep::default();
        assert!(!d.dns_watched(0));
        d.remember(1, "a.example", &[], 5000);
        assert!(!d.dns_watched(5000 + NAME_TTL_MS - 1));
        assert!(d.dns_watched(5000 + NAME_TTL_MS));
    }

    #[test]
    fn name_map_stays_bounded() {
        let mut d = DestRep::default();
        let addrs: Vec<IpAddr> = (0..=u16::MAX)
            .map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 | u32::from(i))))
            .collect();
        d.remember(1, "x.example", &addrs[..MAX_NAMES], 0);
        d.remember(1, "y.example", &addrs[MAX_NAMES..MAX_NAMES + 10], 1);
        assert!(d.names.len() <= MAX_NAMES);
    }
}
