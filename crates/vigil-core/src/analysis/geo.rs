//! Offline IP → country lookup over an embedded table (`data/geo.bin`).
//!
//! Data: DB-IP "IP to Country Lite" (CC BY 4.0, <https://db-ip.com>), compacted by
//! `tools/build-geo.mjs`. Nothing is downloaded or sent anywhere; IPv6 is resolved at /32 granularity.

use std::net::IpAddr;
use std::sync::OnceLock;

static DATA: &[u8] = include_bytes!("../../data/geo.bin");

struct Table {
    v4: &'static [u8],
    v6: &'static [u8],
}

const REC: usize = 6;

fn table() -> Option<&'static Table> {
    static T: OnceLock<Option<Table>> = OnceLock::new();
    T.get_or_init(|| {
        let rest = DATA.strip_prefix(b"VGEO1")?;
        let n4 = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        let v4 = rest.get(4..4 + n4 * REC)?;
        let tail = rest.get(4 + n4 * REC..)?;
        let n6 = u32::from_be_bytes(tail.get(..4)?.try_into().ok()?) as usize;
        let v6 = tail.get(4..4 + n6 * REC)?;
        Some(Table { v4, v6 })
    })
    .as_ref()
}

fn find(recs: &[u8], key: u32) -> Option<String> {
    let (mut lo, mut hi) = (0usize, recs.len() / REC);
    while lo < hi {
        let mid = usize::midpoint(lo, hi);
        let start = u32::from_be_bytes(recs[mid * REC..mid * REC + 4].try_into().ok()?);
        if start <= key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let i = lo.checked_sub(1)?;
    let cc = std::str::from_utf8(&recs[i * REC + 4..i * REC + 6]).ok()?;
    (cc != "??" && cc != "ZZ").then(|| cc.to_owned())
}

/// ISO 3166-1 alpha-2 country code of a public address, or `None` when unknown or non-public.
#[must_use]
pub fn country(ip: IpAddr) -> Option<String> {
    let t = table()?;
    match ip {
        IpAddr::V4(a) => find(t.v4, u32::from(a)),
        IpAddr::V6(a) => find(t.v6, u32::try_from(u128::from(a) >> 96).ok()?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_well_known_addresses() {
        assert_eq!(country("8.8.8.8".parse().unwrap()).as_deref(), Some("US"));
        assert_eq!(country("1.1.1.1".parse().unwrap()).as_deref(), Some("AU"));
        assert!(country("2001:4860:4860::8888".parse().unwrap()).is_some());
    }

    #[test]
    fn private_and_garbage_are_unknown() {
        assert_eq!(country("10.1.2.3".parse().unwrap()), None);
        assert_eq!(country("127.0.0.1".parse().unwrap()), None);
        assert_eq!(country("0.0.0.0".parse().unwrap()), None);
    }
}
