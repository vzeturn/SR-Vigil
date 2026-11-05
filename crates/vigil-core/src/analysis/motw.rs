//! Mark of the Web (`docs/20 §2`): the `Zone.Identifier` stream Windows, browsers and mail clients
//! attach to a downloaded file. Only the numeric zone is used; the stream's `HostUrl` and
//! `ReferrerUrl` are untrusted text and are never read, stored or logged.

/// Whether a `Zone.Identifier` stream marks the file as coming from the Internet (zone 3) or a
/// restricted site (zone 4).
#[must_use]
pub fn from_internet(stream: &str) -> bool {
    let mut in_section = false;
    for line in stream.lines().map(str::trim) {
        if line.starts_with('[') {
            in_section = line.eq_ignore_ascii_case("[ZoneTransfer]");
        } else if in_section
            && let Some((key, val)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("ZoneId")
        {
            return matches!(val.trim(), "3" | "4");
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internet_and_restricted_zones_count_and_local_ones_do_not() {
        assert!(from_internet(
            "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://x/\r\n"
        ));
        assert!(from_internet("[ZoneTransfer]\nZoneId=4"));
        for no in [
            "[ZoneTransfer]\nZoneId=2",
            "[ZoneTransfer]\nZoneId=0",
            "",
            "ZoneId=3",
        ] {
            assert!(!from_internet(no), "{no:?}");
        }
    }

    #[test]
    fn a_zone_outside_the_transfer_section_is_ignored() {
        assert!(!from_internet(
            "[Other]\nZoneId=3\n[ZoneTransfer]\nZoneId=1"
        ));
    }
}
