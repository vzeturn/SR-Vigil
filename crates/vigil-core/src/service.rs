//! Services hosted in `svchost.exe` (FR-021, `docs/04 §3`): service SIDs, `ServiceDll` suspicion and
//! which services may have their network blocked. Pure; the SCM and registry reads live in
//! `vigil-win`.

use sha1::{Digest, Sha1};

use crate::analysis::path::{PathEnv, classify, normalize};
use crate::rules::PathClass;

/// `ServiceSidType` values (`SERVICE_SID_TYPE_*`).
pub const SID_TYPE_NONE: u32 = 0;
pub const SID_TYPE_UNRESTRICTED: u32 = 1;
pub const SID_TYPE_RESTRICTED: u32 = 3;

/// Services the machine needs to reach the network at all; Vigil never cuts them off.
pub const NETWORK_ESSENTIAL: [&str; 12] = [
    "bfe",
    "dhcp",
    "dnscache",
    "lanmanworkstation",
    "mpssvc",
    "netprofm",
    "nlasvc",
    "nsi",
    "rpceptmapper",
    "rpcss",
    "wcmsvc",
    "winhttpautoproxysvc",
];

/// A running Win32 service and the process that hosts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedService {
    pub pid: u32,
    /// Service key name (`Dnscache`), as the SCM reports it.
    pub name: String,
    pub display_name: String,
    /// Expanded `ServiceDll` for services that run inside `svchost.exe`.
    pub dll: Option<String>,
    /// `ServiceSidType` from the registry; absent means [`SID_TYPE_NONE`].
    pub sid_type: u32,
    /// Why the `ServiceDll` is suspicious, if it is (see [`dll_suspicion`]).
    pub suspicious: Option<&'static str>,
}

/// Why a service's network cannot be blocked, if it cannot.
#[must_use]
pub fn block_refusal(name: &str, sid_type: u32) -> Option<&'static str> {
    if NETWORK_ESSENTIAL.contains(&name.to_ascii_lowercase().as_str()) {
        Some("protected_target")
    } else if matches!(sid_type, SID_TYPE_UNRESTRICTED | SID_TYPE_RESTRICTED) {
        None
    } else {
        Some("no_service_sid")
    }
}

/// `NT SERVICE\<name>` as a string SID: `S-1-5-80-` followed by the SHA-1 of the upper-cased
/// UTF-16LE name, read as five little-endian sub-authorities.
#[must_use]
pub fn service_sid(name: &str) -> String {
    let utf16: Vec<u8> = name
        .to_uppercase()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = Sha1::digest(&utf16);
    let subs: Vec<String> = digest
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]).to_string())
        .collect();
    format!("S-1-5-80-{}", subs.join("-"))
}

/// A hosted DLL is suspicious when it is not validly signed or lives outside the Windows and
/// Program Files folders (somewhere a non-administrator could replace it).
#[must_use]
pub fn dll_suspicion(dll: &str, signed: bool, env: &PathEnv) -> Option<&'static str> {
    if !signed {
        return Some("unsigned");
    }
    match classify(&normalize(dll), env) {
        PathClass::System | PathClass::ProgramFiles => None,
        _ => Some("writable_location"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> PathEnv {
        PathEnv {
            system_root: r"c:\windows".into(),
            program_files: vec![r"c:\program files".into()],
            user_writable: vec![r"c:\programdata".into()],
            ..PathEnv::default()
        }
    }

    #[test]
    fn service_sid_matches_windows() {
        // `sc showsid TrustedInstaller` on any Windows install.
        assert_eq!(
            service_sid("TrustedInstaller"),
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
        assert_eq!(
            service_sid("trustedinstaller"),
            service_sid("TrustedInstaller")
        );
    }

    #[test]
    fn signed_dll_in_system32_is_fine_anything_else_is_flagged() {
        let e = env();
        assert_eq!(
            dll_suspicion(r"C:\Windows\System32\dnsrslvr.dll", true, &e),
            None
        );
        assert_eq!(
            dll_suspicion(r"C:\Windows\System32\dnsrslvr.dll", false, &e),
            Some("unsigned")
        );
        assert_eq!(
            dll_suspicion(r"C:\ProgramData\x\svc.dll", true, &e),
            Some("writable_location")
        );
    }

    #[test]
    fn only_services_with_their_own_sid_can_be_blocked_and_never_essential_ones() {
        assert_eq!(block_refusal("Spooler", SID_TYPE_UNRESTRICTED), None);
        assert_eq!(block_refusal("Spooler", SID_TYPE_RESTRICTED), None);
        assert_eq!(
            block_refusal("Spooler", SID_TYPE_NONE),
            Some("no_service_sid")
        );
        assert_eq!(
            block_refusal("Dnscache", SID_TYPE_UNRESTRICTED),
            Some("protected_target")
        );
    }
}
