//! Running Win32 services and their host processes (FR-021): the SCM gives PID → service, the
//! registry gives each service's `ServiceDll` and `ServiceSidType`.

use std::collections::HashMap;

use vigil_core::analysis::path::{PathEnv, expand};
use vigil_core::service::{HostedService, SID_TYPE_NONE, dll_suspicion};
use windows::Win32::Foundation::ERROR_MORE_DATA;
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};
use windows::core::PCWSTR;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

/// SCM handle closed on drop.
struct Scm(SC_HANDLE);

impl Drop for Scm {
    fn drop(&mut self) {
        // SAFETY: the handle came from `OpenSCManagerW` and is closed exactly once.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

/// `(pid, name, display name)` of every running Win32 service. Empty when the SCM refuses.
fn running() -> Vec<(u32, String, String)> {
    // SAFETY: null machine/database names select the local active database.
    let Ok(h) =
        (unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) })
    else {
        return Vec::new();
    };
    let scm = Scm(h);
    let mut buf: Vec<u64> = vec![0; 8 * 1024];
    let (mut needed, mut count) = (0u32, 0u32);
    loop {
        let bytes = buf.len() * 8;
        // SAFETY: the u64 buffer is 8-aligned (enough for the pointer-bearing records) and
        // `bytes` long; out pointers are valid locals; no resume handle (one full call).
        let rc = unsafe {
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                Some(std::slice::from_raw_parts_mut(
                    buf.as_mut_ptr().cast::<u8>(),
                    bytes,
                )),
                &raw mut needed,
                &raw mut count,
                None,
                PCWSTR::null(),
            )
        };
        match rc {
            Ok(()) => break,
            Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() && needed as usize > bytes => {
                buf = vec![0; (needed as usize).div_ceil(8) + 64];
            }
            Err(e) => {
                tracing::debug!(error = %e, "service enumeration failed");
                return Vec::new();
            }
        }
    }
    // SAFETY: on success the buffer starts with `count` records whose strings point into it.
    let records = unsafe {
        std::slice::from_raw_parts(
            buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
            count as usize,
        )
    };
    records
        .iter()
        .map(|r| {
            // SAFETY: SCM-provided NUL-terminated strings inside `buf`, which is still alive.
            let s = |p: windows::core::PWSTR| unsafe { p.to_string() }.unwrap_or_default();
            (
                r.ServiceStatusProcess.dwProcessId,
                s(r.lpServiceName),
                s(r.lpDisplayName),
            )
        })
        .collect()
}

/// `ServiceDll` (expanded) and `ServiceSidType` of one service.
fn registry_facts(name: &str, vars: &HashMap<String, String>) -> (Option<String>, u32) {
    let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(format!(r"{SERVICES}\{name}"), KEY_READ)
    else {
        return (None, SID_TYPE_NONE);
    };
    let sid_type = k
        .get_value::<u32, _>("ServiceSidType")
        .unwrap_or(SID_TYPE_NONE);
    let dll = k
        .open_subkey_with_flags("Parameters", KEY_READ)
        .and_then(|p| p.get_value::<String, _>("ServiceDll"))
        .or_else(|_| k.get_value::<String, _>("ServiceDll"))
        .ok()
        .filter(|d| !d.trim().is_empty())
        .map(|d| expand(d.trim(), vars));
    (dll, sid_type)
}

/// Running services with their DLL, SID type and DLL suspicion. `signed` answers (and may cache)
/// whether a DLL carries a valid signature.
pub fn hosted(env: &PathEnv, signed: &mut dyn FnMut(&str) -> bool) -> Vec<HostedService> {
    let vars: HashMap<String, String> = std::env::vars()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect();
    running()
        .into_iter()
        .map(|(pid, name, display_name)| {
            let (dll, sid_type) = registry_facts(&name, &vars);
            let suspicious = dll
                .as_deref()
                .and_then(|d| dll_suspicion(d, signed(d), env));
            HostedService {
                pid,
                name,
                display_name,
                dll,
                sid_type,
                suspicious,
            }
        })
        .collect()
}

/// Whether `path` carries a valid embedded or catalog signature.
#[must_use]
pub fn is_signed(path: &str) -> bool {
    crate::trust::verify(path).valid()
}

#[cfg(all(test, feature = "integration"))]
mod tests {
    use super::*;

    #[test]
    fn dnscache_runs_from_a_signed_system_dll_with_its_own_sid() {
        let env = crate::observe::env_context().unwrap().path_env;
        let all = hosted(&env, &mut is_signed);
        let dns = all
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("Dnscache"))
            .expect("Dnscache runs on every Windows");
        assert!(dns.pid > 0);
        assert!(
            dns.dll
                .as_deref()
                .is_some_and(|d| d.to_lowercase().ends_with("dnsrslvr.dll"))
        );
        assert_eq!(dns.suspicious, None);
        assert_ne!(dns.sid_type, SID_TYPE_NONE);
    }
}
