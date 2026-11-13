//! Writes audit rows to the Windows Application log (`docs/09 §4.1`).
//!
//! The source's message file is `EventCreate.exe`, whose message table maps ids 1..=1000 to `%1`,
//! so the single insertion string is shown as-is and needs no custom message DLL.

use vigil_core::audit_export::{Event, Level, SOURCE};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, RegisterEventSourceW,
    ReportEventW,
};
use windows::core::{PCWSTR, PSTR};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, RegType};

use crate::{Error, to_wide};

const KEY: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application\Vigil";
const MESSAGE_FILE: &str = r"%SystemRoot%\System32\EventCreate.exe";
/// Error, warning and information.
const TYPES_SUPPORTED: u32 = 7;

/// Registers the `Vigil` source if it is missing or points elsewhere (needs admin; the installer
/// does the same so a non-elevated run still has it).
pub fn ensure_source() -> Result<(), Error> {
    let (key, _) = RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey(KEY)?;
    let current: Option<String> = key.get_value("EventMessageFile").ok();
    if current.as_deref() != Some(MESSAGE_FILE) {
        let raw = winreg::RegValue {
            bytes: to_wide(MESSAGE_FILE)
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect(),
            vtype: RegType::REG_EXPAND_SZ,
        };
        key.set_raw_value("EventMessageFile", &raw)?;
    }
    key.set_value("TypesSupported", &TYPES_SUPPORTED)?;
    Ok(())
}

/// An open event source handle, closed on drop.
pub struct EventLog(HANDLE);

// SAFETY: an event source handle may be used from any thread; `ReportEventW` is thread-safe.
unsafe impl Send for EventLog {}
// SAFETY: see above; `report` only passes the handle to `ReportEventW`.
unsafe impl Sync for EventLog {}

impl EventLog {
    /// Opens the local `Vigil` source.
    pub fn open() -> Result<Self, Error> {
        let name = to_wide(SOURCE);
        // SAFETY: `name` is a NUL-terminated UTF-16 buffer that outlives the call; a null server
        // name means the local machine.
        let h = unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(name.as_ptr())) }?;
        Ok(Self(h))
    }

    /// Writes one event. The text is passed as the only insertion string, never as a format.
    pub fn report(&self, event: &Event) -> Result<(), Error> {
        let text = to_wide(&event.text);
        let strings = [PCWSTR(text.as_ptr())];
        let kind = match event.level {
            Level::Information => EVENTLOG_INFORMATION_TYPE,
            Level::Warning => EVENTLOG_WARNING_TYPE,
        };
        // SAFETY: the handle is open for the lifetime of `self`; `strings` points at one
        // NUL-terminated buffer (`text`) that outlives the call; no SID and no raw data.
        unsafe {
            ReportEventW(
                self.0,
                kind,
                0,
                event.id,
                windows::Win32::Security::PSID(PSTR::null().0.cast()),
                0,
                Some(&strings),
                None,
            )
        }?;
        Ok(())
    }
}

impl Drop for EventLog {
    fn drop(&mut self) {
        // SAFETY: the handle came from `RegisterEventSourceW` and is closed exactly once here.
        let _ = unsafe { DeregisterEventSource(self.0) };
    }
}

#[cfg(all(test, feature = "integration"))]
mod tests {
    use super::*;
    use vigil_core::audit::{AuditEntry, AuditKind};
    use vigil_core::audit_export::event;

    #[test]
    fn writes_one_event_to_the_application_log() {
        ensure_source().expect("register source (elevated shell)");
        let log = EventLog::open().unwrap();
        let row = AuditEntry {
            seq: 0,
            ts: "2026-01-01T00:00:00Z".into(),
            actor: "integration_test".into(),
            kind: AuditKind::Health,
            target: Some("C:/t/%1%%2.exe".into()),
            details: serde_json::json!({}),
            prev_hash: [0; 32],
            hash: [0; 32],
        };
        let e = event(&row);
        assert!(!e.text.contains('%'));
        log.report(&e).unwrap();
    }
}
