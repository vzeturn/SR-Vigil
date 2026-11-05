//! Read-only view of the Microsoft Defender Attack Surface Reduction rule settings
//! (`docs/20 §3`). Group Policy / MDM values win over the local `Set-MpPreference` ones, as in Windows.

use vigil_core::posture::AsrState;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

const POLICY: &str =
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
const LOCAL: &str = r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";

/// Stored state of the rule `guid`, from policy first and then local configuration.
#[must_use]
pub fn state(guid: &str) -> AsrState {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for path in [POLICY, LOCAL] {
        let Ok(key) = hklm.open_subkey_with_flags(path, KEY_READ) else {
            continue;
        };
        // Windows writes the value as a string ("1") or a DWORD depending on who set it.
        let v = key
            .get_value::<u32, _>(guid)
            .ok()
            .or_else(|| key.get_value::<String, _>(guid).ok()?.trim().parse().ok());
        if v.is_some() {
            return AsrState::from_value(v);
        }
    }
    AsrState::NotConfigured
}
