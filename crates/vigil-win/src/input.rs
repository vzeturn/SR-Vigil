//! Interactive-session input idle time, for telling a person's launch from an automated one.

use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

/// Seconds since the last keyboard or mouse input; `u64::MAX` when Windows cannot say
/// (so an unknown reading never counts as a human action).
#[must_use]
pub fn idle_secs() -> u64 {
    let mut info = LASTINPUTINFO {
        cbSize: u32::try_from(size_of::<LASTINPUTINFO>()).unwrap_or(0),
        dwTime: 0,
    };
    // SAFETY: `info.cbSize` is set and `info` outlives the call.
    if !unsafe { GetLastInputInfo(&raw mut info) }.as_bool() {
        return u64::MAX;
    }
    // SAFETY: plain Win32 call without arguments.
    let now = unsafe { GetTickCount() };
    u64::from(now.wrapping_sub(info.dwTime)) / 1000
}
