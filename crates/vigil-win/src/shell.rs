//! Open a vendor download page in the default browser (`docs/16 §5`).

use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, w};

use crate::to_wide;

/// Open `url` with the user's default browser. Only links accepted by
/// [`vigil_core::analysis::catalogue::safe_link`] are handed to the shell, so a file path, a
/// non-HTTPS scheme or an argument-shaped string can never reach `ShellExecuteW`.
///
/// Returns `false` when the link is refused or the shell reports a failure.
#[must_use]
pub fn open_vendor_page(url: &str) -> bool {
    let Some(url) = vigil_core::analysis::catalogue::safe_link(url) else {
        return false;
    };
    let wide = to_wide(url);
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the call; the operation is a
    // static wide literal, the other string arguments are null, and no window handle is passed.
    let code = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute returns a value greater than 32 on success.
    code.0 as isize > 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_links_never_reach_the_shell() {
        assert!(!open_vendor_page(r"C:\Windows\System32\calc.exe"));
        assert!(!open_vendor_page("http://example.com/"));
        assert!(!open_vendor_page("https://example.com/\" --x"));
    }
}
