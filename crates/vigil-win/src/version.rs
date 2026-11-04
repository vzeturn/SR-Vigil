//! `VersionInfo` strings of a PE file (company, product, original file name, copyright).

use std::ffi::c_void;

use vigil_core::observe::VersionInfo;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::core::PCWSTR;

use crate::to_wide;

/// Read `VersionInfo`; `None` when the file has no version resource.
#[must_use]
pub fn read(path: &str) -> Option<VersionInfo> {
    let wpath = to_wide(path);
    let file = PCWSTR(wpath.as_ptr());
    let mut handle = 0u32;
    // SAFETY: `file` is a NUL-terminated UTF-16 string that outlives the call.
    let size = unsafe { GetFileVersionInfoSizeW(file, Some(&raw mut handle)) };
    if size == 0 {
        return None;
    }
    let mut data = vec![0u8; size as usize];
    // SAFETY: `data` is writable for `size` bytes, as the API requires.
    unsafe { GetFileVersionInfoW(file, 0, size, data.as_mut_ptr().cast()) }.ok()?;

    let lang = translation(&data).unwrap_or(0x0409_04B0);
    let get = |name: &str| query_string(&data, lang, name);
    Some(VersionInfo {
        company: get("CompanyName"),
        product: get("ProductName"),
        original_filename: get("OriginalFilename"),
        legal_copyright: get("LegalCopyright"),
    })
}

/// First `\VarFileInfo\Translation` entry as `langid << 16 | codepage`.
fn translation(data: &[u8]) -> Option<u32> {
    let sub = to_wide("\\VarFileInfo\\Translation");
    let mut ptr: *mut c_void = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: `data` is a version block from `GetFileVersionInfoW`; `ptr`/`len` are valid out-params.
    let ok = unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            PCWSTR(sub.as_ptr()),
            &raw mut ptr,
            &raw mut len,
        )
    };
    if !ok.as_bool() || len < 4 || ptr.is_null() {
        return None;
    }
    // SAFETY: the API returned a pointer to at least `len >= 4` bytes inside `data`.
    let (lang, code) = unsafe {
        let p = ptr.cast::<u16>();
        (p.read_unaligned(), p.add(1).read_unaligned())
    };
    Some((u32::from(lang) << 16) | u32::from(code))
}

fn query_string(data: &[u8], lang: u32, name: &str) -> String {
    let sub = to_wide(&format!("\\StringFileInfo\\{lang:08X}\\{name}"));
    let mut ptr: *mut c_void = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: as in `translation`.
    let ok = unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            PCWSTR(sub.as_ptr()),
            &raw mut ptr,
            &raw mut len,
        )
    };
    if !ok.as_bool() || len == 0 || ptr.is_null() {
        return String::new();
    }
    // SAFETY: the API returned a pointer to `len` UTF-16 code units inside `data`.
    let units = unsafe { std::slice::from_raw_parts(ptr.cast::<u16>(), len as usize) };
    let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

#[cfg(test)]
mod tests {
    #[test]
    fn notepad_reports_microsoft() {
        let v = super::read("C:\\Windows\\System32\\notepad.exe").expect("version info");
        assert!(v.company.contains("Microsoft"), "{v:?}");
    }
}
