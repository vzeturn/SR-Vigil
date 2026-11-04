//! DPAPI wrappers (machine scope + caller-supplied entropy) for the stored API key.

use std::ptr::null;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    CryptUnprotectData,
};
use windows::core::PCWSTR;

use crate::Error;

fn blob(b: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(b.len()).unwrap_or(u32::MAX),
        pbData: b.as_ptr().cast_mut(),
    }
}

fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: on success DPAPI returns a LocalAlloc'd buffer of `cbData` bytes at `pbData`; we
    // copy it out and release it exactly once.
    unsafe {
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out.pbData.cast()));
        v
    }
}

/// Encrypt `plain` for this machine; `entropy` must be supplied again to decrypt.
pub fn protect(plain: &[u8], entropy: &[u8]) -> Result<Vec<u8>, Error> {
    let (input, ent) = (blob(plain), blob(entropy));
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input`/`ent` borrow live slices for the call; `out` is a valid out-pointer and
    // its buffer is freed in `take`.
    unsafe {
        CryptProtectData(
            &raw const input,
            PCWSTR::null(),
            Some(&raw const ent),
            Some(null()),
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out,
        )?;
    }
    Ok(take(out))
}

/// Decrypt data produced by [`protect`] with the same `entropy`.
pub fn unprotect(cipher: &[u8], entropy: &[u8]) -> Result<Vec<u8>, Error> {
    let (input, ent) = (blob(cipher), blob(entropy));
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`; the description out-pointer is not requested.
    unsafe {
        CryptUnprotectData(
            &raw const input,
            None,
            Some(&raw const ent),
            Some(null()),
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out,
        )?;
    }
    Ok(take(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_needs_the_same_entropy() {
        let c = protect(b"secret-value", b"entropy-1").unwrap();
        assert!(!c.windows(12).any(|w| w == b"secret-value"));
        assert_eq!(unprotect(&c, b"entropy-1").unwrap(), b"secret-value");
        assert!(unprotect(&c, b"entropy-2").is_err());
    }
}
