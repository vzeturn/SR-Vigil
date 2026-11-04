//! Authenticode and catalog signature verification (`docs/03 §5`, step 5).
//!
//! Revocation is checked against the local cache only (`WTD_CACHE_ONLY_URL_RETRIEVAL`), so a scan
//! never touches the network; an online refresh is a separate, later step.

use std::ffi::c_void;
use std::fmt::Write as _;
use std::os::windows::io::AsRawHandle;

use vigil_core::observe::SignerInfo;
use vigil_core::rules::SignatureState;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_NAME_ATTR_TYPE, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_SHA1_HASH_PROP_ID,
    CertGetCertificateContextProperty, CertGetNameStringW,
};
use windows::Win32::Security::WinTrust::{
    CRYPT_PROVIDER_DATA, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::core::{PCWSTR, w};

use crate::to_wide;

const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const CERT_E_CHAINING: u32 = 0x800B_010A;
const CERT_E_REVOKED: u32 = 0x800B_010C;
const CRYPT_E_NO_REVOCATION_CHECK: u32 = 0x8009_2012;
const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;
const ORG_OID: &[u8] = b"2.5.4.10\0";

/// What the signature itself says, before any catalog fallback.
enum Outcome {
    /// Signed and verified (revocation status unknown counts as valid).
    Valid(Chain),
    /// Not signed (or an unsupported file type): try the catalogs.
    NoSignature,
    Bad(SignatureState, Chain),
}

/// Certificates of the signer chain, leaf first.
#[derive(Default)]
struct Chain {
    names: Vec<String>,
    thumbprints: Vec<String>,
    leaf_org: Option<String>,
}

/// Verify `path` and describe its signer. Never fails: problems map to `Invalid` or `Unsigned`.
#[must_use]
pub fn verify(path: &str) -> SignerInfo {
    match verify_embedded(path) {
        Outcome::Valid(c) => info(SignatureState::ValidEmbedded, &c, false),
        Outcome::Bad(s, c) => info(s, &c, false),
        Outcome::NoSignature => match verify_catalog(path) {
            Some(Outcome::Valid(c)) => info(SignatureState::ValidCatalog, &c, true),
            Some(Outcome::Bad(s, c)) => info(s, &c, true),
            _ => crate::msix::signer(path).unwrap_or_else(SignerInfo::unsigned),
        },
    }
}

fn info(state: SignatureState, c: &Chain, catalog: bool) -> SignerInfo {
    let ms_root = c.names.last().is_some_and(|n| n.contains("Microsoft Root"));
    let leaf = c.names.first().map_or("", String::as_str);
    let valid = matches!(
        state,
        SignatureState::ValidEmbedded | SignatureState::ValidCatalog
    );
    SignerInfo {
        state,
        org: c.leaf_org.clone(),
        chain_names: c.names.clone(),
        thumbprints: c.thumbprints.clone(),
        ms_root,
        os_signed: valid && ms_root && (catalog || leaf.starts_with("Microsoft Windows")),
    }
}

fn classify(code: u32) -> Option<SignatureState> {
    match code {
        0 | CRYPT_E_NO_REVOCATION_CHECK | CRYPT_E_REVOCATION_OFFLINE => None,
        CERT_E_EXPIRED => Some(SignatureState::Expired),
        CERT_E_REVOKED => Some(SignatureState::Revoked),
        CERT_E_UNTRUSTEDROOT | CERT_E_CHAINING => Some(SignatureState::UntrustedRoot),
        _ => Some(SignatureState::Invalid),
    }
}

fn base_data(revocation: bool) -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: u32::try_from(size_of::<WINTRUST_DATA>()).unwrap_or(0),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: if revocation {
            WTD_REVOKE_WHOLECHAIN
        } else {
            WTD_REVOKE_NONE
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    }
}

/// Run `WinVerifyTrust` with state, read the chain, then always close the state.
fn run(data: &mut WINTRUST_DATA) -> (u32, Chain) {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` is fully initialised, its union member points at live structs owned by the
    // caller, and `action` is a valid GUID; the state opened here is closed below.
    let hresult = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &raw mut action,
            std::ptr::from_mut(data).cast::<c_void>(),
        )
    };
    // HRESULTs are compared by bit pattern.
    let code = u32::from_ne_bytes(hresult.to_ne_bytes());
    let chain = extract_chain(data.hWVTStateData);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closes the state opened above with the same data block.
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            &raw mut action,
            std::ptr::from_mut(data).cast::<c_void>(),
        );
    }
    (code, chain)
}

fn verify_embedded(path: &str) -> Outcome {
    let wide = to_wide(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>()).unwrap_or(0),
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };
    let mut data = base_data(true);
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 {
        pFile: &raw mut file,
    };
    let (code, chain) = run(&mut data);
    match code {
        TRUST_E_NOSIGNATURE | TRUST_E_PROVIDER_UNKNOWN | TRUST_E_SUBJECT_FORM_UNKNOWN => {
            Outcome::NoSignature
        }
        c => classify(c).map_or(Outcome::Valid(chain), |s| Outcome::Bad(s, Chain::default())),
    }
}

/// Owns a catalog-admin context.
struct CatAdmin(isize);

impl Drop for CatAdmin {
    fn drop(&mut self) {
        // SAFETY: the context came from `CryptCATAdminAcquireContext2` and is released once.
        let _ = unsafe { CryptCATAdminReleaseContext(self.0, 0) };
    }
}

fn verify_catalog(path: &str) -> Option<Outcome> {
    let file = std::fs::File::open(path).ok()?;
    let hfile = HANDLE(file.as_raw_handle());
    for algo in [w!("SHA256"), w!("SHA1")] {
        let mut raw = 0isize;
        // SAFETY: `raw` is a valid out-pointer; the algorithm name is a static wide string.
        unsafe { CryptCATAdminAcquireContext2(&raw mut raw, None, algo, None, 0) }.ok()?;
        let admin = CatAdmin(raw);

        let mut len = 0u32;
        // SAFETY: first call only queries the hash length; `hfile` is a live file handle.
        unsafe { CryptCATAdminCalcHashFromFileHandle2(admin.0, hfile, &raw mut len, None, 0) }
            .ok()?;
        let mut hash = vec![0u8; len as usize];
        // SAFETY: `hash` is writable for `len` bytes.
        unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin.0,
                hfile,
                &raw mut len,
                Some(hash.as_mut_ptr()),
                0,
            )
        }
        .ok()?;
        hash.truncate(len as usize);

        // SAFETY: `hash` is a valid slice; a null previous-catalog starts the enumeration.
        let cat = unsafe { CryptCATAdminEnumCatalogFromHash(admin.0, &hash, 0, None) };
        if cat == 0 {
            continue;
        }
        let mut cinfo = CATALOG_INFO {
            cbStruct: u32::try_from(size_of::<CATALOG_INFO>()).unwrap_or(0),
            wszCatalogFile: [0; 260],
        };
        // SAFETY: `cat` is a catalog handle from the call above; `cinfo` is initialised.
        let got = unsafe { CryptCATCatalogInfoFromContext(cat, &raw mut cinfo, 0) };
        let outcome = got.ok().map(|()| {
            let tag = to_wide(&hex(&hash));
            let wpath = to_wide(path);
            let mut ci = WINTRUST_CATALOG_INFO {
                cbStruct: u32::try_from(size_of::<WINTRUST_CATALOG_INFO>()).unwrap_or(0),
                pcwszCatalogFilePath: PCWSTR(cinfo.wszCatalogFile.as_ptr()),
                pcwszMemberTag: PCWSTR(tag.as_ptr()),
                pcwszMemberFilePath: PCWSTR(wpath.as_ptr()),
                hMemberFile: hfile,
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: len,
                hCatAdmin: admin.0,
                ..Default::default()
            };
            let mut data = base_data(true);
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.Anonymous = WINTRUST_DATA_0 {
                pCatalog: &raw mut ci,
            };
            let (code, chain) = run(&mut data);
            classify(code).map_or(Outcome::Valid(chain), |s| Outcome::Bad(s, Chain::default()))
        });
        // SAFETY: releases the catalog handle obtained from the enumeration above.
        let _ = unsafe { CryptCATAdminReleaseCatalogContext(admin.0, cat, 0) };
        if outcome.is_some() {
            return outcome;
        }
    }
    None
}

fn extract_chain(state: HANDLE) -> Chain {
    // SAFETY: `state` is the state handle of a just-completed `WinVerifyTrust` call.
    let prov: *mut CRYPT_PROVIDER_DATA = unsafe { WTHelperProvDataFromStateData(state) };
    if prov.is_null() {
        return Chain::default();
    }
    // SAFETY: `prov` is non-null provider data owned by the open state.
    let sgnr = unsafe { WTHelperGetProvSignerFromChain(prov, 0, false, 0) };
    if sgnr.is_null() {
        return Chain::default();
    }
    // SAFETY: `sgnr` is non-null and valid while the state is open.
    let count = unsafe { (*sgnr).csCertChain };
    let mut chain = Chain::default();
    for i in 0..count {
        // SAFETY: `i < csCertChain`, so the helper returns a valid element or null.
        let pc = unsafe { WTHelperGetProvCertFromChain(sgnr, i) };
        if pc.is_null() {
            break;
        }
        // SAFETY: `pc` is non-null; `pCert` is a certificate context kept alive by the state.
        let ctx = unsafe { (*pc).pCert };
        if ctx.is_null() {
            break;
        }
        chain
            .names
            .push(cert_name(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, None));
        chain.thumbprints.push(thumbprint(ctx));
        if i == 0 {
            let org = cert_name(ctx, CERT_NAME_ATTR_TYPE, Some(ORG_OID.as_ptr().cast()));
            chain.leaf_org = (!org.is_empty()).then_some(org);
        }
    }
    chain
}

fn cert_name(ctx: *const CERT_CONTEXT, kind: u32, para: Option<*const c_void>) -> String {
    let mut buf = vec![0u16; 512];
    // SAFETY: `ctx` is a live certificate context; `buf` is writable; `para` is either `None` or a
    // NUL-terminated OID string that outlives the call.
    let n = unsafe { CertGetNameStringW(ctx, kind, 0, para, Some(&mut buf)) } as usize;
    let end = n.saturating_sub(1).min(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn thumbprint(ctx: *const CERT_CONTEXT) -> String {
    let mut buf = [0u8; 20];
    let mut len = 20u32;
    // SAFETY: `buf` has room for the 20-byte SHA-1 property and `len` says so.
    let ok = unsafe {
        CertGetCertificateContextProperty(
            ctx,
            CERT_SHA1_HASH_PROP_ID,
            Some(buf.as_mut_ptr().cast()),
            &raw mut len,
        )
    };
    if ok.is_err() {
        return String::new();
    }
    hex(&buf[..len as usize])
}

/// Upper-case hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02X}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM_DIR: &str = "C:\\Windows\\System32";

    #[test]
    fn embedded_microsoft_signature_is_valid_with_ms_root() {
        let s = verify(&format!("{SYSTEM_DIR}\\notepad.exe"));
        assert!(
            matches!(
                s.state,
                SignatureState::ValidEmbedded | SignatureState::ValidCatalog
            ),
            "{:?}",
            s.state
        );
        assert!(s.ms_root, "{:?}", s.chain_names);
        assert!(s.org.as_deref().is_some_and(|o| o.contains("Microsoft")));
        assert_ne!(s.thumbprints, [] as [std::string::String; 0]);
    }

    #[test]
    fn catalog_signed_system_binary_is_valid() {
        let s = verify(&format!("{SYSTEM_DIR}\\kernel32.dll"));
        assert!(
            matches!(
                s.state,
                SignatureState::ValidEmbedded | SignatureState::ValidCatalog
            ),
            "{:?}",
            s.state
        );
        assert!(s.os_signed);
    }

    #[test]
    fn unsigned_file_is_unsigned_and_tampering_is_not_valid() {
        let dir = std::env::temp_dir().join(format!("vigil-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("plain.exe");
        std::fs::write(&plain, b"MZ not really a pe").unwrap();
        assert_eq!(
            verify(&plain.to_string_lossy()).state,
            SignatureState::Unsigned
        );

        let tampered = dir.join("notepad.exe");
        let mut bytes = std::fs::read(format!("{SYSTEM_DIR}\\notepad.exe")).unwrap();
        let last = bytes.len() / 2;
        bytes[last] ^= 0xFF;
        std::fs::write(&tampered, bytes).unwrap();
        let s = verify(&tampered.to_string_lossy());
        assert!(
            !matches!(
                s.state,
                SignatureState::ValidEmbedded | SignatureState::ValidCatalog
            ),
            "tampered file must not verify: {:?}",
            s.state
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
