//! Trust path for MSIX/Store apps (`docs/10` M1 known gap).
//!
//! Files under `%ProgramFiles%\WindowsApps\<package>\` carry no embedded Authenticode signature; the
//! signature lives in the package's `AppxSignature.p7x`. The folder is writable only by
//! `TrustedInstaller`, and the package manager refuses to install a package whose signature does not
//! verify. So a file there, in a package that has `AppxSignature.p7x`, is package-signed, and the
//! publisher is the `Publisher` of the (equally protected) `AppxManifest.xml`.

use std::path::{Path, PathBuf};

use vigil_core::observe::SignerInfo;
use vigil_core::rules::SignatureState;

const MANIFEST_LIMIT: u64 = 1 << 20;

/// Package root (`...\WindowsApps\<package>`) of `path`, if it lies in a signed package.
fn package_root(path: &str) -> Option<PathBuf> {
    let p = Path::new(path);
    let mut root = PathBuf::new();
    let mut comps = p.components();
    for c in comps.by_ref() {
        root.push(c);
        if c.as_os_str().eq_ignore_ascii_case("WindowsApps") {
            break;
        }
    }
    root.push(comps.next()?);
    (root != p && root.join("AppxSignature.p7x").is_file()).then_some(root)
}

/// Value of the `Publisher` attribute of the first `<Identity>` element.
fn publisher(manifest: &str) -> Option<&str> {
    let identity = &manifest[manifest.find("<Identity")?..];
    let tag = &identity[..identity.find('>')?];
    let rest = &tag[tag.find("Publisher=\"")? + "Publisher=\"".len()..];
    Some(&rest[..rest.find('"')?])
}

/// Organisation (`O=`) of a distinguished name such as `CN=Microsoft Corporation, O=Microsoft Corporation`.
fn organisation(dn: &str) -> Option<String> {
    dn.split(", ")
        .find_map(|part| part.strip_prefix("O="))
        .or_else(|| dn.split(", ").find_map(|part| part.strip_prefix("CN=")))
        .map(|s| s.trim_matches('"').to_owned())
}

/// Signer of a file inside a signed MSIX package, or `None` when it is not one.
#[must_use]
pub fn signer(path: &str) -> Option<SignerInfo> {
    let root = package_root(path)?;
    let manifest = root.join("AppxManifest.xml");
    if std::fs::metadata(&manifest).ok()?.len() > MANIFEST_LIMIT {
        return None;
    }
    let text = std::fs::read_to_string(manifest).ok()?;
    let dn = publisher(&text)?;
    let org = organisation(dn)?;
    let microsoft = org == "Microsoft Corporation";
    Some(SignerInfo {
        state: SignatureState::ValidCatalog,
        org: Some(org),
        chain_names: vec![dn.to_owned()],
        thumbprints: Vec::new(),
        ms_root: microsoft,
        os_signed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_publisher_and_organisation() {
        let xml = r#"<?xml version="1.0"?><Package><Identity Name="n" Publisher="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond" Version="1"/></Package>"#;
        let dn = publisher(xml).unwrap();
        assert_eq!(organisation(dn).as_deref(), Some("Microsoft Corporation"));
        assert_eq!(publisher("<Package/>"), None);
        assert_eq!(organisation("CN=Solo App").as_deref(), Some("Solo App"));
    }

    #[test]
    fn only_signed_packages_in_windowsapps_qualify() {
        assert!(signer(r"C:\Temp\evil.exe").is_none());
        assert!(signer(r"C:\Program Files\WindowsApps").is_none());
        assert!(signer(r"C:\Program Files\WindowsApps\NoSuchPackage_1\a.exe").is_none());
    }
}
