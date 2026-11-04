# 13 — Build, sign and release

**Tóm tắt (VI):** Cách dựng MSI tự chứa, ký, tạo SBOM và kiểm tra chuỗi cung ứng trước khi phát hành.

## 1. Build the MSI

Prerequisites on the **build** machine only (end users need nothing): Rust (stable), Node 22 + pnpm, the WiX CLI (`dotnet tool install --global wix`), and optionally a code-signing certificate.

```powershell
.\installer\build.ps1 -Version 0.1.0            # unsigned
.\installer\build.ps1 -Version 0.1.0 -SignCert <sha1-thumbprint>   # signed
```

Output: `dist\Vigil-<version>.msi` and `dist\Vigil-<version>.msi.sha256`. The binaries link the C runtime statically (`.cargo/config.toml`), so no Visual C++ redistributable is needed. The UI uses the system WebView2 runtime, which ships with Windows 11 and current Windows 10; on an older Windows 10 without it, install the Evergreen runtime once (tracked in `docs/10`).

What the MSI does (`installer/Vigil.wxs`):

- Installs `vigil-svc.exe`, `vigilctl.exe` and `vigil-ui.exe` under `%ProgramFiles%\Vigil`.
- Registers service `VigilSvc` (auto start, LocalSystem, restart on failure) with a DACL that lets only SYSTEM and Administrators control it; every authenticated user may query its status.
- Creates `%ProgramData%\Vigil` with an ACL for SYSTEM and Administrators only (the service re-applies it at start and audits any drift).
- Adds a Start Menu shortcut and a per-machine autostart entry for the UI, which runs as the standard user.
- On uninstall (not on upgrade) runs `vigil-svc.exe --cleanup`, which deletes the persistent WFP filters, sublayer and provider.
- Major upgrades replace the previous version in place; user data in `%ProgramData%\Vigil` is kept.

## 2. Signing

1. Sign `vigil-svc.exe`, `vigilctl.exe`, `vigil-ui.exe`, then the MSI, with SHA-256 and an RFC 3161 timestamp (`build.ps1 -SignCert` does this with `signtool`).
2. Publish the MSI SHA-256 beside the download.
3. After the first signed install run `vigilctl trust bootstrap` (or let the installer record it) so the signer thumbprint becomes the Vigil self-pin (HA-001). Rotate certificates by pinning the new thumbprint before retiring the old one.

Keep the private key in an HSM or a CI secret store; never commit it. An unsigned build is for development only and sets the self-pin from the binary hash when `VIGIL_DEV=1`.

## 3. Supply-chain gates

| Gate | Command | Notes |
|---|---|---|
| Advisories, licences, bans, sources | `cargo deny check` | policy in `deny.toml`; runs in CI |
| RustSec advisories | `cargo audit` | runs in CI |
| SBOM (CycloneDX) | `cargo cyclonedx --format json --all` | one `*.cdx.json` per crate; attached to each release |
| UI dependencies | `pnpm -C apps/ui audit --prod` | run before release |

`cargo xtask check` runs fmt, clippy, tests and, when installed, deny and audit.

## 4. Release checklist

1. `cargo xtask check`, `pnpm -C apps/ui lint && pnpm -C apps/ui test`, and `cargo clippy --manifest-path apps/ui/src-tauri/Cargo.toml --all-targets -- -D warnings` are green.
2. Tag `vN.N.N`; the `release` workflow builds the MSI, checksum and SBOM.
3. Sign the MSI offline or in a protected environment, verify with `signtool verify /pa`.
4. Run the manual VM checks in `docs/11-testing.md` §9–10 on Windows 10 and 11.
5. Publish the GitHub release with MSI, `.sha256` and SBOM.
