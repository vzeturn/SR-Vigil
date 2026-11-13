# 13 — Build, sign and release

**Tóm tắt (VI):** Cách dựng MSI tự chứa, ký, tạo SBOM và kiểm tra chuỗi cung ứng trước khi phát hành.

## 1. Build the MSI

Prerequisites on the **build** machine only (end users need nothing): Rust (stable), Node 22 + pnpm, the WiX CLI (`dotnet tool install --global wix`), and optionally a code-signing certificate.

```powershell
.\installer\build.ps1 -Version 1.0.0            # unsigned
.\installer\build.ps1 -Version 1.0.0 -SignCert <sha1-thumbprint>   # signed
.\installer\build.ps1 -Version 1.0.0 -Arch arm64   # Windows on ARM (cross-compiled)
```

Output: `dist\Vigil-<version>.msi` and `dist\Vigil-<version>.msi.sha256` (x64), or `dist\Vigil-<version>-arm64.msi` and its `.sha256` for `-Arch arm64`; binaries are staged in `dist\bin\<arch>`. The ARM64 build cross-compiles on an x64 host and needs the MSVC ARM64 build tools and clang (for `ring`); the GitHub `windows-latest` image has both. The binaries link the C runtime statically (`.cargo/config.toml`), so no Visual C++ redistributable is needed. The UI uses the system WebView2 runtime, which ships with Windows 11 and current Windows 10. For older systems the script downloads Microsoft's Evergreen bootstrapper once into `dist\cache` and refuses it unless its Authenticode signature is valid and from Microsoft Corporation; the MSI embeds it.

What the MSI does (`installer/Vigil.wxs`):

- Installs `vigil-svc.exe`, `vigilctl.exe` and `vigil-ui.exe` under `%ProgramFiles%\Vigil`.
- Registers service `VigilSvc` (auto start, LocalSystem, restart on failure) with a DACL that lets only SYSTEM and Administrators control it; every authenticated user may query its status.
- Creates `%ProgramData%\Vigil` with an ACL for SYSTEM and Administrators only (the service re-applies it at start and audits any drift).
- Adds a Start Menu shortcut and a per-machine autostart entry for the UI, which runs as the standard user.
- Runs the embedded WebView2 bootstrapper (`/silent /install`) only when neither the machine nor the installing user has the runtime registered (`EdgeUpdate\Clients\{F3017226-…}` value `pv` missing or `0.0.0.0`). The bootstrapper downloads the runtime from Microsoft; this happens at install time, inside Microsoft's installer, not in Vigil. If it fails (for example offline) the install still succeeds: the service protects without the UI, and running the MSI again (repair) retries.
- On uninstall (not on upgrade) runs `vigil-svc.exe --cleanup`, which deletes the persistent WFP filters, sublayer and provider.
- Major upgrades replace the previous version in place; user data in `%ProgramData%\Vigil` is kept.

## 2. Signing

1. Sign `vigil-svc.exe`, `vigilctl.exe`, `vigil-ui.exe`, then the MSI, with SHA-256 and an RFC 3161 timestamp (`build.ps1 -SignCert` does this with `signtool`).
2. Publish the MSI SHA-256 beside the download.
3. Nothing to record for HA-001: each Vigil process pins the SHA-256 of the installed binaries itself (`docs/03`).

Keep the private key in an HSM or a CI secret store; never commit it. An unsigned build still self-pins by hash, but Windows SmartScreen will warn on it.

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

## 5. Version catalogue (M12)

- The client's catalogue endpoint defaults to the project Worker; set the repository variable `VIGIL_CATALOGUE_URL` to override it at build time.
- The Worker (`catalogue/`) is deployed separately with `wrangler deploy`; secrets and key rotation are in `catalogue/README.md`. CI runs its tests (`catalogue-tests` job).
- Release gate: before tagging, `curl` the endpoint and confirm the envelope verifies with the key in `rules/catalogue_keys.toml`.
