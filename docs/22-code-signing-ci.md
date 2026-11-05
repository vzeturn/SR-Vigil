# 22 — Signing Vigil's own binaries

Vigil judges others by signature, so its own `vigil-svc.exe`, `vigilctl.exe`, `vigil-ui.exe` and the MSI must carry a public Authenticode signature. Without one, SmartScreen and antivirus engines score the release low and Vigil's own HA-001 pin falls back to the dev-only hash path (`docs/13 §2`).

## 1. Pipeline (`.github/workflows/release.yml`)

`build` compiles and stages `dist/bin` (`build.ps1 -Stage build`), `sign` submits the three executables to SignPath, `msi` downloads the signed set, packages it (`-Stage package`) and verifies every executable with `Get-AuthenticodeSignature` (fails unless `Valid`). The MSI itself is signed by the same policy in a follow-up request once the project is approved. The `sign` job is skipped while the repository variable `SIGNPATH_ORGANIZATION_ID` is unset, so releases remain possible but unsigned and are labelled as such.

Local or alternative-CA signing is unchanged: `build.ps1 -SignCert <thumbprint>` (`docs/13`).

## 2. Choosing the signer

| Option | Cost | Fits Vigil because |
|---|---|---|
| SignPath Foundation | free for OSI-licensed public projects | MIT/Apache, public repo; signing key never leaves SignPath |
| Certum Open Source certificate | low yearly fee | individual maintainers; key on a token or cloud HSM |
| Azure Trusted Signing | monthly fee | easy CI; identity validation depends on country and entity type |
| OV or EV certificate | high yearly fee, hardware key | commercial distribution; EV no longer bypasses SmartScreen instantly |

Prices and eligibility change: verify on the provider's site before applying. Self-signed certificates give no trust and are not an option.

## 3. One-time owner steps (cannot be automated)

1. Apply to SignPath Foundation for the `vigil` project; create the `release-signing` policy with origin verification set to this GitHub repository.
2. Add repository variable `SIGNPATH_ORGANIZATION_ID` and secret `SIGNPATH_API_TOKEN`.
3. Tag `vX.Y.Z`; confirm the `msi` job passes the signature check.
4. Submit the signed MSI to the Microsoft Defender Security Intelligence portal to build reputation.
5. Run `vigilctl trust bootstrap` after the first signed install so the signer thumbprint becomes the Vigil self-pin (HA-001). Pin the new certificate before retiring an old one.

Keys and tokens live only in the provider and the CI secret store, never in the repository (`CLAUDE.md` rule 7 spirit, `STANDARDS §4`).
