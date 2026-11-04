# 08 — Threat model and compliance mapping

**Tóm tắt (VI):** Vigil bảo vệ ở user-mode nên có giới hạn rõ ràng. Tài liệu liệt kê tài sản, đối thủ, biện pháp giảm thiểu, rủi ro còn lại và ánh xạ sang các điều khoản kiểm soát ISO/IEC 27001:2022 để dùng làm bằng chứng kiểm toán.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Verdict/decision integrity | A wrongly Safe malware or wrongly blocked system component causes harm. |
| Enforcement state (WFP filters, block records) | Tampering silently disables protection. |
| Anthropic/VirusTotal API keys | Financial and abuse risk. |
| Audit log | Evidence; must be tamper-evident. |
| Host telemetry | May contain sensitive paths/destinations. |

## 2. Adversaries

| Tier | Capability |
|---|---|
| A1 | Standard-user malware (no admin), drops payload in user paths, abuses LOLBins. |
| A2 | Admin-level malware/attacker on the host. |
| A3 | Supply chain: trojanised signed software or stolen code-signing certificate. |
| A4 | Malicious or careless local user clicking "Allow". |
| A5 | Prompt-injection author controlling process names, paths, DNS names. |
| A6 | Kernel-mode malware/rootkit (out of scope). |

## 3. Threats and mitigations (STRIDE-oriented)

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | Spoofing: binary named like a system process | HR-002/HR-003, typosquat SIG-020, canonical table | New OS binaries missing from table → keep table versioned, unknown names fall back to scoring |
| T2 | Spoofing: fake publisher metadata | HR-007, SIG-014, pinned issuer chains | Genuine stolen certificate (A3) → relies on revocation, VT, behaviour |
| T3 | Tampering: modify signed file after allow | Hash + path identity, re-verify on start (FR-020), HR-001 | Memory-only tampering (hollowing/injection) → M6 memory checks, residual |
| T4 | Tampering: edit DB/config/rules | Data dir ACL, rule/config validation, audit hash chain, `chain_ok` surfaced in UI | Admin-level actor (A2) can still tamper; chain detects, does not prevent |
| T5 | Disable service / remove filters | Service DACL (Administrators only to stop), SCM auto-restart, persistent denies, tamper alerts via `event.health` | A2 can stop the service; dynamic filters vanish by design (fail-open) |
| T6 | IPC abuse by local process | Pipe ACL, first-instance flag, role by token, optional strict client signature, 1 MiB frame cap, input validation, rate limits | Admin-level client can issue admin methods |
| T7 | Repudiation | Audit entries for every decision/action with actor (`user:<SID>`, `ai`, `rule`) | — |
| T8 | Information disclosure to AI | Redaction contract, off by default, payload preview, acknowledgement, audit | Public DNS names/hashes sent when AI enabled |
| T9 | Key theft | DPAPI machine scope, ACL'd store, never over IPC, `SecretString`/zeroize, no logging | Admin/SYSTEM can decrypt (inherent to DPAPI machine scope) |
| T10 | DoS: popup storms/pending flood | Dedup by `(identity, dest_class)`, rate limit, queue caps (1,000, oldest auto-collapsed) | — |
| T11 | DoS: self-lockout of the host | Fail-open dynamic filters, bootstrap allowlist, learning period, panic, never-kill set | Misconfigured persistent deny rules on system identities → SG-001 prevents |
| T12 | Elevation: UI exploited | Strict CSP, no remote content, minimal Tauri capabilities, bridge validates all strings | WebView2 vulnerabilities → keep runtime updated |
| T13 | Prompt injection (A5) | Data-only framing, forced tool schema, output validation, hard rules > AI, no AI-driven kill by default | Model may be misled to a wrong "unknown"; gates keep it from acting alone |
| T14 | Sideloaded DLL in signed host | M6 module signature checks; persistence audit | Until M6 residual |
| T15 | DNS tunnelling / data exfil through allowed host | Out of scope v1; beaconing signal and destination visibility only | Residual |
| T16 | Allow-all by user fatigue (A4) | Rate-limited prompts, bulk review wizard, AI advisor, `once`/`1h` defaults, publisher-level allow only for valid signers | User choice remains final for Unknown |

## 4. Out of scope and honest limits

- No packet holding: first connect of unevaluated apps may be dropped and retried (documented).
- Code injected into an allowed process inherits that process's permit (identity is per executable).
- Kernel-mode adversaries and bootkits can blind or disable Vigil.
- Not a replacement for AV/EDR; positioned as a complementary control that adds policy and explainability.

## 5. Self-protection checklist (M6)

Status: **done** = implemented and compile/unit verified; **VM** = implemented, needs the manual check in `docs/11` §10; **tracked** = deferred, listed in `docs/10` backlog.

- Binaries Authenticode-signed (`installer/build.ps1 -SignCert`, `docs/13`); self-pin from the signer thumbprint (HA-001). Status: signing script done, pin recording VM/tracked.
- Service DACL restricts control to SYSTEM and Administrators (query-only for users); restart-on-failure recovery configured in `installer/Vigil.wxs`. Status: VM.
- Data dir ACL verified at start (re-applied if drifted, audited as `config_change`). Status: done (`vigil_win::harden::ensure_data_dir_acl`), elevated check VM.
- Load-library search path hardened (`SetDefaultDllDirectories`, System32 only). Status: done.
- Process mitigation policies (dynamic-code prohibit, image-load restrictions): tracked, because they conflict with the WebView2/ETW components until measured.
- Detect and alert on service stop attempts, filter deletions not initiated by Vigil (WFP change events) and data-dir ACL changes: ACL drift at start is audited; live WFP-event subscription is tracked.

## 6. Compliance mapping (ISO/IEC 27001:2022 Annex A, ISO/IEC 27701:2025)

| Control | How Vigil supports it | Evidence |
|---|---|---|
| A.8.7 Protection against malware | Blocks/kills malicious or masquerading executables, policy by verdict | Audit entries, test report |
| A.8.9 Configuration management | Versioned rule pack, policy TOML, change audit | `rule_pack_version`, audit |
| A.8.15 Logging | Tamper-evident audit log, structured service logs | Hash chain, exports |
| A.8.16 Monitoring activities | Realtime process/connection inventory and alerts | Dashboard, `connections` table |
| A.8.19 Installation of software on operational systems | Unknown/unsigned executables require approval | Pending/decision history |
| A.8.20 Networks security | Outbound application-level allow/deny | WFP filter inventory |
| A.5.23 Cloud services | AI/VirusTotal as optional, documented transfers | AI settings, payload contract |
| 27701 data minimisation/transparency | Redaction contract, preview, acknowledgement | `docs/06`, UI |

## 7. Development vs release signing

- Dev builds: unsigned; the self-pin is created from the dev binary hash on first run when `VIGIL_DEV=1` is set; this flag is compiled out of release builds.
- Release: signed with the owner's certificate; `vigilctl trust bootstrap` and the installer record the Vigil self-pin thumbprint.
