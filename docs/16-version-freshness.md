# 16 — Version freshness and the known-good database

**Tóm tắt (VI):** Vigil nhận ra phiên bản của phần mềm an toàn và trừ điểm bản cũ để khuyến khích cập nhật. Dữ liệu "bản mới nhất" và "bản có lỗ hổng" được một Cloudflare Worker định kỳ tự thu thập từ nguồn công khai, ký số và phát hành thành một snapshot nhỏ; máy người dùng chỉ tải snapshot đã ký (tùy chọn) và không phải làm việc gì thay chúng ta. Trạng thái: **đề xuất, chờ người dùng xác nhận nguồn dữ liệu** (xem §7). Hướng dài hạn: dùng chính database này để hỗ trợ cập nhật ứng dụng/tiến trình một cách sạch, do người dùng duyệt (§6).

## 1. Decisions so far (user, 2026-11-04)

| Topic | Decision |
|---|---|
| Penalty | Tiered: slightly old −5, many versions behind −15, known serious CVE −30. |
| Outcome | An outdated legitimate program is never turned Malicious by age alone; it falls toward Unknown with a concrete advice ("open the vendor's download page"). Vigil never updates software for the user. |
| Data work | Done by our own cloud worker, not by users' machines. NIST NSRL is attractive but too large to host and says nothing about "latest". |

## 2. Why not host NSRL ourselves

NSRL RDS holds hundreds of millions of file hashes (gigabytes). It answers "this file is a known product file", not "a newer version exists", and it lags real releases. It stays useful as an *optional per-hash lookup* (see §4), not as the base dataset.

## 3. Data sources (all public, no crowdsourcing)

| Question | Source | Notes |
|---|---|---|
| Which program is this, and what is its newest release? | `microsoft/winget-pkgs` manifests (GitHub): package id, publisher, version history, installer URLs and installer SHA-256 | tens of thousands of apps, updated continuously, free. Installer hashes are *installer* hashes, not installed-file hashes. |
| Is this version known vulnerable? | OSV.dev, NVD and CISA Known Exploited Vulnerabilities (KEV) | KEV hit = "serious" (−30). |
| Is this exact file a known-good vendor file? | Hash of installed files: from our own catalogue (§5) and, optionally, CIRCL hashlookup (NSRL-backed) | only when the user opts in; sends one hash, no path or name. |

Crowdsourcing hashes from users is rejected: it is a poisoning vector (an attacker's file could be "added as safe"), it leaks what people run, and the user explicitly does not want to use their machines for work we can do ourselves.

## 4. Architecture

```
Cloudflare Cron Worker (daily)
  ├─ pulls winget-pkgs delta + OSV/KEV
  ├─ builds catalogue snapshot (product → latest, supported range, CVE flags)
  ├─ signs it (Ed25519, key in Workers secret)
  └─ publishes to R2 / KV  ──►  GET /v1/catalogue (ETag, tiny delta)

Vigil client (opt-in, once a day, user setting "check for newer versions")
  └─ downloads the signed snapshot, verifies the signature, caches it in %ProgramData%\Vigil
```

- The client never uploads anything for this feature. The snapshot is the same for everyone (cacheable on the CDN).
- Signature verification follows the key-rotation rule (advertise old and new keys by `kid`); a bad or missing signature means the bundled catalogue is used, never a partial one.
- Offline users keep the catalogue embedded in the release (`rules/known_software.toml` grows version fields).
- Requires the "signed remote rule-pack updates" item from the post-v1 backlog and an amendment of CLAUDE.md rule 10 (a read-only GET of a public signed file). This is a design change and needs the user's approval before code.

## 5. Matching and scoring

1. Identify the product by the existing catalogue (image name + vendor text + signer), then read the file's `ProductVersion`.
2. Compare with the snapshot entry for that product:

| Condition | Signal | Delta |
|---|---|---|
| Version equals latest or within the supported range | none (KNOW-001 still applies) | 0 |
| One or two releases behind | VER-001 `outdated` | −5 |
| Far behind (more than a configured number of releases, or end-of-support) | VER-002 `far_behind` | −15 |
| Version matches a CISA KEV or high/critical CVE range | VER-003 `known_vulnerable` | −30 |

3. Penalties never fire for a file whose version cannot be read or whose product is unknown. Identity signals (signature, path) are unchanged, so an old but correctly signed program stays Unknown at worst.
4. The Processes page shows "installed X → latest Y" and an *Open vendor download page* button (never auto-install, never delete). The link comes from the signed snapshot (`download_page`, taken from the winget manifest's `PackageUrl`, else `PublisherUrl`) or from `rules/known_software.toml`. It is shown and opened only when `catalogue::safe_link` accepts it (`https://`, plain host name, at most 300 characters, no spaces, quotes, backslashes or credentials); the desktop shell checks it again before `ShellExecuteW` opens it in the default browser.

## 6. Later: clean updates (user direction, 2026-11-04)

The catalogue is the foundation for helping users update applications cleanly. Every release of the online database improves what Vigil can recommend, so the schema must carry more than "latest":

- per product: vendor download page, `winget` package id, silent-install support flag, and the installer SHA-256 the vendor published;
- per release: release date, end-of-support flag, CVE/KEV references.

Planned flow (not in M12): Vigil shows the advice, the user approves, then the update runs through the vendor's own channel (`winget upgrade --id <id>` or the vendor page). Vigil checks the installer hash against the catalogue before running, stops any running process of that product only after user approval (never the never-kill set), and writes an audit row. No silent updates, no auto-update of Vigil itself in v1 (CLAUDE.md rules 4 and 10); this stays a user-triggered action and needs its own design review before code.

## 6b. Status

Done: `FileVersion` read on Windows; VER-001/002/003 and tests; the `vigil-catalogue` Worker (daily cron, winget-pkgs source, Ed25519-signed envelope in KV, `GET /v1/catalogue`); client verification with embedded keys by `kid` (`rules/catalogue_keys.toml`), rollback protection, on-disk cache re-verified at start; opt-in `catalogue.enabled` setting and Settings toggle. Without the setting, or on any verification failure, the embedded catalogue is used.

Done (M12): `freshness.download_page` on the IPC process row and the vendor-page button; the snapshot carries per product `winget_id`, `download_page`, `installer_sha256` (up to 8, lower-case, from the installer manifest) and `end_of_support` (ISO date, curated in `catalogue/overrides.json`). All are optional, so format `v` stays 1 and older clients ignore them.

Open (tracked in docs/10): OSV/KEV automation for `vulnerable_below`; `end_of_support` is carried as data but does not yet raise VER-002 (the clean-update design of §6 decides how a past date is judged).

## 7. Decisions (delegated to engineering best practice, 2026-11-04)

1. **Approved:** cloud-built, Ed25519-signed snapshot on the personal Cloudflare account (Worker + R2). CLAUDE.md rule 10 is amended: opt-in, GET only, nothing uploaded, signature verified before use, bundled catalogue as fallback.
2. **Per-hash NSRL/CIRCL lookup:** not built in M12. If added later it stays opt-in, off by default, one hash and nothing else.
3. **Safety defaults:** VER-* only fires for recognised software in `system`/`program_files`. Its delta is applied *after* the 0–100 clamp (so a strongly signed app cannot absorb it) but never pushes a score below `MALICIOUS_MAX + 1`, so age alone cannot make a program Malicious. Unreadable or non-numeric versions, and catalogue entries without release data, produce no signal.
4. **macOS:** Homebrew Cask metadata is the equivalent source, tracked with M7–M10.
