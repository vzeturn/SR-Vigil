# 23 — URL filter and protection switch

**Tóm tắt (VI):** Bộ lọc tên miền cục bộ chặn trang độc hại, lừa đảo, người lớn và quảng cáo; và nút tạm dừng bảo vệ.

## 1. Goal

Stop name resolution for domains on public blocklists before a connection exists, and let the user pause every automatic block or kill with one switch. User-mode only: no driver, no proxy, no certificate.

## 2. How it works

- A DNS sinkhole listens on `127.0.0.1:53` (UDP and TCP). Names on an enabled list get `0.0.0.0` / `::` for A/AAAA and NXDOMAIN for every other type (so HTTPS/SVCB hints cannot route around the block). Everything else is forwarded unchanged to the resolver the machine used before.
- Lists are declared in `rules/urlfeeds.toml` (id, category, format `hosts`/`domains`, HTTPS URL). Categories: `malware`, `phishing`, `adult`, `ads`. A domain blocks its subdomains.
- Settings (`urlfilter.*` in `default-policy.toml`, via `settings.set`): `enabled` (off by default), `malware` and `phishing` (on), `adult` and `ads` (off), `allow` (user exceptions, domain plus subdomains).
- `dns.status` (Viewer) returns state, list size, counters per category and the last blocked names.
- The UI's *Web filter* page (`docs/07 §4.8a`) shows that status and edits the switch, the categories and the exceptions; the CLI and `settings.set` remain available.

## 3. Safety properties

- **Fail open.** Adapters are set to `[127.0.0.1, previous server]`; if the service dies, the second server answers. DNS is switched only after the listeners bound.
- **Reversible.** The original per-adapter setup (static servers or DHCP) is saved in `%ProgramData%\Vigil\dns-backup.json` and restored on disable, on service stop, and on the next start if a crash left the backup behind.
- **Protected names.** `PROTECTED` in `vigil-core/src/urlfilter` (Microsoft update and connectivity hosts, the advisor, the signed catalogue, the lists themselves, code hosting, signing) can never be blocked, whatever a feed says.
- **Untrusted data.** Feed lines and query names are validated before use and never reach a shell or SQL. Feeds are HTTPS only, capped at 32 MB, replaced atomically, refreshed daily; the cached copy is kept when a download fails.
- Every enable and disable writes an audit row.

## 4. Limits

A browser using DNS-over-HTTPS bypasses a DNS sinkhole; turn off "secure DNS" in the browser or use the browser's own filtering. A site blocked by name is not blocked by raw IP. This is a hygiene layer, not a replacement for the process and connection verdicts.

## 5. Privacy

Lists are downloaded with plain GET; nothing about the machine or the queries is uploaded. Queries stay local.

## 6. Protection switch

`protection.set {enabled}` (Admin; `vigilctl protection on|off`; button in the UI header). While paused:

- no WFP deny or catch-all filter is held, no process is killed (storm, respawn, hard-rule, AI, lockdown), the DNS filter is idle, lockdown refuses to start and an active run ends;
- scoring, verdicts, events and the AI advisor keep running, so assessments stay live;
- manual actions by the user (explicit kill, decisions) still work.

The state is persisted, shown in `status.protection`, audited, and restored at the next start. Resuming re-applies the current mode.
