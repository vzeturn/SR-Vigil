# 19 — Application profiles, tab containment and package origin

Status: built (steps 1–3); deferred items tracked as M14 in `docs/10-roadmap-milestones.md`.

Goal: well-known multi-process programs are recognised for what they are, so Vigil helps everyone
without getting in their way. A browser with forty processes is normal. A single tab that behaves
like malware is stopped on its own, and the browser keeps running.

Data lives in `rules/app_profiles.toml` (embedded, same override rule as other rule files);
logic in `vigil_core::profile` (pure, unit-tested on any OS).

## 1. What was scanned

Browsers (Chromium engine: Edge, Chrome, Brave, Vivaldi, Opera, Chromium; Gecko engine: Firefox,
LibreWolf, Waterfox) and uv/pip console-script launchers (`...\Scripts\<name>.exe`, e.g. the
`awslabs.*` MCP servers). Other multi-process programs (Electron apps, IDEs) are already covered
by `docs/04 §8` exemptions and `KNOW-001`; adding them to the profile file is a data change.

## 2. Browser roles

| engine | a tab is... | everything else |
|---|---|---|
| chromium | a process whose command line has `--type=renderer` | browser, GPU, network, utility, crashpad |
| gecko | `-contentproc ... tab` (last token `tab`) | parent, GPU, socket, RDD |

Only the derived `tab: bool` is stored on the process row. The command line is read only for
processes whose image name is a listed browser, is never stored in full, never logged, and never
reaches a shell, SQL or an AI prompt (`CLAUDE.md` rule 6).

## 3. Per-tab containment

A sandboxed renderer never starts another program. A tab that does has escaped its sandbox. The
service (`tab_scan`, each tick after `storm_scan`) kills that renderer **and what it started**
(`tree: true`), and nothing else:

- no block, no decision, no deny of the browser identity: the user's browser is never refused;
- the browser, its GPU/network/utility helpers and all other tabs keep running;
- it works in every mode, like `storm_scan`, because it is a behaviour kill of an attack in progress;
- every kill writes an audit row through `kill_process` as usual;
- the service emits `event.tab_alert` (`reason: started_program`, `action: stopped`, the browser
  and the program's file name) and the tray shows a notification, so a tab that vanished is
  explained.

### 3.1 Runaway tabs

`tab_cpu_scan` samples each tab's kernel + user CPU time every 10 s (`vigil_core::profile::HotTab`).
A tab using at least 90 % of one core (`HOT_SHARE_PERCENT`) for 5 minutes (`HOT_ALERT_SECS`) is
reported once with `event.tab_alert` (`reason: high_cpu`, `action: warned`, `minutes`). In
`enforce` mode a tab still that hot after 15 minutes (`HOT_STOP_SECS`) is stopped alone
(`tree: false`, no block) with an audit row and a second alert (`action: stopped`); `observe` and
`learning` only alert. One quiet sample resets the clock, and history is keyed by pid and start
time, so a reused pid starts afresh. The user's choice: alert at 5 minutes, stop at 15 in enforce.

## 4. What the operating system cannot tell us

Chromium routes all tab networking through one Network Service process. A connection seen by the
OS belongs to that process, not to a tab, so "this tab connected to a dangerous host" cannot be
attributed to one tab, and killing the network process would break every tab. Containment is
therefore **behavioural** (§3). Destination-based per-tab blocking (needs the browser's own
devtools/extension channel) stays deferred (M14); runaway CPU is handled by behaviour (§3.1).

## 5. Package origin (PKG-001)

uv/pip launchers sit in a user-writable cache and are unsigned, so SIG-010 scores them −15 and
they stay Unknown. The package's own `dist-info/METADATA` names its home. When the `Home-page` or a
`Project-URL` in the header block starts with a `[[dev_source]]` prefix (AWS Labs, Model Context
Protocol, Astral, PyPA), PKG-001 adds +30.

- The metadata is written by the package author: this is **evidence of origin, not proof**
  (typosquatting). Hence a modest bonus, never Safe on its own (net score 65, Unknown).
- Only the header block counts (README text below the first blank line is ignored); the URL must
  begin with the listed prefix including the trailing slash (`github.com/awslabs.evil/` fails).
- The file is size-capped (64 KiB) and read once per new image, in `vigil-win`.
- The AI advisor still decides the rest; hard rules and HA-001/SG-001 are unchanged.

### 5.1 Trusting a package family once

A developer who installs several tools from one source would otherwise answer once per launcher.
When `vigil-win` finds a trusted source in a launcher's metadata it records the executable's
**package family**: `<source prefix>|<tools folder>`, where the tools folder is the folder holding
the environment (for uv, `%AppData%\uv\tools`), case-folded. The Pending card then offers
`apply_to = package_source` ("Same package source and tools folder").

- The decision covers only executables with the **same family**: same source prefix and same tools
  folder. A launcher from the same source in another venv, or from another source in the same
  folder, is not covered.
- The family is re-read every time an image is registered; a launcher whose metadata stops naming
  a trusted source leaves the family and the cover stops at once.
- Every file is still hashed and evaluated; hard rules, HA-001 and SG-001 still win, as for any
  user decision (HA-002).
- `decision.submit` refuses `package_source` for an executable with no family (`INVALID_PARAMS`).
  Exported decisions carry the family; an import of a `package_source` entry without one is skipped.

## 6. Build order and acceptance

1. Profile data + `vigil_core::profile` (done).
2. `tab_scan` + `ProcRow.tab` (done): fixtures `a_tab_that_starts_a_program_is_stopped_alone` and
   `a_quiet_tab_and_a_browser_with_helpers_are_left_alone`.
3. PKG-001 (done): fixture `a_package_from_a_known_source_offsets_the_unsigned_penalty_but_stays_unknown`.

Acceptance: a renderer that spawns a child loses only itself and the child; a browser with many
helpers and tabs is never touched; an `awslabs.*` launcher scores 65 instead of 35.
