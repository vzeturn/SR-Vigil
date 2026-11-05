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
- every kill writes an audit row through `kill_process` as usual.

## 4. What the operating system cannot tell us

Chromium routes all tab networking through one Network Service process. A connection seen by the
OS belongs to that process, not to a tab, so "this tab connected to a dangerous host" cannot be
attributed to one tab, and killing the network process would break every tab. Containment is
therefore **behavioural** (§3). Destination-based per-tab blocking (needs the browser's own
devtools/extension channel) and runaway-CPU renderer handling are deferred (M14).

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

## 6. Build order and acceptance

1. Profile data + `vigil_core::profile` (done).
2. `tab_scan` + `ProcRow.tab` (done): fixtures `a_tab_that_starts_a_program_is_stopped_alone` and
   `a_quiet_tab_and_a_browser_with_helpers_are_left_alone`.
3. PKG-001 (done): fixture `a_package_from_a_known_source_offsets_the_unsigned_penalty_but_stays_unknown`.

Acceptance: a renderer that spawns a child loses only itself and the child; a browser with many
helpers and tabs is never touched; an `awslabs.*` launcher scores 65 instead of 35.
