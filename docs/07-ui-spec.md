# 07 — UI/UX specification

**Tóm tắt (VI):** Tauri v2 + React + Tailwind, phong cách dark-glass hiện đại, realtime. Trọng tâm là popup duyệt nhanh (không cướp focus, không có nút mặc định) và trang chi tiết giải thích lý do chấm điểm. UI không bao giờ chạm vào API key và không tự mở pipe từ JavaScript.

## 1. Stack

| Layer | Choice |
|---|---|
| Shell | Tauri v2 (Rust bridge owns the named pipe; tray; multi-window) |
| Frontend | React 19, TypeScript (strict), Vite |
| Styling | Plain CSS with two-tier CSS-variable tokens (primitive → semantic; components use semantic only). **M2 deviation:** Tailwind/shadcn not adopted, to keep the dependency surface small; revisit if M3 popup needs Radix primitives |
| Motion | Motion (Framer Motion) springs; all motion disabled under `prefers-reduced-motion` |
| Data | `useSyncExternalStore` store fed by the Tauri bridge, which polls `status.get` + paged `process.list`/`connection.list` every 1 s (**M2 deviation:** snapshot polling instead of live subscription; live push arrives with M3 events), TanStack Virtual (large lists). Tauri crate and npm packages must stay on the same minor (2.11.x) |
| Charts/graphs | visx (sparklines, timeline), `@xyflow/react` (process/connection graph) |
| Map (optional) | MapLibre GL with a bundled offline basemap; geo-IP via `maxminddb` in the **service** (user supplies GeoLite2 `.mmdb`) |
| i18n | `react-i18next`, English only (user decision); strings still live in the `apps/ui/src/i18n` table so a locale can be added later |
| Icons/fonts | Lucide; Inter + JetBrains Mono bundled locally (no CDN) |
| Tests | Vitest + Testing Library, Playwright (Tauri webview mode with a mock bridge) |

Security: strict CSP (`default-src 'self'`; no remote scripts/fonts/images), Tauri capabilities limited to the app's own commands/events, no `shell`/`fs` plugins, devtools disabled in release.

## 2. Design language

Dark-first glass UI with a light theme, soft depth, generous spacing, tabular numerals.

| Token | Dark | Light |
|---|---|---|
| `--bg` | `#0A0C10` | `#F5F7FA` |
| `--surface` (glass) | `rgba(255,255,255,0.045)` + `backdrop-filter: blur(24px) saturate(140%)` | `rgba(255,255,255,0.72)` + blur |
| `--border` | `rgba(255,255,255,0.09)` | `rgba(15,23,42,0.10)` |
| `--text` / `--text-dim` | `#E8ECF3` / `#9AA4B5` | `#0F172A` / `#475569` |
| `--accent` | `#7C9CFF` | `#3B5BDB` |
| `--safe` | `#34D399` | `#059669` |
| `--unknown` | `#FBBF24` | `#B45309` |
| `--malicious` | `#F87171` | `#DC2626` |
| radius | 14 px cards, 10 px controls, 999 px chips | same |
| elevation | 0 8 32 -8 `rgba(0,0,0,0.5)`, 1 px inner highlight | lighter shadows |

Verdict is never conveyed by colour alone: each verdict has an icon (shield-check, shield-question, shield-x) and a text label. Contrast ≥ 4.5:1 for text.

Motion: 180 ms ease-out for state changes, spring (stiffness 260, damping 26) for popups and list inserts; new rows flash their verdict colour once.

## 3. Windows

| Window | Size | Behaviour |
|---|---|---|
| Main | 1280×800 (min 960×600), custom title bar | Sidebar navigation, command palette (`Ctrl+K`), global search. |
| Popup | 440 px wide, auto height, bottom-right of the primary display | `alwaysOnTop`, `skipTaskbar`, **does not take focus** on appear (flashes the tray icon + sound optional); queue shows "1 of N"; `Esc` dismisses to the queue (item stays blocked). |
| Tray | icon with verdict-coloured badge (pending count) | Menu: Open, Pending (N), Mode (observe/learning/enforce), **Panic**, Quit UI. |

## 4. Screens

### 4.1 Overview (dashboard)
- Header: mode selector (segmented: Observe · Learning · Enforce) with a status pill and a **Panic** button (always visible, confirm-free but toasts an undo).
- KPI tiles: Safe / Unknown / Malicious counts, Pending, Blocked connections (24 h), AI decisions (24 h).
- Live connections sparkline, "Recent verdict changes" list, "Top destinations" table, optional geo map.
- Health card: ETW, WFP, store, AI states with last error.
- Data: `status.get`, subscriptions `processes`, `connections`, `verdicts`, `health`.

Progressive disclosure: the Overview stays simple. Scores explain themselves on hover (`ScoreTip`: baseline 50, each signal, band, hard rule). "Show N more" expands the attention list; each country expands to its connections, and each connection opens a path map (connection, program with path, signer, launch chain, files it uses). Files come from `process.modules`, read on demand only; without administrator rights or for protected programs the UI shows "Missing permission" instead of an empty list.

### 4.2 Processes
- Virtualized tree-table (parent → child), columns: Name · PID · Verdict chip · Score · Publisher · Path · Connections · Started. Filters: verdict, signed/unsigned, path class, has-connections, text search.
- Row expands inline to show signals. Context menu: Kill, Kill tree, Block, Allow…, Open file location, Copy hash, Look up hash (VirusTotal link).
- `svchost.exe` rows show hosted service names as child nodes.
- Data: `process.list`, `process.get`, events.
- **Live scan board** (default view): one row per running process with a score shown as `x.x/10`; hovering the score lists each issue on its own line. No icon strip on the row. The expanded details hold the identity grid (publisher, signature, path, parent), spoof evidence, impact and advice, the recognised-software label (`KNOW-001`) and **End** (terminate, never-kill set excluded) and **Dismiss** (hide this finding; reversible, audited). Nothing is deleted or disabled without approval.

### 4.3 Connections
- Table + optional force graph (process → destination). Columns: Process · Proto · Local · Remote (DNS name, country flag) · State · Verdict · Bytes (if available) · First/last seen. Filter by verdict, direction, blocked-only.
- Data: `connection.list`, events.

### 4.4 Pending queue
- Cards sorted by severity/recency, bulk select with **Review wizard** (grouped by publisher or folder; "Allow all from this publisher" with scope), per-card AI opinion and "Ask AI" (`ai.explain`).
- Shows the first-connect explanation ("blocked a connection to 203.0.113.7:443").
- Data: `pending.list`, `decision.submit`, events.

### 4.5 Process / identity detail (drawer or page)
- Header: icon, name, verdict chip, score gauge (arc 0–100 with threshold ticks at 30 and 80).
- **Why** panel: ordered signals (id, name, ±delta, plain-language explanation from i18n), hard rule banner if any.
- Tabs: Signature (chain, thumbprints, timestamps) · Metadata · Parent chain · Connections timeline · History (evaluations, decisions) · Persistence · AI opinion (reasons, indicators, model, confidence, payload preview).
- Actions: Allow (scope + apply_to), Block, Kill, Revoke decision.

### 4.6 Rules & Trust
- Trusted publishers list (built-in vs user-pinned, thumbprints, last seen), user allow/deny lists, rule pack viewer (read-only built-ins, editable overrides with live validation and a "test against recent identities" dry run), import/export.

### 4.7 AI Advisor
- Toggle (off/advisor/auto), key entry (write-only field, shows "Key stored ✓"), model fields, thresholds (auto threshold slider with explanation), budgets, "Test connection", **"Preview payload"**, data-categories acknowledgement (required before enabling), usage counters.

### 4.8 Audit
- Filterable timeline (kind, actor, identity), chain-integrity badge (`chain_ok`), export JSON/CSV.

### 4.8a Web filter
- Under *Respond*. On/off switch with state (Active, Starting, Paused, Off), list size and counters from `dns.status` (polled every 5 s), category checkboxes with a blocked count each, the *Always allow* list (add a domain or pasted URL, remove), recently blocked names with an *Allow* button, and the DNS-over-HTTPS note. Changes go through `settings.set {urlfilter}`; Viewers see it read-only (`docs/23`).

### 4.9 Settings
- Language, theme, notifications/sound, popup behaviour (max rate, position), default decision scope, learning duration, never-kill additions, log level, data retention, service diagnostics (version, uptime, ETW drops, WFP filter counts), "Run first-time setup" wizard.
- Opt-in switches, each off by default: the daily version list (`catalogue.enabled`, `docs/16`) and "Block incoming connections to blocked programs" (`enforcement.block_inbound`, FR-017, `docs/04 §1`).

## 5. The approval popup (core interaction)

```
┌──────────────────────────────────────────────┐
│ ⛨?  tool-sync.exe                  Unknown 42 │
│ Unsigned · C:\Users\…\Downloads\               │
│ wants to connect to  api.example.net:443      │
│ ─ Why ─ Unsigned in user-writable path (−15)  │
│        Created 3 min ago (−0)                 │
│ AI (Claude): unknown 0.62 — "No publisher …"  │
│ [ Allow ▾ ]   [ Block ]   [ Kill ]   [ Later ]│
│  scope: 1 h ▾   apply to: this file ▾         │
└──────────────────────────────────────────────┘
```

Rules: no default (Enter does nothing); shortcuts `A`/`B`/`K` active only after the user has clicked inside the window (prevents accidental keystrokes from other apps); `Allow` dropdown offers scope (`once`, `1h`, `24h`, `forever`) and apply-to (`file`, `publisher` when a valid signer exists); `Kill` shows a confirmation chip with the process tree count; one popup per 5 s maximum, the rest queue. **Quiet by default:** the popup and toast appear only for an item with `alert = true` (an established incident); Unknown programs are assessed silently by the AI and wait in the Pending list and its badge. The popup has Previous/Next to revisit items.

**Network prompt** (`ThreatView`, `docs/24`): shown before launcher and pending items, after a frozen reopen. It names the program, the destination and the interval, states that nothing has been sent to the AI, and offers **Ignore**, **Analyze with AI** (only when the advisor is configured; the assessment then appears in place) and **Block**.

## 6. States and quality bar

- Every view has loading skeletons, empty states with guidance, and error states with retry and "service unreachable" banner (reconnect backoff visible).
- Viewer role: all mutating controls disabled with an explanatory tooltip.
- Lists: 5,000 rows at 60 fps (virtualization, row memoization, batched store updates every 100 ms).
- Keyboard: full tab order, visible focus ring, `Ctrl+K` palette, `g p` / `g c` / `g q` navigation shortcuts.
- Copywriting: short, concrete, no scare wording.

## 7. Project structure (`apps/ui`)

```
apps/ui/
├── src-tauri/        # Rust bridge: pipe client, tray, windows, capabilities
├── src/
│   ├── app/          # routes, layout, providers
│   ├── features/     # overview, processes, connections, pending, detail, rules, ai, audit, settings
│   ├── components/   # design-system components (VerdictChip, ScoreGauge, GlassCard, …)
│   ├── lib/          # bridge client (generated types), stores, formatters
│   ├── locales/      # en only
│   └── styles/       # tokens.css, tailwind.css
├── tests/            # vitest + playwright
└── package.json
```
