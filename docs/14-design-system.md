# 14 — Design system

Vigil's UI follows **Microsoft Fluent 2 (Windows 11)**: a native-feeling, calm, content-first look. This doc is the contract; code lives in `apps/ui/src/design/`.

## 1. Principles

1. **Native first.** Looks like a Windows 11 app: Mica-like backdrop, rounded content layer, Segoe UI Variable.
2. **Content is the hero.** Neutral surfaces; colour carries meaning only (brand = action, green/amber/red = verdict).
3. **Calm by default.** One primary action per view; no decorative gradients, no infinite animation.
4. **Honest states.** Every data view has loading, empty and error states; offline is explained and actionable.

## 2. Tokens (`design/tokens.css`)

Two tiers. Primitives (raw values) exist only in that file; components use semantic roles only.

| Role | Token | Notes |
|---|---|---|
| Window backdrop / content layer / card | `--bg` / `--bg-layer` / `--surface` | Fluent neutral ramp, light and dark via `light-dark()` |
| Hover / selected fill | `--surface-hover`, `--surface-strong`, `--surface-selected` | |
| Stroke | `--border`, `--border-strong` | 1 px hairlines |
| Text | `--text`, `--text-dim` | ≥ 4.5:1 on every surface |
| Brand | `--accent`, `-hover`, `-press`, `-subtle`, `--on-accent` | Fluent blue `#0f6cbd` / `#479ef5` |
| Verdict | `--safe`, `--unknown`, `--malicious` + `-subtle` fills | Never colour alone: chips carry text |
| Focus | `--focus` | 2 px ring, offset 2 px, ≥ 3:1 |
| Elevation | `--elev-2` (card), `--elev-8`, `--elev-28` (dialog) | |

- **Spacing** 4/8 scale: `--space-1…10`. **Radius**: control 4, card 8, dialog 12, chip pill.
- **Type ramp**: caption 12/16, body 14/20, subtitle 16/22 (600), title 20/28 (600), display 28/36 (600). Tabular figures for numbers. UI font `Segoe UI Variable Text`, display `Segoe UI Variable Display`, mono `Cascadia Mono`; Inter and JetBrains Mono ship as fallbacks.
- **Motion**: 100 / 150 / 200 ms, `cubic-bezier(.33,0,.67,1)`; disabled under `prefers-reduced-motion`.
- **Theme**: dark by default; the OS preference applies when `data-theme` is unset.

## 3. Components (`design/components.css`)

Button (`primary`, default, `subtle`, verdict `allow/block/kill`), input/select (underline accent on focus), segmented control, card, chip (`safe/unknown/malicious`), count badge, status pill, banner, data grid (virtualised rows, 36 px), list/facts, dialog (scrim + `--elev-28`), hero info card, feature card, AI advisory card. Height 32 px (hit area ≥ 24 px), nav items 36 px.

## 4. Layout (`styles.css`)

Shell = 248 px navigation on the backdrop + one rounded content layer (`.main`) with a 24/32 px gutter. Page header = `h1` + status pill. Navigation is grouped under caption headings (Monitor, Respond, Review) with Settings pinned at the foot above a divider; the brand mark sits in a 32 px accent-subtle tile. Selected nav item: filled, accent icon and a 16 px accent indicator that grows in (`--dur-gentle`, off under reduced motion); idle icons use `--text-dim`.

## 5. Accessibility

WCAG 2.2 AA: contrast ≥ 4.5:1 (3:1 large/UI), visible focus ring never clipped, icon-only controls labelled, `aria-current` for navigation, `role="status"` for live state, reduced-motion respected.

## 6. Rules for contributors

1. No hex, px font size or colour literal outside `design/tokens.css`.
2. New look = new token or variant, never a one-off override.
3. Every user string through i18n (`en`, `vi`).
