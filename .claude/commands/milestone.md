---
description: Execute a Vigil milestone (M0–M6) end-to-end from the design docs
argument-hint: M0 | M1 | M2 | M3 | M4 | M5 | M6
---

Execute milestone **$ARGUMENTS** of Vigil.

1. Read `CLAUDE.md`, then the milestone's section in `docs/10-roadmap-milestones.md` and its prompt in `docs/12-handoff-prompts.md`, then every doc the prompt lists.
2. Create a task list from the milestone's **Deliver** items and a final task "verify acceptance". Work in the order given by the prompt; write `vigil-core` tests before the code they cover.
3. Commit in small steps on a branch named `ms/<id>-<slug>` using the `area: summary` message format.
4. If a Windows API or dependency behaves differently from what the docs assume, or two requirements conflict, stop, record the finding in the relevant doc, and ask the user before changing the design.
5. Before finishing run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (plus UI lint/tests when `apps/ui` changed) and fix everything.
6. Finish with a report: each acceptance box from `docs/10` marked verified (with test name or evidence), or not verified (with the reason and what the user must run, for example VM-only checks). Do not tick a box you did not verify.
