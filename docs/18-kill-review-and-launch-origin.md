# 18 — Kill review, launch origin and root-cause handling

Status: design (approved direction, not yet built). Tracked as M13 in `docs/10-roadmap-milestones.md`.

Goal: a kill is never a dead end for the user. Every kill can be reviewed, undone and excepted; a
program the user opens by hand is asked about once, with the reasons; programs started by other
programs never produce a popup flood, and the thing that keeps starting them is what we deal with.

## 1. Every kill is reviewable and revocable

- A **Kill list** (UI page and `vigilctl decisions`) shows each active kill/block: program, when,
  *why* (rule or signal ids, storm kind, AI reasons and confidence), who decided (`rule`, `ai`,
  `user`), how many respawns were stopped.
- **Revoke** lifts the decision and its respawn block (exists: `decision.revoke`).
- **Exception** = revoke + an `allow` decision with `apply_to` file or publisher and a note. A user
  exception beats storm/behaviour kills and AI verdicts; it never beats a hard rule (HR-*) or HA-001.
- **Report false positive** = exception + the evidence (signals, process tree, launch origin) is
  queued for a deep AI review; the outcome is written to the offline memory (`docs/06`) and, when
  confident, proposed as a rule/known-software entry in `rules.d/` for the user to accept. Nothing
  is changed silently.

## 2. Local knowledge base (learn what is normal here)

A `baselines` table in `vigil.db`: per `(publisher thumbprint | sha256, parent identity, child
identity)` the count, first/last seen and typical fan-out. Detectors (storm, LaunchFlood, MOD-001)
consult it: a signed IDE that has always started 10 shells is normal; the same program starting 200
is not. Baselines are only learned from programs that are validly signed or user-allowed, and are
capped so a hijack cannot slowly raise its own ceiling (max 3x the first week's p95). Feeds the AI
payload as `usual_behaviour`.

## 3. Launch origin (human or not)

Each new process gets `origin`, computed in user mode when first seen:

| origin | evidence |
|---|---|
| `user` | parent is the shell (`explorer.exe`, Start/Search host, taskbar, Jump List) **and** the interactive session saw input within 5 s (`GetLastInputInfo`) **and** the process owns or is about to own a visible window |
| `script` | parent is `cmd`, `powershell`, `wscript`, `mshta`, `python`, a build tool, or another unknown/unsigned program |
| `autostart` | matches a Run key, startup folder or scheduled task entry (`persistence_items`) |
| `service` | parent is `services.exe` / `svchost.exe` / Task Scheduler |
| `agent` | parent is a signed app that is an IDE/agent (baseline says it routinely spawns shells) |

`origin` is a UX gate, not a security gate: malware can imitate `user`, so hard rules and the
authority order are unchanged and `user` origin never lowers a score.

## 4. Re-opening a killed program

When a program with an active kill block starts, the respawn guard no longer kills it blind:

1. It **suspends** the new process (`NtSuspendProcess`, in `vigil-win`), so it does nothing meanwhile.
2. If `origin = user`: one popup (per identity, at most once per 10 min): "You opened X. It was
   stopped on <date> because <reasons>. [Keep stopped] [Allow it]". *Allow* revokes the kill and
   resumes the process; *Keep stopped* kills it and silences this identity's popup for 24 h.
   No answer within 60 s: kill (fail closed for something we already judged).
3. Any other origin: **no popup**, kill as today, and the event goes to root-cause handling (§5).

## 5. Root cause: who keeps starting it?

Respawns are attributed to a **launcher** (the parent chain, a scheduled task, a Run key, a
service). When one launcher starts blocked programs ≥ 5 times in 60 s, or the same one ≥ 3 times
after a kill, we stop acting on the children and decide about the launcher:

- Evidence: image, signer, command line (as data), how it was started, what it started, AI review
  with the deep model.
- **One** popup about the launcher: "<launcher> started <child> 12 times in a minute. [Allow
  launcher] [Stop launcher] [Disable its autostart (reversible)] [Ignore]".
- No answer in 60 s: keep the child blocked; kill the launcher **only if** it is unsigned, not in
  the never-kill set, not user-allowed, and the advisor says malicious at ≥ 0.95 (the
  attack-in-progress gate of `docs/06 §4`). Otherwise it is left running and listed as pending, so
  a legitimate tool the user forgot about is never killed on a timer.
- Autostart sources are disabled only through the reversible `persistence` flow (`CLAUDE.md` rule 4).

## 6. Popup discipline

One popup per identity per 10 min, global max one per 5 s (`docs/04 §2`), coalesced into a badge
beyond that. Non-human origins never open a popup about the child; they only feed §5.

## 7. Build order

1. Kill list + revoke/exception UI, `vigilctl` parity, false-positive report (§1).
2. `origin` classification + `baselines` table (§2, §3).
3. Suspend-and-ask on re-open (§4).
4. Launcher attribution and root-cause popup (§5).

Acceptance: a fixture where a script respawns a killed program 20 times produces exactly one
popup, about the script; opening the program from Explorer produces one popup with the reasons and
*Allow* resumes it; revoke restores the program in all cases.
