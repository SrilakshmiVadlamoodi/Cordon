# CLAUDE.md

This file is read automatically at the start of every session in this
repo. If anything here conflicts with what you're about to do, stop and
flag it rather than proceeding.

## Orientation — do this first, every session

You have no memory of prior sessions. Before writing or changing anything:

1. Read `INTENT.md` — mission, architecture, tech stack, roadmap.
2. Read the `intent.md` of whichever `features/<name>/` you're working in.
3. Read `DECISIONS.md` if it's present on disk (it's local-only as of
   2026-09-24, gitignored, not guaranteed to exist in every checkout —
   see the DEVLOG.md section below) — don't re-litigate a decision
   already made there; if you think a past decision was wrong, say so
   explicitly and why, don't just quietly do it differently. Also read
   `DEVLOG.md`, which is checked in and covers the same ground in
   curated, public-facing form.
4. Confirm environment: `uname -a` should say Linux. If it doesn't, stop
   and tell me — do not attempt Linux-only work (namespaces, seccomp,
   ptrace) on a non-Linux shell.
5. Run `go test ./... -v`, `gofmt -l .`, `go vet ./...`. Don't trust a
   prior session's reported "green" — re-verify now, on this machine.
   - *Known fresh-shell gap:* the Go toolchain lives at `~/.local/go/bin`
     and is now added to `PATH` in `~/.bashrc`. If `go: command not found`
     in a non-interactive shell that doesn't source `.bashrc`, prepend
     `PATH="$HOME/.local/go/bin:$PATH"` for the command.

## Workflow — hybrid Spec/Intent-Driven

- `INTENT.md` is the durable source of truth (mission, architecture,
  stack, roadmap-as-checkboxes). It is thorough, not lean, and gets
  updated whenever an architecture or stack decision changes — don't let
  it go stale.
- Each `features/<name>/intent.md` is short: **Inherits / Why / Done
  checklist (2–5 checkboxes) / slice-specific constraints**. No separate
  `spec.md` or `validate.md` — the done checklist *is* the validation
  record.
- Before implementing: read the relevant intent docs, then propose your
  approach in a few sentences and **stop and wait for confirmation**
  before writing code.
- Tests are real, checked-in files — never ephemeral, never purely
  in-session. Update them when behavior changes.
- Checkboxes in any `.md` file reflect true current state. When something
  is genuinely done, edit the file to tick it — don't just report it in
  chat and leave the file stale.
- If intent is ambiguous, or you're inferring something non-obvious
  (a platform assumption, a constraint not stated in the docs), flag it
  explicitly and wait rather than silently assuming.

## DECISIONS.md (local-only) and DEVLOG.md (checked in) — as of 2026-09-24

`DECISIONS.md` was, until 2026-09-24, a checked-in, continuously
maintained decision log. It is now **gitignored and local-only** — kept
by the user as a private reference, not committed, not updated by you
unless asked. Its own final entry (still readable via
`git show 5f9d1f9:DECISIONS.md` or in the local file, if present)
records this change and the objection logged at the time: this
contradicts the "maintain continuously, checked in" spirit this section
used to state, and the concrete cost is losing dated, version-controlled
history of reasoning from that point forward. Git history is untouched
— old entries remain recoverable from past commits.

`DEVLOG.md` is the replacement, checked-in and public-facing. Add an
entry there for the same kinds of things `DECISIONS.md` used to capture
— a real choice between alternatives, a kernel/Go/runtime behavior that
forced our hand, a bug that took real debugging, a knowingly accepted
limitation — as part of finishing each feature, not just when reminded.
The bar for inclusion is the same; the *form* is different: no
verification transcripts, no internal back-and-forth, no session
narration — just what happened, why it mattered, and what changed,
written for a stranger reading the repo cold. See DEVLOG.md's existing
entries for the tone and length to match.

If you think an instruction is a mistake, still say so explicitly
before proceeding (per the top of this file) — logging the objection in
DEVLOG.md is appropriate when it's a real technical or architectural
tradeoff worth a stranger reading later; a one-off process instruction
(like this section's own change) doesn't need a permanent public entry
for every future occurrence, just the flag at the time.

## Project-specific ground rules (see INTENT.md for full detail)

- Go 1.23+, Linux only, kernel 5.10 floor. No macOS/Windows support, ever.
- Rootless: no sudo, no setuid helper, no file capabilities. Pure
  user-namespace path only.
- Never fork manually — use `exec.Cmd` + `SysProcAttr`. The Go runtime
  does not survive a raw `fork()`.
- `runtime.LockOSThread()` is mandatory wherever ptrace is used.
- `features/` holds intent docs only. Go code lives under `internal/`.
- **Detection is best-effort, isolation is a hard boundary** — never
  write code, docs, or output text that implies total anomaly-detection
  coverage. This is a defect against INTENT.md if it happens.

## Explaining code to me

I'm learning Go as we go and need to be able to defend every line of
this in interviews. When you write non-trivial code, explain the
Go-specific and Linux-specific reasoning inline or in your summary —
don't just hand me working code.