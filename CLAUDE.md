# CLAUDE.md

This file is read automatically at the start of every session in this
repo. If anything here conflicts with what you're about to do, stop and
flag it rather than proceeding.

## Orientation — do this first, every session

You have no memory of prior sessions. Before writing or changing anything:

1. Read `INTENT.md` — mission, architecture, tech stack, roadmap.
2. Read the `intent.md` of whichever `features/<name>/` you're working in.
3. Read `DECISIONS.md` — don't re-litigate a decision already made there;
   if you think a past decision was wrong, say so explicitly and why,
   don't just quietly do it differently.
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

## DECISIONS.md — maintain continuously, without being asked

This is not optional and not something to do only when I remind you.
Append an entry **as part of finishing the work**, the same way you'd
update a checklist — before you report a feature or fix as done, check
whether it produced a decision worth logging.

Append an entry whenever a non-obvious decision gets made: a real choice
between alternatives, a kernel/Go/runtime behavior that forced our hand,
a bug that took real debugging, or a knowingly accepted limitation. This
file is interview-prep material — write every entry so it can be read
cold, months later, by someone who's forgotten everything.

Format:
```
## [date] Short title
**Context:** what problem forced a choice
**Options considered:** the real alternatives, with actual tradeoffs
**Chose:** what we did
**Why:** the reasoning, including what we gave up
**Consequences:** what this makes easy, what it makes hard later
**If asked to defend this:** the 2-3 sentence spoken version
```

Include specific technical detail — syscall names, kernel version
constraints, actual runtime behavior — not vague summaries. Log
decisions that turned out wrong too, with what was learned. If you think
an instruction I give is a mistake, log the objection even if we
proceed my way anyway.

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