# faux-node-gyp

**Models:** A legitimate native build — a package with a `binding.gyp`
that runs `node-gyp rebuild` on install (`sharp`, `bcrypt`, `better-
sqlite3`, ...). This is the single most important false-positive to
avoid: per INTENT.md §2, a tool that flags every native compile gets
uninstalled on day one.

**Behavior (in the traced process):**
- ~8 file opens under `build/` and the project tree, most of them
  failed probes — what a `configure` step does.
- Two file writes to `build/`.
- One `connect(2)` to `203.0.113.11:443` (TEST-NET-3, unroutable) —
  models node-gyp downloading the Node headers.
- Two `exec.Command("/bin/true")` launches — models shelling out to the
  compiler and linker. These are separate processes; their syscalls are
  NOT traced (process-tree gap, features/syscall-capture-tree).

It reads **no** credential-shaped path. That is the crux of the fixture.

**Exercises:** The false-positive guardrail. A legitimate build
legitimately connects out and forks — neither alone may reach HIGH.

**Expected report:**
- `[MEDIUM] Network connection` for `203.0.113.11:443` — present, not
  escalated (no credential-read finding exists to pair it with).
- **No HIGH finding.**
- "WHAT CORDON DID NOT OBSERVE" reports **at least 2** other processes
  launched and not traced. The fixture launches exactly two subprocesses;
  the count also picks up the Go runtime's one-time `clone(CLONE_PIDFD)`
  support probe on first `os/exec` (a short-lived throwaway child),
  which is why the test asserts `>= 2`, not `== 2`. This is deliberate:
  the count is an honest "processes we saw and did not trace", not a
  curated "subprocesses you asked for" (see DECISIONS.md 2026-09-05).

**What this fixture does not prove:** that a *real* `node-gyp` run
produces no HIGH finding — only that this stand-in, built to match
node-gyp's observable shape, does not. A real corpus package with a C
toolchain would be a stronger check; this environment has no compiler.
