# delayed-process

**Models:** A package trying to evade detection by timing, not
indirection — background a child, exit immediately so the wrapped
command's own run "looks clean," and let the child do the sensitive work
later. This is a plausible real strategy: if the report is generated
once the primary process exits, an action that hasn't happened yet
can't be in it.

**What was investigated, empirically, before writing this fixture or its
assertions:** whether Cordon's `syscallcapture.Run`/`sandbox.runChild`
waits for a detached descendant before the report is finalized and the
namespace tears down, or whether it exits regardless. Built a standalone
probe (a fixture backgrounding `sleep 2 && write-marker`, run through the
real `cordon` binary, checked from the host afterward) rather than
reading the code and assuming. Result: **the marker file never appears**,
even several seconds past the child's own `sleep 2`.

**Root cause, confirmed via `pid_namespaces(7)`:** when `runChild` — PID 1
of the sandbox's PID namespace — calls `os.Exit`, the kernel immediately
`SIGKILL`s every other process still alive in that namespace. This is
deterministic, kernel-guaranteed behavior, not a race that happened to
resolve this way in one test run: PID 1 exiting always tears down the
whole namespace this way, unconditionally.

**By design, or by accident? Neither, precisely — flagged explicitly so
this isn't miscited as an engineered defense.** Nothing in `runChild` or
`syscallcapture.Run` waits for or explicitly kills descendants for
isolation reasons; `runChild` simply calls `os.Exit` once the wrapped
command's own result is known (the PID-1 architecture exists for signal-
fidelity reasons — DECISIONS.md 2026-09-04 — not this). The teardown-
kills-everything behavior is a *side effect* of that separately-motivated
design, not a property anyone verified or built specifically to bound
delayed evasion. It is reliable (kernel-mandated, every time), but nobody
should point at it as a designed defense without this caveat.

**What this does and does NOT buy:**
- It bounds *slow* delay: any action requiring more wall-clock time than
  the wrapped command's own run cannot complete at all — not "missed by
  Cordon," but **prevented from finishing**, a stronger property than
  detection.
- It buys nothing against *fast* delay: a descendant whose action
  completes before (or immediately as) the primary exits faces no
  penalty, and is exactly as invisible to the report as
  [[credential-read-gap]]'s subprocess case — same tracing-scope gap,
  timing changes nothing about visibility.

**Rule NOT triggered / assertion:** `wantMiss`-equivalent, but the
assertion here is not on report text (there is no credential read in
this fixture to detect or miss) — it is a side-effect assertion:
`cmd/cordon/corpus_test.go` checks that `marker-file` does **not** exist
in the project directory, both immediately after `cordon run` returns
and again after waiting past the child's own delay. This doesn't fit the
`{wantHit, wantMiss}` report-text schema, so it's a dedicated test
function alongside the table, not a table row.

**If asked to defend this:** "A detached background process that outlives
the wrapped command gets SIGKILLed the instant the sandbox's PID 1
exits — verified directly, not assumed, by backgrounding a sleep-then-
write and confirming the write never lands even seconds later. That's a
real, kernel-guaranteed property, but it's a side effect of the PID-1
architecture we built for signal fidelity, not something engineered as
an anti-evasion feature — and it only helps against *slow* delay. A
descendant that finishes fast enough gets no penalty and no detection
either, which is the same visibility gap named in
`credential-read-gap`."
