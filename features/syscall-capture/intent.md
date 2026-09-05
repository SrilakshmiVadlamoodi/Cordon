# syscall-capture

**Inherits:** INTENT.md §3 Observation layer, §1 detection-is-best-effort

**Why:** The report is only as good as what we observe — raw fds and
sockaddrs are useless, we need real paths and hostnames.

**Done:**
- [x] `openat`, `connect`, `execve` captured from the single directly
      launched child process (see Scope split below — the process *tree*
      is a named follow-up, not this slice)
      *(`internal/syscallcapture`, seccomp-BPF `SECCOMP_RET_TRACE` +
      ptrace. Was unchecked 2026-09-04 for the sibling-OS-thread event
      drop (a multi-threaded traced process, e.g. Node.js's libuv thread
      pool, was silently missing events from its own worker threads) —
      fixed the same day via the `Tgid`-vs-`Pid` distinction in `Run`'s
      auto-attach dispatch; see DECISIONS.md "sibling OS thread events
      were silently dropped — fixed via Tgid, not Pid" and the regression
      test `TestRun_CapturesOpenatFromSiblingOSThread`. Re-verified on
      the real install: dropped-stop count with a different Tgid than
      the primary (genuine forked descendants, still correctly
      unobserved per the scope split below) unchanged; dropped stops
      *sharing* the primary's Tgid confirmed at 0 across 3 runs.)*
- [x] Arguments resolved: fds → real paths, sockaddrs → hostnames
      *(openat: `/proc/<pid>/fd/<n>` readlink after the call, so a
      resolved path only appears on success — see Event's doc comment for
      why "hostnames" is address:port, not a resolved DNS name — a
      documented gap, not silently promised)*
- [x] Test child that opens a known path and connects to a known host
      produces exactly one matching event for each, no duplicates — not
      a literal total-event-count of 2 (see DECISIONS.md 2026-09-04: a
      Go-runtime test helper makes its own real, correctly-captured
      startup opens ahead of the two under test)
      *(`TestRun_CapturesOpenatAndConnect_ExactlyTwoEvents`)*
- [x] Overhead on a real `npm install` measured and recorded
      *(DECISIONS.md 2026-09-04, real dependency tree + forked
      postinstall, after the openat fast-path fix: +0.50s absolute,
      +32.7% relative — still fails INTENT.md §3's "must not take
      noticeably longer" bar, an open decision, not yet resolved; the
      original no-fork lodash measurement (~0.71s/~88%) and the
      pre-fast-path real-install measurement (~1.06s/~72%) are both
      superseded, see the chain of entries under that date)*

**Constraints (slice-specific):** Missed syscalls are acceptable and
expected per §1. Silently *dropping* a captured event is not — that's a bug,
not a coverage limit.

**Scope split (decided 2026-09-04, see DECISIONS.md):**
- **Tracing** is scoped to the single directly-launched child this slice.
  `PTRACE_O_TRACEFORK`/`TRACEVFORK`/`TRACECLONE` auto-attach — needed to
  see grandchildren, e.g. `node-gyp` spawning `cc` — is explicitly
  deferred to [[syscall-capture-tree]]. Building that here would be scope
  past what this doc's own Done checklist asks for.
- **Reaping** every descendant that reparents to our PID 1, traced or
  not, is *not* deferred — it's mandatory the moment the sandbox has a
  real PID 1 init shim (this slice introduces one; see DECISIONS.md),
  independent of tracing scope. Skipping it leaves zombies pinning the
  namespace. Build it in this slice regardless of what gets traced.
- Those same three `PTRACE_O_TRACE{FORK,VFORK,CLONE}` options *are* set
  in this slice too, despite the first bullet — not to trace descendants,
  but because the seccomp filter is inherited by every forked process
  whether we attach to it or not, and an untraced descendant hitting a
  filtered syscall gets refused outright (`ENOSYS`), not silently
  skipped. This slice auto-attaches just enough to immediately release
  each descendant so it keeps running; it never reads its registers or
  reports an event for it. See DECISIONS.md 2026-09-04 "Seccomp filter
  inheritance vs. ptrace attachment" for the failure this fixed.
  [[syscall-capture-tree]]'s job is turning that same attach point into
  real capture and attribution, not adding the options themselves.
