# syscall-capture-tree

**Inherits:** INTENT.md §4 Phase 5 (Tree Tracing, deferred, revisit after
Phase 4), §3 Observation layer, §1 detection-is-best-effort;
[[syscall-capture]] (builds directly on its PID-1 init shim, its ptrace
attach, and its seccomp-BPF filter — this slice widens who gets traced,
it doesn't change how)

**Why:** `npm install` is a real process tree — npm spawns node, which
spawns `node-gyp`, which spawns `cc`/`make`. A capture scoped to only the
single directly-launched child (the deliberate boundary [[syscall-capture]]
shipped with) sees none of a native build's actual syscalls, which is most
of what an install with real side effects does. Scoped into INTENT.md
Phase 5 ("Tree Tracing", deferred, revisit after Phase 4) — split out of
`syscall-capture` (DECISIONS.md 2026-09-04) as a named decision rather
than built past what that slice's intent asked for.

**Done:**
- [ ] Events captured and reported from every auto-attached descendant,
      not just the primary traced pid — [[syscall-capture]] already sets
      `PTRACE_O_TRACEFORK`/`TRACEVFORK`/`TRACECLONE` and already resumes
      each new tracee's first stop (it has to, to avoid the `ENOSYS`
      failure logged in DECISIONS.md 2026-09-04), it just always resumes
      without reading registers or calling `onEvent`. This slice is that
      same attach point turned into real capture.
- [ ] Events attributed to the actual PID/TID that made them, not the
      tree root
- [ ] Test tree (parent forks a child that forks a grandchild that opens
      a file) produces one event per actual syscall, attributed correctly
      — same "exactly these events, no more" bar as [[syscall-capture]]
- [ ] Overhead re-measured against a real `npm install` now that every
      process in the tree is traced, not just one

**Constraints (slice-specific):** Reaping already covers the whole tree
as of [[syscall-capture]] (that part was never scoped to one process —
see its Scope split note); this slice only has to widen tracing to match.
Missed syscalls are still acceptable per §1; dropping a captured event
from *any* traced process in the tree is still a bug, not a coverage gap.

**Known concretely, not just anticipated (DECISIONS.md 2026-09-04,
"Closing check" entry):** a forked descendant spawns its *own* sibling
OS threads once it execs into something like `node` — observed directly
on a real install (a postinstall's `sh` → `node` acquired a 6-thread
libuv pool of its own). So "trace the descendants" here means the same
`Tgid`-vs-`Pid` distinction [[syscall-capture]] already applies for the
primary process, applied *per descendant process* too — not "trace every
new wpid," but "trace every new wpid, grouped by which process's thread
group it actually belongs to."
