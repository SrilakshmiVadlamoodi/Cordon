# syscall-capture

**Inherits:** INTENT.md §3 Observation layer, §1 detection-is-best-effort

**Why:** The report is only as good as what we observe — raw fds and
sockaddrs are useless, we need real paths and hostnames.

**Done:**
- [ ] `openat`, `connect`, `execve` captured from the sandboxed process
      **and its children**
- [ ] Arguments resolved: fds → real paths, sockaddrs → hostnames
- [ ] Test child that opens a known path and connects to a known host
      produces exactly those two events, no more
- [ ] Overhead on a real `npm install` measured and recorded

**Constraints (slice-specific):** Missed syscalls are acceptable and
expected per §1. Silently *dropping* a captured event is not — that's a bug,
not a coverage limit.
