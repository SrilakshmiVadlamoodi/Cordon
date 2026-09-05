# sandbox-runner

**Inherits:** INTENT.md §3 Isolation layer, §3 Platform

**Why:** Nothing is worth observing if the process can trivially escape —
every other feature depends on confinement existing first.

**Done:**
- [x] Child runs in mount + PID + network + user namespaces
      *(also UTS + IPC; proven by `TestRun_ChildIsInNewNamespaces`, which
      compares every `/proc/self/ns/*` inode against the parent's)*
- [x] Project dir is read-write; `$HOME` is not visible
      *(`TestRun_ProjectDirWritableAndHomeInvisible`: `$HOME` is the project
      dir, the real home is never mounted)*
- [x] Test child attempting to read `~/.ssh` or write outside the project
      dir fails, proven by a checked-in test
      *(same test: `HOME_SSH_BLOCKED`, `ABS_SECRET_BLOCKED`,
      `ETC_WRITE_READONLY`, `ROOT_WRITE_READONLY`; secret contents asserted
      absent from output)*
- [x] Wrapped command's exit code, stdout and stderr pass through unchanged
      *(`TestRun_PassesThroughExitCode`,
      `TestRun_PassesThroughStdoutAndStderrUnchanged`; signal-death fidelity
      deferred to the init shim — see DECISIONS.md 2026-09-01)*

**Constraints (slice-specific):** none beyond master — rootless and the
no-manual-fork rule both come from INTENT.md §3.
