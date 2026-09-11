# credential-read-gap

**Models:** The same credential theft as [[credential-read]], performed
one process level down — a lifecycle script that shells out to `cat`,
`node -e`, or any other subprocess to do the actual file read, instead of
reading it inline.

**This is an EXPECTED MISS, asserted as such, not just an absence of
assertion.** `syscallcapture`'s tracing scope
(`features/syscall-capture/intent.md`, "Scope split", decided
2026-09-04) covers only the single directly-launched process and its own
OS threads. Every other forked process is auto-attached only to stop it
from ENOSYS-ing on its own `execve`/`openat` (DECISIONS.md 2026-09-04,
"Seccomp filter inheritance vs. ptrace attachment") — its syscalls are
never read or reported. `subprocess-read.go`'s `cat $HOME/.ssh/id_rsa`
therefore produces **no** `Credential file read` finding, even though
the exact same secret is read as in `credential-read`'s fixtures.

**Rule NOT triggered:** Rule 1 (credential-read, HIGH) — `wantMiss` in
`cmd/cordon/corpus_test.go`'s table, with the reason above as the
required justification string.

**What is still true, and asserted:** the report's `UnobservedDescendants`
count is `>= 1` (the `cat` process, plus whatever the Go runtime itself
forks) — the report does not stay silent about the gap, it says plainly
that a process was launched and not traced. The miss is in *what* got
flagged, not in whether Cordon admits it doesn't know.

**Closing this gap requires:** `features/syscall-capture-tree/intent.md`
— widening tracing to auto-attached descendants instead of just
releasing them, plus per-task attribution (a descendant acquires its own
sibling OS threads too, per that doc's "Known concretely" note). Not
scheduled to a roadmap phase as of this writing.

**Related, not the same gap:** [[delayed-process]] explores whether
*timing* (backgrounding, then acting after the primary exits) changes
anything about this. It doesn't — see that group's own findings.
