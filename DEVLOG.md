# Cordon — Engineering Notes

Curated highlights from the project's internal decision log: real bugs
found, real tradeoffs made, and the honest current limitations. This is
not a full session-by-session transcript — it's the substance a
stranger reading this repo would actually want, condensed from a much
longer, more detailed local record the maintainer keeps but doesn't
publish. Dates mark when each decision was made.

---

## Real bugs found

### Seccomp filters are inherited across `fork`; ptrace attachment is not (2026-09-04)

Cordon uses seccomp-BPF for the fast allow/deny path and ptrace to
inspect the arguments of flagged syscalls. Those two mechanisms follow
different inheritance rules, and the gap between them nearly broke every
real install Cordon wraps.

A seccomp filter installed on a process is inherited by every child it
forks or clones, unconditionally. Ptrace attachment is not — it only
covers the one process explicitly attached to. When a forked-but-untraced
child hit a syscall the inherited filter marked `SECCOMP_RET_TRACE`, and
no tracer was attached to *that specific task* to receive the trap, the
kernel didn't skip the syscall quietly — it refused to execute it at all,
returning `ENOSYS`. For a real `npm install`, where most of the actual
work happens in forked children (`node-gyp`, `cc`, `make`, arbitrary
postinstall scripts), this meant every subprocess the wrapped command
forked would fail its own `execve`, breaking the install itself, not
just Cordon's visibility into it.

The fix auto-attaches to every new descendant the traced process forks —
enough to give the kernel a tracer to route the trapped syscall to — and
immediately resumes it without ever reading its registers or reporting
an event for it. Full attribution across the whole process tree is a
separate, still-unbuilt feature; this fix only keeps forked children
from being refused syscalls outright.

### Sibling OS threads were silently dropped from capture (2026-09-04)

ptrace and seccomp operate on Linux *tasks*, not processes. A `Pid`
equals its own `Tgid` for a freshly launched process, but any sibling
thread that process later creates gets its own `Pid` while sharing the
same `Tgid`. Cordon's dispatch loop only recognized the one `Pid` it
launched, so a real Node.js install's libuv thread pool — separate OS
threads inside the same traced process — had its `openat`/`connect`
calls silently classified as unrelated, unobserved descendants and
never reported.

The fix reclassifies each newly-seen task once, by reading its `Tgid`
from `/proc/<pid>/status` instead of comparing raw `Pid`s, and folds
sibling-thread events into the same reporting path the primary thread
already uses. Verified with a synthetic two-thread test proven to fail
without the fix, and confirmed on a real install that same-thread-group
drops fell to zero across repeated runs.

### A step-summary race, then a second, unrelated bug hiding behind it (2026-09-14)

The GitHub Action's "run wrapped command" step used
`2> >(tee "$CORDON_REPORT_FILE" >&2)` — process substitution — to
stream stderr live while also capturing it to a file. Bash doesn't wait
for a process-substitution subshell before continuing, so the very next
line's file check could run before `tee` had finished writing. On a
real hosted runner, the whole step completed in 32ms — fast enough to
lose that race consistently. Fixed with a plain synchronous redirect
instead of streaming tee.

That fix didn't make the failing CI job pass. Tracing both sides of the
boundary (`wc -c` on the file immediately before and after the write, on
both ends) found a second, independent bug: GitHub Actions allocates a
distinct `$GITHUB_STEP_SUMMARY` file *per step*, not one shared file per
job — so a later verification step reading that env var was structurally
looking at an empty file that could never contain an earlier step's
output, race or no race. Both bugs were real, found independently, and
both fixes are kept — one doesn't supersede the other. The concrete
lesson generalizes: a later step can't read an earlier step's step
summary through the env var; read the underlying artifact the earlier
step actually wrote instead.

### `ubuntu-latest` gates unprivileged user namespaces by default (2026-09-14)

Cordon's rootless sandbox depends on unprivileged user namespaces
(`CLONE_NEWUSER`). Whether GitHub's hosted `ubuntu-latest` runners
allowed this had been an open, unverified assumption since the project
started. A real run on a hosted runner (triggered via a pull request,
since `workflow_dispatch` refuses to dispatch a workflow that doesn't
yet exist on the default branch) confirmed it: `ubuntu-latest` had
rolled to an Ubuntu 24.04-class base with
`kernel.apparmor_restrict_unprivileged_userns=1` set, which blocks
`clone(CLONE_NEWUSER)` outright for unconfined binaries — a real
platform blocker to Phase 3's "three lines in a workflow file" promise,
not a Cordon bug. The composite Action now attempts a best-effort,
scoped `sudo sysctl` lift of that one setting on its own ephemeral
runner VM, loud when it works, non-fatal (and non-masking) when it
doesn't.

---

## Architecture tradeoffs

### Rootless via user namespaces, one UID mapped

No sudo, no setuid helper, no file capabilities — the entire sandbox
runs in a pure user-namespace path. `CLONE_NEWUSER` is created in the
same `clone()` call as the other namespaces, since an unprivileged
process gains a full namespace-scoped capability set on creating one.
The accepted cost: only a single UID mapping (host UID → UID 0 inside)
is possible without a setuid `newuidmap` helper, which the rootless
design explicitly rules out. This means npm's own privilege-drop
behavior (dropping to the target directory's owner when it detects it's
running as root) fails outright inside the sandbox — a known, accepted
gap, not solved speculatively ahead of the corpus work that actually
needed it.

Namespace setup itself never manually `fork()`s — the Go runtime does
not survive a raw `fork()` (most runtime state is frozen mid-operation
in the child). Cordon instead re-execs `/proc/self/exe` into a hidden
child mode, matching `runc`'s own approach: a brand-new, fully
initialized Go process does the namespace setup, then `execve`s the
real wrapped command so no Go code survives into it.

### Single-process syscall tracing, by deliberate scope cut

Full process-tree tracing was the original design target, but got
scoped down to a single directly-launched process before any tracing
code was written — landing ptrace+seccomp attachment, register reads,
and fd resolution *and* multi-tracee tree tracking in one slice looked
like two independently hard pieces of work bundled together. That
judgment call was validated almost immediately: the very next bug found
(seccomp inheritance vs. ptrace attachment, above) was a real
correctness failure in single-process tracing *alone*. Full tree
tracing (following `node-gyp`, `cc`, and other grandchildren) remains a
named, unbuilt follow-up feature — real work, not yet started, and a
real current gap: a real `npm install` with a forked postinstall script
captures zero syscalls from that postinstall's own process tree today.

Every forked descendant is still reaped regardless of whether it's
traced — that's what owning PID 1 means, not a scope choice — so the
tracing gap doesn't create zombie processes, only a visibility gap.

### `arm64` refused at compile time, not shipped broken (2026-09-05)

Cordon's ptrace register access assumes the amd64 `PtraceRegs` layout.
Rather than let `GOOS=linux GOARCH=arm64 go build` silently produce a
binary with unimplemented runtime stubs, the arm64 build path fails at
compile time — a real, loud build failure instead of a binary that
looks like it works and doesn't. The same principle carried into the
release matrix: `arm64` is simply absent from the goreleaser
configuration, not listed and left to fail — a missing release asset is
a smaller, more honest failure mode than a listed one that 404s.

---

## Detection judgment calls

### A missing `.env` marker was a coverage bug, not a tradeoff (2026-09-11)

While building a corpus fixture meant to *demonstrate* a marker gap, the
gap found was `.env` itself — the single most common secrets file for
the Node/Python ecosystems Cordon targets, and it simply wasn't in the
credential-path marker list. Unlike `.npmrc` (a real precision tradeoff:
the file legitimately might not hold a secret), there's no legitimate
reason an install should be reading a project's `.env` at all — this
was a plain false negative, fixed in a one-line change rather than
logged as an accepted gap.

### The allowlist can't be gamed by the package it's auditing (2026-09-11)

Because syscall capture traces `openat`, never file *content*, no
path-based rule can distinguish a token-free `.npmrc` from a stolen one
— hence the allowlist mechanism, letting a developer explicitly clear a
known-safe path. The obvious attack: could a package under audit write
its own allowlist entry mid-run to clear a path it's about to read?
Traced the actual code path — the allowlist is loaded and returns,
synchronously, strictly before the traced process that becomes the
wrapped command is even started — and then didn't stop at that
argument: built a corpus fixture that actually attempts the self-write
and read in the same run. The credential-read finding still fires; no
suppression appears. What this doesn't close: editing the allowlist file
ahead of a *future* run still works — the mitigation there is
procedural (check it into version control so a surprise edit is a
visible diff), not enforced in code.

### Finding order got a confidence tier, not a third severity level (2026-09-11)

The roadmap called for severity tiers so the highest-value finding
surfaces first. The actual gap was narrower: multiple simultaneous HIGH
findings had no defined ordering at all. Rather than add a third
severity level, findings got a secondary confidence-based sort
(`Possible credential exfiltration` always ranks first; among the rest,
markers with no legitimate non-secret reading — private keys, cloud
credentials — rank above path-only heuristics like `.npmrc`). One
specific classification call is logged on the record rather than
silently made: `.netrc` was treated as high-confidence by analogy to git
credential files, since unlike `.npmrc` it has no legitimate
secret-free reading.

---

## Honest limitations, as of 2026-09-24

- **Overhead is over budget.** Measured against a real install with a
  moderate dependency tree and a forked postinstall script: **+32.7%**
  wrapped vs. unwrapped, after fixing the biggest early driver (an
  initial measurement came in at +72%). The remaining cost is
  instrumented and understood — fixed per-call ptrace cost on `openat`,
  roughly half of it spent on calls that were always going to fail
  (Node's own speculative module-resolution probing) and were never
  going to be security-relevant. This is logged as an accepted,
  measured Phase 1 gap, not silently carried forward as if it met the
  stated "must not take noticeably longer" bar.
- **Tracing is single-process.** A real install's grandchildren
  (`node-gyp`, `cc`, arbitrary forked subprocesses) are not observed at
  all today — confirmed directly, not assumed, by a real install
  producing zero captured syscalls from its own postinstall's process
  tree. Every run reports a concrete, per-run count of how many
  processes were launched and not traced (a lower bound, not an exact
  figure) rather than a generic disclaimer.
- **Detection is best-effort; isolation is the hard boundary.** Every
  detection rule above is a path-based heuristic against what was
  observed — it can be evaded by anything outside the current tracing
  scope, and makes no claim of total coverage. The sandbox's namespace
  and mount isolation is the actual security boundary; the behavior
  report is a best-effort diagnostic on top of it, not a second
  boundary of its own.
- **No released binary exists on GitHub Releases yet.** The
  `linux/amd64`-only goreleaser release matrix is built and validated
  in CI via snapshot builds, but no tagged release has been cut. The
  GitHub Action still compiles Cordon from source on every invocation.
- **Linux only, amd64 only.** Namespaces and seccomp are Linux
  features, permanently out of scope for macOS/Windows. `arm64` fails
  at compile time by design, not by omission (see above).
