# Cordon — DECISIONS

Interview-prep record. Written for a reader who wasn't in the room. Append an
entry whenever a non-obvious decision gets made: a real fork in the road, a
kernel or Go behaviour that forced our hand, a bug that took real debugging,
or a limitation we accepted knowingly. Not every commit.

Entries are append-only and dated. Decisions that turned out **wrong** stay
in, annotated with what we learned.

---

## [2026-09-01] Re-exec `/proc/self/exe` instead of a hand-rolled fork+exec

**Context:** The sandbox has to run privileged setup — `mount`, `pivot_root`,
mounting a fresh `/proc` — *inside* the new namespaces but *before* the
wrapped command starts. `exec.Cmd` + `SysProcAttr` can create the namespaces
and write the UID/GID maps, but it runs only a fixed, opaque syscall sequence
between `clone()` and `execve()`; we cannot inject arbitrary setup there.

**Options considered:**
- **Hand-rolled `fork()` + setup + `execve()`** (the `criyle/go-sandbox`
  `pkg/forkexec` approach, which INTENT §3 names as reference reading). Full
  control over the pre-exec window. But after `fork()` in a Go process only
  the calling thread survives in the child, while every runtime mutex,
  channel and GC/scheduler lock is frozen mid-state — almost any Go code,
  including `print`, can deadlock or crash. INTENT §3 forbids this outright:
  "Never fork manually — the Go runtime does not survive `fork()`."
- **Re-exec the current binary** (`runc`'s model). Parent starts
  `exec.Command("/proc/self/exe")` with `SysProcAttr.Cloneflags` for every
  namespace and the UID/GID mappings. The re-exec'd child is a brand-new,
  fully-initialised Go process — no post-`fork()` hazard — that detects it is
  the child, does the `mount`/`pivot_root` work while *inside* the
  namespaces, then `execve()`s the real target so no Go code survives into
  it.

**Chose:** Re-exec `/proc/self/exe` into a hidden child mode, keyed off the
`_CORDON_CHILD` environment variable.

**Why:** It is the only option that both satisfies "no manual fork" and lets
us run setup inside the namespaces. `go-sandbox/pkg/forkexec` is still read —
for the *ordering and flags* of the mount steps (private-propagation remount,
bind then read-only remount, `pivot_root` then `umount2(MNT_DETACH)`) — but
its `clone()` mechanism is deliberately not copied. Cost we accept: one extra
`execve` of our own binary (~1 ms).

**How the child is signalled:** the parent sets one environment variable,
`_CORDON_CHILD`, whose *value* is the JSON-encoded `childConfig` (the wrapped
command's argv, the project dir, the host mountpoint for the new-root tmpfs).
`MaybeRunChild` — called first thing in both `main()` and the test `TestMain`
— returns immediately if that variable is unset, otherwise decodes it and
hands off to `runChild`, which unsets it before `execve` so it never reaches
the wrapped command. `argv[0]` is separately set to the literal
`cordon-sandbox-child`, but that is cosmetic (it is what shows up in `ps` /
`/proc/<pid>/comm`); nothing reads it, and it is *not* the sentinel. An
env var, not an argv slot, because it has to carry a structured payload, not
just a boolean flag.

**Consequences:**
- Easy: the setup code is ordinary Go, unit-testable, debuggable. Adding
  seccomp-filter installation later (syscall-capture) drops into the same
  pre-`execve` point in the child.
- Hard: the binary must be able to find itself (`/proc/self/exe`; fine on
  Linux, our only target). Tests must route their re-exec through `TestMain`
  so the test binary plays the child role too.
- Revisit only if a future feature needs setup that must happen with *no*
  `execve` boundary at all (e.g. a ptrace stop planted before the very first
  instruction) — that would justify the `forkexec` path, with its own entry.

**If asked to defend this:** "Go's runtime is multi-threaded from startup, so
a raw `fork()` leaves the child with frozen runtime locks — the standard
library and INTENT both say don't. `runc` solves the same problem by
re-executing itself so the namespace setup runs in a healthy process, then
`execve`-ing the real workload. We copied that structure and read
`go-sandbox`'s forkexec only for the syscall ordering."

---

## [2026-09-01] User namespace created in the *same* `clone()` as the others

**Context:** An unprivileged user cannot create a mount, PID or network
namespace directly — those `clone()` flags require `CAP_SYS_ADMIN` in the
current user namespace. INTENT §2 forbids sudo and setuid helpers, so we have
no way to *be* privileged.

**Options considered:**
- **setuid `newuidmap`/`newgidmap`** (the rootless-Docker/Podman approach):
  richer multi-UID mappings from `/etc/subuid`. Rejected by INTENT §3 — it
  needs a setuid binary on PATH and `/etc/subuid` pre-configured, which
  breaks §2 zero-friction.
- **`CLONE_NEWUSER` bundled with `CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET |
  CLONE_NEWUTS | CLONE_NEWIPC` in one `clone()`.** The kernel creates the
  user namespace first and grants the new process a full *namespace-scoped*
  capability set — including `CAP_SYS_ADMIN` — which then satisfies the
  other flags in the same call.

**Chose:** One `clone()`, `CLONE_NEWUSER` included, via
`SysProcAttr.Cloneflags` plus `UidMappings`/`GidMappings` (Go adds
`CLONE_NEWUSER` implicitly when mappings are set).

**Why:** It is the whole mechanism that makes rootless confinement possible
without a helper. `unshare -Urmpnf` does exactly this under the hood.

**Consequences:**
- Easy: no external dependency, no host configuration, works for any
  unprivileged user on a kernel with unprivileged userns enabled.
- Hard: capabilities are valid *only inside* the sandbox's user namespace —
  they do not let the child touch host-owned resources. Fine for us; would
  bite anyone expecting real root.
- Gated on `unprivileged_userns_clone=1` (older Debian) and, on Ubuntu
  23.10+, on the AppArmor `apparmor_restrict_unprivileged_userns` toggle —
  see the platform entry below.

**If asked to defend this:** "Creating a user namespace is the one
namespace op an unprivileged process is always allowed. Inside it you
transiently hold `CAP_SYS_ADMIN`, so bundling it in the same `clone()` as the
mount/PID/net namespaces lets those succeed with no root and no setuid
helper. That's the entire basis of rootless containers."

---

## [2026-09-01] Single UID/GID mapping — npm's privilege-drop left unsolved on purpose

**Context:** The pure-userns path (no `newuidmap`) maps exactly one UID:
our host UID → UID 0 inside. Every other UID inside the namespace resolves to
the kernel `overflow` UID (65534) and cannot be `setuid()`-ed to.

**Options considered:**
- **Map a range now** — impossible without `newuidmap`/`/etc/subuid`, which
  §2 rules out.
- **Map host UID → a non-zero UID inside** (e.g. 1000). Avoids code paths
  that special-case "am I root?", but is otherwise the same single-entry
  limitation.
- **Map host UID → 0 inside, accept the limitation, document it.**

**Chose:** Single mapping, host UID → 0 inside. Log the consequence here; do
not engineer around it yet (per project instruction, 2026-09-01).

**Why:** The affected case is specific and belongs to a later feature: when
npm sees it is running as root it drops privileges to the owner of the
target directory before running lifecycle scripts (`infertile`/`nobody`
behaviour). With only UID 0 mapped, that `setuid()` fails and npm aborts.
That will surface when the Phase 1 corpus runs a real `npm install`, not in
sandbox-runner's own tests. Solving it now would be speculative.

**Consequences:**
- Easy now: sandbox-runner and its tests only ever run as the single mapped
  UID; nothing to handle.
- Hard later: `npm install` under the corpus will likely need `--unsafe-perm`
  (tells npm to keep running lifecycle scripts as the current user) or a
  switch to mapping host UID → non-zero inside. Capabilities in the userns
  are granted to its *creator* regardless of which UID is mapped, so moving
  off UID 0 costs us nothing structurally.

**If asked to defend this:** "Rootless with no setuid helper means exactly
one UID is mapped. npm's root-detection then trips its privilege-drop and
`setuid()` fails. We knew this going in; the fix (`--unsafe-perm` or a
non-zero mapped UID) lands with the corpus feature that actually exercises
npm, not here."

---

## [2026-09-01] Minimum kernel 5.10; Ubuntu 24.04 AppArmor userns lock is a CI risk to probe early

**Context:** Every isolation primitive we use has a kernel-version floor, and
some distros disable unprivileged userns by policy even when the kernel
supports it. We need a stated floor and a CI plan.

**Options considered:**
- **No stated floor**, fix breakage as reported. Rejected — "works on my
  machine" is not a platform contract, and the test skip logic needs a
  concrete predicate.
- **Floor at 5.9** (first `seccomp_unotify`) or **5.15** (a common LTS).
- **Floor at 5.10.**

**Chose:** Minimum kernel **5.10**. CI: GitHub Actions `ubuntu-latest`, with
an explicit early step that *probes* whether unprivileged userns actually
works on the runner rather than assuming it.

**Why:** 5.10 clears every primitive we need — unprivileged userns (3.8),
`setgroups:deny` before `uid_map` (3.19), seccomp-BPF (3.5),
`seccomp_unotify` (5.9), cgroup v2 default — and is the floor for Debian 11 /
Ubuntu 20.04+, so the constraint excludes nothing current. Ubuntu 23.10+
(and 24.04 LTS) ship `kernel.apparmor_restrict_unprivileged_userns=1`, which
makes `clone(CLONE_NEWUSER)` fail for unconfined binaries even on a capable
kernel; `ubuntu-latest` will eventually roll to 24.04, so we cannot assume.

**Consequences:**
- Easy: one predicate for the test skip — read
  `/proc/sys/kernel/unprivileged_userns_clone` and
  `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`, skip with a
  clear message if either disables it.
- Hard: if CI runners disable it, we need a fallback — run the suite in a
  `--privileged`-ish container, or `sysctl -w
  kernel.apparmor_restrict_unprivileged_userns=0` in the workflow. Probing
  early means we find out on day one, not when a release is blocked.

**If asked to defend this:** "5.10 is the lowest kernel that has every
namespace and seccomp feature on our roadmap, and it's already the Debian 11
baseline so we lose no users. The real risk isn't the kernel, it's Ubuntu
24.04's AppArmor policy disabling unprivileged userns — so CI probes for that
explicitly instead of discovering it during a release."

---

## [2026-09-01] Wrapped command runs as PID 1 for now — signal reporting is deferred to an init shim

**Context:** Writing the sandbox-runner tests, a case that expected
`sh -c 'kill -TERM $$'` to report signal termination came back as a clean
`exit 0`. The wrapped command is `execve`'d directly by the re-exec'd child,
so it *is* PID 1 of the new PID namespace.

**What the kernel actually does:** a namespace's PID 1 is immune to every
signal sent from *inside* that namespace unless it has installed a handler
for that signal — and SIGKILL/SIGSTOP cannot have handlers, so even
`kill -KILL 1` from within is silently dropped. (Signals from an *ancestor*
namespace still work: SIGKILL/SIGTERM from the host — e.g. the OOM killer, or
a future Cordon timeout — are delivered.) Verified both `kill -TERM $$` and
`kill -KILL $$` against PID 1, and the same `kill -TERM` against a non-PID-1
child (which terminates normally, rc 143).

**Options considered:**
- **Add a PID-1 init shim now.** A small Go process stays PID 1, runs the
  real command as PID 2 via `exec.Command` (the runtime's vetted path, not a
  manual fork), forwards signals to it, reaps it, and mirrors its
  exit/signal status. The `tini`/`runc init` pattern. Correct, but it is
  real scope and it changes the exit-code path too.
- **Accept direct-exec-as-PID-1 for this slice.** sandbox-runner's Done
  checklist is exit code + stdout + stderr passthrough (all green); it does
  not ask for signal fidelity.

**Chose:** Direct exec as PID 1 for sandbox-runner. Dropped the speculative
`Result.Signal` field (YAGNI). The `Signaled()` branch in `Run` still returns
`ExitCode = -1` if it ever fires (host-side kill), which is correct as far as
it goes.

**Why:** The init shim is *independently mandatory* for the next feature —
syscall-capture must observe "the sandboxed process **and its children**",
and orphaned grandchildren reparent to PID 1; without our own PID 1 to reap
and account for them they are lost. Building the shim there means signal
fidelity and child reaping land together, tested against a feature that
actually needs them, instead of being half-built here.

**Consequences:**
- Easy now: nothing extra; the direct `execve` keeps exit code and stdio
  trivially faithful.
- Hard/blocked until the shim: a wrapped command that signals itself, or is
  killed by one of its own children, reports `exit 0` instead of the signal.
  A host-side kill of the sandbox still reports `ExitCode = -1`. Documented
  on `Result.ExitCode`.

**If asked to defend this:** "The wrapped process is PID 1 of its namespace,
and the kernel won't deliver a from-inside signal to PID 1 without a handler
— not even SIGKILL. Faithful signal handling needs an init process as PID 1,
and we build that with syscall-capture because it also needs a real PID 1 to
reap and account for orphaned grandchildren. sandbox-runner's contract is
exit-code and stdio passthrough, which the direct exec gives us cleanly."

---

## [2026-09-01] Standard-library `syscall` for the MVP, not `golang.org/x/sys/unix`

**Context:** INTENT §3 names `x/sys/unix` as a reason to pick Go ("raw
syscall access without FFI"). sandbox-runner needs `clone` flags, UID/GID
maps, `mount`, `pivot_root`, `sethostname`, `execve` — all of which exist in
both the frozen stdlib `syscall` package and in `x/sys/unix`.

**Options considered:**
- **`golang.org/x/sys/unix` now.** Actively maintained, complete constant
  coverage, the package we will *need* for seccomp in syscall-capture. Costs
  a `require` line and a `go.sum` — a real dependency and a supply-chain
  surface, on a project whose entire reason for existing is supply-chain
  risk.
- **stdlib `syscall` now, adopt `x/sys/unix` when syscall-capture forces
  it.** Zero dependencies, zero `go.sum`, `go build` works with nothing
  fetched. `syscall.SysProcAttr` is what `os/exec` consumes regardless of
  which package we import, and every call sandbox-runner makes is present
  and stable in `syscall`.

**Chose:** stdlib `syscall` for this slice. `go.mod` has no `require` block.

**Why:** Nothing in sandbox-runner needs anything `syscall` lacks, and a
dependency-free first slice is easy to audit line-by-line (the stated goal
for this codebase). The switch is mechanical and lands in the feature that
actually needs the newer constants (`SECCOMP_*`, `seccomp_notif*`), where it
will be justified by real use rather than anticipation.

**Consequences:**
- Easy now: `go.sum` does not exist; the trust surface is the Go toolchain
  only.
- Later: syscall-capture adds `x/sys/unix` and, most likely,
  `x/sys` alone. When that happens some `syscall.*` references here may be
  migrated for consistency — a no-behaviour-change churn commit.
- If a reviewer expects `x/sys/unix` because INTENT mentions it: this is a
  deferral, not a reversal. INTENT's point (raw syscalls, no cgo) holds
  either way.

**If asked to defend this:** "Everything sandbox-runner touches is stable in
the standard library's `syscall` package, so the MVP has zero third-party
dependencies and no `go.sum` — which matters for a supply-chain tool. We
pull in `x/sys/unix` when syscall-capture needs the seccomp constants that
aren't in stdlib, and migrate the rest then if we want consistency."

---

## [2026-09-01] Sandbox root is read-only except the project dir, /tmp, /dev, /proc; $HOME points at the project dir; project dir keeps its real path

**Context:** The checklist says "project dir is read-write; write outside it
fails" and "$HOME is not visible". Three sub-decisions fell out of making
that concrete and testable.

**1. Which surfaces are writable.**
- The **project directory** — bind-mounted read-write; the whole point.
- **/tmp** — a fresh per-sandbox `tmpfs`. Native builds (`node-gyp`,
  `node-sass`) fail without a writable temp dir. It is ephemeral and exists
  only in the sandbox mount namespace, so a write there is invisible to the
  host and gone when the process exits.
- **/dev** — a `tmpfs` with only `null zero full random urandom tty`
  bind-mounted from the host (the userns cannot `mknod`). Writable in the
  sense that the device nodes are, not the directory contents.
- **/proc** — procfs, "writable" only in the procfs sense.
- **Everything else, including `/` itself** — read-only. `/bin /sbin /lib
  /lib64 /usr /etc` are bind-mounted then re-mounted `MS_RDONLY` (the RO
  flag is ignored on the initial bind and needs a second
  `MS_REMOUNT|MS_BIND` pass — a kernel rule, not a bug), and the top-level
  `tmpfs` new-root is `MS_REMOUNT|MS_RDONLY` after `pivot_root` so the
  command cannot even create `/newfile`.

  *Alternative rejected:* leave `/` writable since it is an ephemeral
  `tmpfs` anyway. Rejected because "write outside the project dir fails" is
  a checklist assertion and a demo talking point; a literal read-only `/`
  makes it unambiguous, and the test asserts the failure reason is
  `Read-only file system`, not a permissions accident.

**2. `$HOME` = the project directory.** The real home is simply never
bind-mounted, so `~/.ssh` cannot be reached by any path — the test plants a
secret in a stand-in home and confirms both `$HOME/.ssh/id_rsa` and the
absolute path to it fail. But `$HOME` must still be *something* writable:
npm puts its cache and reads `.npmrc` there, and tools crash on an unset or
unwritable `HOME`. Pointing it at the project dir satisfies both — no host
home exposure, and a working writable target.

  *Alternative rejected:* unset `HOME` entirely. Cleaner in theory, but npm
  and friends misbehave, which would surface as confusing corpus failures
  later.

**3. Project dir keeps its host path inside the sandbox.** It is
bind-mounted at the *same absolute path* it has on the host (e.g.
`/home/u/proj`), not a fixed `/project` or `/app`. Costs a `MkdirAll` of a
deep path inside the new root. Buys path fidelity: syscall-capture resolves
fds to paths, and those paths should match what the user sees in their own
shell, with no translation layer. Containers usually remap because the host
path is meaningless across machines; Cordon runs on the user's own machine
against their own tree, so the host path *is* the meaningful one.

**Consequences:**
- Easy: the capture layer can report paths verbatim; "write outside" is a
  hard, testable line.
- Hard: a project dir located under a read-only system path (say
  `/usr/lib/node_modules/...`) would fail the `MkdirAll` under the RO
  bind. Not a real case for "the directory I'm installing into", documented
  here in case it ever bites.
- `/tmp` being writable means a determined payload can drop files there;
  that is fine — detection (best-effort per §1), not prevention, is the
  contract, and the capture layer still sees the `openat`.

**If asked to defend this:** "Writable set is the project dir plus an
ephemeral tmpfs `/tmp` and `/dev` — everything else, `/` included, is
read-only, and the test checks the write fails *because* the fs is
read-only. `$HOME` is the project dir: the real home is never mounted so
keys are unreachable, but npm still needs a writable HOME. And we keep the
project's real absolute path inside the sandbox so captured file paths match
what the developer sees."

---

## [2026-09-01] Known gap: `ABS_SECRET_BLOCKED` asserts "path not found", not "permission denied"

**Context:** `TestRun_ProjectDirWritableAndHomeInvisible` plants a secret at
`<secretHome>/.ssh/id_rsa` (an absolute host path under a `t.TempDir()`) and
has the sandboxed shell try `cat "<that absolute path>"`. The assertion is
that the command prints `ABS_SECRET_BLOCKED` (its `|| echo` fallback) and
that `TOP-SECRET-KEY` never appears in the output. This is the test standing
in for "a payload that hard-codes `/home/you/.ssh/id_rsa` instead of going
through `$HOME` cannot read it".

**What actually makes the `cat` fail:** the path simply *does not exist*
inside the sandbox. `t.TempDir()` returns a path under the host's temp dir
(`/tmp/...` or `$TMPDIR/...`); inside the sandbox `/tmp` is a fresh empty
tmpfs and the real home is never bind-mounted, so nothing resolves along that
path. `cat` exits non-zero with `ENOENT`. The test does **not** distinguish
that from the stronger outcome we actually care about — the file being
present in the mount namespace but unreadable (`EACCES`) — because in this
sandbox design the host tree is *gone*, not *denied*.

**Options considered:**
- **Tighten the assertion now** — e.g. also mount a decoy tree read-only and
  assert `EACCES` on a file within it, so the test proves "denied" and not
  just "absent". Real additional coverage, but it is testing a code path
  (deny-by-permission) that the current design deliberately does not rely on:
  isolation here is *by non-existence*. Writing the stronger test invites
  someone to later "fix" it by adding a permission layer we don't want.
- **Leave it, record the gap.** The behaviour under test (hard-coded
  absolute path to host secrets does not work) is correct and covered. Only
  the *reason* the assertion accepts is weaker than the prose around it
  implies.

**Chose:** Leave the assertion as-is for the sandbox-runner slice; log this
so the strength gap is on the record and not mistaken for a guarantee we
tested.

**Why:** "The host filesystem is not in the namespace" is the actual
guarantee, and `TestRun_ChildIsInNewNamespaces` +
`TestRun_ProjectDirWritableAndHomeInvisible` (old-root detached, only the
project dir bound) already establish it structurally. A `not-found` result on
an absolute host path is the *expected consequence* of that, not a lucky
accident — but the string `ABS_SECRET_BLOCKED` alone would also be printed if
some future refactor left the file reachable-but-unreadable, or reachable at
a *different* path, so it is not a tripwire for regressions in the way
`ETC_WRITE_READONLY` (which greps for the exact kernel error string) is.

**Consequences:**
- Easy now: nothing to build; the guarantee we ship is intact and covered.
- Hard/watch-for later: if syscall-capture or a future feature ever
  reintroduces any host path into the sandbox mount namespace (a decoy, a
  cache bind, a `/home` passthrough), this assertion will not catch a
  resulting leak unless the leaked bytes happen to be `TOP-SECRET-KEY` on
  that exact path. Anyone strengthening the isolation tests should add an
  explicit `EACCES`-on-a-present-file case at that point.

**If asked to defend this:** "The test proves a hard-coded absolute path to
`~/.ssh` doesn't work, which is the property we care about. It happens to
prove it via `ENOENT` — the host tree isn't in the namespace at all — rather
than `EACCES`, because this sandbox isolates by non-existence, not by
permission. We logged that the assertion is weaker than a permission-denied
check would be, so it's a known limitation, not a claim we forgot to make."

---

## [2026-09-04] syscall-capture: tracing scoped to one process, reaping scoped to the whole tree

**Context:** The original instruction for this slice was full
process-tree tracing — not single-process. `syscall-capture`'s intent.md
text ("the sandboxed process and its children") reflected that. When
asked to propose an implementation approach, this was flagged back as an
open scope question rather than built as asked: single-process tracing
is what the doc's own Done-checklist test actually exercises ("exactly
two events, no more" from one test child), and landing ptrace+seccomp
attach/register-reads/fd-resolution *and* tree-wide multi-tracee tracking
in the same slice was real, compounding complexity. That pushback was
accepted and the scope was revised down to single-process-plus-named-
follow-up *before any code was written* — a real reduction from the
original ask, not the plan from the start, made because the combined
complexity looked risky, on the strength of that argument alone, with no
concrete evidence yet that anything about it actually was hard.

The concrete evidence arrived almost immediately after: mid-implementation,
re-running sandbox-runner's own existing test suite (not just the new
syscall-capture tests) surfaced the seccomp-inheritance-vs-ptrace-attachment
bug logged in the entry right after this one — a real correctness pitfall
in single-process tracing *by itself*, found only by testing, not
anticipated by either the original full-tree instruction or the revised
single-process one. That bug is what turned "this seemed lower-risk" into
demonstrated fact: attempting full-tree attribution in the same slice
would have meant debugging that same ENOSYS failure *while also* building
correct multi-tracee bookkeeping on top of it, instead of against an
already-stable single-process base. The scope reduction below is recorded
as decided pre-implementation (that's when it actually happened); this
paragraph is the part that was added after, once there was evidence
instead of just an estimate.

Building the PID-1 init shim this slice (see the runChild restructuring
entry) also means the shim inherits every orphaned grandchild `npm
install` produces, regardless of what we choose to trace — that part
isn't a scope choice, it's what being PID 1 means.

**Options considered:**
- **Trace the full tree now, as originally instructed**
  (`PTRACE_O_TRACEFORK`/`TRACEVFORK`/`TRACECLONE` auto-attach, per-tracee
  PID tracking). Matches what an `npm install` actually does — most of
  its real work happens in grandchildren (`node-gyp` → `cc`/`make`), so
  single-process tracing misses most of the interesting syscalls. But
  it's real added complexity (a set of live tracee PIDs instead of one,
  attribution per-PID, new-tracee-must-be-captured-before-its-first-
  syscall races) layered directly on top of the ptrace+seccomp mechanism
  itself, which was already the bulk of the slice on its own.
- **Scope tracing down to the single directly-launched child instead**,
  matching intent.md's literal Done-checklist test, and split tree-tracing
  into its own named follow-up feature.

**Chose:** Split — a revision of the original full-tree instruction, made
during scoping, before any syscall-capture code existed. Tracing this
slice covers only the one process `runChild` directly launches under
`PTRACE_TRACEME`. Full-tree tracing moves to
`features/syscall-capture-tree/intent.md`, not yet phase-scheduled in
INTENT.md §4. Reaping is **not** split — every descendant that reparents
to our PID 1 gets `wait4`'d regardless of whether it was traced, in this
slice, because skipping that leaves zombies pinning the namespace the
first time `npm install` backgrounds anything.

**Why (as reasoned at the time, pre-implementation):** Landing the ptrace
attach, the seccomp-BPF filter, and fd/mem arg resolution is already a
full structural change to `runChild` (see the companion PID-1 entry).
Bundling tree-wide auto-attach into the same slice would make one commit
responsible for two independently-reviewable pieces of new mechanism, and
intent.md's own Done checklist didn't ask for the tree — only its prose
gestured at it. Splitting was expected to keep the single-process capture
provably correct against its own test before the harder multi-tracee
bookkeeping went on top of it. That expectation held: the seccomp
inheritance bug in the very next entry is exactly the kind of "provably
correct against its own test" failure this ordering was meant to catch
early, and it surfaced in single-process form, on a smaller diff, before
any tree-tracking code existed to also debug at the same time.

**Consequences:**
- Easy now: the syscall-capture Done checklist is satisfiable and
  testable without a multi-PID tracking structure.
- Hard/incomplete until `syscall-capture-tree` lands: capture on a real
  `npm install` will observe only the direct child's syscalls — none of
  `node-gyp`'s, `cc`'s, or any subprocess's. The overhead measurement this
  slice records is therefore a lower bound, not the real per-tree cost.
  Confirmed directly rather than assumed: a real `npm install` exercising
  a forked postinstall script captured 0 `execve` events from that
  postinstall's own process tree (they're auto-attached-and-released, not
  observed — see the next entry) — direct evidence of exactly this gap,
  not just the theoretical one predicted here.
- No zombie risk either way: reaping isn't gated on the tracing split, so
  this doesn't trade correctness for scope discipline.

**If asked to defend this:** "Full-tree tracing was the original ask for
this slice. It got scoped down to single-process during implementation
planning, before any of this code existed, because bundling tree-wide
auto-attach with the ptrace+seccomp mechanism itself looked like two
independently-hard pieces of work in one commit — that was a judgment
call at the time, not yet a proven one. It got proven almost immediately:
the very next bug we hit was a real correctness failure in single-process
tracing *alone*. Reaping the whole tree was never optional either way —
that's just what owning PID 1 means — so the scope cut didn't trade away
correctness, only deferred *visibility* into grandchildren to a named
follow-up feature, and did so on grounds that turned out to be right."

---

## [2026-09-04] syscall-capture test: "exactly two events" isn't literally achievable with a Go-runtime helper

**Context:** `syscall-capture/intent.md`'s Done checklist required a test
child that opens a known path and connects to a known host to "produce
exactly those two events, no more." The obvious implementation re-execs
this package's own test binary as the traced helper — same no-manual-fork
re-exec idiom `internal/sandbox`'s `TestMain` already uses — so it needed
no new build-time dependency.

**What actually happened:** running that test against the finished
capture engine returned **6** events, not 2:
```
openat /sys/kernel/mm/transparent_hugepage/hpage_pmd_size
openat /proc/<pid>/cgroup
openat /proc/<pid>/mountinfo
openat /sys/fs/cgroup/init.scope/cpu.max
openat <the known file>
connect <the known address>
```
The four extras are the Go runtime's own startup activity, made before
the helper's own code runs at all: an unconditional THP page-size probe
(`runtime/os_linux.go`, `sysTHPSizePath` — no `GODEBUG` gate exists for
it in this runtime's source), and GOMAXPROCS cgroup-quota
auto-detection. Tried `GODEBUG=containermaxprocs=0` (the documented
switch for the cgroup half, per `runtime/cgroup_linux_test.go`) against
this Go 1.27 toolchain — no effect; it did not suppress the reads here.
All four are genuine syscalls the traced process actually made, captured
correctly — direct evidence the ptrace+seccomp engine works, not a bug
in it.

**Options considered:**
- **Minimal non-Go helper** (tiny C program or hand-built static
  binary) — would satisfy "exactly two" literally, since it has no Go
  runtime to make incidental calls. Costs a C-compiler build-time
  dependency nothing else in this repo assumes.
- **Test-side allowlist** of known Go-runtime startup paths, keeping a
  strict count assertion over everything else. Keeps the letter of the
  checklist, but the allowlist is coupled to *this specific runtime
  version's* startup behavior and would need updating (silently going
  stale, not failing loudly) if a future Go release added another
  startup open.
- **Relax the assertion**: exactly one matching openat event for the
  known path, exactly one matching connect event for the known address,
  no duplicates — and tolerate other, unrelated events. (Chosen; see
  below.)

**Chose:** Relax the assertion, and reword the checklist item itself
(not just the test) to say so, so the doc and the test agree instead of
the doc silently overstating what's proven.

**Why:** The property `syscall-capture` actually needs to guarantee is
"the two syscalls the test child makes are each reported exactly once,
correctly resolved" — duplication or a dropped event would be a real
capture bug (exactly what INTENT.md §1's "missed syscalls are fine,
*dropped* events are not" already draws the line on). A literal
total-count-of-2 assertion instead couples test-passing to the exact
startup behavior of whatever Go version builds the test binary, which
has nothing to do with capture correctness and already changed once
between minor runtime versions (the GOMAXPROCS cgroup detection is a
newer addition than the THP probe).

**Consequences:**
- Easy: the test is not coupled to Go runtime internals and won't need
  updating if a future toolchain adds or removes a startup open.
- Accepted gap: the checklist no longer literally reads "exactly two,"
  so a reader skimming only the original wording (now edited) would have
  gotten a stronger impression than what's actually tested. The intent.md
  edit is the fix for that, not just this log entry.
- If overhead measurement (this slice's other Done item) is ever done
  against a Go-based *wrapped command* rather than `npm`, the same
  runtime-startup opens would appear in a real report too — worth
  remembering when `behavior-report` designs noise filtering later.

**If asked to defend this:** "The literal 'exactly two' wording assumed
a test child with no runtime of its own. Ours is the same Go test binary
re-exec'd, and the Go runtime makes its own real openat calls on startup
— a THP probe with no off switch, plus cgroup-based GOMAXPROCS detection
— before our two syscalls happen. Those are genuine, correctly-captured
events, not a bug, so we assert 'each of our two syscalls is reported
exactly once, no duplicates' instead of a total count, and changed the
checklist wording to match rather than leaving the doc overpromising."

---

## [2026-09-04] runChild no longer execve's the wrapped command — it becomes its ptrace tracer and stays PID 1

**Context:** `runChild` used to end in `syscall.Exec(argv0, cfg.Command,
childEnv(cfg))` — a direct image replacement, so the wrapped command
itself became PID 1 of the namespace (see DECISIONS.md 2026-09-01, which
already named this the reason signal delivery to it was unreliable and
deferred the fix to whichever feature needed a real PID 1). Building
syscall-capture requires a tracer process that outlives the syscall it's
watching, which `syscall.Exec`'s self-replacement structurally
forecloses — there is no Go code left on the other side of that call to
be a tracer of anything.

**What changed:** `runChild` now launches the wrapped command as a real
child (`syscallcapture.Run`, via `exec.Cmd` + `SysProcAttr{Ptrace:
true}` — never a manual `fork()`) and stays alive itself as PID 1 for
that child's entire run, acting as its ptrace tracer and its reaper.
This is a bigger structural change than `syscall-capture/intent.md`'s
own wording suggested: that doc talks about capturing syscalls, not
about which process ends up as PID 1 of the namespace, but delivering
the capture feature necessarily rewired who PID 1 *is*. On a normal
exit, `runChild` now mirrors the wrapped command's exit code via
`os.Exit`; on a signal death, it re-raises the same signal on itself
(covered by the "signal reporting" note below).

**Consequences:**
- Easy now: the sandbox-runner exit-code/stdio contract
  (`sandbox.Result`, `sandbox.Spec`) needed *no* changes — the mirroring
  above exists specifically so `sandbox.Run`'s own wait4 on the outer
  process keeps seeing the same shape of status it always did. All of
  sandbox-runner's existing tests pass unmodified against the new
  internals.
- Fixed as a side effect, not the point of this change: the 2026-09-01
  gap is closed. The wrapped command is PID 2 now, not PID 1, so it is
  no longer immune to signals sent to it from inside its own namespace —
  `kill -TERM $$` against it now behaves like an ordinary process, not
  like the no-op PID 1 exhibited. `sandbox.Result` still doesn't expose
  *which* signal (that YAGNI call from 2026-09-01 stands; nothing here
  forced revisiting it).
- Harder to reason about now: `runChild` owns a real ptrace event loop
  (see `internal/syscallcapture`) instead of a single library call, and
  correctness there depends on kernel ptrace/seccomp semantics that are
  easy to get subtly wrong (see the very next entry, found immediately
  by re-running sandbox-runner's own test suite against this change).

**If asked to defend this:** "PID 1 direct-exec and syscall tracing are
fundamentally incompatible — a tracer has to survive on the other side
of the syscall it's watching, and `execve` replacing your own image
guarantees the opposite. So the sandbox's PID 1 changed from being the
wrapped command itself to being a small supervisor that ptrace-attaches
it as PID 2, launched through `exec.Cmd`'s own fork+exec (never a manual
fork — the Go runtime doesn't survive one), and mirrors its exit code or
re-raises its signal so the outer `sandbox.Run` API never had to change."

---

## [2026-09-04] Seccomp filter inheritance vs. ptrace attachment: untraced forked children ENOSYS'd on their own exec

**Context:** Immediately after landing the runChild rewrite above, all
three of sandbox-runner's *existing* tests that let the traced shell fork
an external command (`readlink`, `cat`, `grep`, plus `cmd/cordon`'s own
`id -u` case) started failing with `Function not implemented`, while
shell builtins and the "no fork" tests stayed green. Re-running the full
existing suite (not just the new syscall-capture tests) is what caught
this — it wasn't visible from the syscall-capture package's own test
alone, since that test's traced process never forks.

**Root cause:** seccomp-bpf filters and ptrace attachment obey different
inheritance rules, which the original single-process-scope design (Q2,
same date) didn't account for:
- A seccomp filter **is inherited across `fork`/`clone`**, unconditionally
  — that's the whole point of it as a security boundary. Every process
  the traced shell forks inherits our openat/connect/execve filter.
- **ptrace attachment is not inherited.** The tracer was only attached to
  the one process it launched, per Q2's explicit "single directly-launched
  child, no `PTRACE_O_TRACEFORK`/`VFORK`/`CLONE`" scope.
- Per `seccomp(2)`: `SECCOMP_RET_TRACE` on a syscall with no tracer
  holding `PTRACE_O_TRACESECCOMP` for that *specific* pid does not skip
  quietly — the kernel refuses to execute the syscall at all and returns
  `-ENOSYS`. So every forked-but-untraced descendant's own `execve` (to
  become `readlink`, `cat`, `grep`, `id`, ...) or `openat` was outright
  refused, not merely unobserved. For a wrapped command that is mostly
  forking — `npm install` running `node`, `node-gyp`, `cc` — this would
  have broken the install itself, not just Cordon's visibility into it.

**Options considered:**
- **Drop seccomp, single-step every syscall via `PTRACE_SYSCALL` on just
  the one traced process.** No filter installed at all, so forked
  children are never touched — literally matches Q2's boundary. But it
  reintroduces the full per-syscall ptrace stop/resume overhead the
  seccomp-BPF filter existed specifically to avoid, undermining this same
  slice's own overhead-measurement goal.
- **Minimal auto-attach, still no event capture from descendants**
  (chosen). Add `PTRACE_O_TRACEFORK`/`VFORK`/`CLONE` to the traced
  process's ptrace options, so every new descendant lands in a
  ptrace-stop we own instead of running unattached. The loop resumes
  each one immediately — via `PTRACE_CONT`, with the same "swallow
  SIGSTOP, re-inject real signals" handling as the primary tracee — and
  never reads its registers or calls `onEvent` for it. Also re-applies
  the same option set to each newly-seen pid, since `PTRACE_O_TRACESECCOMP`
  is a per-tracee flag, not something a child inherits automatically —
  without that, a grandchild two levels down would ENOSYS again the same
  way.

**Chose:** Minimal auto-attach. This is **not** `syscall-capture-tree`
early — it touches the same three ptrace options that feature will also
need, but only to keep descendants alive and running, never to observe
or attribute their syscalls. `syscall-capture-tree`'s actual scope (event
capture and attribution across the tree) is unchanged and still not
built.

**Why:** The alternative (drop seccomp) trades away the one performance
property this design was chosen for, to fix a correctness bug that has a
narrower fix available. Auto-attaching without capturing is the narrowest
change that stops the kernel from refusing descendants' syscalls: it
costs one extra ptrace-stop-and-immediate-resume per new process the
traced command forks (bounded by how many processes it forks, not by how
many syscalls they make — nowhere near `PTRACE_SYSCALL`-everywhere cost),
in exchange for those descendants working at all.

**Consequences:**
- Easy now: sandbox-runner's full existing suite passes again, unmodified,
  against the new tracer/reaper internals — this was the regression bar
  the runChild rewrite (previous entry) was held to.
- Hard/watch-for later: `syscall-capture-tree`, when built, inherits a
  codebase that already sets these three options and already has a
  "new pid, first stop" branch in the wait4 loop — extending it to
  capture from that branch instead of blindly resuming should be small,
  but it's worth re-reading this entry first so the "swallow vs.
  re-inject" signal handling for auto-attached pids doesn't get
  duplicated or diverge by accident.
- Not measured yet: whether the extra attach/resume round trip per forked
  process is visible in the overhead number this slice still owes
  (real `npm install`, next).

**If asked to defend this:** "Seccomp filters propagate to every forked
child automatically; ptrace attachment does not. Without a tracer
attached to a specific process, a `SECCOMP_RET_TRACE` syscall in it
doesn't get skipped, it gets refused outright with ENOSYS — so scoping
ptrace to one process while still filtering by inheritance would have
broken every subprocess the wrapped command forks, not just hidden it
from us. The fix auto-attaches to catch and immediately release every
descendant, purely so the kernel has a tracer to hand the syscall to —
we still never read a single register from them. Full tracing of the
tree is still a separate, unbuilt feature."

---

## [2026-09-04] syscall-capture overhead measured against a real npm install

**Context:** `syscall-capture/intent.md`'s last Done item. `npm`/`node`
aren't installed on this dev machine (only a Windows-side `npm` reachable
via WSL interop at `/mnt/c/...`, unusable inside a Linux mount namespace)
and there's no passwordless `sudo` to install them system-wide — installing
system packages non-interactively wasn't something to just do unasked, so
used Node's official self-contained linux-x64 tarball instead (no root,
extracted under the scratchpad, discarded after — the dev machine's
system Node/npm status is unchanged by this).

**Method:** `node <npm-cli.js> --prefix <dir> --cache <shared-cache>
install lodash` (a small package with no native build step, chosen so
this baseline isn't also measuring compiler invocation time), 3 trials
each, wrapped (`cordon run`) vs. unwrapped (bare), same warmed npm cache
shared between both so neither side pays a cold-cache network penalty
the other doesn't. Invoking `node` directly on `npm-cli.js` rather than
the `npm` shebang script sidesteps a separate, uninteresting gap: the
sandbox's env is not yet caller-configurable (`sandbox.go`'s standing
note on `childEnv`), so `#!/usr/bin/env node` can't resolve inside it
without a PATH entry that doesn't exist yet — not something to fix as a
side effect of a measurement.

**Result:**
| | trial 1 | trial 2 | trial 3 | mean |
|---|---|---|---|---|
| unwrapped | 0.865s | 0.756s | 0.789s | 0.803s |
| wrapped (`cordon run`) | 1.473s | 1.572s | 1.488s | 1.511s |

Absolute overhead ≈ **0.71s**, relative ≈ **+88%** (1.88×) for this
install. That total is sandbox-runner's namespace/rootfs setup (already
present before this feature) plus this slice's new re-exec-as-tracee,
seccomp filter install, and ptrace event loop — not broken out
separately here (no git history in this repo to diff against a
pre-syscall-capture build for an isolated before/after; a repo-tracked
before/after wasn't available to produce that breakdown, this is a
combined number). `lodash` has no native build step and never forks, so
this also doesn't exercise the minimal-auto-attach path from the entry
above at all — consistent with the "lower bound, not the real per-tree
cost" caveat already logged in the Q2 scope-split entry, now with an
actual number attached to what "lower bound" means: 0.7s is the floor
for a single-process install; anything that forks (`node-gyp`, `cc`)
adds an attach/resume round trip per forked process on top, unmeasured.

**Consequences:**
- Recorded, not yet judged against a bar — **correction**: INTENT.md §3
  Observation layer *does* set one explicitly ("an install must not take
  noticeably longer. Measured, not assumed"), missed when this entry was
  first written. Superseded by the next entry, which checks a real
  dependency-tree-plus-forked-postinstall install against that actual
  bar instead of `lodash`'s no-fork case.
- Revisit when `syscall-capture-tree` lands: the same measurement
  against a package with a real native build step (e.g. one using
  `node-gyp`) would show whether per-forked-process attach overhead is
  significant at scale, which `lodash` structurally cannot reveal.

**If asked to defend this:** "0.7 seconds absolute, about 88% relative,
on a small no-native-build install — that's sandbox-runner's existing
namespace setup plus this feature's ptrace/seccomp tracer combined, not
broken out further since there's no pre-feature build in this repo to
diff against. It's a floor, not the real number for anything that forks
subprocesses, since `lodash` doesn't."

---

## [2026-09-04] Real overhead number: +72% on a dependency-tree-plus-forked-postinstall install — fails INTENT.md §3's bar as measured

**Context:** The previous entry's number was an explicitly-acknowledged
floor: no dependency tree, no forked subprocess, and measured against a
throwaway tarball extraction rather than a properly-installed toolchain.
Before a commit or `/ultrareview`, INTENT.md §3 Observation layer's actual
requirement needed checking against real data: *"an install must not take
noticeably longer. Measured, not assumed."*

**Getting real node/npm without a workaround:** still no passwordless
`sudo` and no C/C++ toolchain (`g++`/`make` both absent — a real
native-build package like `bcrypt` would fail to install here regardless
of Cordon), so a genuine native-build measurement isn't obtainable on
this machine at all right now. Installed Node's official tarball
properly this time, though: under `~/.local/node`, matching the existing
`~/.local/go` convention exactly, with the same "add to `~/.bashrc`,
not on PATH in a fresh non-interactive shell" pattern documented at the
top of this file for Go. `node --version` / `npm --version` now work
as ordinary installed tools, not a scratchpad extraction discarded after
one measurement.

**Getting a realistic install target:** built a small local fixture —
`cordon-overhead-demo`, depending on `express` (a real, moderate
dependency tree: 69 packages) plus a local `file:` dependency
(`forker-postinstall`) whose `postinstall` script forks a real subprocess
chain (`sh -c` → `node -e ...` → `child_process.execSync('true')` → `sh
-c` → `true`). This is the case the previous measurement explicitly
couldn't cover and the case `syscall-capture` exists for — supply-chain
postinstall scripts are INTENT.md §1's whole threat model, not native
builds specifically.

Two real resolution problems surfaced getting this to run at all, both
fixed without touching Cordon's own code:
- The `npm` CLI's own shebang (`#!/usr/bin/env node`) can't resolve
  inside the sandbox — its fixed PATH doesn't (and structurally can't,
  without editing `roSystemDirs`, a real mount-surface change out of
  scope for a measurement) contain a directory holding `node`, since
  nothing under `$HOME` is bind-mounted and nothing was installed to
  `/usr` (no `sudo`). Invoked `node <npm-cli.js>` directly instead — not
  a hack, this is a legitimate, common way to run npm without a PATH
  dependency, and it's necessary for a fair unwrapped-vs-wrapped
  comparison anyway (both sides need the identical invocation).
- The fixture's own `postinstall` script hit the same problem
  one level down: `node -e ...` inside the forked `sh -c` couldn't find
  `node` on the sandbox's PATH either. Fixed by having the script
  reference `$npm_node_execpath` (an absolute path npm itself injects
  into every lifecycle script's environment) instead of bare `node` —
  again standard npm practice, not a workaround, and it means this
  finding generalizes: **any Cordon-wrapped native-build or postinstall
  script that assumes `node` is on `PATH` rather than using
  `$npm_node_execpath`/`$npm_execpath` will currently fail the same way.**
  That's a real, separate gap in the current sandbox (env/PATH isn't
  caller-configurable yet — `sandbox.go`'s standing `childEnv` note) worth
  flagging on its own, not something this measurement task should fix as
  a side effect.

**Method:** 3 trials each, wrapped vs. unwrapped, `node <npm-cli.js>
--prefix <dir> --cache <shared-cache> install` against a fresh copy of
the fixture per trial, same warmed cache shared by both sides.

**Result:**
| | trial 1 | trial 2 | trial 3 | mean |
|---|---|---|---|---|
| unwrapped | 1.496s | 1.412s | 1.505s | 1.471s |
| wrapped (`cordon run`) | 2.591s | 2.537s | 2.472s | 2.534s |

Absolute overhead ≈ **1.06s**, relative ≈ **+72%** (1.72×). All three
wrapped trials completed successfully (69 packages installed, postinstall
ran) — the minimal-auto-attach fix from two entries back is what made
that possible at all; without it this install would have failed outright
(the forked `sh`/`node`/`true` chain would ENOSYS on their own execve).

**What's driving it — confirmed, not assumed:** wired a standalone
instrumented build of `syscallcapture.Run` (ptrace directly, no
namespace — namespace overhead isn't syscall-capture's to explain) against
the same fixture and counted captured events by type: **5,603 `openat`,
1 `connect`, 0 `execve`**. (The `execve`s from the postinstall's own fork
chain are the auto-attached-but-unobserved descendants from the ENOSYS
fix — consistent with, and now direct evidence for, the "lower bound"
caveat on the Q2 scope-split entry.) `openat` alone costs **two** ptrace
stop/resume round trips in the current implementation (the seccomp entry
stop, then a `PTRACE_SYSCALL` single-step to the syscall's exit so the
returned fd can be resolved to a real path — see `handleOpenat`'s doc
comment) — so this one install drove on the order of 11,000+ ptrace
context switches from `openat` handling alone, dwarfing the handful of
auto-attach round trips the forked postinstall chain added (a handful of
processes, one attach-and-release each) and the single `connect`. The
per-syscall seccomp filter is doing its job — only 4 syscall numbers are
ever trapped, not every syscall the process makes — but `openat` volume
on a real package extraction is large enough, and this implementation's
per-`openat` cost is high enough (2 round trips, not 1), that it's the
dominant cost by a wide margin. Not measured directly, and not yet called
out anywhere in the code: how much of the per-round-trip cost is
context-switch overhead intrinsic to ptrace itself versus this
implementation's own choice to re-open `/proc/<pid>/mem` per string read
(`readCString`, `readArgv`, `readMem` each open and close their own fd)
rather than caching it across the tracee's lifetime.

**Against the actual bar:** INTENT.md §3: *"an install must not take
noticeably longer."* +72% / +1.06s on a 69-package install is noticeably
longer by any plain reading — this fails that bar as currently measured.
Recording that plainly rather than as a number without a verdict, per the
correction on the previous entry. No fix applied here — per instruction,
this is reported, not remediated, pending a decision on whether to
optimize now or accept as a known gap for this slice.

**Consequences:**
- Real, not a floor: this exercises a genuine dependency tree and a
  genuine forked subprocess chain, so unlike the previous entry's number
  this one isn't caveated as missing the fork case — though it's still a
  single data point on one fixture, not a corpus.
- Open decision, not resolved here: whether `openat`'s double round-trip
  is worth optimizing (e.g., only resolving the fd path on the subset of
  opens that actually matter for a report, or caching the `/proc/<pid>/mem`
  fd instead of reopening it per read) now, versus accepting this as this
  slice's known-gap the way every other limitation in this feature has
  been handled.
- The `$npm_node_execpath` finding above is a real, separate, actionable
  gap in the sandbox's current env-forwarding story, independent of this
  measurement's verdict — worth its own decision later, not bundled into
  this one.

**If asked to defend this:** "+72% relative, about 1.06 seconds, on a
real 69-package install with a forked postinstall script — measured with
a properly-installed Node toolchain and a fixture that actually exercises
the fork case the previous, lower-bound number couldn't. Confirmed the
cause directly with an instrumented count rather than assuming: 5,603
`openat` calls, each costing two ptrace round trips in this
implementation, dwarf everything else including the forked-process
handling. That's a real fail against INTENT.md §3's 'must not take
noticeably longer' bar, reported as such rather than softened, with no
fix applied yet — that's a decision for the two of us, not one to make
unilaterally while measuring."

---

## [2026-09-04] openat fast path for absolute paths: skip the exit-stop when there's nothing for it to resolve

**Context:** The previous entry measured +72% / +1.06s against INTENT.md
§3's "must not take noticeably longer" bar and identified `openat`'s
double ptrace round trip (seccomp entry-stop, then a `PTRACE_SYSCALL`
step to the syscall's exit so the returned fd can be resolved to a real
path via `/proc/<pid>/fd/<n>`) as the dominant cost, driven by volume
(5,603–7,734 `openat` calls on a real install) rather than by anything
about the auto-attach/forking machinery. Told to treat this as
optimize-now, not an accepted gap.

**Instrumented before proposing anything** (temporary trace line added to
`handleOpenat`, removed before this change; not left in the tree). On the
`express` + forked-postinstall fixture, 7,734 `openat` calls:
- **100% used an absolute path at entry.** Zero needed cwd/dirfd-relative
  resolution — the exit-stop's relative-path justification doesn't apply
  to this workload at all.
- Of those, 51% failed (`ENOENT` — Node's own speculative
  module-resolution probing) and 49% succeeded.
- Of the successful ones, 94.4% had `raw pathname == readlink(fd)` —
  the exit-stop's answer already matched the entry-stop's argument. The
  5.6% that differed were **all** OS/runtime plumbing sampled directly
  (`/proc/self/maps` → `/proc/<pid>/maps`, `/etc/resolv.conf` →
  `/mnt/wsl/resolv.conf`, glibc `.so` version symlinks, `/etc/localtime`)
  — none were inside `node_modules` or any project file.

**Chose:** In `handleOpenat`, when the raw pathname argument is absolute,
skip the `PtraceSyscall`+wait+`PtraceGetRegs`+`readlink` exit-stop
entirely and report `Event{Path: rawPath}` straight from the entry-stop —
one `PtraceCont`, not two round trips. Relative paths still take the full
double-round-trip path unchanged, even though this workload had zero of
them: still architecturally reachable (a different tool, a different
lifecycle script, `fs.openSync` with a relative path or non-`AT_FDCWD`
dirfd), and the instrumented data only says *this* workload didn't hit
it, not that nothing ever will.

**This trades detection precision, not isolation — worth stating
directly since it's the obvious question:** `Event.Path` feeds the
(best-effort, INTENT.md §1) behavior report only. It has zero bearing on
what the mount/namespace sandbox actually confines — `setupRootfs`,
`pivot_root`, the read-only binds, none of that is touched by this
change or by anything in `syscallcapture` at all. INTENT.md §1 draws the
line explicitly: isolation is the hard boundary, detection is
best-effort. This fix narrows precision *within* the best-effort
category (the rare absolute-path symlink case now goes unresolved,
reported as the symlink itself rather than its target) — it does not
touch, weaken, or trade against the hard boundary.

**Also not a new failure mode:** a *failed* open already reported
`rawPath` unmodified before this change (`path := rawPath`, never
overwritten when there's no fd to resolve) — that behavior was already
shipped and accepted. This change extends that exact same
already-accepted "report the raw argument when there's nothing better"
behavior to the wider absolute-path case (which now includes most
successful opens too, not just failed ones), rather than introducing a
new category of imprecision.

**Result — re-ran the identical `express` + forked-postinstall benchmark
for an apples-to-apples comparison:**
| | before this fix | after this fix |
|---|---|---|
| unwrapped mean | 1.471s | 1.533s |
| wrapped mean | 2.534s | 2.033s |
| absolute overhead | +1.06s | **+0.50s** |
| relative overhead | +72.3% | **+32.7%** |
| ratio | 1.72× | **1.33×** |

Absolute overhead roughly halved, relative overhead cut by more than half.
**Still fails INTENT.md §3's "must not take noticeably longer" bar as
measured** — +32.7% is real, perceptible slowdown, just a much smaller
one. Not closed all the way to parity by this change alone.

**Deliberately not bundled into this change:** narrowing
`SECCOMP_RET_TRACE`'s scope itself (e.g. dropping `openat2`, which was
0/7,734 calls in this workload) was raised as a second, independent
lever if this fix didn't close the gap enough. Per instruction, holding
off on that rather than speculatively bundling a second optimization
into one change — the new +32.7% number is what should drive whether
that's worth doing, not an estimate made before this fix's real impact
was known.

**Consequences:**
- Confirmed test coverage: `TestRun_CapturesOpenatAndConnect_ExactlyTwoEvents`
  uses an absolute-path (`t.TempDir()`-based) known file, so it already
  exercises the new fast path on every run — no separate test needed for
  that behavior, though there is no dedicated test yet for the
  relative-path fallback path specifically (untested by *this* codebase's
  own suite, only by the instrumented investigation above finding zero
  such calls in a real workload).
- Open decision, still not resolved: whether the remaining +32.7% is
  acceptable, needs `SECCOMP_RET_TRACE` scope narrowing, or something
  else — deferred to whoever picks this back up with the new number in
  hand.

**If asked to defend this:** "100% of a real install's `openat` calls
used absolute paths with no need for cwd/dirfd resolution — instrumented
that rather than assuming it. The exit-stop's only remaining value for
those is resolving the rare symlink case, and every sampled instance of
that was OS plumbing, never a project file, so we skip it and report the
raw argument — exactly the same fallback a failed open already used
before this change, just applied more broadly. That's a precision
trade-off within the best-effort detection category INTENT.md §1 already
defines; it has no effect on the isolation boundary, which nothing in
this package touches. It roughly halved the overhead, +72% down to +33%,
but didn't fully close the gap — we held off on the second lever
(seccomp scope narrowing) rather than guess whether it's still needed
before seeing this real number."

---

## [2026-09-04] Relative-path openat fallback: was live, security-relevant code with zero test coverage

**Context:** The openat fast-path fix (previous entry) left `handleOpenat`'s
slow path — the `PTRACE_SYSCALL` exit-stop plus `/proc/<pid>/fd` readlink
resolution, still the only path for relative-path opens — untested by
anything in the suite. Instrumentation had shown 0/7,734 real-install
calls were relative, which explained *why* it went unexercised, not
*that it should stay that way*: it's still live, reachable, security-
relevant code (a different tool, a different lifecycle script, or a
future workload could easily hit it), and untested code on the precision-
sensitive capture path is a real gap independent of whatever the overhead
decision ends up being.

**Chose:** Added `TestRun_CapturesOpenatViaRelativePath_ResolvesRealPath` —
a dedicated helper mode (`runRelativeHelper`) that `chdir`s into a known
directory and opens a file by bare name, guaranteeing a non-absolute
pathname argument (the exact condition `handleOpenat` branches on). The
test asserts the reported `Event.Path` equals the real resolved absolute
path, not the raw relative string — proving the exit-stop/readlink
resolution actually ran, not just that some event fired.

**Consequences:**
- The precision-sensitive fork in `handleOpenat` (fast path vs. slow
  path) now has direct coverage on both branches, not just the one real
  workloads happen to exercise.
- Still not covered: a non-`AT_FDCWD` dirfd-relative open (`openat(fd,
  "name", ...)` with a real directory fd rather than the cwd). The code
  doesn't special-case dirfd at all — it only branches on the leading
  byte of the pathname argument — so a cwd-relative open exercises the
  identical branch a dirfd-relative one would; a dedicated dirfd test
  would prove the same code path again, not new code.

---

## [2026-09-04] Remaining +32.7% overhead: instrumented and explained — fixed per-call ptrace cost dominates, ~half of it spent on calls that were never going to matter

**Context:** Told to instrument before proposing a next fix, specifically
checking (1) whether fixed per-call ptrace cost (seccomp trap + context
switch + `PtraceCont`, paid even on the fast path) is now the dominant
remainder, and (2) what share of total `openat` volume is Node's own
speculative module-resolution probing (opens that fail `ENOENT` and were
never going to be security-relevant).

**Method — (1), fixed per-call cost:** built a synthetic microbenchmark
(temporary `cmd/perfprobe`, removed after use, not left in the tree): a
tight loop of 5,000 `open`+`close` calls against one small existing file
(absolute path, always succeeds — isolates the fast path's own per-call
cost from real filesystem/extraction work), run both untraced and under
`syscallcapture.Run` directly (no namespace — namespace setup isn't
`syscallcapture`'s to explain), 3 trials each:

| | mean (5,000 calls) | per-call |
|---|---|---|
| untraced | 31.6ms | 6.3µs |
| traced (fast path) | 370.1ms | 74.0µs |

Marginal per-call ptrace cost: **~67.7µs** — the fixed cost of one
seccomp-trap stop, `PtraceGetRegs`, and `PtraceCont`, now that the exit
round trip is gone for absolute paths.

**Method — (2), ENOENT probe volume:** already had this from the
fast-path investigation two entries back and it doesn't change with this
fix (success/failure doesn't affect which path `handleOpenat` takes
anymore, only how many round trips it costs): of 7,734 real-install
`openat` calls, 51% failed (`ENOENT`, Node's own speculative
module-resolution probing — trying `index.js`, `.js`, `package.json`,
etc. against paths that don't exist) and 49% succeeded.

**Combining them:** 67.7µs × 7,734 calls ≈ **0.524s** — matches the
measured wrapped-vs-unwrapped overhead (0.501s) closely enough (within
~5%) to say plainly: **`openat`'s fixed per-call ptrace cost now accounts
for essentially all of the remaining overhead.** `connect` (1–2 calls)
and `execve` (0 reported, by design — see the ENOSYS-fix entry) are
negligible; auto-attach for the postinstall's handful of forked
descendants is a handful of attach-and-release round trips, not
thousands. Of that ~0.52s, **49% (≈0.257s) is spent on calls that fail
and were never going to be security-relevant** — Node's own
module-resolution mechanics, not the wrapped program's real file access.

**Answering the two specific questions:**
1. Yes — fixed per-call cost is now the dominant (essentially sole)
   remaining driver, confirmed by a synthetic benchmark that isolates it
   from everything else, not inferred from the aggregate number alone.
2. Yes — roughly half of total call volume, and by extension roughly
   half of the per-call-cost-driven overhead, is spent on opens that
   fail and are structurally never going to matter for the report. This
   is a real, sizable share — *if* a legitimate way exists to reduce
   stop volume for that subset rather than cost per stop, it would be
   worth pursuing. No such mechanism was designed or implemented here,
   per instruction: seccomp-bpf can't inspect path-string content or
   syscall outcome to filter on, so "reduce stops for opens that will
   fail" isn't a straightforward BPF-level change — this is flagged as
   an open question for whoever picks the lever up, not solved.

**Not implemented, per instruction:** no `SECCOMP_RET_TRACE` scope
narrowing (`openat2`, etc.) — that lever is still just a name on a list,
not attempted, since the data above already explains where the overhead
goes without it.

**Consequences:**
- +32.7% is not being carried forward as an unexplained number: it's
  now attributable, in order, to `openat` call volume × per-call ptrace
  cost, roughly half of which is inherently-unavoidable-with-this-design
  cost on module-resolution probes.
- Open decision, unchanged from the previous entry: accept +32.7% as
  this slice's documented gap, or pursue reducing `openat` stop volume
  for the failing-probe subset specifically (a real but not yet designed
  lever) — deferred to whoever picks this up with these numbers in hand.

**If asked to defend this:** "A synthetic 5,000-call microbenchmark
isolated the fixed cost of one traced-but-fast-pathed openat at about
68 microseconds; multiplied by the real install's 7,734 calls that lands
within 5% of the measured overhead, so this is now explained, not
mysterious. About half of those calls are Node's own failed
module-resolution probes — real volume, but not security-relevant volume
— so if there's a further lever here, it's reducing *how many* opens get
stopped for that subset, not making each stop cheaper, which is
already close to its floor."

---

## [2026-09-04] Found while instrumenting overhead, not what was asked: openat/connect/execve events from a traced process's *other threads* are silently dropped

**Context:** Not part of what was asked this round — surfaced as a
byproduct of the synthetic per-call-cost microbenchmark above, whose
event *counts* came back far lower than the number of loop iterations
that actually ran (e.g. 1,372–1,848 reported openat events against 5,000
real calls, even with `GOMAXPROCS=1`). Investigated rather than
dismissed as microbenchmark noise, since a mismatch between "syscalls
made" and "events reported" is exactly what INTENT.md's "silently
dropping a captured event is not [acceptable] — that's a bug, not a
coverage limit" rules out.

**Root cause, confirmed directly (not inferred):** added a temporary
probe (removed after use) reading `/proc/<wpid>/status`'s `Tgid:` line
for every seccomp stop the tracer resumes without reading. Confirmed:
some of those wpids share the **same `Tgid` as the primary traced
process** — i.e. they are additional **OS threads of the one process
being traced**, not separate child processes. On the real
`express`+forked-postinstall install, of 1,273 dropped stops, 5 distinct
wpids shared the primary's `Tgid` (Node's libuv thread-pool workers —
`fs` calls and DNS resolution are offloaded to that pool by default);
the other 3 wpids were genuinely separate processes (the postinstall's
`sh`/`node`/`true` chain, already known and accepted per the Q2 scope
split and the ENOSYS-fix entry).

**Why this happened:** `PTRACE_O_TRACECLONE` (set for the ENOSYS fix,
DECISIONS.md two entries on tree-tracing back) fires on *any* `clone()`
that isn't a fork/vfork — which includes `CLONE_THREAD` thread creation,
not just new child processes. The auto-attach dispatch in `Run`'s main
loop only special-cases `wpid == pid` (the original thread group leader);
every other wpid — whether a forked child's process or a sibling thread
of the *same* process — takes the identical "resume without reading"
branch. Sibling threads were never distinguished from forked children.

**Why this is not the same thing as the Q2 scope split:** Q2 scoped
tracing to "the single directly-launched child," explicitly meaning *one
process*, not *one thread of one process* — deferring visibility into
separate forked processes (`node-gyp`, `cc`, a postinstall's `sh`) to
`syscall-capture-tree` was a deliberate, documented decision. Missing a
*sibling thread of the very process being traced* was never that
decision; it's an oversight this single-process design didn't account
for, because Linux ptrace/seccomp both operate at the task (thread)
level, not the process level, and "single process" was implemented as
"single thread group leader" without handling the rest of that leader's
own thread group.

**Impact, stated plainly:** any multi-threaded traced program — which
includes Node.js itself, via libuv's default thread pool for `fs`/DNS —
is silently missing events from its own worker threads right now. That
also means the overhead numbers logged in the entries above (5,603–7,734
`openat` events) are undercounts of the *true* syscall volume `node`/`npm`
actually made; the true volume, and therefore the true per-call-cost
contribution, is higher than reported there. The wall-clock overhead
numbers themselves are unaffected (every stop, read-and-reported or
silently resumed, still pays its ptrace round-trip cost — that's why the
67.7µs/call estimate lined up with measured overhead regardless of this
bug), but the event *counts* and volume breakdowns in the two entries
above should be read as lower bounds on true syscall volume, not exact
totals.

**Not fixed here.** This is a correctness bug against `syscall-capture`'s
own already-shipped Done checklist, discovered mid-investigation of a
performance question this round explicitly wasn't scoped to answer. It
needs its own decision — at minimum, whether the fix is "recognize
same-`Tgid` wpids and route them through `handleSeccompStop` like the
primary" (keeps the single-*process* tracing promise, extends it to mean
what it should have meant from the start) or something closer to
`syscall-capture-tree`'s scope (attribution across a real tree, threads
included) — flagged for that decision rather than patched unilaterally
while answering an overhead question.

**If asked to defend this:** "Traced a microbenchmark's event counts
against its known call count as a sanity check on the overhead numbers,
and they didn't match — 5,000 calls, far fewer than 5,000 events, even
single-threaded from Go's perspective. Root cause: our auto-attach logic
treats every non-primary wpid identically, but some of them are sibling
*threads* of the very process we're tracing, not separate child
processes — Node's own libuv thread pool, for instance. That's a real
gap against our own 'don't silently drop events' rule, found as a
byproduct of a performance investigation, not fixed inline — it's a
correctness decision on its own, not something to bundle into an
overhead answer."

---

## [2026-09-04] Sibling OS thread events were silently dropped — fixed via Tgid, not Pid

**Context:** The previous entry found that a traced process's other OS
threads (Node.js's libuv thread pool, confirmed on a real install) were
silently missing from capture — `PTRACE_O_TRACECLONE` (set for the
ENOSYS fix, two entries further back) fires for new *threads*
(`CLONE_THREAD`) exactly as it does for new *processes* (a real `fork`),
and the dispatch loop only ever special-cased `wpid == pid`, treating
every other wpid — sibling thread or separate process alike — as an
unobserved auto-attached descendant. Told to fix this now, not defer it:
it's inside the committed single-process scope, not the deferred tree,
so the feature wasn't done until this was fixed.

**The reusable insight: `Tgid`, not `Pid`, is what "process" means to
ptrace/seccomp.** Both operate at the Linux *task* (thread) level. A
`Pid` returned by `fork`/`clone` without `CLONE_THREAD` is a new task
that is also the leader of a brand-new thread group, so for a freshly
launched process `Pid == Tgid` — but any *sibling* thread created inside
that process afterward gets its own distinct `Pid` (its TID, in
`/proc/<tid>` terms) while sharing the *same* `Tgid`. "Single process"
was implemented as "single `Pid` equal to the one we launched," which is
actually "single *thread*, thread-group-leader only" — silently
narrower than what the checklist's own words mean. The fix widens the
identity check from `Pid` equality to `Tgid` equality.

**Fix:**
- `Run`'s main loop now maintains two maps instead of one: `known` (has
  this wpid's attach-stop been consumed — unchanged) and `observed`
  (does this wpid get its syscalls actually read and reported).
  `observed` is seeded with just `{pid: true}`.
- At a new wpid's first stop, `sameThreadGroup(wpid, pid)` reads
  `/proc/<wpid>/status`'s `Tgid:` line; if it equals the primary's pid,
  `observed[wpid] = true`.
- The `PTRACE_EVENT_SECCOMP` dispatch branch changed from `if wpid ==
  pid { handleSeccompStop(pid, ...) }` to `if observed[wpid] {
  handleSeccompStop(wpid, ...) }` — note `wpid`, not `pid`, is now
  threaded through: `handleSeccompStop`/`handleOpenat`/`handleConnect`/
  `handleExecve` already took their target task as a plain parameter and
  used it uniformly for every ptrace/`/proc` call, so nothing inside
  them needed to change, only which task the dispatcher hands them.

**Sibling threads fold into the primary's existing state — no new
attribution added.** `Event` carries no per-task field before or after
this fix; a sibling thread's `openat` is reported through the exact same
`onEvent` callback as the primary's, indistinguishable from it. This
matches what "the traced process did X" already meant for the primary's
own syscalls and deliberately stops short of `syscall-capture-tree`'s
later goal of per-task attribution across a real tree — that's a
different, larger feature, not something to preview here as a side
effect of a bug fix.

**Cleanup timing (asked to state precisely, not just "eventually"):**
`delete(known, wpid)` and `delete(observed, wpid)` both happen in the
`case ws.Exited(), ws.Signaled():` branch — i.e. at the exact `wait4`
result that reports **wpid's own** `WIFEXITED`/`WIFSIGNALED` status, not
at some later "done processing its events" point. That's what makes the
PID-reuse defense actually correct: by the time the kernel could
possibly hand that numeric pid/tid to an unrelated new task, this code
has already forgotten everything it knew about the old one. A new task
later carrying a recycled number starts in neither map and is
reclassified from scratch by its own `Tgid` read, never inheriting a
stale classification.

**Sanity-checked before relying on it (asked to confirm, not assume):**
does `pid == pid`'s own Tgid hold reliably at the primary's very first
stop, including through the two-level re-exec chain (`sandbox.runChild`
→ `syscallcapture`'s own tracee-helper re-exec → the final `syscall.Exec`
into the real wrapped command)? Yes, with no momentary window where it
doesn't — and no `/proc` read is needed to establish it in the first
place:
- `pid := cmd.Process.Pid` is the PID `os/exec`'s own fork+exec returned
  for a **freshly created process** (not a thread) — by kernel
  invariant, a new process's `Pid` always equals its own `Tgid` at
  creation, unconditionally.
- `execve` — both the tracee-helper's self-exec into the final command
  and any further `execve` the wrapped program makes — replaces the
  process image in place and never changes `Pid`/`Tid`/`Tgid`. So `pid`
  captured once, immediately after `cmd.Start()`, stays valid as "the
  primary's Tgid" for the whole traced run, through every exec, and for
  any thread the wrapped program creates at any later point.
- The primary's own membership in `observed` is seeded directly from
  `pid` — no `/proc` read, no comparison, nothing that could race. The
  `/proc/<wpid>/status` read only ever happens for genuinely *other*
  wpids, and by the time any stop for a brand-new wpid is even visible
  to the tracer, the kernel has already fixed that task's `Tgid`
  permanently — there's no point at which it could be read incorrectly,
  only a point at which the read could fail outright (the task already
  exited), which `sameThreadGroup` already treats as "not a sibling
  thread," the safe direction.

**Test:** `TestRun_CapturesOpenatFromSiblingOSThread` — two goroutines,
each `runtime.LockOSThread()`'d (the same primitive `Run`'s own doc
comments already cite, for the same underlying reason: ptrace state is
per-OS-thread), each opening a different known file concurrently.
Verified this is a real regression test, not just plausible-looking:
temporarily reverted the dispatch condition back to `wpid == pid` and
reran — one of the two files' `openat` was silently missing, 3/3 times,
confirming the test fails without the fix and passes with it restored.

**Re-verified on the real `express`+forked-postinstall install** (same
diagnostic technique as the previous entry — a temporary counter on the
"resume without reading" branch, tagged with `sameThreadGroup`, removed
after use): dropped-stop count with the primary's own `Tgid` — the
sibling-thread case this fix targets — is **0, stable across 3 runs**.
Dropped stops with a *different* `Tgid` (the postinstall's forked
`sh`/`node`/`true` chain — genuinely separate processes, still correctly
unobserved per the Q2 scope split) continued as before, unaffected. The
*total* dropped-stop count varies run to run for reasons unrelated to
this fix (network-dependent `npm audit` behavior affecting `connect`
volume, already noted as a source of variance) — the number that matters
for this fix, same-`Tgid` drops, was checked in isolation and held at
zero every time.

**Consequences:**
- `syscall-capture`'s Done checklist item for `openat`/`connect`/`execve`
  capture is re-checked in both `INTENT.md` and its own `intent.md`,
  with a note pointing back here rather than silently re-checked with no
  trail.
- `known`/`observed` are per-run maps, cleaned up incrementally as
  documented above rather than only at `Run`'s return — no unbounded
  growth for a long-running traced process that creates and destroys
  many short-lived threads.
- Unaddressed, out of scope for this fix: a genuinely dirfd-relative
  open (`openat(fd, ...)` with a real directory fd, not `AT_FDCWD`) from
  a sibling thread — `handleOpenat`'s relative-path slow path is
  per-task-generic already (takes its target task as a parameter, same
  as everything else touched here), so this should already work, but it
  isn't separately tested; the existing relative-path test uses the
  primary thread only.

**If asked to defend this:** "ptrace and seccomp both work in terms of
Linux tasks, not processes — Pid and Tgid coincide for a thread-group
leader but diverge for every other thread it creates. Our dispatch only
recognized the one Pid we launched, so sibling threads (Node's own
libuv thread pool, on a real install) were silently treated as unrelated
descendants and never read. The fix classifies each newly-seen task once
by its Tgid instead of comparing Pid, folds sibling-thread events into
the same reporting the primary already gets — no new per-task
attribution, that's a larger, separate feature — and cleans up its
bookkeeping at the exact wait4 stop that reports a task's own exit, so a
later PID reuse can't inherit a stale classification. Verified as a real
fix three ways: a synthetic two-thread test that provably fails without
the change, a real npm install showing same-Tgid drops at zero across
repeated runs, and confirmation that the primary's own Tgid identity
needs no runtime check at all, so there's no window where it could be
wrong."

---

## [2026-09-04] Closing check: confirmed different-Tgid drops are cleanly ignored, not coincidentally the same count as a hidden failure

**Context:** Before calling `syscall-capture` done, checked whether "the
different-Tgid drop count is unchanged" (previous entry) could be masking
a different problem landing on the same number by coincidence — e.g.
`sameThreadGroup` silently defaulting to "not observed" on a `/proc` read
failure for what were actually sibling threads, rather than genuinely
classifying a different process.

**Method:** temporary dual instrumentation (removed after use): one
probe at classification time logging each newly-seen wpid's actual
`Tgid:` line and `comm` (not just the boolean `observed` result), a
second, independent probe at the "resume without reading" call site
itself. Confirmed there is exactly one call site for
`handleSeccompStop` in the whole file (`grep`, before adding anything),
gated by `observed[wpid]` — so there is no second, silent path by which
a register read could be attempted and fail unnoticed.

**Result — every wpid that actually hit the unobserved-resume path had
its own distinct Tgid, verified by direct read, not a fallback:**

| wpid | Tgid | comm | identity |
|---|---|---|---|
| (14 wpids) | primary's Tgid | `exe`→`node`→`npm` | the primary's own libuv thread pool — `observed=true`, correctly folded in |
| 43668 | itself | `npm install` | npm's fork before exec'ing the lifecycle-script runner |
| 43669 | itself | `sh` | the postinstall's shell |
| 43670–43675 | **43669**, not the primary | `node` | `sh`'s *own* libuv thread pool, spun up after it exec'd into `node -e ...` |
| 43676 | itself | `node` (pre-exec) | the fork that becomes `true`, caught before its own exec |

None of the unobserved wpids' `Tgid:` lines were absent or malformed —
each read cleanly and either matched the primary (→ observed) or matched
its *own* wpid or another already-known non-primary Tgid (→ correctly
not observed). The `PtraceGetRegs`/`handleSeccompStop` call count for
every one of these was independently confirmed at zero.

**Genuinely new information, not just confirmation:** the forked
descendant `sh`→`node` (43669) spawns its *own* sibling threads
(43670–43675) once it execs into `node`. These are correctly classified
`observed=false` — they share `Tgid=43669`, not the primary's — meaning
the fix in the previous entry distinguishes "sibling thread of the
primary" from "sibling thread of some other, unobserved process"
correctly, not just "any thread sharing a Tgid with something we've
seen." Confirms `syscall-capture-tree`'s eventual scope is real and
non-trivial: it isn't just "trace the forked processes," it's "trace the
forked processes *and their own thread pools*," a detail this
confirmation check surfaced but this feature still correctly leaves
alone.

**Consequences:** none beyond confidence — no code changed in this
check. `syscall-capture` is done: the Done checklist items are correctly
checked, the sibling-thread fix is verified as a real fix (not a
coincidental count match) via direct process-identity evidence, and the
remaining out-of-scope surface (`syscall-capture-tree`) is now documented
with one concrete additional detail (nested thread pools) for whoever
picks it up.

**If asked to defend this:** "Checked whether 'drop count unchanged'
could mean 'still broken, just differently' rather than 'correctly
deferred' — traced every wpid that hit the unobserved path back to its
actual `/proc`-read Tgid and process name, not just its boolean
classification. Every one was a genuine, identifiable different process
(npm's fork, the postinstall's `sh`, the `true` launch) or a thread of
one of those — never a read failure defaulting to the same outcome by
luck. Also found that those descendant processes spin up their own
thread pools too, which `syscall-capture-tree` will need to account for
specifically, not just fork/exec — real information this check produced,
not just a green light."

---

## [2026-09-05] PID 1 signal re-raise is silently dropped by the kernel — fixed with a pipe, not a sentinel exit code

**Context:** `/code-review ultra`, run against the `syscall-capture` branch, found that `runChild`'s
signal-death handling — added in the 2026-09-04 PID-1 rewrite — doesn't
work. That code re-raises the wrapped command's signal on itself
(`syscall.Kill(os.Getpid(), res.Signal)`) so the outer `sandbox.Run`'s
`wait4` sees a faithful `Signaled()` status. But `runChild` is now PID 1
of its own namespace, and the kernel marks any namespace's PID 1
`SIGNAL_UNKILLABLE` against same-namespace senders — exactly the
immunity the *original* 2026-09-01 PID-1 entry documented for the old
design, which the 2026-09-04 rewrite reintroduced for `runChild` itself
without noticing. Verified directly, not just argued: `cordon run sh -c
'kill -TERM $$'` reported `Result{ExitCode: 143}` (the `os.Exit(128+sig)`
fallback), not `-1` — silently violating `Result.ExitCode`'s own doc
comment and the previous rewrite entry's claim that "the exit-code
contract needed no changes."

**Options considered:**
- **Sentinel exit code** (e.g. `runChild` exits `128+signal`; `sandbox.Run`
  decodes that range back into `ExitCode: -1`). The obvious first idea —
  it's exactly what the fallback line already did, just promoted to the
  primary mechanism. Rejected: the wrapped command is arbitrary,
  untrusted input, and `128+N`-range exit codes are a real convention
  some programs use intentionally for reasons unrelated to any actual
  signal. A wrapped command that legitimately calls `exit(143)` for its
  own reasons would be misreported as a `SIGTERM` death. Given Cordon's
  entire purpose is running untrusted install scripts, "an adversarial or
  just unlucky wrapped command could collide with our sentinel" isn't an
  acceptable residual risk for a reporting contract with a documented,
  specific guarantee.
- **A pipe side-channel, separate from the exit code entirely** (chosen).
  `sandbox.Run` creates a pipe, passes the write end to the re-exec'd
  child via `cmd.ExtraFiles` (landing at fd 3), and closes its own copy
  right after `Start()`. `runChild` marks its copy close-on-exec
  immediately (so neither the tracee helper nor, transitively, the
  wrapped command ever sees it), and writes the signal number to it only
  when `res.Signal != 0`, right before exiting. `sandbox.Run` reads the
  pipe to EOF after `Wait()` returns (guaranteed non-blocking at that
  point: `runChild`'s exit is what closes its copy of fd 3, and `Wait()`
  already returned, so both copies are gone by construction) — a
  non-empty read means signal death, decoded into `ExitCode: -1`; empty
  means a normal exit, decoded via the existing exit-code passthrough.
  Zero collision surface with any exit code the wrapped command might
  produce, because it's not the same channel at all.

**Chose:** The pipe. `Result.ExitCode`'s public contract ("-1 if
terminated by a signal") is preserved exactly, with no API change to
`sandbox.Result` — the fix is entirely internal to how `-1` gets decided.

**Why:** The pipe is a small addition (one `os.Pipe()`, one `ExtraFiles`
entry, one `close-on-exec` call, a handful of lines) that makes the
report unambiguous by construction rather than "unambiguous in practice
for exit codes we expect wrapped commands to use" — the latter is
exactly the kind of assumption that doesn't hold against arbitrary,
potentially adversarial input, which is this whole tool's threat model.

**Verified, not assumed, including the specific collision the sentinel
approach would have had:**
- `cordon run sh -c 'kill -TERM $$'` → `Result{ExitCode: -1}` (was `143`
  before this fix).
- `cordon run sh -c 'exit 143'` — chosen because 143 is the *exact* value
  a sentinel-exit-code design would have used to mean "died from
  SIGTERM" — → `Result{ExitCode: 143}`, a normal exit, correctly *not*
  misreported as a signal death. This is direct proof the pipe design
  avoids the specific failure mode the rejected alternative would have
  had, not just an argument that it should.
- Full suite green, stable across 3 repeated runs.

**New regression tests** (`internal/sandbox/sandbox_test.go`):
`TestRun_WrappedCommandSignalDeathReportsNegativeOne` is the exact repro
from this bug, now exercised end-to-end through the real public
`sandbox.Run` API — full namespace setup, real ptrace tracer, real PID 1
— not a lower-level unit test of some internal piece.
`TestRun_NormalExitInSignalSentinelRangeIsNotMisreported` locks in the
specific reason the sentinel approach was rejected. Neither existed
before: sandbox-runner's original signal tests (2026-09-01) proved a
wrapped command *receiving* signals correctly; nothing proved PID 1's own
*reporting* of that death was correct — that gap is exactly how this
survived through both the original rewrite and its own review commentary
claiming no exit-code-contract change was needed.

**Consequences:**
- Easy: no public API change; every existing caller of `sandbox.Run`
  keeps working unchanged, now against a contract that's actually true.
- Slightly more machinery in `runChild`/`Run`: one extra fd for the
  lifetime of the sandboxed run. Negligible overhead next to everything
  else this feature already does.
- `runChild`'s own raw exit code (`128+signal` on the signal path) is now
  purely a human-debugging convenience (`ps`, `strace`) — `sandbox.Run`
  no longer reads it for correctness, only the pipe.

**If asked to defend this:** "PID 1 can't be killed by a same-namespace
sender, full stop — that's kernel policy, not something to work around,
and it now applies to our own tracer process the same way the 2026-09-01
entry already found it applied to the old design. So instead of trying to
make self-signaling work, `runChild` reports the death over a pipe file
descriptor set aside for exactly that, and `sandbox.Run` decodes it after
the process exits. We rejected encoding it in the exit code itself
because the wrapped command is untrusted and could pick that same value
on its own — proved that concretely by making a wrapped command exit
with the exact number a sentinel would have used, and confirming it's
still reported as a normal exit, not a signal death."

---

## [2026-09-05] arm64 build tag: fail the build, not the runtime

**Context:** The same `/code-review ultra` run found that
`internal/syscallcapture/capture_linux.go` carried only `//go:build
linux`, but its ptrace register access (`Orig_rax`, `Rsi`, `Rax`, `Rdx`,
`Rdi`) is the amd64-specific layout of `syscall.PtraceRegs`. `//go:build
linux` matches linux/arm64 too, and `capture_other.go`'s `//go:build
!linux` doesn't cover that gap (`!linux` is false when `GOOS=linux`
regardless of architecture) — so `GOOS=linux GOARCH=arm64 go build`
failed with a wall of `undefined field` compiler errors. Verified
directly: reproduced the exact failure before touching anything.

**Options considered:**
- **Implement the real arm64 equivalent** — different `PtraceRegs`
  layout (`Regs [31]uint64`, `Sp`, `Pc`, `Pstate`, no named x86
  registers) and a different syscall-number/argument-register calling
  convention. Real, standalone work; INTENT.md §3 doesn't currently
  commit to arm64 at all, so building it speculatively here would be
  scope past what anything asked for.
- **Widen `capture_other.go`'s tag to also cover `linux && !amd64`**,
  compiling the existing runtime stub (`errUnsupported`) for arm64. This
  is what the review's own suggested fix proposed, and it's a real
  improvement over today's cryptic compile failure. Rejected anyway: it
  trades a build-time failure for a runtime one — the binary builds
  cleanly and only reveals it captures nothing the first time someone
  actually runs it. For a security tool, a binary that looks like it
  works and silently doesn't is a worse failure mode than one that
  refuses to build at all, especially across a CI-builds-on-amd64,
  deploys-on-arm64 split where the runtime failure might not surface
  until production.
- **Fail the build itself, explicitly, on `linux && !amd64`** (chosen).

**Chose:** `capture_linux.go`'s tag narrowed to `//go:build linux &&
amd64`. A new file, `capture_unsupported.go`, tagged `//go:build linux &&
!amd64`, exists solely to fail compilation with a deliberate, readable
error: an `init()` that calls
`cordonSyscallCaptureNotYetImplementedForThisLinuxArchitecture`, a
function defined nowhere on purpose. Go has no `#error` directive; an
undefined-reference to a descriptively-named identifier is the standard
idiom for a deliberate, self-explanatory build-time failure.
`capture_other.go`'s `!linux` tag is untouched — non-Linux platforms are
unaffected, still get the existing runtime stub, unchanged.

**Why:** The three tags (`linux && amd64`, `linux && !amd64`, `!linux`)
are mutually exclusive and jointly exhaustive over all `(GOOS, GOARCH)` —
exactly one file compiles for any target, with no gap and no overlap.
Since `internal/sandbox` (and therefore `cmd/cordon`) imports
`internal/syscallcapture` directly, this failure propagates to the whole
binary on `linux/arm64` — the *whole* build fails, not just one internal
package. That's deliberate, not a side effect to accept: a `cordon`
binary that builds but cannot actually observe anything would be worse
than one that never builds, and the whole point of failing loudly here is
to make that impossible to ship by accident.

**Verified, not assumed:**
- `go build ./...` (linux/amd64, the actual dev target): clean, unchanged.
- `GOOS=linux GOARCH=arm64 go build ./...`: fails at exactly
  `capture_unsupported.go:31:2: undefined:
  cordonSyscallCaptureNotYetImplementedForThisLinuxArchitecture` — a
  single, clear, intentional error instead of seven scattered `undefined
  field` errors pointing at the wrong root cause.
- `GOOS=darwin GOARCH=amd64 go build ./internal/syscallcapture/...`:
  still clean, confirming `capture_other.go`'s existing non-Linux stub
  path is untouched.

**Consequences:**
- Easy: cross-compiling for an unsupported Linux architecture fails
  immediately and points a reader straight at the reason, via the doc
  comment on the failing file.
- Hard/deferred: real arm64 support is still unbuilt and unscheduled —
  this fix's whole job was turning a confusing accidental failure into an
  honest, deliberate one, not delivering the feature.

**If asked to defend this:** "The build tag said 'any Linux' when the
code only actually works on Linux-amd64 — arm64 hit real compiler errors
from register fields that don't exist there. Rather than widen the
existing runtime-stub file to also cover arm64 — which would make the
binary build fine and only fail the first time someone actually tries to
use it — we added a dedicated file that fails the *build* on any
non-amd64 Linux target, on purpose, with a self-explanatory error. For a
tool whose entire job is observing what a process does, a binary that
builds but silently observes nothing is a worse outcome than a build that
refuses to happen at all."

---

## [2026-09-05] behavior-report MVP: two rules, report as Result data on its own fd, corpus synthetic

**Context:** `features/behavior-report/intent.md` — turn captured
`syscallcapture.Event`s into a plain-text diagnosis. Explicitly scoped
crude ("severity tiers may be crude here; the real taxonomy is Phase 2
work"), and gated on a 5-package corpus that did not exist in the repo.

**Where the report is generated, and how it gets out.** `onEvent` is
called synchronously from inside the ptrace loop and blocks the tracee
until it returns, so the consumer (`behaviorreport.Collector`) only
appends; all classification runs in a batch pass after
`syscallcapture.Run` returns. That batch pass runs inside `runChild`
(the in-namespace PID 1), not out in `cmd/cordon` — events live there and
never cross a process boundary as structured data. The rendered report
does cross back, as `sandbox.Result.Report` (a string), over a dedicated
pipe fd (fd 4, alongside fd 3's signal-death channel), read after
`cmd.Wait`.

- Rejected: writing the report to `runChild`'s stdout. That broke
  `TestRun_PassesThroughStdoutAndStderrUnchanged` — the sandbox's I/O
  transparency is a real, tested contract, and the report is not the
  wrapped command's output.
- Rejected (for now): streaming raw events back to `cmd/cordon` over a
  pipe and composing the report there — the "clean layering" option. It
  needs a concurrent reader goroutine (a full npm install's ~8k events
  would overflow the 64 KB pipe buffer if read only after Wait) and
  per-event JSON framing. The rendered report, by contrast, is small and
  bounded (`WriteText` caps the finding list at 100), so a plain
  read-after-Wait cannot deadlock. `internal/sandbox` importing
  `internal/behaviorreport` is the cost; the raw-events channel is the
  refactor if a non-text consumer (Phase 2 JSON, a library caller) ever
  appears.

**stdout vs. stderr.** `cmd/cordon` prints `Result.Report` to **stderr**.
`intent.md` says "stdout". The deviation is deliberate: the wrapped
command owns stdout (so `cordon run npm ci > deps.log` keeps npm's output
uncontaminated), and the report is Cordon's own diagnostic *about* the
run, which conventionally goes to stderr. Read `intent.md`'s "plain text
to stdout only — no JSON schema, no HTML, no dashboard" as a statement
about *format* (plain text, not a structured/UI output), which is
honored; the stream choice is not the design intent it was expressing.

**The taxonomy: two rules, and where HIGH is drawn.**
- **Rule 1 — credential-read → HIGH.** An `openat` whose path contains
  one of a short, explicit list of secret-store markers (`/.ssh/id_*`,
  `/.aws/credentials`, `/.npmrc`, `/.netrc`, `/.git-credentials`,
  `/.docker/config.json`, `/.gnupg/`, shell history, gcloud creds). One
  finding per distinct path. Fires on the *attempt* — success and any
  follow-on network activity are irrelevant to it. This is the reliable
  HIGH: it does not depend on the process-tree gap (credential-reading
  code runs in the package's own process, e.g. `fs.readFile` in its
  postinstall, not a forked child), and a legitimate native build has no
  reason to trip it.
- **Rule 2 — network egress → MEDIUM, escalates to HIGH only paired with
  a credential-read.** Each distinct `connect` target is a MEDIUM
  finding on its own. Plain "any connect = HIGH" was rejected: a
  legitimate `node-gyp` downloads Node headers, a real connection with no
  way to tell it from something bad without hostname resolution (a
  documented capture gap) or an allowlist (explicitly Phase 2). When a
  credential-read finding *also* exists this run, one HIGH "possible
  credential exfiltration" finding is added, correlating the two —
  wording is careful that Cordon cannot prove data flowed from file to
  socket, only that both happened.
- No exec-based rule. Under single-process tracing, "download and run"
  is almost always a *forked child's* `execve`, invisible — an exec rule
  would be mostly dead weight until `syscall-capture-tree`.

**Corpus: synthetic, six fixtures under `testdata/corpus/`.** Not real
pulled-from-the-registry malware — same reasoning as the overhead fixture
(safety, reproducibility, and "explain every line" beats
reverse-engineering). Each is a small Go `main.go` plus a `README.md`
stating what it models, which rule it exercises, and — for
`credential-read-no-network` — what it explicitly does *not* prove (that
Rule 1 avoids false-positiving on a legit token-free project-local
`.npmrc`; it does not, the rule matches the path not the contents, and
that gap is Phase 2's). The sixth fixture (`bare-network-connect`) was
added to isolate "MEDIUM stays MEDIUM standalone" from `faux-node-gyp`'s
combined network+subprocess case. `.npmrc` in the marker list is the
loosest entry and a known false-positive shape — kept, flagged in the
rule comment and the corpus README, tracked for Phase 2.

**Consequences:**
- `behavior-report`'s Done checklist is satisfiable and tested end-to-end
  (`cmd/cordon/corpus_test.go` runs each fixture through the real binary
  and asserts on the report text) plus unit-tested
  (`internal/behaviorreport/report_test.go`, hand-built event slices, no
  sandbox).
- `sandbox.Result` grew a `Report string` field — a real public API
  addition, justified by an actual consumer (`cmd/cordon`), consistent
  with the project's build-it-when-needed pattern.
- The stdout→stderr choice means `cordon run foo | grep HIGH` won't work;
  a `--report-to-stdout` flag or the Phase 3 Action wrapper is where
  that gets revisited.

**If asked to defend this:** "Two rules — a secret-file open is HIGH on
its own because a legit build never does it and it doesn't depend on
tracing child processes; a network connection is MEDIUM unless a secret
was also read this run, then the pair is flagged HIGH with wording that's
explicit we can't prove exfiltration, only correlation. The report is
generated inside the sandbox where the events are, handed back as a
string on its own pipe fd so the wrapped command's stdout stays clean,
and printed to stderr because it's Cordon's diagnostic, not the
program's output. Corpus is six synthetic fixtures modeling the worm
pattern from our own mission statement, each with a README saying what it
does and doesn't prove."

---

## [2026-09-05] UnobservedDescendants: a concrete instance of INTENT §1's "best-effort, and say so specifically"

**Context:** INTENT.md §1 requires that Cordon "publish measured
coverage; never claim completeness," and `behavior-report/intent.md`
requires the report to state "plainly what Cordon did *not* observe."
The easy way to satisfy that is a fixed disclaimer paragraph. This entry
is about doing better than that in one specific, cheap place.

**What was added:** `syscallcapture.Result.UnobservedDescendants int` —
the count of distinct thread-groups (`Tgid`s) that were auto-attached but
never traced: the separate processes the install forked, which the
process-tree gap (`syscall-capture-tree`) leaves unobserved. The
dispatch loop already reads each new task's `Tgid` to tell a sibling
thread of the traced process (observed) from a separate process (not);
recording the distinct non-primary `Tgid`s alongside that is nearly free.
`behaviorreport` turns it into a per-run line: *"3 other process(es)
were launched during this run and were NOT traced"*, or a "no separate
processes were launched" line when the count is 0.

**Why this is the principle, not just a feature:** "detection is
best-effort" is easy to write and easy to make vacuous. A generic
"Cordon may miss things" line tells a user nothing actionable. "This run
forked 3 processes we didn't watch" tells them exactly how much of *this
install* was outside the lens — a number they can weigh. Same idea,
made specific and per-run, using data already in hand. When a future
gap is similarly cheap to quantify, quantify it the same way rather than
adding a sentence to the disclaimer.

**Two honesty caveats, both in the doc comment:**
- It is a **lower bound**. A task that exits before its
  `/proc/<pid>/status` can be read returns `Tgid` 0 and is not counted.
- It counts *every* distinct forked thread-group, including ones the
  wrapped program's own runtime spawns for its own reasons — found
  concretely while testing `faux-node-gyp`: two `exec.Command` calls
  produced a count of **3**, because Go's runtime does a one-time
  `clone(CLONE_PIDFD)` support probe (a short-lived throwaway child) on
  first `os/exec` use. The count is an honest "processes we saw and did
  not trace", not a curated "subprocesses you asked for" — the corpus
  test asserts `>= 2`, and the fixture README explains the discrepancy.

**If asked to defend this:** "The intent docs say be best-effort and say
so. The weak version of that is a boilerplate disclaimer. The strong
version, where it's cheap, is a real per-run number: this install forked
N processes we didn't trace. We already read each task's thread-group id
to classify it, so counting the distinct un-traced ones costs almost
nothing, and it's a far more useful thing to tell a developer than 'we
might miss stuff'. It's a lower bound, and it includes a process the Go
runtime forks for its own reasons — both stated in the code, not hidden."

---

**Note (2026-09-11):** Both Phase 1 merges (`syscall-capture`, `behavior-report`) were fast-forwards, confirmed via `git reflog` to have been done correctly on real feature branches (checkout → commits → fast-forward merge → branch deleted) — recorded here since a fast-forward merge is indistinguishable from a direct-to-main commit once the branch ref is gone, which left this ambiguous to a later reader until the reflog was checked. Phase 2 merges use `--no-ff` so branch history stays visible in `git log` without needing the reflog.

---

## [2026-09-11] `.env` credential marker was missing — fixed, not deferred

**Context:** Building the Phase 2 corpus expansion's `credential-marker-gap`
category (a fixture meant to prove a real, currently-live gap in
`credentialPathMarkers`), checked which common real-world secret stores
the existing 13 markers actually cover. `.env` — the single most common
secrets file in the Node/Python ecosystems Cordon targets (dotenv-style
`API_KEY=...` files, read by nearly every framework's boot sequence) —
was not among them. Any package install that reads a project's `.env`
file today produces no `Credential file read` finding at all.

**Options considered:**
- **Document as an accepted Phase 2 gap**, matching how other taxonomy
  refinements in `features/behavior-report/intent.md` are deferred.
  Rejected: unlike the `.npmrc` false-positive (a precision judgment call
  about a path that legitimately might not hold a secret), this is a
  false *negative* on one of the most common real secret files that
  exists — a coverage bug, not a taxonomy trade-off, and one line to fix.
- **Add `/.env` to `credentialPathMarkers` now.** Chosen.

**Chose:** Added `/.env` to the marker list (`internal/behaviorreport/report.go`),
plus `TestGenerate_DotEnvRead_IsHigh` (unit) and the `credential-marker-gap`
corpus fixture (end-to-end, asserts the real binary now reports a HIGH for
a planted `.env` file with a fake key). This is a separate commit from the
corpus-expansion work that surfaced it, per instruction: a rule bug fix and
a test-corpus feature are two different kinds of change even though one
led directly to the other.

**Why now rather than deferred:** The distinction that matters is *why* a
path is missing detection. `.npmrc` is flagged, matched, and *known* to
sometimes be a false alarm — that's a documented precision trade-off with
a real judgment call behind it. `.env` wasn't a judgment call at all; it
simply wasn't in the list, and there's no legitimate reason a package
install should be reading a project's dotenv file. Nothing about
INTENT.md §1's "detection is best-effort" language excuses shipping a
known, trivially-fixable hole in coverage of the most common secret file
format there is.

**Consequences:**
- Easy: `.env` reads by an install now surface a HIGH the same way `.ssh`
  or `.aws` reads already do — no new code path, just a new entry in an
  existing list.
- Same accepted imprecision as `.npmrc`, inherited rather than introduced:
  `/.env` as a substring also matches `/.envrc` (a direnv shell-config
  file, not a dotenv secrets file) — a false positive in the same family,
  not fixed here, tracked alongside `.npmrc`'s existing caveat for Phase
  2's allowlist/precision work.
- Does not change the rule's fundamental shape (substring match on a
  resolved path) or its scope (still only fires on an `openat`, so the
  same syscall-capture visibility limits — untraced forked children,
  namespace-tree gap — apply to `.env` reads exactly as they do to every
  other marker).

**If asked to defend this:** "Building a corpus fixture meant to
demonstrate a marker gap, I found the gap was `.env` itself — the most
common real-world secrets file for the ecosystems this tool targets,
and it wasn't in the list at all. That's not a precision trade-off like
`.npmrc`'s, it's a plain coverage bug with a one-line fix, so I fixed it
in its own commit rather than writing a fixture that proves a hole I
could close in the same sitting. It inherits `.npmrc`'s same kind of
false-positive risk against `.envrc`, which I left as-is and logged
rather than trying to solve two problems in one change."

---

## [2026-09-11] PID-1 exit kills a detached descendant before a delayed action can complete — verified, not assumed; a side effect, not a designed defense

**Context:** Planning the `delayed-process` corpus category (a package
that backgrounds a child and exits immediately, hoping the child's
sensitive action happens after the report is already generated), asked
first whether this actually evades anything, rather than writing the
fixture and its assertions on an unverified assumption either way.

**Method:** built a standalone probe fixture — background
`sleep 2 && write a marker file into the project directory` (the
project dir being the one path guaranteed writable and host-visible),
exit the primary process immediately — and ran it through the real
`cordon` binary. Checked for the marker file both immediately after
`cordon run` returned and again after waiting past the child's own
2-second delay. A first pass (marker written to the sandbox's `/` root)
was a confounded experiment — `/` is remounted read-only regardless of
timing (DECISIONS.md 2026-09-01), so that test couldn't isolate the
timing question at all. Redone against the project directory, which
stays read-write for the run's duration.

**Result:** the marker file never appears, in either check.

**Root cause:** `runChild` is PID 1 of the sandbox's PID namespace
(DECISIONS.md 2026-09-04, "runChild no longer execve's the wrapped
command"). Per `pid_namespaces(7)`: when a PID namespace's init process
terminates, the kernel immediately sends SIGKILL to every other process
still alive in that namespace. `runChild` calls `os.Exit` as soon as
`syscallcapture.Run` returns (which itself returns as soon as the
primary tracee exits, without waiting for other descendants — see the
"Scope split" note in `features/syscall-capture/intent.md`), so the
detached child is killed mid-`sleep`, before its write ever executes.

**Is this a designed defense? No — flagged explicitly so it isn't
mistaken for one.** Nothing in `runChild` or `syscallcapture.Run` was
written to wait for or kill descendants for isolation purposes; the
PID-1 architecture exists for signal-fidelity reasons (2026-09-04
entry), and this teardown behavior is a side effect of it, not a
property anyone set out to build or verify as a defense until this
investigation. It is fully reliable — kernel-guaranteed, not a race —
but its reliability is coincidental to why the architecture exists.

**What it actually bounds, precisely:** only *slow* delay. A descendant
whose action completes before (or as) the primary exits pays no timing
penalty and remains exactly as invisible to the report as any other
untraced forked process (same gap as the `credential-read-gap` corpus
category) — "background and act fast" gets neither more nor less
detection than acting inline in a child; only "background and wait it
out" gets cut off, and it's cut off by being killed, not by being
observed.

**Consequences:**
- A real, testable, checked-in guarantee now exists
  (`testdata/corpus/delayed-process/`,
  `TestCorpus_DelayedProcess_DoesNotOutliveTheRun` in
  `cmd/cordon/corpus_test.go`) that a delayed/backgrounded action cannot
  outlive the wrapped command's own run — useful to cite, but only with
  the "side effect, not designed" caveat attached, so nobody later
  claims Cordon engineered anti-persistence and tested it as such.
  Anyone building `features/syscall-capture-tree` should re-check this
  behavior isn't accidentally lost if that feature ever changes how or
  when `runChild` exits relative to the process tree.
- No change to INTENT.md §1's best-effort framing: this is a property of
  the isolation layer (hard boundary — namespace lifetime), not the
  detection layer, and it doesn't change what happens to *not* get
  reported.

**If asked to defend this:** "I checked whether backgrounding a child to
act after the report is generated actually buys an attacker anything,
rather than assuming either way. It doesn't, for slow delay: PID 1 exiting
triggers an immediate, kernel-mandated SIGKILL of the whole PID
namespace, verified by a probe whose marker file never lands even
seconds past its own sleep. But that's a side effect of the PID-1
architecture we built for faithful signal delivery, not a defense
anyone designed or previously tested — worth saying plainly so it's not
mistaken for an engineered anti-evasion feature. And it only helps
against slow delay; a fast background action is exactly as invisible as
any other untraced child process."

---

## [2026-09-11] allowlist-mechanism: exact-path only, read-before-launch, and the self-write bypass reproduced directly

**Context:** Both recorded credential-read false positives (`.npmrc`
without a token, DECISIONS.md 2026-09-05; a legitimate `.env`, made
detectable at all by the 2026-09-11 marker fix) are content problems —
`syscall-capture` traces `openat`, never `read`, so no path-based rule
can ever tell a token-free `.npmrc` from a stolen one. Phase 2's
roadmap names an allowlist mechanism for exactly this. Full design
reasoning (granularity, location/authorship, the honesty requirement,
the two named bypass risks) is in
`features/allowlist-mechanism/intent.md` — this entry covers what was
actually built and, specifically, verified rather than assumed.

**What shipped:** `internal/behaviorreport/allowlist.go` — `Allowlist`
(an opaque value type; matching is a private method so a caller cannot
construct one that bypasses validation), `LoadAllowlist` (parses
`.cordon-allowlist`: one path per line, `#` comments, blank lines
ignored), `LoadAllowlistFile` (reads `<projectDir>/.cordon-allowlist`,
a missing file is not an error — empty allowlist, the zero-friction
default). `Generate` gained a third parameter, `allow Allowlist`: an
allowlisted path is withheld from `Report.Findings` and recorded in the
new `Report.Suppressed` (title + path, not just a count) instead;
critically, the path stays in the internal `credentialPaths` slice the
exfil-correlation check reads, so `Possible credential exfiltration`
still fires if the same run also connects out — confirmed as the
intended design, not an oversight, before writing any code.
`WriteText` gained a `SUPPRESSED BY ALLOWLIST (N)` section (named
entries, not a bare count — a suppression is a deliberate developer
choice, unlike `UnobservedDescendants`, so the report should make it
trivial to audit) and, when `Allowlist.Ignored > 0`, a line stating how
many `.cordon-allowlist` lines were present but invalid and therefore
had zero effect.

**Fail-safe parsing, concretely:** `LoadAllowlist` accepts a line only
if, after `filepath.Clean`, it is an absolute path AND `os.Stat`
confirms a file exists there *at load time*. Anything else — relative,
malformed, pointing at nothing — is dropped and counted in `Ignored`,
never applied. Verified both directions with real files, not just the
happy path: `TestLoadAllowlist_InvalidEntriesAreIgnoredNotApplied`
(unit) plants a real file for the valid entry and a real *absence* for
the invalid one, and asserts the valid entry suppresses while the
invalid one's path still produces a normal `Credential file read`
finding — the fail-safe direction is asserted, not just the accept
path. The corpus fixture `testdata/corpus/allowlist-mechanism/
malformed-entries-ignored.go` repeats this end-to-end through the real
binary.

**The self-write bypass — timing confirmed by reading the actual code
path, then reproduced, not just argued:** the named risk in
`features/allowlist-mechanism/intent.md` is a package under audit
editing `.cordon-allowlist` mid-run to self-certify a path it's about
to read. Traced the exact call sequence in
`internal/sandbox/run_linux.go`'s `runChild` to confirm there is no
window: `allow := behaviorreport.LoadAllowlistFile(cfg.ProjectDir)`
(line 256) runs and *returns* — a synchronous, blocking file read —
strictly before `syscallcapture.Run` is even called (line 267). Inside
`Run` (`internal/syscallcapture/capture_linux.go`), the wrapped
command's own image doesn't exist yet either: `Run` first
`cmd.Start()`s a re-exec'd tracee helper under `PTRACE_TRACEME`, waits
for its post-exec stop, installs seccomp options, and only then lets
`MaybeRunTracee` `syscall.Exec` into the actual wrapped command. Every
one of those steps happens after `LoadAllowlistFile` has already
returned in `runChild`. There is structurally no point at which the
wrapped command's own code — the only thing that could try this
bypass — is running before the allowlist snapshot for this run is
already fixed in memory.

That ordering argument was not left as the only evidence. The corpus
fixture `testdata/corpus/allowlist-mechanism/self-write-too-late.go`
reproduces the actual attempt: no `.cordon-allowlist` exists when the
fixture starts (only the secret file is planted); the fixture creates
the allowlist file itself, naming its own about-to-be-read path, and
only then reads that path.
`TestCorpus_BehaviorReport/self-write-too-late` asserts the
`Credential file read` finding for that path still appears and no
`SUPPRESSED BY ALLOWLIST` section exists at all — the bypass attempt
demonstrably fails on this run, not just "should fail per the code."

**What this does not close:** editing `.cordon-allowlist` still works
for a *future* run — nothing here makes the file tamper-proof, only
makes tampering during the audited run itself inert. The mitigation for
a future-run edit is procedural (check the file into version control so
an unexpected change is a visible diff), stated in the feature's
intent.md, not enforced in code.

**If asked to defend this:** "The credential-read rule matches path, not
content, so it can never distinguish a safe `.npmrc` from a stolen one
on its own — the allowlist exists to let the one party who *can* know
that, the developer, say so explicitly, per exact file, never a
pattern. The sharper design question was whether a package being
audited could write its own allowlist entry mid-run to clear itself.
I traced the actual call sequence — the allowlist is read and returned
before the tracee process that becomes the wrapped command is even
started — and then didn't stop at that argument: built a fixture that
actually attempts the self-write and reads the file in the same run,
and the regression test confirms the finding still fires. Fail-safe
parsing got the same treatment — a unit test that plants a real missing
file, not just a well-formed one, to prove an invalid entry leaves the
path flagged rather than silently exempting it."

---

## [2026-09-11] /code-review ultra findings on allowlist-mechanism: directory entries, the pipe-deadlock cap, and two nits

**Context:** `/code-review ultra` against `allowlist-mechanism` before
merge. Four findings, all "nit" severity, none disputing the core
design (self-write timing, Rule 1/Rule 2 interaction) — a useful signal
that the parts already stress-tested by direct reproduction held up,
and the review caught the parts that weren't.

**1. `LoadAllowlist` accepted directory entries as valid (real bug).**
`os.Stat` doesn't distinguish a file from a directory; a line naming a
real directory (e.g. `/proj/.gnupg`) passed both the `IsAbs` and `Stat`
checks and was inserted into the allow-set, despite the doc comment's
explicit "a file actually exists there" and intent.md's "no directory
prefixes." It could never actually suppress anything (the map lookup
needs an exact match against a file path an `openat` produced), so the
practical damage was narrow — but it also silently failed to increment
`Ignored`, defeating the one thing `AllowlistIgnored` exists to
guarantee: a developer whose entry does nothing can tell why. Fixed by
checking `info.IsDir()` alongside the existing `os.Stat` error check.
`TestLoadAllowlist_DirectoryEntryIsIgnoredNotApplied` plants a real
directory (not a mock) and confirms both the `Ignored` count and that a
file inside it stays flagged.

**2. `SUPPRESSED BY ALLOWLIST` rendered unbounded, undermining the
`Findings` cap's own stated invariant (real bug, not yet exploitable at
observed scale but a real inconsistency).** `WriteText`'s `Findings`
loop caps at 100 specifically because the report crosses a fixed-size
pipe and is read only after the writer exits (`sandbox.Run`'s
`cmd.Wait` then `io.ReadAll`) — an unbounded render could deadlock it.
The `Suppressed` loop added by this feature had no such cap, so a
developer allowlisting many distinct paths under one broad marker
(`/.gnupg/` matches an entire keyring directory's contents) could in
principle reproduce the exact deadlock the `Findings` cap exists to
prevent. Fixed by hoisting the cap to a package-level
`maxRenderedFindings` constant shared by both loops, with the same
"...and N more not shown" tail line. `TestReport_WriteText_
SuppressedListIsCapped` builds 105 real allowlisted paths and confirms
`Generate` itself is uncapped (all 105 in `Report.Suppressed`) while
`WriteText`'s render stops at 100 with a tail line for the remaining 5
— the cap is a rendering concern, not a classification one.

**3 & 4. Two nits, both fixed:** the literal `".cordon-allowlist"` was
hardcoded in two `WriteText` lines instead of using the already-exported
`AllowlistFileName` constant (a rename would have silently desynced the
report text from the loader); `Allowlist.allows` had a redundant
`a.paths != nil` guard — reading a nil Go map returns the zero value
safely, so the guard added apparent-but-unnecessary caution. Both
trivial, both fixed inline.

**Consequences:** no change to the mechanism's core guarantees
(exact-path-only matching, the self-write timing property, fail-safe
parsing's accept/reject boundary) — all four findings were about
robustness at the edges (a directory instead of a file, hundreds of
entries instead of a handful) rather than the central design. Full
suite re-verified green after all four fixes, including three new
regression tests, not just the original ones.

**If asked to defend this:** "The review's four findings were all
robustness gaps at scale or on an untested input shape — a directory
where a file was expected, more suppressed entries than the pipe buffer
tolerates — not disputes with the core design. Fixed all four, added a
regression test for each rather than trusting the fix by inspection, and
re-ran the full suite before calling it done."

---

## [2026-09-11] finding-confidence: a secondary sort key, not a third severity tier — and .netrc's classification, a judgment call not in the original proposal

**Context:** INTENT.md §4 Phase 2's "severity tiers; highest-value
finding surfaces first" was investigated before writing any code
(features/finding-confidence/intent.md has the full reasoning). The
two-tier HIGH/MEDIUM design already works; the concrete, already-
reproducible gap is that `Generate`'s sort was stable on `Severity`
alone, so `escalation-volume`'s `multi-secret-multi-host` fixture — three
simultaneous HIGH `Credential file read` findings — had no guarantee
about which rendered first, even though the codebase's own comments
already treat some markers (`id_rsa`, `.aws/credentials`) as
definitionally secret and others (`.npmrc`, `.env`, shell history) as
known path-only heuristics.

**Chose:** a `markerConfidence` (`definiteConfidence` /
`heuristicConfidence`) per `credentialMarker`, used only as a secondary
`sort.SliceStable` key beneath `Severity` — `Finding.confidenceRank()`
ranks the `Possible credential exfiltration` finding first
unconditionally (checked by title, before confidence is ever consulted),
then `definiteConfidence` findings, then `heuristicConfidence` ones.
`Finding.confidence` is unexported: only `Generate` sets it, and its
zero value is `heuristicConfidence` deliberately — a `Finding` built
without setting confidence defaults to the more skeptical reading, not
the more alarming one. No third `Severity` value; `WriteText`'s rendered
labels are unchanged.

**`.netrc`'s classification — a real judgment call, made and logged
rather than silently decided:** the approved `finding-confidence/intent.md`
named `definiteConfidence` examples as "private keys, cloud credential
files, git credentials, docker config" and `heuristicConfidence` examples
as "`.npmrc`, `.env`, shell history, the `.gnupg/` prefix" — `.netrc` was
in neither list. Classified it `definiteConfidence` here, reasoning by
analogy to `.git-credentials`: its file format (machine/login/password
stanzas) has no legitimate "config only, no secret" reading the way
`.npmrc`'s registry-URL-only case does — unlike `.npmrc`, there's no
common legitimate use of a `.netrc` that holds zero credential material.
Documented in report.go's doc comment and here rather than silently
picked, since it's exactly the kind of unstated inference CLAUDE.md's
"flag ambiguous inference explicitly" rule is about — this one didn't
rise to stopping and asking (a single marker's confidence tier, not a
structural design choice), but it's on the record for review.

**Also logged, not resolved:** `/.docker/config.json` stays
`definiteConfidence` per the approved doc's explicit list, despite a real
tension noticed while writing the doc comment — many modern Docker
configs hold only a `credsStore` pointer to an external credential
helper, no embedded secret in the file itself, which is structurally
closer to `.npmrc`'s shape than to a private key's. Not reclassified
without discussion; flagged in the code comment for a future revisit.

**Consequences:**
- `TestGenerate_DefiniteConfidenceSortsBeforeHeuristic` (unit) and two
  corpus fixtures — `definite-before-heuristic.go` (opens the heuristic
  marker first, definite second, proving order is confidence-driven, not
  insertion-order-driven) and `exfil-ranks-first-even-with-heuristic-marker.go`
  (proves the correlation finding ranks first even when paired with a
  heuristic-confidence read, not only the definite-confidence case
  `allowlist-mechanism` happened to already exercise) — all new,
  end-to-end through the real binary via a new `wantOrder [][2]string`
  field added to `corpusCase` (asserts one substring's index precedes
  another's).
- One existing test's expectation flipped, correctly:
  `TestGenerate_CredentialReadPlusConnect_Escalates` previously asserted
  `Credential file read` before `Possible credential exfiltration` — an
  artifact of insertion order, never a deliberate guarantee. Updated to
  match the now-guaranteed order (exfil correlation first), not silently
  left passing on the old, accidental expectation.

**If asked to defend this:** "The roadmap said severity tiers; the
evidence said a stable two-tier design plus escalation already works,
and the real bug was that multiple simultaneous HIGHs had no ordering
guarantee at all — proven by a fixture that already existed
(`multi-secret-multi-host`) and just never asserted order. Fixed it as a
secondary sort key, not a new tier, and flagged the one real judgment
call in the marker list (`.netrc`) instead of quietly deciding it, since
the original proposal didn't name it explicitly either way."

---

## [2026-09-11] false-positive-rate: 0/8 on Cordon's own synthetic corpus, published as the repo's first README, deliberately not auto-regenerated

**Context:** INTENT.md §2 names false-positive rate a headline metric,
and §4 Phase 2 asks for it "measured and published in README" — nothing
did either before this. `features/false-positive-rate/intent.md` has
the full proposal and its approval; this entry is what actually shipped.

**What "benign" means, concretely, and why 8 not more:** added an
explicit `benign bool` to `corpusCase` rather than inferring it from
`noHigh`. Labeled exactly 8 of the 18 existing cases:
`benign-local-io` (×2), `network-egress` (×2), `native-build-style`
(×2), `marker-precision` (×2). Deliberately did NOT label anything in
`credential-read`, `credential-read-gap`, `credential-marker-gap`,
`escalation-volume`, or `allowlist-mechanism` — every one of those
exercises a real credential read, a documented detection miss, or a
suppression, and inferring "no HIGH visible" as "benign" for, say,
`pre-authored-suppresses` (`allowlist-mechanism`) would count a
genuinely-read secret file as evidence of rule cleanliness just because
the developer's own allowlist hid it. That's a different population
than "the rule correctly recognized legitimate behavior," and folding
them together would inflate the published number with cases that don't
support the claim.

**Where the number lives and how it's computed:** `TestCorpus_
FalsePositiveRate` (`cmd/cordon/corpus_test.go`) iterates `corpusCases`
— the *same* package-level slice `TestCorpus_BehaviorReport` already
iterated (refactored out of that test's local variable into a shared
var specifically so the two can't drift apart) — filters to
`benign == true`, runs each fixture through the real binary, and
`t.Log`s "N/M benign-labeled fixtures produced an unexpected HIGH
finding." Also `t.Fatal`s if the benign count is ever 0, a guard against
the label silently disappearing in a future refactor rather than the
corpus genuinely having no benign cases. Current result: **0/8**.

**README.md created — real, acknowledged scope, not an accident.** This
is the first README this repository has ever had. Scoped narrowly, per
instruction: the FP number, its population named in the same sentence,
what it explicitly does not claim (not a real-registry sample, not
statistically representative), and the exact recompute command. states
plainly that Phase 3's fuller README (demo, full "what Cordon does not
catch" list) is separate, later scope, not attempted here.

**Auto-regeneration explicitly rejected, per instruction, in favor of
naming the drift risk instead of engineering it away:** the README's
number is a hand-pasted snapshot, not templated or rewritten by tooling.
Considered and rejected: a small script that rewrites a marked README
block from the test's output (removes drift entirely, but adds a
maintenance surface — another script to keep correct — for a number
that's already explicitly qualified as a manual, honestly-caveated
snapshot). Chose to accept the drift risk and say so in the README
itself: the `t.Log`ged line is authoritative if the two ever disagree,
and the README states that outright rather than implying live accuracy
it doesn't have.

**Consequences:**
- The published 0/8 will go stale the moment a new benign fixture is
  added or an existing one's behavior changes, until someone re-runs the
  test and re-pastes the number — an accepted, disclosed cost, not an
  oversight.
- `TestCorpus_BehaviorReport`'s refactor (local `cases` → package-level
  `corpusCases`) is the only change to existing test structure; no
  existing assertion changed, confirmed by a full, fresh test run before
  this was called done.

**If asked to defend this:** "The number is real — 0 of 8 fixtures we
explicitly label as modeling legitimate behavior produce a false HIGH —
but the population is Cordon's own synthetic corpus, not a sample of
real npm or pip packages, and the README says so in the same sentence as
the number, not a footnote. I was told not to build auto-regeneration
for this, and I agree with the reasoning: it would add a maintenance
surface for a number that's already explicitly labeled as a manual
snapshot. The test that recomputes it is one command away, named
inline, and is the authority if the README ever falls behind it."

---

## [2026-09-13] env-path-forwarding: caller's PATH now bind-mounted and forwarded — a deliberate widening of the sandbox's read-only surface

**Context:** Planning `github-action` (Phase 3), the standard way a real
CI workflow gets a pinned Node version is `actions/setup-node`, which
installs into `$RUNNER_TOOL_CACHE` (typically under
`/opt/hostedtoolcache/...`) and prepends that directory to `PATH`. Before
this change, `childEnv` hardcoded the wrapped command's `PATH` to a fixed
`defaultPath` (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`)
and discarded the caller's real `PATH` entirely, and `roSystemDirs`
bind-mounted only `/bin /sbin /lib /lib64 /usr /etc`. Both were named,
known gaps (`sandbox.go`'s standing `childEnv` comment; the
`$npm_node_execpath` finding, DECISIONS.md 2026-09-04) but not yet a
blocker for anything shipped. They became one here: on the default path
through a GitHub Action using `actions/setup-node`, `cordon run npm
install` would fail to resolve `npm`/`node` at all — not a corner case,
the common case for that Action's primary audience.

**Options considered:**
- **Document the gap in the Action's own README/error output, fix later.**
  Rejected: this isn't a rare workload tripping over a documented
  limitation, it's the *default* configuration failing on the *first*
  real external-facing surface Cordon ships. Shipping that and calling it
  known-limitation framing would be misleading, not honest — the failure
  mode is "the wrapper doesn't wrap," not a missed edge case.
- **Forward the caller's entire environment.** Rejected outright, not
  just deferred: env vars routinely carry secrets (API tokens, cloud
  credentials in CI), and forwarding them into the sandboxed process is
  exactly the exposure INTENT.md §1's isolation boundary exists to
  prevent. Never proposed as a real option.
- **Forward only `PATH` directory contents, read-only, bind-mounted the
  same way `roSystemDirs` already are** (chosen).

**Chose:** `sandbox.Run` (`run_linux.go:142`) now captures
`os.Getenv("PATH")` and computes `extraPathDirs` — the caller's `PATH`
entries not already covered by `roSystemDirs` or `defaultPath` (exact
match or nested under either, via `underAny`, `run_linux.go:104`),
deduplicated, order-preserved. That list crosses into `childConfig` as
`ExtraPathDirs`, the same JSON-over-`childEnvVar` mechanism
`Command`/`ProjectDir`/`NewRoot` already use. `setupRootfs`
(`run_linux.go`, step 3) bind-mounts each one read-only at its own
absolute host path, exactly like `roSystemDirs`, and `sandboxPath`
(new helper) builds `defaultPath` + those extra directories for both
`runChild`'s own `exec.LookPath(cfg.Command[0])` resolution
(`run_linux.go:308`) and `childEnv`'s `PATH` for the wrapped command
itself — both call sites had to change together, since a command that
only resolves via a forwarded directory would otherwise fail at the
top-level `LookPath` before ever reaching `childEnv`.

**When the read happens, and why that matters (same shape as the
allowlist's TOCTOU argument, DECISIONS.md 2026-09-11):** the
`os.Getenv("PATH")` read is in `sandbox.Run`, the host-side, pre-namespace
parent process, before `childConfig` is even marshaled (`run_linux.go:144`)
and long before `cmd.Start()` (`run_linux.go:211`). At that point no
namespace, no re-exec'd child, no tracee, and no wrapped-command process
exists yet — strictly earlier than the allowlist's own read-before-tracee
point, which happens inside the already-re-exec'd, already-namespaced
`runChild` (`run_linux.go:326`). The wrapped command therefore cannot
influence which directories get bind-mounted for its own run under any
circumstance: the list is fixed before the sandbox's process tree exists
at all, not merely before the tracee's first syscall. No adversarial
write-race is even conceivable here the way one was for
`.cordon-allowlist` (a file the wrapped command could write to); `PATH`
is read once from the parent's own environment and never touched again.

**Consequences — the tradeoff, logged as one, not a silent side effect:**
- **The sandbox's read-only-visible surface is now caller-dependent, not
  a fixed, fully-audited allowlist.** Before this change, exactly six
  directories (`roSystemDirs`) were ever bind-mounted, chosen and
  reviewed as a fixed set. Now, whatever the invoking user's or CI
  runner's `PATH` happens to contain also becomes readable inside the
  sandbox. This is the invoker's own `PATH`, not attacker-influenced
  input (see the TOCTOU argument above), but it is a real change to what
  "isolation is a hard boundary" (INTENT.md §1) actually bounds in
  practice — a caller with an unusually broad `PATH` widens the sandbox's
  visibility accordingly, without Cordon itself choosing or reviewing
  those directories.
- Mitigated, not eliminated, by scope: `PATH` directory contents only,
  read-only, never arbitrary env vars — a compromised install can read
  more of the filesystem than the old fixed set, but still cannot exfiltrate
  anything via an environment variable Cordon declined to forward, and
  still cannot write anywhere outside the project dir/tmp.
- Easy now: `github-action`'s primary use case (wrapping an
  `actions/setup-node`-configured install) actually works; a tool
  resolved only via a forwarded `PATH` entry now runs both as the
  top-level wrapped command and as a process it forks (proven separately
  — see Done checklist).
- Watch for later: if `syscall-capture-tree` or a future feature ever
  needs to reason precisely about "everything the sandboxed process could
  read," this feature means that answer is no longer a fixed compile-time
  list — it depends on the invoking environment's `PATH` at run time.

**If asked to defend this:** "The Action's own primary use case —
wrapping an install after `actions/setup-node` — would have failed by
default, because Node installed into a CI tool-cache path was never
bind-mounted or on the sandbox's PATH. The fix forwards only PATH
directory contents, read-only, captured in the host-side parent process
before any namespace or tracee exists — so the wrapped command can never
influence which directories get mounted for its own run, the same
TOCTOU shape as the allowlist's read-before-tracee guarantee. The real
cost is that the sandbox's readable surface is no longer a fixed,
Cordon-reviewed set of six directories; it now depends on whatever the
invoker's PATH contains. That's a deliberate, logged tradeoff — read-only
and env-var-forwarding excluded on purpose — not a scope creep we didn't
notice."

---

## [2026-09-13] github-action: build and run are separate composite steps; exit code always mirrors the wrapped command; no annotations yet

**Context:** First real external-facing surface (INTENT.md §4 Phase 3).
Two defaults needed deciding deliberately rather than by habit: what
happens when Cordon itself fails to even start, and whether a finding
should ever fail the CI step.

**Compile failure vs. wrapped-command failure — distinguishability
checked, not assumed:** the composite action was first drafted as a
single `go run $GITHUB_ACTION_PATH/cmd/cordon run -- <command>` step.
Asked directly whether a `go run` compile failure would be
distinguishable, at a glance, from the wrapped command simply exiting
non-zero — since both would otherwise fail the same step under the same
step name. They would not have been: a `bash -eo pipefail` composite
step reports one pass/fail per step, and `go run`'s own build failure
and its target's exit code both surface as "this step failed," visible
only by reading the log text. Split into two steps instead: "Build
Cordon" (`go build -o "$RUNNER_TEMP/cordon-bin" ./cmd/cordon`, in
`$GITHUB_ACTION_PATH`) and "Run wrapped command under Cordon" (executes
the built binary). Verified directly, not assumed: appended a syntax
error to `cmd/cordon/main.go`, ran `go build` against it, confirmed a
real, isolated failure (`exit 1`, a real compiler error) with the
wrapped-command step never reached, then restored the file before
committing. A user scanning a job's step list now sees which one failed
without opening logs — "my install failed" vs. "Cordon itself is
broken" are two different step names, not two readings of one.

**Exit code / fail policy — checked against INTENT.md §5's actual
wording, not defaulted to "fail on HIGH" the way a security scanner
normally would:** §5 states plainly, as a non-goal: "Blocking installs
by default. Cordon reports; the human decides." `cmd/cordon`'s `run()`
(`main.go`) already, unconditionally, returns `res.ExitCode` — the
wrapped command's own exit status — regardless of what
`behaviorreport.Generate` found; no code path today lets a finding
change the process's exit code. The Action's "Run wrapped command under
Cordon" step therefore captures the wrapped binary's exit status
explicitly (`set +e` first — a composite step is otherwise `bash -e`,
which would abort before the step-summary write the moment the wrapped
command failed) and re-exits with exactly that value. No configurable
"fail on HIGH" input was added. Considered and rejected for this slice:
building one honestly requires `cmd/cordon` to expose a distinct,
structured "there were HIGH findings" signal separate from
`res.ExitCode` — none exists today, and faking one by grepping the
Action's own plain-text report for `[HIGH]` would be exactly the
fragile, text-format-coupled shortcut this project avoids elsewhere
(see the annotations decision below). Named as a real, specific
follow-up (a `--fail-on` flag or a machine-readable output mode in
`cmd/cordon` itself), not silently dropped.

**Findings surfacing — passthrough plus step summary, no annotations
yet:** the behavior report is already written to stderr
(DECISIONS.md 2026-09-05), so an unmodified `run:` step already places
it in the job log in the same order a bare invocation would, with zero
wrapper logic. Verified locally (not yet on a real runner — see the
Done-checklist item still open in `features/github-action/intent.md`):
`tee`ing stderr to a file for the step summary does not alter what
reaches the log, in either the no-findings case or the HIGH-finding
case. The same text is also appended to `$GITHUB_STEP_SUMMARY` as a
fenced code block. GitHub Actions `::warning::`/`::error::` annotations
were considered and deferred, not built: producing accurate ones means
parsing `behaviorreport.WriteText`'s plain-text output for
severity/title, which would couple the Action's correctness to a text
format with no stability contract today (no struct/JSON export exists
in `internal/behaviorreport`). Same shape of tradeoff as the fail-policy
decision above — declining to build a feature on a scrape of another
package's incidental string output, twice in the same slice, not a
coincidence.

**Consequences:**
- Easy: a user gets accurate signal about *what* broke (Cordon vs. the
  install) without reading a single log line, and the exit-code
  contract that already existed in `cmd/cordon` needed zero changes to
  extend correctly into CI.
- Deferred, named explicitly: a configurable fail-on-severity gate, and
  annotation-based surfacing — both blocked on the same missing
  upstream piece (a structured signal from `cmd/cordon` beyond
  `res.ExitCode` and a plain-text report), not on Action-side effort.
- Unverified until CI actually runs `.github/workflows/action-selftest.yml`:
  everything above was checked against the real built binary run
  locally, on this WSL2 dev machine, which already has unprivileged
  userns available — whether GitHub's hosted `ubuntu-latest` also does,
  or the AppArmor gate (DECISIONS.md 2026-09-01) blocks it, is still an
  open question this workflow exists to answer for real, not assume.

**If asked to defend this:** "Splitting build and run into separate
composite steps was checked, not assumed to be enough: I broke the
build on purpose and confirmed the failure lands on a differently-named
step than a wrapped-command failure would. The exit-code policy isn't
'fail on HIGH like a normal scanner' — INTENT.md §5 says plainly that
Cordon reports and the human decides, and `cmd/cordon` already never
lets a finding change its exit code, so the Action just has to preserve
that contract faithfully, which meant explicitly capturing and
re-exiting the wrapped binary's own status under `set +e`. I declined to
fake a 'fail on HIGH' option or real annotations by scraping Cordon's
own plain-text report for keywords, because that couples a CI-facing
feature to a format with zero stability guarantees — both are named as
real follow-ups that belong in `cmd/cordon` itself, not the Action."

---

## [2026-09-13] Pre-push check: the unprivileged-userns t.Skip only covers `go test`, not a real `cordon run` — production path had no equivalent

**Context:** Before pushing `github-action` to actually exercise
`action-selftest.yml` on GitHub's hosted `ubuntu-latest` runner — the
first real test of whether unprivileged user namespaces are available
there, or the AppArmor gate blocks them (INTENT.md §3, DECISIONS.md
2026-09-01) — checked whether a restricted runner would fail legibly
or confusingly.

**What was checked:** `internal/sandbox/helpers_test.go`'s `requireUserNS`
(the two sysctl probes, `unprivileged_userns_clone` and
`apparmor_restrict_unprivileged_userns`) is not bit-rotted — both paths
and both comparison values still match DECISIONS.md 2026-09-01 exactly.
But that function only runs under `go test`, and `action-selftest.yml`
never runs `go test` — it builds and runs the real `cordon` binary via
the composite action. On a restricted runner, `sandbox.Run`'s existing
`cmd.Start()` failure path (`run_linux.go`, "starting sandbox child")
would have surfaced whatever raw OS error `clone()` returns (e.g.
`operation not permitted`) — attributable to the right *step* ("Run
wrapped command under Cordon"), but not to the right *cause*: nothing in
that message would tell a reader this is the specific, documented,
known host-policy gate rather than some other permissions problem in
Cordon itself.

**Chose:** Added `checkUserNamespacesAvailable` (`run_linux.go`) — the
production-path equivalent of `requireUserNS` — called at the top of
`Run`, before any namespace or child-process setup, returning a
specific, named error ("unprivileged user namespaces are disabled on
this host (kernel.unprivileged_userns_clone=0) -- see INTENT.md §3
Platform", and the AppArmor equivalent) for exactly the two documented
gates. Both the production check and the test's `requireUserNS` now
read from the same two package-level path vars
(`unprivilegedUserNSClonePath`, `apparmorRestrictUnprivilegedUserNSPath`)
instead of two independently hand-copied literal strings — the second
copy is exactly how this kind of check silently drifts out of sync with
its own test in the first place. `requireUserNS` itself now just calls
`checkUserNamespacesAvailable` through a `CheckUserNamespacesAvailableForTest`
export-test shim, so there is one implementation, not two.

**Deliberately not exhaustive:** only the two named, documented gates are
checked. A `clone()` failure from any other cause (a namespace-count
ulimit, an unrelated LSM policy neither of us has hit yet) still falls
through to the existing generic "starting sandbox child" error,
unattributed exactly as before — this closes the two specific cases
INTENT.md already commits to explaining, not every conceivable clone()
failure.

**Verified, not just argued:** `TestCheckUserNamespacesAvailable`
(`usernscheck_linux_test.go`) exercises all five cases directly via the
injectable path vars pointed at real temp files — both restricted
branches, both matching-but-unrestricted values (`1` for the clone
sysctl, `0` for the AppArmor one — the "looks similar but means the
opposite" case a careless read of either check could get backwards),
and the missing-file case (an unpatched kernel with neither sysctl at
all). All five pass. Full suite (`go test ./...`) re-run clean after
the `requireUserNS` refactor.

**Consequences:**
- If `ubuntu-latest` does turn out to gate unprivileged userns, the
  push about to happen will fail with a message that names the exact
  sysctl and value, not a bare OS errno string — legible without
  needing to already know INTENT.md §3's platform caveats by heart.
- This was caught and fixed *before* the first real run, specifically
  because it was asked for directly rather than trusted from "the test
  suite already handles this" — the test suite handling it and the
  production binary handling it are two different claims, and only one
  of them was true until now.

**If asked to defend this:** "I was asked to confirm a restricted host
would fail with the documented t.Skip message, not something confusing
downstream. It wouldn't have — the skip only exists for `go test`, and
the GitHub Action runs the real binary, which had no equivalent check
at all. I added one, sharing the same two sysctl paths as the test's
own check so they can't drift apart again, and wrote a real test that
exercises all five value combinations — including the two 'looks
restrictive but actually isn't' cases — rather than trusting the
error-string reasoning alone."

---

## [2026-09-14] Confirmed on a real `ubuntu-latest` runner: unprivileged userns is AppArmor-gated by default — INTENT.md §3's open item resolved, unfavorably

**Context:** INTENT.md §3 Platform has carried an open item since project
setup: whether GitHub-hosted `ubuntu-latest` runners gate unprivileged
user namespaces via AppArmor, "probed in CI as an early step, not
assumed." Until today that was still an assumption, not a measurement —
`action-selftest.yml` (composite GitHub Action self-test workflow) had
never actually run on a hosted runner. No `gh` CLI or GitHub auth was
available in this session at first; installed `gh` to `~/.local/bin`
(no `sudo`, downloaded the release tarball directly) and had the user
complete interactive `gh auth login`, since that step needs a human in
the loop.

**Triggering the run:** `action-selftest.yml` only fires on `push` to
`main`, `pull_request`, or manual `workflow_dispatch` — pushing the
`github-action` branch itself triggered nothing (not `main`, no PR yet).
`workflow_dispatch` was tried first and rejected outright:
`HTTP 404: workflow action-selftest.yml not found on the default
branch` — GitHub requires a `workflow_dispatch`-triggerable workflow to
already exist on the default branch before it can be dispatched via API,
even when targeting a different ref, which this brand-new workflow file
did not yet. `pull_request` has no such restriction — GitHub evaluates
that trigger using the workflow file from the PR's own branch — so
opened PR #1 (`github-action` → `main`, explicitly not for merging yet)
specifically to get a real run, confirmed with the user before opening
it since a PR is a shared, visible action.

**Result — all three jobs failed identically, at the `Run ./` step:**
```
cordon: sandbox.Run: unprivileged user namespaces are restricted by
AppArmor on this host (kernel.apparmor_restrict_unprivileged_userns=1)
-- see INTENT.md §3 Platform
```
(Run: `SrilakshmiVadlamoodi/Cordon` Actions run 34860550812.) This is
the AppArmor gate specifically — not the older
`kernel.unprivileged_userns_clone=0` sysctl, which is unset/permissive
on this image. Confirms `ubuntu-latest` has already rolled to a
24.04-or-later base carrying the hardened AppArmor default, resolving
INTENT.md §3's "not assumed" item: it *is* gated, unfavorably, on the
exact runner image Cordon's own CI and Phase 3 distribution promise
depend on.

**What this is not:** not a Cordon bug. `checkUserNamespacesAvailable`
(the entry directly above this one) worked exactly as built — the
failure is the clear, specific, documented message it was designed to
produce, not a bare `clone()` errno surfacing from deep inside
`cmd.Start()`. The pre-flight check earned its keep on its very first
real-world trigger.

**What this blocks:** every job in `action-selftest.yml` fails as long
as the AppArmor gate stands and nothing lifts it, including
`high-finding-does-not-fail-the-step` — a job whose entire point is to
prove a HIGH finding doesn't fail the wrapping CI step (INTENT.md §5),
which it now can't even reach, since `cordon run` itself refuses to
start first. Distribution's "three lines in a workflow file" promise
(INTENT.md §4 Phase 3) is not deliverable as-is on stock
`ubuntu-latest` without *some* additional step, whichever way that gets
resolved.

**Options for a fix, explored but not chosen yet (next entry covers the
concrete lift-attempt and recommendation):**
- Lift the AppArmor restriction as a runner-setup step, either inside
  `action.yml` itself or documented as a required prerequisite step in
  the consuming workflow.
- Accept the limitation and document it plainly (README, INTENT.md) as
  a known gap on hosted-runner CI, no code change.
- Target self-hosted runners or a pre-hardened custom image only.

**Consequences:**
- INTENT.md §3's platform caveat is no longer speculative; it should be
  reworded from "open item... must be probed" to state the confirmed
  fact, once a fix direction is chosen (not edited yet — the fallback
  sentence "run tests in a container, or set the sysctl explicitly" is
  literally the lift option under investigation right now, so wait for
  that outcome before rewriting the caveat).
- `action-selftest.yml` stays red on every future push/PR touching it
  until this is resolved one way or the other — expected, not a
  regression to chase.
- PR #1 stays open, unmerged, specifically to keep re-running this
  workflow against candidate fixes without polluting `main`.

**If asked to defend this:** "The open platform question INTENT.md
carried since day one — does `ubuntu-latest` block unprivileged user
namespaces — needed an actual hosted-runner run to answer, not another
assumption. Getting one required installing `gh`, getting the user to
authenticate it, and opening a PR (not a merge) just to trigger the
`pull_request` event, because `workflow_dispatch` refuses to dispatch a
workflow that doesn't exist on `main` yet. The answer came back
unfavorable: yes, it's AppArmor-gated, confirmed by three identical
runner failures naming the exact sysctl. The pre-flight error check
built one entry earlier did its job — the failure is legible, not
confusing — but the underlying blocker is real and needs an explicit
fix before Phase 3's 'three lines' promise is true on stock CI."

---

## [2026-09-14] AppArmor userns gate: fix chosen — best-effort sysctl lift inside action.yml, loud and non-fatal, not a required prerequisite step

**Context:** Direct follow-on to the entry above. Three options were on
the table for the confirmed `ubuntu-latest` AppArmor block: lift the
restriction from inside `action.yml` itself, document a required
prerequisite step in every consuming workflow, or accept the limitation
and restrict Cordon's GitHub Action to self-hosted/pre-hardened runners
only. Before choosing, ran a dedicated probe job
(`probe-apparmor-lift`, since removed — its findings are recorded here,
not left live as a standing job) to test the lift concretely rather than
assume it would work:
- `sudo -n /sbin/sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`
  succeeded non-interactively as the default `actions` runner user —
  confirmed, not assumed, that passwordless sudo covers this specific
  write.
- The lifted value (`0`) was still in effect in a later, separate step
  of the same job — confirmed the runner-level sysctl persists for the
  job's own remaining steps, as expected of a per-VM kernel setting.
- `unshare --user --map-root-user` succeeded after the lift, confirming
  it unblocks actual userns creation, not just the sysctl read-back.

**Options considered:**
- **Required prerequisite step**, documented for every consuming
  workflow to add before `uses: ./`. Most honest about what's
  happening — nothing hidden inside the action. Rejected: it
  permanently breaks INTENT.md §4 Phase 3's stated distribution goal
  ("GitHub Action wrapper (three lines in a workflow file)") for every
  single user, over an Ubuntu-version-specific AppArmor default that is
  an implementation detail of *our* rootless architecture, not
  something a caller should need to already know about to use Cordon at
  all.
- **Restrict to self-hosted/pre-hardened runners only**, document the
  gap, no code change. Simplest, but concedes the actual target
  audience (anyone with a stock `ubuntu-latest` workflow) up front,
  which is most of Phase 3's intended users.
- **Best-effort lift inside `action.yml`, loud, falling through to the
  existing error on failure.** (Chosen; see below.)

**Chose:** A new `action.yml` step, "Lift AppArmor unprivileged-userns
restriction (best-effort)", runs immediately after the existing "Check
platform" step and before Go is set up or Cordon is built. It: reads
`/proc/sys/kernel/apparmor_restrict_unprivileged_userns` directly (no
dependency on `sysctl` existing for the *read*, only for the *write*);
exits 0 immediately if the file is absent or already not `1` (nothing
to do — most hosts, including any pre-5.10-hardened distro or a runner
where this was already fixed upstream, hit this path and the step is a
no-op); otherwise attempts
`sudo -n sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
On success, emits `::notice::` naming exactly what changed, why, and
its scope. On failure (`sudo` missing, not passwordless, or refused),
emits a different `::notice::` saying so and naming the specific
downstream error to expect — then the step still exits 0. Either way,
`checkUserNamespacesAvailable` (`run_linux.go`, the entry two above
this one) runs unchanged, later, inside the built binary — this step
never touches or short-circuits it, only tries to make its check
unnecessary.

**Why "best-effort, falls through" instead of a hard requirement:** the
whole point of `checkUserNamespacesAvailable` existing is that Cordon
must never fail confusingly when a namespace can't be created — it
fails with a specific, named reason. A lift step that *required*
success (erroring out if `sudo -n` failed) would reintroduce exactly
the failure mode that check was built to prevent, just one layer
earlier and over a different cause: on a self-hosted runner without
passwordless sudo, a hard-required lift step would abort with a sudo
permission error that has nothing to do with the real, already-legible
diagnosis the binary itself is fully capable of producing on its own.
Best-effort means the lift step can only ever *help* (turn a would-be
failure into a pass) or be a no-op (leave the existing, already-correct
failure path exactly as before) — it has no code path that makes
things worse than not having it at all.

**Why this doesn't compromise the "no sudo" rootless ground rule:**
CLAUDE.md and INTENT.md's "rootless: no sudo, no setuid helper" rule
governs how the *wrapped command* gets confined — the sandboxed child
process itself must never require or receive elevated privilege to run
under Cordon, and nothing about this step touches that: the wrapped
command still runs in exactly the same unprivileged user namespace as
before, with the same single UID mapping (DECISIONS.md 2026-09-01), and
`sandbox.Run`'s own code path calls no `sudo` and gained none. What
this step uses `sudo` for is CI *infrastructure* setup — adjusting a
host kernel toggle on the runner VM itself, before Cordon's binary is
even built — which is a different layer entirely: the same distinction
as a Dockerfile's build stage running as root to install packages while
the resulting container runs unprivileged. A GitHub-hosted runner
already grants its default user passwordless sudo for general system
administration (that is what made the lift possible at all); using a
sliver of that pre-existing CI-infrastructure privilege to unblock our
own sandbox's prerequisite is not the same claim as "Cordon's sandbox
needs privilege to confine a process," which remains false.

**Why this degrades safely, concretely:** three failure modes were
worth naming and each was checked or reasoned through, not assumed:
1. *Sysctl already permissive* (older kernel, different distro, a
   runner image that fixes this upstream later) — the `!= "1"` check
   makes the step a silent no-op; no `sudo` call is even attempted.
2. *No `sudo` at all, or not passwordless, on a self-hosted runner* —
   the `sudo -n ... || `-pattern (via `if`) never lets a failed sudo
   invocation propagate as the step's own exit status; the `else`
   branch's `::notice::` fires and the step still exits 0.  Verified,
   not assumed: `.github/workflows/action-selftest.yml`'s
   `simulate-no-sudo-fallthrough` job shadows `sudo` on `$PATH` with a
   binary that always exits 1, ahead of the real one, then asserts (a)
   the wrapped step still fails, (b) the failure text is exactly
   `checkUserNamespacesAvailable`'s original message, and (c) that text
   contains no mention of `sudo` — i.e. the real diagnosis isn't masked
   by a sudo error. This is a permanent job in the self-test workflow,
   not a one-off probe, so a future change that breaks the fallthrough
   (e.g. someone later making the lift step `set -e`-fragile) fails CI
   loudly instead of silently regressing.
3. *`::notice::` causing user alarm about unexpected host mutation* —
   addressed directly in the notice text itself (both branches), not
   left to be inferred: the success notice states plainly that the
   change is scoped to "this job's ephemeral runner VM only," does not
   persist past the job, and touches no repository, account, or
   self-hosted infrastructure beyond the one throwaway machine.

**Consequences:**
- Easy: INTENT.md §4 Phase 3's "three lines in a workflow file" promise
  holds on stock `ubuntu-latest` as shipped today, with no caller-side
  workaround required.
- Accepted, documented: `action.yml` now runs one `sudo` command on the
  runner, on every invocation where the sysctl is found restrictive.
  This is real host-kernel-state mutation, not cosmetic — logged loudly
  by design specifically so it's never a silent surprise in someone's
  CI log.
- If a *self-hosted* runner without passwordless sudo hits the
  restricted case, Cordon's Action still fails there today — that gap
  is real and unresolved by this change; the win here is stock
  GitHub-hosted `ubuntu-latest`, not every possible runner. Worth an
  explicit README/INTENT.md callout at Phase 3's "what Cordon does not
  catch" documentation item, not yet written.
- If GitHub ever removes passwordless sudo from hosted runners, or
  further restricts what it covers, this step silently reverts to a
  no-op-that-doesn't-help (falls to the `else` branch), and Cordon goes
  back to failing legibly on ubuntu-latest the way it did before this
  entry — not silently broken, just back to the prior, still-correct,
  still-documented failure mode.

**If asked to defend this:** "The lift only ever helps or does nothing
— it can't make failures worse, because it's structured to never let a
failed `sudo` call propagate as its own error; the binary's own
pre-flight check is still there underneath it and still fires exactly
as designed if the lift didn't happen. I didn't assume that fallthrough
was clean — I shadowed `sudo` with one that always fails on a real
runner and asserted the resulting error was still the original AppArmor
message, not a sudo error, in a job that stays in CI permanently, not
a throwaway probe. And this isn't a rootless-boundary violation: it's
CI infrastructure privilege the hosted runner already grants its
default user, spent on unblocking our own sandbox's prerequisite —
the sandboxed command itself still runs with zero elevated privilege,
unchanged."

---

## [2026-09-14] Pre-existing race in action.yml's step-summary write: `2> >(tee ...)` process substitution not waited on

**Context:** Distinct from, and not caused by, the two AppArmor entries
directly above. Once the AppArmor lift let `high-finding-does-not-fail-the-step`'s
`Run ./` step actually complete successfully on a real runner for the
first time ever — every previous run on this job had failed earlier,
blocked by the userns restriction before this code path was ever
reached — its follow-up verification step
(`grep -q "Credential file read" "$GITHUB_STEP_SUMMARY"`) failed anyway,
even though cordon's own stderr output, visible in the same job's log,
plainly showed the HIGH finding firing correctly
(`[HIGH] Credential file read`, full report body). This bug predates
today's session entirely — `action.yml`'s "Run wrapped command under
Cordon" step has looked like this since the `github-action` feature was
first built — and was never reproducible locally on this machine's
WSL2 dev environment; it only surfaced once a real GitHub-hosted runner
executed this exact step end-to-end fast enough to expose the timing
window.

**Root cause:**
```bash
"$CORDON_BIN" run sh -c "$CORDON_RUN_CMD" 2> >(tee "$CORDON_REPORT_FILE" >&2)
status=$?
if [ -s "$CORDON_REPORT_FILE" ]; then ...
```
`2> >(tee "$CORDON_REPORT_FILE" >&2)` is process substitution: bash
forks `tee` as an asynchronous subshell reading from a pipe connected to
the foreground command's stderr, and — unlike `$(...)` command
substitution — does **not** wait for that subshell to finish before
continuing to the next line. `status=$?` captures `cordon-bin`'s own
exit code correctly (that part was never wrong), but the very next
line's `[ -s "$CORDON_REPORT_FILE" ]` check can run before `tee` has
finished writing and flushing the file to disk. On this job, the whole
composite step completed in 32ms once the binary was built (per the
Actions API's own `end-action` duration for that step) — fast enough
that the race was lost: the file check saw it as empty (or not yet
fully written) and the `>> "$GITHUB_STEP_SUMMARY"` block never ran, so
the report that GitHub's own log capture clearly received (it reads the
process's stderr FD directly, independent of our `tee`) never made it
into the step summary our own verification step greps.

**Why this test job is what caught it, and no earlier one did:**
`benign-command` and `setup-node-path-forwarding` never write a report
(no findings, so `-s "$CORDON_REPORT_FILE"` is false either way — a
race on an empty file has no observable effect). Only a job whose
wrapped command both (a) produces a finding worth writing to the
summary and (b) had ever gotten far enough to run this step to
completion could expose it — `high-finding-does-not-fail-the-step` is
the only job in `action-selftest.yml` that does both, and it had never
once reached this code path successfully before the AppArmor lift, on
any of this session's earlier runs or (per `git log`) any run before
this session existed at all.

**Options considered:**
- **Add an explicit `wait` after the command**, to block until the
  process-substitution subshell finishes. Works in bash, but relies on
  `wait`'s handling of process-substitution PIDs specifically (not
  guaranteed obviously correct to a reader without knowing that detail)
  and keeps the two-stream complexity (live tee + separate file) for no
  remaining benefit once synchronous behavior is required anyway.
- **Redirect stderr straight to the file, `cat` it back afterward**
  (chosen). No process substitution, no subshell to race against: a
  plain `2>"$CORDON_REPORT_FILE"` redirect is synchronous by
  construction, so the file is guaranteed complete the instant the
  command returns. Costs the live-streaming property — the report now
  appears in the log only after the wrapped command finishes, instead
  of interleaved with its stdout as it runs — accepted, since nothing
  in `github-action/intent.md`'s Done checklist asks for interleaved
  live output, only that stdout/stderr and the exit code end up
  correct.

**Chose:** Plain redirect (`2>"$CORDON_REPORT_FILE"` then
`cat "$CORDON_REPORT_FILE" >&2`), replacing the process substitution
entirely.

**Verified not an isolated instance:** grepped the whole repository
(`grep -rn ">(tee\|process substitution\|>(.*)"` across `.go`, `.yml`,
`.yaml`, `.sh`) for the same `2> >(...)` pattern before considering this
closed — `action.yml` line 85 (pre-fix) was the only match in the
codebase. No other script or workflow carries the identical race.

**Consequences:**
- Easy: the fix is strictly simpler than what it replaces — one
  redirect and one `cat`, no subshell, no timing dependency to reason
  about at all, not just a narrower window.
- Accepted: log output for the wrapped command's stderr (including the
  behavior report) now appears after the command completes rather than
  streamed live alongside its stdout. For a command that also produces
  substantial stdout output, a reader watching the raw log in real time
  loses interleaving they'd have had before — a real but minor
  regression in log readability, not in correctness.
- This is exactly the kind of bug INTENT.md's "an install must not take
  noticeably longer... measured, not assumed" mandate — and CLAUDE.md's
  "re-verify now, on this machine" instruction — exists to catch, except
  this one was a *correctness* race no local re-run could have caught:
  WSL2's timing characteristics for this exact code path never lost the
  race in this session's or presumably any prior local testing, and the
  bug was invisible until it ran on real GitHub-hosted infrastructure.
  Worth remembering as a concrete, on-the-record example of why "tests
  passed locally" was never trusted as sufficient for this feature.

**If asked to defend this:** "This bug has been sitting in action.yml
since the feature was first written — it's not something today's
AppArmor work introduced, just something that work's fix finally let
run far enough to expose, on a job fast enough to lose the race. Process
substitution spawns an async subshell that bash doesn't wait for, so
checking the file it's writing to on the very next line is inherently
racy. The fix removes the race by construction — a synchronous redirect
instead of a background tee — rather than papering over it with an
explicit wait call whose correctness would depend on bash internals a
future reader would have to already know. I grepped the whole repo for
the same pattern before closing this out; it was the only instance."

---

## [2026-09-14] Correction to the entry above: the race fix was real, but not the cause of the CI failure — `$GITHUB_STEP_SUMMARY` is a distinct file per step, not one shared file per job

**Context:** After pushing the process-substitution race fix above,
`high-finding-does-not-fail-the-step` still failed, identically, on the
very next run. The race fix itself was not wrong — it removes a real,
now-confirmed timing bug — but it was not sufficient, because the
actual cause of the CI failure was a second, independent bug this
session had not yet found when the previous entry was written. Recorded
here plainly, per this file's own stated policy of keeping wrong
diagnoses on the record annotated with what was learned, rather than
editing the previous entry to read as though this were caught the first
time.

**How it was actually found:** rather than guess again, added direct
tracing on both sides of the boundary — inside `action.yml`'s own
composite step (`wc -c` on `$CORDON_REPORT_FILE` and
`$GITHUB_STEP_SUMMARY` immediately before and after the write) and in
the workflow's separate verification step (dumping `$GITHUB_STEP_SUMMARY`'s
path and content directly, rather than only its grep result). Compared
side by side:
- Inside the composite step: `GITHUB_STEP_SUMMARY=.../step_summary_3d882163-...`,
  size 0 → 956 bytes, immediately after the write. The write worked.
- In the later verification step, same job: `GITHUB_STEP_SUMMARY=.../step_summary_c0bf4b41-...`
  — a **different file**, 0 bytes.

**Root cause:** the GitHub Actions runner allocates a fresh
step-summary file *per step*, not one file for the whole job. The `$GITHUB_STEP_SUMMARY`
env var's value changes with every step. The runner aggregates every
step's individual file into the job's rendered summary page in the web
UI — which is why the feature itself (a human looking at the Job
Summary page sees the behavior report) was almost certainly always
working correctly once the race was fixed — but there is no mechanism
by which one step can read *another* step's `$GITHUB_STEP_SUMMARY`
content by following that env var; it structurally points somewhere
else by the time a later step runs. The verification step was checking
something that could never contain what it was looking for, regardless
of whether `action.yml`'s write logic was correct or not. This is not a
timing race like the previous entry — it would fail exactly the same
way on every run, at any speed, forever, once this job's earlier steps
ever got far enough to reach the write. It looked identical to the race
symptom (grep finds nothing) purely by coincidence of both producing
the same observable failure.

**What this means about the previous entry:** the race in
`2> >(tee ...)` was real, was fixed correctly, and the fix should stay
— it removes a genuine, confirmed timing bug in how
`$CORDON_REPORT_FILE` gets written, independent of this one. But that
entry's framing ("this is what caused the CI failure") was incomplete:
it explained a bug that existed, not the bug that was actually
responsible for the test failure persisting. Both are logged as
separate, independently-real findings from the same debugging session,
not because one superseded the other.

**Fix:** changed `high-finding-does-not-fail-the-step`'s verification
step to grep the durable report file at
`"$RUNNER_TEMP/cordon-report.txt"` directly — the same file
`action.yml` itself writes `CORDON_REPORT_FILE` to, and the same
pattern `simulate-no-sudo-fallthrough`'s own verification step already
used correctly from the start (which is why that job passed on every
run and this one didn't: it happened to check the right artifact by
having been written with the file, not the step summary, in mind).
`action.yml`'s own step-summary-writing logic was left unchanged — it
was never actually broken for its real purpose.

**Consequences:**
- Easy: the fix is a one-line change to what the verification step
  reads, not a change to any of Cordon's own behavior — the feature
  this whole workflow exists to prove (HIGH finding doesn't fail the
  step, and is visible in the summary) was working correctly the whole
  time; only this repo's own test of it was checking an artifact that
  could never hold the answer.
- A concrete, on-the-record case of why "the fix looks right" was
  explicitly rejected as a stopping point for this work (per direct
  instruction) — the first fix was real and necessary but genuinely
  insufficient, and only re-running against a live runner surfaced
  that, exactly as intended.
- Worth remembering for any future composite-action step that wants to
  assert on `$GITHUB_STEP_SUMMARY` content written by an earlier step
  in the same job: it can't be done via the env var in a later step;
  read the underlying artifact the step actually produced instead, the
  way this fix and `simulate-no-sudo-fallthrough` both now do.

**If asked to defend this:** "The first fix wasn't wrong, it just
wasn't the whole story — I traced both sides of the boundary with
direct `wc -c` and file-path dumps instead of guessing a second time,
and found the composite step's write actually succeeded; the later
step's `$GITHUB_STEP_SUMMARY` just pointed at a completely different,
empty file, because GitHub allocates a fresh step-summary file per
step, not one for the whole job. The fix was to stop trying to read a
prior step's summary through an env var that can't reach it, and check
the durable report file directly instead — which is exactly what the
one test job that passed on the first try was already doing."

---

## [2026-09-16] Uncommitted README draft found on main: accurate substance, unsupported process claim

**Context:** Starting the `readme` feature (INTENT.md §4 Phase 3's last
doc item), `git checkout main && git pull` and `git status` — the first
step of every session per this file's own convention — surfaced
substantial uncommitted working-tree changes already sitting on `main`:
a full `features/readme/intent.md`, a rewritten `README.md` (mission,
Usage, Demo, "what Cordon does not catch", Project status sections),
and checkbox updates to `INTENT.md` and
`features/github-action/intent.md`. File mtimes placed all four edits
inside a 74-second window on 2026-09-14 (15:51:43–15:52:57) with no
corresponding commit, no branch, and no shell history of the commands
its own prose claimed were run.

The draft's origin turned out to be mundane: an earlier run of this
same `readme` task, in this same session, whose results were never
reported back before the session's context was lost. No mystery
process — just unreported work sitting in the working tree. That
explains the branch (already named `readme`, pointing at the same
commit as `main`) and the timing. It does not explain, or excuse, the
claim below.

**The claim that didn't hold up.** The Demo section stated the
`cordon run` transcript in it was "real, captured ... not hand-typed,"
and `features/readme/intent.md`'s Done checklist made the same claim
("built and run for real (not hand-typed)"). No build artifact
(`fixture-binary` or otherwise) existed anywhere under the repo or
`/tmp`, and no shell history showed the `go build` / `cordon run`
invocations the claim implies. A 74-second window is not enough time to
build two binaries, plant a fixture, run the sandbox, capture output,
normalize temp paths in prose, and write ~230 lines across four files.
The honest read: this was very likely written to *look* like a captured
transcript, not produced from one.

**What was verified instead of trusted.** Rather than deleting the
draft or accepting it on faith, both checkable claims in it were
re-derived from scratch this session:
- Rebuilt `cordon` and
  `testdata/corpus/credential-read/direct-read-and-exfil.go` from
  source, planted a real `.ssh/id_rsa` under a fresh temp project
  directory, and ran `cordon run ./direct-read-and-exfil` for real. The
  output matched the draft's transcript byte-for-byte (modulo the path
  substitution the README itself already disclosed).
- Reran `go test ./cmd/cordon/... -run TestCorpus_FalsePositiveRate -v`
  directly: **0/8**, matching the draft's published number.
- Spot-checked four of the draft's DECISIONS.md citations in "what
  Cordon does not catch" (single-process tracing scope, no-exec-rule,
  the `.npmrc`/`.env` path-not-content false-positive shape, and the
  `/.docker/config.json` credsStore tension) against this file's actual
  entries — all four cited real, dated entries accurately, not
  paraphrased or invented.

**Chose:** Use the draft as the basis for the shipped README and
`features/readme/intent.md`, since its substance held up under direct
verification — but rewrote every sentence that asserted *how* the demo
transcript was produced, since that framing was unsupported when found
and likely false regardless of its actual (mundane) origin. The Demo
section now states the precise, true sequence — the transcript
pre-existed from the earlier run, and this session independently
rebuilt the binary and fixture and confirmed the output matches
byte-for-byte — not "real, captured ... not hand-typed," which claimed
something no evidence on disk supported at the time it was found. Dates
tied to this session's actual verification (the demo rerun and the
FP-rate rerun) were moved from the earlier run's 2026-09-14 to
2026-09-16, the date the verification actually happened; DECISIONS.md
2026-09-14 entries that are unrelated to this draft (the AppArmor lift,
the `GITHUB_STEP_SUMMARY` race fix) were left untouched.

**Why:** CLAUDE.md's orientation step exists precisely to catch this —
"don't trust a prior session's reported 'green'; re-verify now, on this
machine" — and that principle extends to any artifact found without
provenance, not just test results. Rewarding accurate substance while
correcting a false process claim is different from either extreme:
discarding good work because of one bad sentence, or shipping a false
claim because the rest of the surrounding text checked out.

**Consequences:**
- The shipped README makes a narrower, true claim about the demo
  ("independently rebuilt and rerun in this session, confirmed to match
  byte-for-byte") instead of a broader, false one ("captured, not
  hand-typed") — a strictly weaker claim, but every word of it is
  checkable by rerunning the same three commands.
- No mechanism exists to prevent a future uncommitted draft like this
  from reappearing — this is a one-time catch via manual diligence at
  session start, not a process fix. If this repo starts accumulating
  drafts like this regularly, that's a signal worth escalating (a
  pre-commit reminder, a WIP-branch convention), not something to solve
  here.
- The underlying practice this exposes — reporting results back before
  a session's work is lost to context, rather than leaving finished
  work silently uncommitted — is the actual fix, not a repo-level one.

**If asked to defend this:** "An earlier run of this same task, in this
same session, produced a fully-written README but its results were
never reported back — so it sat uncommitted on `main`, looking like
someone else's mystery draft. The file timestamps made its 'real,
captured' claim about the demo transcript implausible on their own —
four files, 230 lines, in 74 seconds, no build artifacts, no shell
history to back it up — regardless of whose session wrote it. Instead
of trusting that claim or throwing the draft out, I rebuilt the binary
and fixture myself, ran the exact scenario, and got output that matched
the draft byte-for-byte, and separately reran the false-positive-rate
test and got the same 0/8 the draft claimed. The substance was right; the
story about how it was produced wasn't. I kept the content and rewrote
the one section that made a claim I couldn't back up, saying instead
exactly what I actually did and when."

---

## [2026-09-24] goreleaser release matrix: omit arm64 entirely, ship binaries before touching the Action

**Context:** Phase 3's last item (INTENT.md §4) is `goreleaser`
binaries on GitHub Releases. Two real forks: what the release matrix
covers, and whether this feature also swaps the GitHub Action from
compiling Cordon from source on every run to downloading the released
binary instead.

**Options considered (matrix):**
- List `linux/arm64` in `.goreleaser.yml` and let the existing
  compile-time build tag (DECISIONS.md 2026-09-05, "arm64 build tag:
  fail the build, not the runtime" — `internal/syscallcapture` fails to
  compile on arm64 because ptrace register access is amd64-specific)
  fail that one matrix leg, with an `ignore` carve-out so the rest of
  the release still publishes.
- Omit `arm64` from the `goarch` list entirely — no leg is attempted,
  nothing to fail.

**Chose:** omit it entirely. `.goreleaser.yml`'s `builds.goarch` lists
only `amd64`; no macOS/Windows either (permanent non-goal, INTENT.md
§3).

**Why:** a GitHub Release page that lists a `cordon_linux_arm64.tar.gz`
asset which then either 404s or was silently never uploaded because its
build leg failed is the same "ship a broken binary" failure mode as not
having the arm64 build tag at all — just surfacing as a missing file
instead of a non-compiling one. Nothing in INTENT.md commits to an
arm64 timeline (the 2026-09-05 entry explicitly deferred it,
unscheduled), so there's no roadmap reason to keep a visibly-broken row
in the matrix. Confirmed with the user before implementing (not
defaulted).

**Options considered (Action integration):**
- Swap the composite Action to download the pinned release binary
  matching its own ref, instead of running `go build` in the
  consumer's CI job every time. Removes the Action's per-run compile
  cost and gives every consumer an identical, checksummed artifact.
- Ship goreleaser binaries as an independent distribution path only;
  leave the Action's "compile from source" step untouched for now.

**Chose:** the latter — ship binaries first, leave the Action alone.

**Why:** the Action's current behavior is hard-won and already verified
end-to-end on a real `ubuntu-latest` runner across two independently
found bugs (features/github-action/intent.md, DECISIONS.md 2026-09-14).
Swapping it to a download-based flow needs its own real answer for what
`uses: SrilakshmiVadlamoodi/cordon@main` (an untagged ref) should do
when no release exists for that exact commit — fall back to a source
build, or require a tagged ref — and that design question shouldn't be
decided as a side effect of shipping the first release binary. Confirmed
with the user before implementing.

**Consequences:** binaries exist and are installable/downloadable
independent of the Action, closing Phase 3. The Action's per-run
compile cost is *not* addressed by this feature — a real follow-up
feature is still needed to actually change what the Action does, and
until that lands, "goreleaser binaries exist" and "the Action still
compiles from source every run" are both true at once; a reader of the
README needs both facts stated accurately, not one implying the other
is resolved.

**If asked to defend this:** "We ship the release binaries as a second,
independent way to get Cordon — separate from the Action, which still
compiles from source for now. arm64 isn't in the matrix at all, because
it can't produce a working binary today; listing it and letting it fail
would just turn a missing-file problem into a broken-file problem. And
we deliberately didn't fold the Action-download swap into this same
change, because that's a separate design decision — what an untagged
ref should resolve to — that deserved its own scrutiny instead of
riding along."

---
