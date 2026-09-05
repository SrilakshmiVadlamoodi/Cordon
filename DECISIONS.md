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
