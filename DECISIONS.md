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
