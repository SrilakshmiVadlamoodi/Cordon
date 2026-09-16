# Cordon — INTENT

Durable source of truth for this project. Read before starting any feature
work. Update whenever architecture or stack decisions change.

---

## 1. Mission

### The problem

`npm install` and `pip install` execute package-authored lifecycle scripts
(`preinstall`, `install`, `postinstall`; `setup.py` at build time) with the
full privileges of the invoking user, before anyone has reviewed the package
contents. That code has unrestricted read access to SSH keys, cloud
credentials, shell history and browser profiles; unrestricted outbound
network access; and the ability to spawn arbitrary child processes. Neither
ecosystem sandboxes this by default.

This is the confirmed mechanism behind multiple real supply-chain incidents,
including self-propagating npm worms that stole credentials via `postinstall`
and republished themselves using the victim's own publish tokens.

### Why existing solutions leave a gap

We are **not** claiming this is an unsolved problem. Honest landscape:

| Existing | What it does | Why the gap remains |
|---|---|---|
| `npm --ignore-scripts` | Disables lifecycle scripts entirely | Breaks legitimate native builds (`node-gyp`, `sharp`, `maturin`), so most teams leave it off |
| Socket.dev, Phylum | Commercial; real dynamic analysis in sandboxes | Priced for companies; not something an individual runs locally for free |
| Deno permissions | Runtime-level capability model | More fundamental fix, but requires leaving the Node/npm ecosystem |
| npm provenance, OpenSSF Scorecard | Publisher attestation, build reproducibility | Addresses *who published it*, not *what it did on your machine* |

**The gap Cordon fills is a tier of availability, not a novel technique:**
a free, local, self-hosted tool that shows a developer what an install
actually did on their own machine. Nothing in the list above serves the
individual developer or the small team with no security platform.

### Scope of the guarantee — deliberate and non-negotiable

- **Isolation is a hard boundary.** The confined process should not write
  outside the project tree or reach the network unobserved. This we build
  to be correct.
- **Detection is best-effort.** Behavioral classification will have false
  negatives against a determined adversary (env-var indirection, delayed
  execution, syscalls we didn't filter) and false positives against unusual
  but legitimate builds. We publish measured coverage; we never claim
  completeness.

Any feature, README line, or summary implying total detection coverage is a
**defect against this document**.

---

## 2. Users

Individual developers and small teams with no security platform team.
They run Cordon from a terminal or as a GitHub Action step.

Two consequences that are product requirements, not polish:

1. **Signal-to-noise gates adoption.** A tool that flags every `node-gyp`
   compile gets uninstalled on day one. False-positive rate is a headline
   metric, measured and published.
2. **Zero-friction install or no users.** No account, no daemon, no
   sudo, no separate database service.

---

## 3. Architecture & tech stack

### Language and toolchain

| Choice | Value | Rationale |
|---|---|---|
| Language | **Go** 1.23+ | `x/sys/unix` gives raw syscall access without FFI; the entire container ecosystem (runc, containerd, Docker) is Go, so reference implementations are readable; static single-binary output; fast build loop |
| Module path | `github.com/SrilakshmiVadlamoodi/cordon` | Phase 3 ships `go install`-able binaries and a GitHub Action; a bare path would force a rename across every import later |
| Not Rust | — | Borrow checker fights you at the same time the kernel does; can't debug two hard things at once. Revisit for an eBPF rewrite later |
| Build/release | `goreleaser` | Cross-compile matrix, GitHub Releases |
| Lint | `golangci-lint`, `go vet` | |
| Test | stdlib `testing` | Checked-in test files, maintained. No external framework |

### Isolation layer

- Linux **namespaces**: mount, PID, network, user.
- Project directory mounted read-write; everything else read-only or
  invisible. `$HOME` not visible by default.
- **Rootless** — no sudo, no setuid helper, no file capabilities on the
  binary. Pure user-namespace path: `CLONE_NEWUSER` in the same clone as
  the other namespaces, since an unprivileged process gains a full
  namespace-scoped capability set (incl. `CAP_SYS_ADMIN`) on creating one.
  **Explicitly not** `newuidmap`/`newgidmap` — depending on a setuid helper
  and `/etc/subuid` being configured violates §2 zero-friction.
  *Known consequence:* single UID mapping means unmapped UIDs appear as the
  overflow UID and `setuid()` to them fails. npm drops privileges to the
  package-dir owner when it detects it is root — expect this to surface
  when the Phase 1 corpus runs. Hedges: `--unsafe-perm`, or map to a
  non-zero UID (capabilities are granted to the userns creator regardless
  of mapped UID).
- Namespace setup via `exec.Cmd` + `SysProcAttr` at exec time.
  **Never fork manually** — the Go runtime does not survive `fork()`.

### Observation layer

- **seccomp-BPF** for the fast allow/deny path on syscalls.
- **ptrace** (or `seccomp_unotify`) only for syscalls whose *arguments*
  must be inspected — resolving fds to real paths, sockaddrs to hostnames.
- `runtime.LockOSThread()` is **mandatory** wherever ptrace is used.
  Without it, ptrace calls may originate from a different OS thread than
  the one that attached, producing failures with no apparent cause
  (golang/go#28315).
- Overhead budget: an install must not take noticeably longer. Measured,
  not assumed.

### Storage

- Local only. SQLite at most, for cross-version behavioral baselines
  (Phase 4). No service, no server, no cloud.

### Platform

- **Linux only.** Namespaces and seccomp are Linux features. macOS and
  Windows are out of scope, permanently, not "later".
- **Minimum kernel 5.10.** Covers user namespaces (3.8), `setgroups:deny`
  before uid_map write (3.19), seccomp-BPF (3.5), `seccomp_unotify` (5.9,
  needed for Phase 4), and cgroup v2 as default. 5.10 is the floor for
  Debian 11 / Ubuntu 20.04+, so nothing current is excluded.
- **Dev:** WSL2. **CI:** GitHub Actions `ubuntu-latest`.
- **Open item:** Ubuntu 24.04 gates unprivileged user namespaces behind
  AppArmor (`kernel.apparmor_restrict_unprivileged_userns`). Runner
  configuration must be probed in CI as an early step, not assumed.
  Fallback: run tests in a container, or set the sysctl explicitly.
- Linux-only code carries `//go:build linux`; tests `t.Skip` with a clear
  message when unprivileged userns is unavailable, so CI failures point at
  the environment rather than the code.

### Reference material

- `criyle/go-sandbox` — closest existing Go implementation. **Read for
  reference; do not vendor or fork.** Start with `pkg/forkexec`.
- `opencontainers/runc` — production seccomp filter setup in
  `libcontainer/specconv`.

---

## 4. Roadmap

### Phase 1 — MVP *(current)*

Sandbox one `npm install`, capture file/network/process events, print a
plain-text report (to **stderr** — the wrapped command owns stdout; see
`features/behavior-report/intent.md` and DECISIONS.md 2026-09-05).

- [x] `sandbox-runner` — rootless namespace confinement
- [x] `syscall-capture` — `openat` / `connect` / `execve` with resolved
      args, traced process scoped to the single directly-launched child
      (see `features/syscall-capture/intent.md` Scope split) — unchecked
      2026-09-04 for a sibling-thread event drop, fixed same day, see
      that doc
- [ ] `syscall-capture-tree` — widen tracing to the full process tree
      (fork/clone/exec auto-attach); deferred out of `syscall-capture`,
      scoped into Phase 5 (deferred, revisit after Phase 4) — see
      `features/syscall-capture-tree/intent.md`
- [x] `behavior-report` — plain-text diagnosis (to stderr; two crude
      rules — credential-read / network-egress; see that feature's
      intent.md for deviations)
- [x] Correct on the MVP corpus — built as 6 **synthetic** fixtures
      (`testdata/corpus/`: 2 benign, 1 native-build-style, 2
      malicious-pattern, 1 bare-connect), not real registry packages;
      `cmd/cordon/corpus_test.go` is the check. A real-package corpus is
      still worthwhile later (Phase 2 expands it anyway).
- [x] Overhead on a real install measured and recorded (DECISIONS.md
      2026-09-04: +32.7% after the openat fast-path fix — still over
      INTENT §3's "not noticeably longer" bar, accepted as a documented
      gap for this phase)

### Phase 2 — Signal-to-noise

- [ ] Corpus expanded to ~50 packages across ecosystems
      *(9 archetype groups / ~16 fixtures shipped so far — synthetic, not
      registry packages, same reasoning as Phase 1's corpus; see
      `features/corpus-expansion/intent.md`. Short of ~50; open question
      whether more categories/variants are still wanted.)*
- [ ] Behavior taxonomy with written rationale per rule
- [x] Severity tiers; highest-value finding surfaces first
      *(deviation, deliberate: no third numeric severity tier added —
      the existing two-tier HIGH/MEDIUM split plus exfil-correlation
      escalation already earns its keep; "highest-value finding surfaces
      first" is instead satisfied via a confidence-based secondary sort
      key beneath severity, so multiple simultaneous HIGHs render in a
      deterministic, confidence-ordered sequence; see
      `features/finding-confidence/intent.md` and DECISIONS.md
      2026-09-11)*
- [x] Allowlist mechanism for known-good patterns
      *(deviation, deliberate: exact developer-authored paths only, not
      patterns — a path pattern loose enough to cover a legitimate file
      is loose enough to cover a malicious one at a similarly-shaped
      path; see `features/allowlist-mechanism/intent.md` "Why not
      globs" and DECISIONS.md 2026-09-11)*
- [x] False-positive rate measured and published in README
      *(0/8 on Cordon's own synthetic benign-archetype corpus, published
      in README.md; see `features/false-positive-rate/intent.md` and
      DECISIONS.md 2026-09-11)*

### Phase 3 — Distribution

- [x] GitHub Action wrapper (three lines in a workflow file)
      *(merged to `main`; verified end-to-end on a real GitHub-hosted
      `ubuntu-latest` runner, including two independently-found and
      fixed bugs only a live runner surfaced — see
      `features/github-action/intent.md` and DECISIONS.md 2026-09-14)*
- [ ] `goreleaser` binaries on GitHub Releases
- [ ] README with demo, FP numbers, and an explicit list of what Cordon
      does not catch
      *(in progress — see `features/readme/intent.md`)*
- [x] Cordon runs on Cordon's own CI
      *(`action-selftest.yml` runs on every push to `main`; confirmed
      green after the `github-action` merge, DECISIONS.md 2026-09-14)*

### Phase 4 — Reach

- [ ] pip / `setup.py` support
- [ ] Cross-version behavioral baselines ("this version started doing X")
- [ ] Evaluate eBPF (Aya, or Go equivalents) to replace ptrace

### Phase 5 — Tree Tracing (deferred, revisit after Phase 4)

This phase is explicitly lower priority than Phase 3 (distribution) and
Phase 4 (reach) by deliberate decision — the tool's current single-process
scope is honestly documented as a known limitation (see
`features/syscall-capture-tree/intent.md`, DECISIONS.md, and the
credential-read-gap fixture), not silently downplayed, and closing it is
being weighed against the resume/adoption value of shipping distribution
work first. Revisit after Phase 4 to decide whether to build it at all.

- [ ] Auto-attach `PTRACE_O_TRACEFORK`/`TRACEVFORK`/`TRACECLONE`/`TRACEEXEC`
      for real forked child processes (not just sibling OS threads,
      already covered by `syscall-capture`)
- [ ] Extend the tracee-set/dispatch logic from single-process to a full
      process tree
- [ ] `credential-read-gap` and `delayed-process` corpus fixtures flip
      from documented misses to regression-tested catches
- [ ] Re-measure overhead — tree tracing multiplies ptrace stops across
      every traced process, not just one

---

## 5. Non-goals

- Being a security boundary users rely on to run known-malicious code.
- Static analysis, CVE scanning, or license checks — other tools own these.
- Windows or macOS support.
- Blocking installs by default. **Cordon reports; the human decides.**
- A dashboard, a web UI, or a hosted service.
