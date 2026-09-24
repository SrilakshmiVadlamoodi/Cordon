# Cordon

Rootless namespace sandbox for `npm install` (and friends) that reports
what a package's lifecycle scripts actually did — file reads, network
connections, process launches — so a developer can look before trusting.

## What Cordon is, and why

`npm install` and `pip install` run package-authored lifecycle scripts
(`preinstall`, `install`, `postinstall`; `setup.py` at build time) with
the full privileges of the invoking user, before anyone has reviewed the
package contents. That code has unrestricted read access to SSH keys,
cloud credentials, shell history, and browser profiles; unrestricted
outbound network access; and the ability to spawn arbitrary child
processes. Neither ecosystem sandboxes this by default. This is the
confirmed mechanism behind real supply-chain incidents, including
self-propagating npm worms that stole credentials via `postinstall` and
republished themselves using the victim's own publish tokens.

This isn't an unsolved problem — `npm --ignore-scripts` exists, and
commercial tools (Socket.dev, Phylum) do real dynamic analysis in
sandboxes. The gap Cordon fills is a tier of availability, not a novel
technique: a free, local, self-hosted tool that shows a developer what
an install actually did on their own machine, with no account, no
daemon, and no sudo.

**Two guarantees, and they are not the same strength:**

- **Isolation is a hard boundary.** The confined process cannot write
  outside the project directory or reach the network unobserved. This is
  built to be correct, and tested as such.
- **Detection is best-effort.** Behavioral classification has real,
  documented false negatives against a determined adversary and false
  positives against unusual but legitimate builds. Cordon publishes
  measured coverage and never claims completeness — see
  [What Cordon does not catch](#what-cordon-does-not-catch) below.

See [INTENT.md](INTENT.md) for the full mission, architecture, and
roadmap. See [DEVLOG.md](DEVLOG.md) for a curated account of the real
bugs found, tradeoffs made, and limitations accepted along the way —
several are cited by date throughout this README as `DECISIONS.md
<date>`, which refers to the maintainer's local, uncurated decision log
(not tracked in this repo as of 2026-09-24); DEVLOG.md is the published
version of that same material.

## Usage

Both usage paths run the same underlying `cordon run` — a local
sandboxed process with the wrapped command's own exit code always
preserved. **A finding never fails the run by itself**: INTENT.md §5,
"Blocking installs by default. Cordon reports; the human decides." Only
the wrapped command's own exit code can end the run non-zero.

### Command line

```
cordon run npm ci
```

Runs `npm ci` inside the sandbox from the current directory (the project
directory — read-write; everything else read-only or invisible, `$HOME`
mapped to the project directory) and prints the behavior report to
stderr after the command finishes.

### GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: SrilakshmiVadlamoodi/cordon@main   # pin to a commit SHA until a tagged release exists
  with:
    run: npm ci
```

Compiles Cordon from source on each run (`go build`, pinned to this
repo's own `go.mod` Go version, see
[`features/github-action/intent.md`](features/github-action/intent.md)),
runs the given command inside the sandbox, and appends the behavior
report to the job's step summary. Linux runners only (`ubuntu-latest`),
per INTENT.md §3. Verified end-to-end on a real hosted runner, including
a best-effort fix for Ubuntu 24.04's default AppArmor restriction on
unprivileged user namespaces (DECISIONS.md 2026-09-14). A `linux/amd64`
release build (`goreleaser`) exists and is validated in CI, but no
tagged GitHub Release has been cut yet, so this Action does not yet
download a pre-built binary instead of compiling — see
[`features/goreleaser-binaries/intent.md`](features/goreleaser-binaries/intent.md).

## Demo

A `cordon run` transcript against
[`testdata/corpus/credential-read/direct-read-and-exfil.go`][fixture],
the canonical pattern from this project's own mission statement: read an
SSH key, send it to a remote host, all inside the install's own process.
Independently rebuilt and rerun in this session, and confirmed to match
byte-for-byte. Reproduction steps are below the transcript.

```
$ cordon run ./fixture-binary
credential-read-and-exfil: done
=== Cordon behavior report ===

FINDINGS (3)

  [HIGH] Possible credential exfiltration
    A credential file was read AND a network connection was made in the same run:
      read:    /home/you/project/.ssh/id_rsa
      connect: 203.0.113.21:443
    Cordon cannot confirm the file's contents were sent — only that both happened.

  [HIGH] Credential file read
    The install opened a file matching a known secret path:
      /home/you/project/.ssh/id_rsa
    A package install has no legitimate reason to read this.

  [MEDIUM] Network connection
    The install opened a network connection to:
      203.0.113.21:443
    Shown as IP:port — the hostname the install asked for is not captured.

OBSERVED
  4 file open(s), 1 network connection(s), 0 program execution(s)

WHAT CORDON DID NOT OBSERVE
  - Only file opens, network connects, and program executions are traced.
    What a program does with an open file (read vs. write, how much) is not
    captured, and connection targets are shown as IP:port, not the hostname
    the program resolved.
  - No separate processes were launched by the install this run; if any had
    been, their syscalls would not have been traced.
  - Detection is best-effort by design (INTENT.md §1): a determined package
    can act through syscalls Cordon does not watch, or through a child process.
```

(Paths above are shown relative to a project directory for readability;
the actual verification run resolved to a temp directory. Reproduce it
yourself: `go build ./testdata/corpus/credential-read/direct-read-and-exfil.go`,
plant `.ssh/id_rsa` in a project directory, `cd` there, and
`cordon run ./direct-read-and-exfil`.)

[fixture]: testdata/corpus/credential-read/direct-read-and-exfil.go

## False-positive rate

**0 / 8** benign-labeled fixtures in Cordon's own test corpus produce an
unexpected HIGH finding, as of 2026-09-16.

**What this number is a statement about, precisely:** the 8 fixtures
under `testdata/corpus/` that are explicitly labeled `benign` in
[`cmd/cordon/corpus_test.go`](cmd/cordon/corpus_test.go)'s `corpusCases`
table — synthetic, self-authored Go programs modeling legitimate install
behavior (a pure-JS package with no side effects, ordinary in-project
file writes, a `node-gyp`-shaped native build, a file access adjacent to
but distinct from a real credential marker). Of those 8, zero produce a
`[HIGH]` finding.

**What this number is *not* a statement about:** it is **not** a
measurement against real npm, pip, or any other registry's packages.
Cordon's corpus contains no packages pulled from any real registry —
every fixture is synthetic, for reasons of safety, reproducibility, and
determinism (see `DECISIONS.md`, 2026-09-05 and the `corpus-expansion`
feature). This is not a statistical sample of anything; it describes
only how Cordon's own two rules classify the specific archetypes this
project deliberately built to represent legitimate behavior. Treat it as
a regression guarantee ("we haven't shipped a rule that flags our own
benign fixtures"), not a market-representative false-positive rate.

**How current this is:** this is a manually-recorded snapshot, not a
live-generated number — nothing rewrites this file automatically when
the corpus changes. Recompute it yourself, and trust that output over
this file if they ever disagree:

```
go test ./cmd/cordon/... -run TestCorpus_FalsePositiveRate -v
```

That test walks the same `corpusCases` table this README's number is
drawn from, so a new benign fixture, or a rule change, is reflected the
next time someone runs it — this file only updates when a human notices
and re-pastes.

## What Cordon does not catch

Isolation is a hard boundary; detection is best-effort (INTENT.md §1).
These are the specific, known, documented gaps in the detection layer —
not a hedge, an actual list, each traceable to a real finding in this
repo's own history.

- **Forked child processes are invisible.** Tracing is scoped to the
  single directly-launched process; a credential read or network
  connection made by a forked child (`node-gyp`, `cc`, a postinstall's
  own subprocess chain) is not captured. This is most of what a native
  build or a multi-stage install actually does. Deliberately scoped this
  way, not an oversight — see DECISIONS.md 2026-09-04 ("tracing scoped
  to one process, reaping scoped to the whole tree") and the
  `credential-read-gap` corpus fixture, which demonstrates exactly this
  miss end-to-end. Widening this is `syscall-capture-tree`, deferred to
  Phase 5 with no committed timeline (see
  [Project status](#project-status)).
- **No exec-based rule.** Under single-process tracing, "download and
  run" is almost always a forked child's `execve`, which falls under the
  gap above — an exec rule would be mostly dead weight until
  process-tree tracing exists (DECISIONS.md 2026-09-05).
- **Detection is path-based, not content-based.** Rules match on the
  *path* a file was opened at, never its contents — `openat` is traced,
  `read` is not. A credential-path match fires on a token-free `.npmrc`
  or a legitimate `.env` exactly as it would on a real secret (known
  false-positive shape, DECISIONS.md 2026-09-05 and 2026-09-11); an
  actual secret under a path Cordon doesn't recognize produces no
  finding at all. The `.cordon-allowlist` mechanism lets a developer
  suppress a known-safe exact path (never a pattern — see
  `features/allowlist-mechanism/intent.md`, "Why not globs"), but that's
  a mitigation, not a fix to the underlying blindness.
- **`/.docker/config.json` is classified as definite-confidence despite
  a known tension:** many modern Docker configs hold only a
  `credsStore` pointer to an external credential helper, no embedded
  secret — structurally closer to `.npmrc`'s "config, not necessarily a
  secret" shape. Logged, not reclassified (DECISIONS.md 2026-09-11).
- **Connection targets are IP:port, not hostname.** The resolved
  address is captured, not the DNS name the program asked for — a
  legitimate `node-gyp` header download and a malicious exfiltration
  target look identical in the report unless a reader recognizes the IP.
- **Delayed/backgrounded actions are cut off, but only slow ones, and
  by a side effect, not a designed defense.** A child process
  backgrounded to act after the primary process exits is killed by the
  kernel's PID-namespace teardown (every process in a namespace is
  SIGKILLed when its PID 1 exits) — but this is a consequence of the
  architecture built for signal fidelity, not an anti-evasion feature
  anyone set out to build, and it only stops *slow* delay. A background
  action that completes before the primary process exits gets neither
  more nor less detection than the same action running inline
  (DECISIONS.md 2026-09-11).
- **Single UID mapping affects npm's own privilege-drop behavior.**
  Cordon's rootless design (no setuid helper, no `/etc/subuid`) maps
  exactly one UID into the sandbox. npm detects it is running as root
  and attempts to drop privileges before lifecycle scripts — that
  `setuid()` fails under a single mapping. Known, accepted limitation,
  not yet worked around (DECISIONS.md 2026-09-01; INTENT.md §3).
- **arm64 is unsupported, on purpose, at build time.** `cordon` refuses
  to *build* at all on `linux/arm64` rather than shipping a binary that
  silently observes nothing — a deliberate choice over the alternative
  of a binary that looks like it works (DECISIONS.md 2026-09-05).
- **Overhead is measurable and currently exceeds this project's own
  bar.** INTENT.md §3 requires "not noticeably longer, measured, not
  assumed." A real dependency-tree install with a forked postinstall
  script measured **+32.7%** wrapped vs. unwrapped after the current
  fast-path optimization — down from an initial +72%, but still over
  the stated bar, and accepted as a documented Phase 1 gap rather than
  silently carried (DECISIONS.md 2026-09-04, the openat fast-path
  entries).
- **On GitHub-hosted `ubuntu-latest`, the AppArmor unprivileged-userns
  restriction is lifted best-effort, not guaranteed.** The Action
  attempts a passwordless-sudo sysctl lift and falls through cleanly to
  a clear, specific error if it can't — verified, not assumed
  (DECISIONS.md 2026-09-14). A self-hosted runner without passwordless
  sudo will still hit that failure directly.

## Project status

See [INTENT.md §4](INTENT.md#4-roadmap) for the full roadmap; this is a
summary.

- **Phase 1 (MVP) — complete.** Rootless sandbox, single-process syscall
  capture, plain-text behavior report, correct on Cordon's own synthetic
  corpus. Overhead measured at +32.7% — over budget, logged as an
  accepted Phase 1 gap rather than silently carried forward.
- **Phase 2 (signal-to-noise) — complete** against the roadmap as
  written, with one item's scope deliberately narrower than its literal
  wording: severity tiers were not added as a third numeric tier
  (evidence didn't support it); "highest-value finding surfaces first"
  is instead satisfied via a confidence-based secondary sort. Corpus
  breadth (~16 fixtures across 9 archetypes, short of the roadmap's
  "~50 packages" framing) is an open question, not a gap — see
  `features/corpus-expansion/intent.md`.
- **Phase 3 (distribution) — in progress.** The GitHub Action is merged
  and verified end-to-end on a real hosted runner; Cordon now runs on
  its own CI; this README shipped. The `goreleaser` release matrix
  (`linux/amd64` only — `arm64` deliberately excluded, see
  [What Cordon does not catch](#what-cordon-does-not-catch) below and
  DECISIONS.md 2026-09-05) is built and validated in CI via snapshot
  builds, but no tagged release has been cut yet, so there is still no
  downloadable binary on GitHub Releases. The Action still compiles
  Cordon from source on every invocation — swapping it to download the
  release binary instead is a deliberate follow-up, not bundled into
  shipping the release matrix (DECISIONS.md 2026-09-24).
- **Phase 4 (reach) — not started.** pip/`setup.py` support,
  cross-version behavioral baselines, an eBPF evaluation.
- **Phase 5 (tree tracing) — deferred, no committed timeline.**
  Widening capture from a single process to the full process tree is
  explicitly lower priority than distribution and reach, by deliberate
  decision: the current single-process scope is honestly documented as
  a known limitation (see [What Cordon does not catch](#what-cordon-does-not-catch)
  above) rather than silently downplayed, and closing it is weighed
  against the adoption value of shipping distribution work first.
  INTENT.md §4 revisits this decision after Phase 4, not before.
