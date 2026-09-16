# github-action

**Inherits:** INTENT.md §4 Phase 3 ("GitHub Action wrapper (three lines in
a workflow file)"), §5 Non-goals ("Blocking installs by default. Cordon
reports; the human decides."); [[env-path-forwarding]] (merged
prerequisite — without it, the Action's default configuration,
`actions/setup-node` before `cordon run npm ci`, fails to resolve
`node`/`npm` at all); [[sandbox-runner]], [[syscall-capture]],
[[behavior-report]] (what a CI consumer actually receives from a run)

**Why:** Phase 3 is distribution — the point at which Cordon stops being
something only run from a local checkout and becomes something a
stranger's CI can use in three lines. The GitHub Action is the actual
distribution mechanism (goreleaser binaries and the README both serve
it or depend on it existing); it is also the first real external-facing
surface, so its defaults get scrutinized here rather than discovered
wrong later by a user. `cmd/cordon`'s `run()` today always exits with
the wrapped command's own exit code (`main.go:63`, `res.ExitCode`),
completely unaffected by findings — this feature does not change that;
it explicitly relies on it.

**Done:**
- [x] A composite action, checked into this repo's root
      (`action.yml`), that a consumer workflow references with
      `uses: SrilakshmiVadlamoodi/cordon@<ref>` after checking out its
      own repo — no separate checkout of Cordon's own source required
      (GitHub Actions checks the action repository out to
      `$GITHUB_ACTION_PATH` automatically at the pinned ref)
- [x] Runs `cordon run <the consumer's command>` against the consumer's
      checked-out working directory (`$GITHUB_WORKSPACE`), not the
      action's own source tree
      *(`working-directory` is only set on the "Build Cordon" step,
      which `cd`s into `$GITHUB_ACTION_PATH`; the run step keeps the
      default cwd)*
- [x] Compiling Cordon and running the wrapped command are two
      separate, distinctly-named composite steps ("Build Cordon" vs.
      "Run wrapped command under Cordon"), so a `go build` failure (bad
      pin, toolchain problem, a break in Cordon itself) is
      distinguishable at a glance, by which step failed, from the
      wrapped command simply exiting non-zero — confirmed directly, not
      assumed: a deliberately broken `cmd/cordon/main.go` reproduced a
      real build failure isolated to the build step (`go build` exit 1),
      restored before committing
- [x] A real end-to-end run on GitHub's hosted `ubuntu-latest` runner,
      via Cordon's own CI (Phase 3's separate "Cordon runs on Cordon's
      own CI" item, but the first real proof this Action works at all,
      not just that it's plausible) — specifically checks whether
      unprivileged user namespaces are available there or the AppArmor
      gate (INTENT.md §3, DECISIONS.md 2026-09-01) blocks it, rather
      than assuming either way
      *(confirmed: `ubuntu-latest` is AppArmor-gated by default
      (DECISIONS.md 2026-09-14). Fixed with a best-effort, loud,
      non-fatal sysctl lift in `action.yml`, plus two independent bugs
      found and fixed only by iterating against the real runner — a
      process-substitution race and `$GITHUB_STEP_SUMMARY` being scoped
      per-step, not per-job (DECISIONS.md 2026-09-14, both entries).
      All four `action-selftest.yml` jobs verified green on a real
      runner before merge, and again on the first real `push`-to-`main`
      trigger after merge.)*
- [x] The wrapped command's own stdout/stderr, and Cordon's report,
      both appear in the workflow's job log in the natural order a plain
      `run:` step would already produce, unmodified — no re-formatting
      that could drop or reorder wrapped-command output
      *(verified locally: stdout from the wrapped command and the
      stderr report interleave in the same order a bare `run:` step
      would produce, `tee` only duplicates the report to a file, it
      does not alter what reaches the log)*
- [x] The report additionally appears in the run's step summary
      (`$GITHUB_STEP_SUMMARY`), so a developer sees it without expanding
      the step's log
      *(verified locally with `GITHUB_STEP_SUMMARY` pointed at a real
      file; both the benign and HIGH-finding cases produced a populated
      summary)*
- [x] The Action's own exit code equals the wrapped command's exit code
      in every case — a HIGH finding never fails the step; verified with
      a fixture that produces a HIGH finding on an otherwise
      zero-exit-code command, asserting the step still succeeds
      *(verified locally: a command that reads `$HOME/.ssh/id_rsa` and
      exits 0 produced a HIGH "Credential file read" finding and exit
      code 0; `action-selftest.yml`'s `high-finding-does-not-fail-the-
      step` job runs the same case for real, plus a follow-up step that
      greps the step summary so a vacuous pass — the rule not firing at
      all — can't be mistaken for the policy working)*
- [x] README states the fail-policy explicitly, so a team wanting a
      hard gate knows today's Action does not offer one, rather than
      discovering it by reading source
      *(README.md "Usage in CI" section)*

**Constraints (slice-specific):**

1. **Wrapper mechanism: build and run are two separate composite
   steps, not one `go run`.** `actions/setup-go` pinned via
   `go-version-file: $GITHUB_ACTION_PATH/go.mod` (so the Go version
   tracks whatever Cordon's own `go.mod` declares — `go 1.23.0` today —
   rather than a separately-maintained version string that can drift out
   of sync); a "Build Cordon" step (`working-directory:
   $GITHUB_ACTION_PATH`) runs `go build -o "$RUNNER_TEMP/cordon-bin"
   ./cmd/cordon`; a separate "Run wrapped command under Cordon" step
   invokes that binary. Split deliberately, not merged into a single
   `go run` invocation: a compile failure (bad pin, toolchain problem, a
   break in Cordon itself) must fail a *differently-named* step than the
   wrapped command failing on its own, so a user scanning the job's step
   list can tell "my install failed" from "Cordon itself is broken"
   without opening any logs — confirmed by deliberately breaking
   `cmd/cordon`'s build and observing the failure isolated to the build
   step. Assumes: the runner is Linux (`runner.os == 'Linux'`, checked
   explicitly with a clear failure message otherwise — INTENT.md §3 is
   Linux-only, permanently); the consumer's workflow does its own
   `actions/checkout` before this action runs, since Cordon needs a real
   project directory to sandbox, not the action's own source tree.
   goreleaser binaries (the separate Phase 3 item) don't exist yet, so
   compiling from the action's pinned source on every invocation is the
   only option now; once released binaries exist, downloading the
   pinned release asset instead (still as its own distinct step) is a
   faster follow-up, not part of this slice.
2. **Findings surface as: unmodified stdout/stderr passthrough (the
   report is already written to stderr per DECISIONS.md 2026-09-05, so a
   plain `run:` step already puts it in the job log with no wrapper
   logic needed) plus a copy of the same report text appended to
   `$GITHUB_STEP_SUMMARY`.** No GitHub Actions annotations
   (`::warning::`/`::error::`) in this slice: producing accurate
   annotations means parsing Cordon's plain-text report to extract
   severity/title/location, which couples the Action's correctness to
   `behaviorreport.WriteText`'s exact wording — a text format with no
   stability contract today. Deferred rather than built on a
   free-floating scrape.
3. **Exit code / fail policy: the Action's exit code is always exactly
   the wrapped command's own exit code. A HIGH finding, by itself, never
   fails the CI step.** This is not a new decision invented for this
   slice — it is INTENT.md §5's existing, explicit non-goal ("Blocking
   installs by default. Cordon reports; the human decides") plus
   `cmd/cordon`'s current, already-shipped behavior (`res.ExitCode`,
   unconditional). No configurable "fail on HIGH" input in this slice:
   building one honestly would require `cmd/cordon` itself to expose a
   distinct, structured signal for "there were HIGH findings" separate
   from the wrapped command's exit code — none exists today, and adding
   one is a real, separate feature (a `--fail-on` flag, or a
   machine-readable output mode), not something to bolt onto the Action
   wrapper by scraping its own text report. Named here as a real
   candidate follow-up, not silently dropped.
