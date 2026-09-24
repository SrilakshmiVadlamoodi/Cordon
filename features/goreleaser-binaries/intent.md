# goreleaser-binaries

**Inherits:** INTENT.md §4 Phase 3 ("`goreleaser` binaries on GitHub
Releases" — the last unchecked Phase 3 item); §3's Build/release line
(`goreleaser` already named as the tool, cross-compile matrix +
GitHub Releases); §3 Platform ("Linux only... macOS and Windows are out
of scope, permanently") and the arm64 compile-time refusal
(DECISIONS.md 2026-09-05, "arm64 build tag: fail the build, not the
runtime" — `GOOS=linux GOARCH=arm64 go build ./...` fails at compile
time in `internal/syscallcapture`, deliberately, not a runtime stub);
[[github-action]] (the composite action that currently compiles from
source on every invocation — this feature is a candidate to change what
that action does, not a separate distribution path).

**Why:** Phase 3's other two items are done and merged
([[github-action]], [[readme]]). This is what's left. Today, using
Cordon at all — via the Action or directly — means compiling from
source: the Action's "Build Cordon" step runs `go build` in the
consumer's own CI job on every single invocation, and there is no
`go install`-able or downloadable binary anywhere. That's a real cost
(a Go toolchain setup + full build on every wrapped command, on every
consumer's CI run) and a real trust/reproducibility gap (nothing is
pinned to a released, checksummed artifact).

**Proposal (stop here — confirm before implementing):**

## Release matrix

- **Target:** `linux/amd64` only.
- **`linux/arm64` is deliberately excluded, not silently attempted.**
  It cannot produce a working binary today: `internal/syscallcapture`
  fails to compile on arm64 by design (DECISIONS.md 2026-09-05), because
  ptrace register access is amd64-specific (`syscall.PtraceRegs` layout)
  and no arm64 equivalent has been implemented or committed to. Two
  ways to make that failure visible in a *release* context rather than
  just a local `go build`:
  1. Omit `arm64` from `.goreleaser.yml`'s `goarch` list entirely — no
     release artifact is attempted, nothing to fail loudly on.
  2. List it, but rely on the existing compile-time build tag to fail
     that one matrix leg, and set `ignore` conditions elsewhere so the
     overall `goreleaser release` doesn't abort on one failed leg.
  - **My recommendation: (1), omit it.** A GitHub Release page listing
    a `cordon_linux_arm64.tar.gz` asset that then 404s or was never
    uploaded because its build leg failed is worse than the asset
    simply not being listed — it's the "silently ship a broken binary"
    failure mode by omission, just via a missing file instead of a
    broken one. Nothing in INTENT.md commits to arm64 timeline-wise
    (DECISIONS.md 2026-09-05 explicitly deferred it, unscheduled), so
    there's no roadmap reason to keep a visibly-broken row in the
    matrix. If/when real arm64 `PtraceRegs` support lands, this list
    gains an entry then.
  - No macOS, no Windows — permanent non-goals, §3 Platform, not
    revisited by this feature.
- Archive format: `.tar.gz` (goreleaser default for Linux), containing
  the `cordon` binary plus `LICENSE` and `README.md`.
- Checksums file (`goreleaser` default `checksums.txt`) published
  alongside, so a consumer pinning a binary in CI has something to
  verify against.

## Integration with the Action

**Decided (confirmed before implementation): (B).** This feature ships
goreleaser binaries as a separate, independent distribution path only
— a person installing Cordon manually, or wiring their own CI step
without the Action. The Action keeps compiling from source for now;
zero change to [[github-action]]'s already-verified end-to-end
behavior (its hard-won `ubuntu-latest` AppArmor/userns fixes). Swapping
the Action to download the pinned release binary instead of compiling
from source is out of scope here — a real follow-up feature, once the
`@main`-vs-tagged-ref → release-artifact mapping question has its own
answer and can be tested without risking the Action's current
known-good state.

## Testing this without a real tag/release

**Decided (confirmed before implementation): stop at snapshot/dry-run
validation.** `goreleaser` supports `goreleaser release --snapshot
--clean` (no tag required, no publish, builds the full matrix locally)
and `goreleaser build --single-target` for a fast local sanity check.
1. Validate the `.goreleaser.yml` config and the amd64-only matrix
   locally first via `--snapshot` (no git tag, no GitHub Release
   created, nothing pushed).
2. Wire a `workflow_dispatch`-triggered CI job that runs
   `goreleaser release --snapshot --clean` on `ubuntu-latest` — proves
   the matrix builds in the actual CI environment (same runner class
   [[github-action]] already validated) without cutting a real tag or
   publishing a release, and is safely re-runnable.
3. Cutting a real annotated git tag (`v0.1.0`) and letting
   `goreleaser release` publish an actual public GitHub Release is
   explicitly **out of scope for this feature** — a real,
   externally-visible action to be requested and confirmed separately,
   not bundled in here.

**Done:**
- [x] `.goreleaser.yml` at repo root: `linux/amd64` only, `arm64`
      omitted from the `goarch` list (not listed-and-failed — simply
      absent), `.tar.gz` archives containing the `cordon` binary plus
      `LICENSE` and `README.md`, default `checksums.txt`
- [x] `goreleaser release --snapshot --clean` succeeds locally, single
      `linux_amd64` artifact produced (`cordon_0.0.0-SNAPSHOT-<sha>_linux_amd64.tar.gz`),
      no `arm64` artifact attempted or listed — verified by inspecting
      `dist/` directly, not just a green exit code
- [x] Sanity-checked: resulting binary actually runs — extracted the
      snapshot archive, ran the binary directly (no args), confirmed it
      prints `usage: cordon run <command> [args...]` to stderr and
      exits 2, matching `cmd/cordon/main.go`'s real no-args behavior,
      not just "the build step exited 0"
- [x] A `workflow_dispatch`-triggered CI job
      (`.github/workflows/goreleaser-snapshot.yml`) runs
      `goreleaser release --snapshot --clean` on `ubuntu-latest`,
      asserts exactly one `linux_amd64` archive and zero `arm64`
      archives exist in `dist/`, and extracts + runs the binary to
      confirm real usage output — no tag cut, no release published.
      Also triggers on `push`/`pull_request` for changes under
      `cmd/**`, `internal/**`, or the goreleaser config itself, so a
      future build-breaking change is caught without waiting for a
      manual dispatch.
- [x] DECISIONS.md entry logging the arm64-omission choice and the
      ship-binaries-first-then-swap-Action sequencing decision

**Constraints (slice-specific):**
- No `GOOS`/`GOARCH` beyond `linux/amd64` produces a listed release
  asset. `arm64` inclusion is a separate, future feature once real
  ptrace support for it exists, not a checkbox here.
- A real, tag-triggered `goreleaser release` (one that publishes a
  public GitHub Release) is not run as part of "implementing" this
  feature without a separate, explicit go-ahead — snapshot/dry-run
  validation only until that's confirmed.
