# native-build-style

**Models:** A legitimate native build during install — a package with a
`binding.gyp` running `node-gyp rebuild` (`sharp`, `bcrypt`,
`better-sqlite3`, ...), or any compile/codegen step. This is the single
most important false-positive class to avoid: INTENT.md §2 states a tool
that flags every native compile gets uninstalled on day one.

**Rule NOT triggered:** neither Rule 1 nor Rule 2 escalates to HIGH for
any fixture in this group — that is the entire point. Where Rule 2 fires
at all (network fetch of build headers), it stays MEDIUM.

**Fixtures:**
- `faux-node-gyp.go` — node-gyp's observable shape without an actual
  compiler (this environment has none, and it isn't what's being
  tested): build-dir file probes, two build-artifact writes, one network
  connection (Node headers download), two subprocess launches (compiler,
  linker — their own syscalls are NOT traced, process-tree gap; the
  report's unobserved-descendant count is `>= 2`).
- `temp-artifact-build.go` — a different build shape: heavy `/tmp`
  scratch-file churn (20 write/read/remove cycles), no subprocess, no
  network at all. Isolates whether raw file-I/O *volume* alone can trip
  a finding — it must not, since none of it touches a credential-shaped
  path.

**What neither fixture proves:** that a *real* native build with an
actual C toolchain produces no HIGH finding — only that these
stand-ins, built to match the observable shape, do not. This dev
environment has no C compiler to run a real one against (see
DECISIONS.md 2026-09-04, the overhead-measurement entries, for the same
constraint).
