# Cordon

Rootless namespace sandbox for `npm install` (and friends) that reports
what a package's lifecycle scripts actually did — file reads, network
connections, process launches — so a developer can look before trusting.
See [INTENT.md](INTENT.md) for the full mission, architecture, and
roadmap.

This section is intentionally narrow: it publishes the false-positive
number INTENT.md §4 Phase 2 asks for, and nothing else. A fuller README
— demo, install instructions, a complete list of what Cordon does not
catch — is Phase 3 scope
([`features/false-positive-rate/intent.md`](features/false-positive-rate/intent.md)),
not attempted here.

## False-positive rate

**0 / 8** benign-labeled fixtures in Cordon's own test corpus produce an
unexpected HIGH finding, as of 2026-09-11.

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
