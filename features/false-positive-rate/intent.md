# false-positive-rate

**Inherits:** INTENT.md §4 Phase 2 ("False-positive rate measured and
published in README"), §1 scope of guarantee (never claim total or
generalized detection coverage), §2 Users ("False-positive rate is a
headline metric, measured and published"); [[corpus-expansion]] (the
corpus this rate is computed over)

**Why:** INTENT.md §2 names false-positive rate a headline metric, but
nothing publishes one today — there is no `README.md` in this repo at
all yet. `corpus-expansion`'s table in `cmd/cordon/corpus_test.go`
already distinguishes, fixture by fixture, which are meant to produce no
HIGH finding and which are deliberately malicious-shaped; that table is
the one honest population Cordon can currently measure itself against.
It is **not** a statistically representative sample of real npm/pip
registry packages — every fixture is synthetic and self-authored
(DECISIONS.md 2026-09-05, "corpus: synthetic, six fixtures," and
`corpus-expansion/intent.md`'s own sourcing constraint) — and any number
this feature publishes must say so in the same sentence it's given, not
in a footnote a reader can skip past.

**Done:**
- [ ] Each `corpusCase` in `cmd/cordon/corpus_test.go` carries an
      explicit `benign bool` label — not inferred from `noHigh` or the
      absence of a `wantHit` HIGH, since inference would conflate
      "deliberately clean" with incidental non-HIGH cases that mean
      something different (an allowlist-suppressed finding, a documented
      detection miss) that must not silently count toward a false-clean
      population
- [ ] A dedicated test walks exactly the `benign`-labeled subset and
      `t.Log`s the count on every run — "false positives: N/M
      benign-labeled fixtures produced an unexpected HIGH finding" —
      so the number is recomputed by the act of running `go test`, never
      hand-counted and never silently stale relative to the table it's
      drawn from
- [ ] A minimal `README.md` states the current number with its
      population named in the same sentence: which corpus, how many
      fixtures, and that it is Cordon's own synthetic archetypes, not a
      measurement against real registry packages
- [ ] The same section states plainly what the number does *not* claim:
      not validated against any real npm/pip package, not a statistical
      sample of any registry, and only as current as the last deliberate
      re-run — with the exact test command that recomputes it named
      inline, not just implied

**Constraints (slice-specific):**
- This is **not** Phase 3's README. INTENT.md §4 Phase 3 separately asks
  for "README with demo, FP numbers, and an explicit list of what Cordon
  does not catch" — a fuller document. This slice creates only the
  minimal file/section Phase 2's roadmap line requires (the FP number,
  honestly scoped); the demo and the "does not catch" list are Phase 3's
  job, not built here.
- The published number is a **point-in-time snapshot**, hand-copied into
  `README.md` from the test's own `-v` output after a deliberate re-run —
  not live-generated at README-render time. No templating or
  README-rewriting tooling is introduced for this. This is a deliberate
  minimalism choice, flagged explicitly because it has a real cost: the
  README can drift from the corpus's actual current state if a fixture
  changes without a human re-running the test and re-pasting the number.
  The `t.Log`ged line is the authoritative value if the two ever
  disagree — the README should say so.
- "False positive," for this metric, means specifically "a
  `benign`-labeled fixture produced a HIGH finding." A standalone MEDIUM
  on a benign fixture is not counted as a false positive here — that
  matches Rule 2's own existing design (`network-egress`'s fixtures are
  deliberately MEDIUM-producing and are not false positives by that
  rule's own stated logic, DECISIONS.md 2026-09-05).
