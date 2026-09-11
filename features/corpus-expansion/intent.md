# corpus-expansion

**Inherits:** INTENT.md §4 Phase 2 ("Corpus expanded to ~50 packages
across ecosystems"), §2 Users (signal-to-noise); [[behavior-report]]
(the rules this corpus tests)

**Why:** Six fixtures proved `behaviorreport`'s two rules work on their
intended cases. They didn't prove anything about the rules' known edges —
where they miss (forked children, an unlisted marker), where they might
over-match (a path adjacent to a real marker), or how they hold up at
realistic volume. A corpus that only exercises the happy path isn't
signal-to-noise evidence, it's a smoke test.

**Done:**
- [x] Fixtures organized into archetype groups, not one README per
      fixture — one `group.md` per category covering what it models,
      which rule it exercises, and what it does not prove; individual
      fixture files carry only a short doc-comment header
      *(9 groups shipped under `testdata/corpus/`: `credential-read`,
      `credential-read-gap`, `credential-marker-gap`, `network-egress`,
      `native-build-style`, `benign-local-io`, `marker-precision`,
      `delayed-process`, `escalation-volume` — ~16 fixture files total)*
- [x] Test schema can express an expected non-detection as a real
      asserted outcome, not an absence of assertion
      *(`cmd/cordon/corpus_test.go`'s `expectedMiss` requires a
      non-empty `reason` per miss, logged via `t.Log` so it appears in
      `-v` output as a confirmed, explained gap)*
- [x] At least one category demonstrates a real, previously-live
      detection gap end-to-end, not just a taxonomy note
      *(`credential-read-gap`: a subprocess credential read, currently
      invisible per `syscall-capture`'s tracing scope)*
- [x] Any rule bug this work surfaces gets fixed in its own commit,
      distinguishable from the corpus/test changes that found it — not
      silently folded in, and not just logged as an accepted gap if it's
      a real coverage bug rather than a judgment call
      *(surfaced: `.env` missing from `credentialPathMarkers` — fixed in
      its own commit, see DECISIONS.md 2026-09-11)*

**Constraints (slice-specific):**
- Sourcing stays synthetic/self-authored, not real registry packages —
  offline, deterministic `go test`, no version drift. The Phase 2
  roadmap's "~50 packages" is read as ~50 *behavioral archetypes*, not a
  literal count of npm packages pulled from the registry (flagged
  explicitly and confirmed before building).
- The grouped structure must let a category grow new variants without a
  new `group.md` per fixture — breadth is meant to come from adding
  fixture files to an existing group over time, not by starting flat
  and expanding it later.
- A fixture whose meaningful assertion is a host-visible side effect
  (e.g. a file's absence after a wait) rather than report text is
  expected not to fit the `{wantHit, wantMiss}` report schema, and
  should be a dedicated test function instead of a forced table row.

**Open, not resolved by this slice:** whether ~16 fixtures across 9
categories is sufficient breadth for Phase 2's signal-to-noise goal, or
whether more categories/variants are still wanted before INTENT.md §4's
"~50 packages" line can be checked off — see that line's own annotation
for the current count.
