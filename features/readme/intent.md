# readme

**Inherits:** INTENT.md §4 Phase 3 ("README with demo, FP numbers, and an
explicit list of what Cordon does not catch"), §1 Mission (the
problem/gap statement this needs to condense), §1's hard rule that any
claim of total detection coverage is a defect against that document;
the existing `README.md` ([[false-positive-rate]] — the FP section) and
its "Usage in CI" section ([[github-action]]) — this feature **extends
both in place**, it is not a rewrite from scratch and does not create a
second document.

**Why:** Phase 3's doc item is the last unchecked box in a phase whose
other two items are now real and live: [[github-action]] is merged to
`main`, verified end-to-end on a real hosted runner across two
independently-found bugs (DECISIONS.md 2026-09-14), and
[[false-positive-rate]] already published a real, precisely-scoped
number. Both of those shipped under an explicit "narrow section only,
fuller README is later scope" disclaimer written into the README itself
at the time. A reader arriving at the repo cold today gets a mission
one-liner, a CI snippet, and an FP number with no surrounding context —
no statement of what Cordon is *for*, no direct-CLI usage example, and
critically no "what Cordon does not catch" section, which INTENT.md §1
treats as non-optional: publishing measured coverage and never implying
completeness is a stated project requirement, not a nice-to-have doc
section.

**Done:**
- [x] Mission section: condenses INTENT.md §1 (the problem, the honest
      landscape table, the hard isolation/detection split) into a form
      a reader who will never open INTENT.md still gets right —
      "isolation is a hard boundary, detection is best-effort" survives
      the condensation intact, not softened into "Cordon catches
      malicious installs"
- [x] Usage section: one combined "Usage" section, CLI and GitHub Action
      as two subsections under it rather than two independent top-level
      sections — decided explicitly, not defaulted, since both are the
      same `cordon run` contract with two front doors, not two separate
      features. The exit-code/fail-policy line ("a finding never fails
      by itself") is stated once, generally, since it's true
      unconditionally (`cmd/cordon`'s `run()` always mirrors the wrapped
      command's own exit code), not duplicated per-subsection or left
      implying CLI usage behaves differently. The Action's three-line
      snippet is carried forward from the current "Usage in CI" section
      unchanged, not silently dropped or reworded.
- [x] Demo: a `cordon run` transcript against
      `testdata/corpus/credential-read/direct-read-and-exfil.go` — the
      transcript pre-existed in an earlier, unreported run of this same
      task; this session independently rebuilt the binary and fixture,
      planted a real `.ssh/id_rsa` in a fresh temp project directory,
      reran it, and confirmed the output matched byte-for-byte before
      trusting it. The temp-directory paths in the raw output were
      normalized to a readable example path in prose around the block,
      with that substitution stated explicitly and reproduction steps
      given. (The pre-existing transcript's own framing — "real,
      captured ... not hand-typed" — was not itself verifiable from
      anything on disk at the time it was found, and was reworded to
      state only what this session actually confirmed; see DECISIONS.md
      2026-09-16, "Uncommitted README draft found on main.")
- [x] "What Cordon does not catch" section: every claim cites a specific
      DECISIONS.md entry (date) or feature `intent.md`, the same
      precision standard the existing FP section already holds itself
      to ("as of 2026-09-11", "see DECISIONS.md 2026-09-05") — no claim
      that isn't traceable to a real, dated finding in this repo
- [x] Project status section: Phase 1 and Phase 2 marked complete
      against INTENT.md §4's actual current checkbox state (corrected
      first — see the stale-checkbox note below), Phase 3 marked
      in-progress with what's actually left, Phase 5 (tree tracing)
      named explicitly as deferred with no committed timeline, not
      folded silently into "future work"
- [x] FP-rate section re-verified against a fresh
      `TestCorpus_FalsePositiveRate` run before publishing, not
      republished on trust that the 2026-09-11 number still holds — rerun
      2026-09-16, unchanged at 0/8; README date updated to reflect the
      re-verification, not silently left at the old date

**Constraints (slice-specific):**
- Extends `README.md` in place. Does not create `docs/`, a second
  markdown file, or a rewritten-from-scratch README — the FP section's
  own scoping language ("A fuller README ... is Phase 3 scope, not
  attempted here") is itself now stale once this ships and must be
  removed as part of this change, not left contradicting the doc it
  sits in.
- Whether the existing "Usage in CI" section becomes a subsection of a
  broader "Usage" section, or stays a standalone section the new
  content wraps around, is an open structural question for the
  proposal, not decided here — see the structure proposal itself.
- No line, section, or demo implies total detection coverage
  (INTENT.md §1). A "what Cordon does not catch" section existing at
  all is the mechanism that keeps the rest of the README honest by
  construction — the demo/usage sections can be confident about what
  Cordon *does* precisely because the gaps get their own named section
  rather than being hedged inline everywhere.
- Every citation is checked against the actual DECISIONS.md entry or
  intent.md line before being written, not paraphrased from memory of
  this session's earlier reading — matching the standard the CI-usage
  section already set (its INTENT.md/DECISIONS.md references are exact,
  not approximate).
- Housekeeping found while reading, fixed alongside this feature rather
  than left stale: INTENT.md §4 Phase 2's "False-positive rate measured
  and published in README" checkbox (shipped 2026-09-11, still
  unchecked) and `features/github-action/intent.md`'s "real end-to-end
  run on GitHub's hosted `ubuntu-latest` runner" checkbox (proven done,
  DECISIONS.md 2026-09-14 entries and the `main` merge) — both get
  ticked as part of this change, not as a separate, unrelated commit,
  since the project status section this feature adds depends on reading
  those states correctly in the first place.

**Resolved before implementation, both decided explicitly rather than
defaulted:** "Usage in CI" folds into a combined "Usage" section (CLI
and Action as subsections, not siblings) rather than staying standalone
next to a new CLI-only section; a verified transcript is included in
this pass rather than deferred.
