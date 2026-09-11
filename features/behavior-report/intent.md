# behavior-report

**Inherits:** INTENT.md §2 Users (signal-to-noise), §1 scope of guarantee

**Why:** A raw syscall log is useless to the target user — the product is
the diagnosis, not the trace.

**Done:**
- [x] Both malicious corpus packages surface a credential-read or
      unexpected-egress finding at the top of the output
      *(synthetic fixtures `testdata/corpus/credential-read-and-exfil`
      and `credential-read-no-network`; `cmd/cordon/corpus_test.go`
      asserts a `[HIGH]` finding is first)*
- [x] The legitimate native build (`node-gyp`) produces no high-severity
      finding
      *(`testdata/corpus/faux-node-gyp` — models node-gyp's observable
      shape without a compiler this environment lacks; test asserts no
      `[HIGH]` despite a network connection and two subprocess launches)*
- [x] Output states plainly what Cordon did *not* observe, per §1
      *(a fixed capabilities paragraph plus a real per-run line —
      "N other process(es) were launched and NOT traced" — from
      `syscallcapture.Result.UnobservedDescendants`; see DECISIONS.md
      2026-09-05)*

**Constraints (slice-specific):** Plain text only — no JSON schema, no
HTML, no dashboard. Severity tiers may be crude here; the real taxonomy
is Phase 2 work.

**Deviations / notes (2026-09-05, see DECISIONS.md):**
- The report goes to **stderr**, not stdout as the line above originally
  said: the wrapped command owns stdout, the report is Cordon's own
  diagnostic about the run.
- Corpus is synthetic (6 Go fixtures under `testdata/corpus/`), not real
  registry malware — same reasoning as the overhead-measurement fixture.
- Two rules only: credential-read (HIGH), network egress (MEDIUM, → HIGH
  only when paired with a credential-read in the same run). The `.npmrc`
  path marker is a known false-positive shape (matches a legit
  token-free project-local `.npmrc` too) — addressable, not fixed, by
  [[allowlist-mechanism]]: a developer can exempt their own `.npmrc`
  path, but the rule itself still cannot tell a safe one from a stolen
  one on its own.
