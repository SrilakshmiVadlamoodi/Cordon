# finding-confidence

**Models:** Not a package-behavior archetype like the other groups —
this models the **report's own ordering guarantee**, the same way
`allowlist-mechanism`'s corpus group models that mechanism itself rather
than a specific malware shape. See
`features/finding-confidence/intent.md`.

**Rule exercised:** `Generate`'s secondary sort key within HIGH severity
(`internal/behaviorreport/report.go`'s `confidenceRank`). Not a new
detection rule — no fixture here changes whether something fires, only
what order multiple simultaneous HIGHs render in.

**Fixtures:**
- `definite-before-heuristic.go` — opens `.npmrc` (heuristic) BEFORE
  `id_rsa` (definite), the reverse of the required display order.
  Proves ordering is driven by marker confidence, not by which `openat`
  happened first. This is the exact gap `escalation-volume`'s
  `multi-secret-multi-host` fixture left open: that fixture asserts all
  three HIGHs appear, never their relative order.
- `exfil-ranks-first-even-with-heuristic-marker.go` — reads `.npmrc`
  (heuristic, not a private key) and connects out in the same run.
  Proves `Possible credential exfiltration` ranks first regardless of
  the underlying credential read's own confidence — not only when
  paired with a definite-confidence marker like `id_rsa`
  (`allowlist-mechanism/still-correlates-with-network.go` already covers
  that combination, incidentally, since it happens to use `id_rsa`).

**What neither proves:** that confidence changes *whether* a finding
fires, or that it interacts with allowlisting — it doesn't do either;
confidence only reorders what's already going to be shown after
suppression (`allowlist-mechanism`) has already run.
