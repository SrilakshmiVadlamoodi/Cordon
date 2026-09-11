# finding-confidence

**Inherits:** INTENT.md §4 Phase 2 ("Severity tiers; highest-value
finding surfaces first"), §2 Users (signal-to-noise gates adoption);
[[behavior-report]] (`Generate`/`WriteText`, `credentialPathMarkers`)

**Why:** The two-tier HIGH/MEDIUM design plus the exfil-correlation
escalation already earns its keep — DECISIONS.md 2026-09-05 and every
passing corpus case confirm the split and the escalation behave as
designed. Adding a third numeric severity tier on top of that would be
invention without a demonstrated need, which the roadmap phrase
"severity tiers" invites but the evidence doesn't support.

What the evidence *does* support: "highest-value finding surfaces first"
is not actually true the moment a single run produces more than one
HIGH finding at genuinely different confidence levels. `report.go`'s own
comments and `allowlist-mechanism/intent.md` already say plainly that
not all thirteen `credentialPathMarkers` entries carry the same
confidence — `/.ssh/id_rsa` or `/.aws/credentials` existing at all is
inherently secret material, while `/.npmrc`, `/.env`, shell history, and
the `/.gnupg/` prefix are path-only heuristics that can legitimately
hold nothing sensitive (the exact false-positive shapes
`allowlist-mechanism` exists to let a developer exempt). `Generate`'s
sort is stable on `Severity` alone, so among two-or-more HIGHs the
display order is whatever order the underlying `openat` calls happened
in — not confidence order. `escalation-volume`'s
`multi-secret-multi-host` fixture already produces three simultaneous
HIGH `Credential file read` findings (`.ssh/id_rsa`, `.aws/credentials`,
`.npmrc`) and makes no assertion about their relative order — a real,
already-demonstrated gap, not a hypothetical one.

**Done:**
- [ ] Each `credentialPathMarkers` entry is tagged with a confidence
      level: `definite` (the file's mere existence is inherently secret
      material — private keys, cloud credential files, git credentials,
      docker config) or `heuristic` (a known path-only marker that can
      legitimately hold no secret — `.npmrc`, `.env`, shell history,
      the `.gnupg/` prefix)
- [ ] Within HIGH severity, `Generate` sorts `definite`-confidence
      `Credential file read` findings before `heuristic`-confidence
      ones. This is a secondary sort key beneath the existing `Severity`
      primary key — MEDIUM still sorts last, exactly as today
- [ ] The `Possible credential exfiltration` finding remains the single
      highest-priority HIGH regardless of which confidence tier the
      underlying credential read belongs to — it is the strongest
      combined signal Cordon can produce, independent of any one
      marker's own confidence
- [ ] A corpus fixture with two-or-more HIGH findings at different
      confidence levels in one run asserts the `definite` one renders
      first — closing the exact gap `multi-secret-multi-host` left open,
      not just adding a parallel case
- [ ] No new `Severity` enum value, and `WriteText`'s rendered label
      stays exactly `[HIGH]` / `[MEDIUM]` — confidence is an internal
      ordering signal only, never a new user-facing tier. Three visible
      severities would be the tier-proliferation the roadmap phrase
      could be misread as asking for; this explicitly isn't that.

**Constraints (slice-specific):**
- Confidence is a different axis from allowlist suppression. An
  allowlisted path is removed from `Findings` entirely regardless of its
  confidence tier — confidence only orders what's still shown after
  suppression, it never changes what gets suppressed.
- No change to which markers produce a HIGH at all, and no change to
  which markers are known false-positive shapes. This slice is a pure
  ordering refinement; it does not touch detection or precision — those
  are `allowlist-mechanism` (shipped) and a possible future marker-list
  change (not this).
