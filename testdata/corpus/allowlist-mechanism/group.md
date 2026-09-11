# allowlist-mechanism

**Models:** The developer-authored `.cordon-allowlist` mechanism itself
(`internal/behaviorreport/allowlist.go`,
`features/allowlist-mechanism/intent.md`) — both its intended use and
the two failure modes that mechanism was explicitly designed against.

**Fixtures:**
- `pre-authored-suppresses.go` — the intended use: a credential path
  planted AND pre-authored into `.cordon-allowlist` before the process
  starts. No network. Proves the standalone `Credential file read` HIGH
  is suppressed and named in the report's `SUPPRESSED BY ALLOWLIST`
  section, not silently dropped.
- `still-correlates-with-network.go` — the same pre-authored path, plus
  a network connection in the same run. Proves allowlisting suppresses
  only the standalone finding: `Possible credential exfiltration` still
  fires, because that correlation considers every matched credential
  path regardless of allowlist status (a confirmed design decision, not
  an oversight — see `internal/behaviorreport/report.go`'s `Generate`
  doc comment).
- `self-write-too-late.go` — **the concrete regression test for the
  named self-write bypass risk.** No `.cordon-allowlist` exists when
  this process starts (only the secret file is planted). The fixture
  creates the allowlist file itself, from scratch, naming its own
  about-to-be-read path, then reads that path — an attempt to
  self-certify its own credential read within the same run. This is
  reproduced directly, not just argued from the code's read-before-launch
  ordering: the test asserts the `Credential file read` finding for that
  path still appears, unsuppressed. See DECISIONS.md for the timing
  analysis this fixture is proving, not merely illustrating.
- `malformed-entries-ignored.go` — the harness plants one valid
  allowlist entry (absolute, existing path) and one invalid entry
  (relative path) for two different credential files. Proves fail-safe
  parsing: the invalid entry is dropped entirely — its path stays
  flagged exactly as if no entry existed — while the valid entry still
  suppresses normally. `LoadAllowlist`'s `Ignored` count (surfaced in the
  report's `WHAT CORDON DID NOT OBSERVE` section) is also asserted.

**What none of these prove:** that the allowlist protects against a
path being *re-purposed* after being allowlisted — allowlisting is
path-based, not content-based, and a legitimately-allowlisted path whose
file later gets a real secret appended is a disclosed, accepted
limitation (features/allowlist-mechanism/intent.md, "Content-blindness
is inherited, not solved"), not something exercised here.
