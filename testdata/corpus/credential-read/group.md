# credential-read

**Models:** The canonical self-propagating npm worm described in
INTENT.md §1: a lifecycle script that reads a well-known secret file —
an SSH key, an npm publish token, cloud credentials — from inside its
own process (no child involved, so tracing scope is not a factor here;
see [[credential-read-gap]] for when it is).

**Rule exercised:** `behaviorreport`'s Rule 1 (credential-read, HIGH) and
its exfil-correlation escalation (Rule 1 + Rule 2 → an additional HIGH),
both defined in `internal/behaviorreport/report.go`.

**Fixtures:**
- `direct-read-and-exfil.go` — reads `$HOME/.ssh/id_rsa` (planted by the
  test harness) and sends it to `203.0.113.21:443` (TEST-NET-3,
  unroutable — the `connect` syscall is what's captured, not success).
  Both HIGH findings fire: the read, and the correlated exfil warning.
- `direct-read-no-network.go` — reads `$HOME/.npmrc` (planted by the
  harness) with no network call at all. Proves the HIGH finding does not
  depend on a paired connection existing.
- `multi-secret.go` — reads two distinct secret paths (`.ssh/id_rsa` and
  `.aws/credentials`) in one run, no network. Proves each distinct secret
  produces its own finding — dedup is per-path, not per-run — without a
  higher severity tier to escalate to (see `escalation-volume` for the
  same idea at more realistic volume, alongside network egress).

**What none of these prove:** that Cordon caught an actual
exfiltration — `Possible credential exfiltration` findings say plainly
they cannot confirm data flowed from the file to the socket, only that
both happened in the same run. They also don't prove the rule
distinguishes a legitimate project-local `.npmrc` (registry config, no
token) from a stolen one — that's a known false-positive shape, tracked
for Phase 2 (see `credential-read-no-network`'s original README history
in DECISIONS.md, and `.npmrc`'s doc comment in `report.go`).
