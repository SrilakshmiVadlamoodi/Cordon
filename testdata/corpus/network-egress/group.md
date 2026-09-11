# network-egress

**Models:** A package that phones home during install — telemetry, a
version check, a CDN fetch — with no credential access and no child
process involved.

**Rule exercised:** `behaviorreport`'s Rule 2 (network egress, MEDIUM),
in isolation from the credential-read escalation path (see
[[credential-read]] for the combined case).

**Fixtures:**
- `bare-connect.go` — one `connect(2)` to `203.0.113.7:443`. Proves a
  standalone connection is MEDIUM and does not escalate to HIGH absent a
  credential-read finding to correlate with.
- `multi-host-connect.go` — three distinct targets in one run. Proves
  each distinct address produces its own MEDIUM finding (dedup is
  per-address) and that volume alone still doesn't escalate anything —
  escalation requires a credential read, not just more connections (see
  [[escalation-volume]] for what happens when both are present at
  volume).

All targets across this group's fixtures are TEST-NET-3 (RFC 5737,
reserved/unroutable) — the connections fail inside the sandbox's network
namespace, and the `connect` syscall being captured is the point, not
connection success.
