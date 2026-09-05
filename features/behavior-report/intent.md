# behavior-report

**Inherits:** INTENT.md §2 Users (signal-to-noise), §1 scope of guarantee

**Why:** A raw syscall log is useless to the target user — the product is
the diagnosis, not the trace.

**Done:**
- [ ] Both malicious corpus packages surface a credential-read or
      unexpected-egress finding at the top of the output
- [ ] The legitimate native build (`node-gyp`) produces no high-severity
      finding
- [ ] Output states plainly what Cordon did *not* observe, per §1

**Constraints (slice-specific):** Plain text to stdout only — no JSON
schema, no HTML, no dashboard. Severity tiers may be crude here; the real
taxonomy is Phase 2 work.
