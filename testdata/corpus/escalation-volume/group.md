# escalation-volume

**Models:** A worst-case-shaped run — several distinct secrets read,
several distinct exfil targets contacted, with repeats — stress-testing
`Generate`'s dedup and ordering logic (already unit-tested in
`internal/behaviorreport/report_test.go`'s
`TestGenerate_DuplicatePathsAndAddrsCollapse`) at a volume closer to what
a real determined worm might actually do, run through the real binary
end-to-end rather than hand-built `Event` slices.

**Rule exercised:** Rule 1, Rule 2, and the exfil-correlation escalation,
all together, with each rule's dedup exercised at 3 distinct paths/addrs
× 2 repeats instead of the 1-of-each every other group uses.

**Fixture:** `multi-secret-multi-host.go` reads `.ssh/id_rsa`,
`.aws/credentials`, and `.npmrc` (each twice), then connects to three
distinct TEST-NET-3 addresses (each twice).

**Expected report:**
- Exactly 3 `Credential file read` findings (one per distinct path, not
  6), each HIGH.
- Exactly 1 `Possible credential exfiltration` finding (the correlation
  fires once per run, not once per secret×target pair — see
  `Generate`'s implementation: it checks "any credential path AND any
  connect address," not a full cross-product).
- Exactly 3 `Network connection` findings (one per distinct address, not
  6), each MEDIUM.
- Highest severity first: both HIGH kinds sort before all three MEDIUMs.

**What this does not prove:** anything about detection at *tree* scale —
every read and connect here happens in the one directly-traced process,
same as [[credential-read]]. It stresses the report's own aggregation
logic, not the tracing-scope gap ([[credential-read-gap]] covers that).
