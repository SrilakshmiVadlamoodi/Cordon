# credential-read-no-network

**Models:** A package that reads your npm publish token from `.npmrc` —
the mechanism behind worms that republish themselves under the victim's
account — but does not exfiltrate it over a connection Cordon can see. It
might stage the token to disk, or act on it through a channel outside the
three syscalls Cordon watches.

**Behavior:** Opens `$HOME/.npmrc` (planted by the test harness; sandbox
maps `$HOME` to the project directory). No network, no child process.

**Exercises:** Rule 1 (credential-read) *without* the Rule 2 pairing —
proves a HIGH finding does not depend on a network finding existing. Also
exercises the honesty section: a credential read with no observed egress
is still flagged, and the report says what it cannot tell you.

**Expected report:**
- `[HIGH] Credential file read` naming the `.npmrc` path, at the top.
- No network finding, no exfiltration correlation.
- OBSERVED shows 0 connections, 0 process launches.

**What this fixture does NOT prove:** it confirms Rule 1 fires on a
`.npmrc` that contains a token. It does **not** show that the rule avoids
false-positiving on a legitimate *project-local* `.npmrc` that holds only
registry configuration and no token — the rule matches the path
substring `/.npmrc` and does not inspect contents, so that legitimate
case would also be flagged HIGH. That false-positive shape is a known,
open gap, tracked for Phase 2's allowlist / false-positive-rate work
(INTENT.md §4 Phase 2). It is called out here, in the corpus, so it is
visible without reading the rule source.
