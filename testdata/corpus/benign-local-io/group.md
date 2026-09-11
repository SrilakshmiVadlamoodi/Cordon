# benign-local-io

**Models:** The ordinary, unremarkable majority of installs — a pure-JS
package with no lifecycle side effects, or a package doing legitimate
local codegen/asset work, both entirely inside the project tree.

**Rule NOT triggered:** neither rule fires for any fixture in this
group — the quiet-run baseline.

**Fixtures:**
- `noop-install.go` — reads its own `package.json`, prints a line, exits.
  The most common real case. Proves `Generate` does not manufacture
  findings out of an unremarkable run.
- `local-file-writes.go` — creates a `build/` dir, writes and reads three
  files, all inside the project directory. No network, no subprocess, no
  credential-shaped path. Proves ordinary in-project file activity —
  including writes — is not flagged; the distinction that matters is
  "wrote inside the project directory" (normal) vs. "read a credential
  file" (not), and only the second produces a finding.

**Expected report for both:** No HIGH or MEDIUM findings; `noop-install`
specifically renders the literal `No findings.` line.
