# credential-marker-gap

**Models:** A package reading a project's `.env` file — the most common
real-world secrets file for the Node/Python ecosystems Cordon targets
(dotenv-style `API_KEY=...` files loaded by nearly every framework's
boot sequence).

**History:** this category was originally scoped to *demonstrate* a live
gap — `.env` was absent from `credentialPathMarkers`. While writing this
fixture, that turned out to be a plain coverage bug rather than a
taxonomy judgment call (unlike `.npmrc`'s legitimate ambiguity), so it
was fixed directly instead of just documented — see DECISIONS.md
2026-09-11 ".env credential marker was missing" for the full reasoning
on why this was fixed now rather than deferred to Phase 2. This
fixture's job changed accordingly: it now proves the fix, not the gap.

**Rule exercised:** Rule 1 (credential-read, HIGH) — `dotenv-read.go`
reads `$HOME/.env` (planted by the test harness) with no network and no
subprocess. `wantHit` in `cmd/cordon/corpus_test.go` asserts a HIGH
`Credential file read` finding naming `.env`.

**Known, accepted imprecision inherited from the fix (not from this
fixture):** `/.env` as a substring also matches `/.envrc` (a direnv
shell-config file, not a secrets file) — the same class of
false-positive as `.npmrc`, tracked for Phase 2's allowlist/precision
work, not exercised by a fixture here (see `marker-precision` for the
category that tests marker specificity directly).
