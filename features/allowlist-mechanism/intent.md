# allowlist-mechanism

**Inherits:** INTENT.md §4 Phase 2 ("Allowlist mechanism for known-good
patterns"), §1 scope of guarantee (detection is best-effort, never claim
total coverage), §2 Users (signal-to-noise gates adoption);
[[behavior-report]] (the rule this suppresses findings from)

**Why:** Two real false positives are already on record, both
unaddressed: a project-local `.npmrc` holding no auth token (DECISIONS.md
2026-09-05) and a legitimate, non-secret `.env` file (a precision problem
reintroduced, not created, by the `.env` marker fix — DECISIONS.md
2026-09-11 — since fixing the coverage gap means these files are now
*detectable*, which is exactly when the precision problem starts to
matter). Both rules match on *path*, not *content*: `syscall-capture`
traces `openat`, never `read`, so Cordon structurally cannot tell a
token-free `.npmrc` from a stolen one, or a dummy `.env` from a live one,
no matter how the taxonomy is refined later. The only party who can know
that is the developer running Cordon against their own project. Without
a way for that developer to say "I've checked this specific file, it's
fine," every project with a legitimate token-free `.npmrc` or a committed
placeholder `.env` gets a permanent, correct-per-the-rule-but-wrong-in-
practice HIGH finding — exactly the signal-to-noise failure INTENT.md §2
says gets a tool uninstalled.

**Done:**
- [x] A developer can mark one exact file path in their own project as
      known-safe for Rule 1 (credential-read), and that path's
      `Credential file read` finding is suppressed on later runs
      *(`internal/behaviorreport/allowlist.go`'s `Allowlist`/
      `LoadAllowlist`/`LoadAllowlistFile`; corpus fixture
      `allowlist-mechanism/pre-authored-suppresses.go`)*
- [x] Suppression is accounted for in the report, never silent: the
      report states which finding(s) were suppressed, naming the path
      and the allowlist entry responsible, plus a count — "no findings"
      must never mean "no findings, or some were hidden," those stay
      distinguishable
      *(`Report.Suppressed` + `WriteText`'s `SUPPRESSED BY ALLOWLIST (N)`
      section, named entries not a bare count;
      `TestReport_WriteText_SuppressedSectionNamesPathAndTitle`)*
- [x] An allowlisted credential path remains visible to Rule 2's
      exfil-correlation check — allowlisting suppresses the standalone
      `Credential file read` HIGH, not this run's read+connect signal in
      combination (see Constraints for why)
      *(`Generate` keeps allowlisted paths in `credentialPaths` for the
      correlation check; `TestGenerate_AllowlistedPath_
      StillCorrelatesWithConnect` and corpus fixture
      `still-correlates-with-network.go`)*
- [x] A change made to the allowlist file *during* the run it's meant to
      affect has zero effect on that run's own report — proven by a
      corpus fixture that actually attempts this (creates or edits
      `.cordon-allowlist` from inside its own execution, naming its own
      about-to-be-read path, then reads it), not argued from design
      reasoning alone
      *(corpus fixture `self-write-too-late.go`; DECISIONS.md 2026-09-11
      traces the exact call sequence in `runChild` confirming the
      allowlist read returns before the tracee process exists, then
      reproduces the attempt rather than resting on that argument alone)*
- [x] Fail-safe parsing: a malformed line, a relative path, or a
      nonexistent-file entry in `.cordon-allowlist` is ignored for
      matching purposes — that path stays flagged, exactly as if no
      entry existed, never silently allowed
      *(`LoadAllowlist`'s `filepath.IsAbs` + `os.Stat` validation, both
      counted in `Allowlist.Ignored` and surfaced in the report;
      `TestLoadAllowlist_InvalidEntriesAreIgnoredNotApplied` plants a
      real missing file to assert the fail-safe direction, not just the
      accept path; corpus fixture `malformed-entries-ignored.go`)*

**Constraints (slice-specific):**
- **Granularity: exact absolute path only.** Matched against the same
  resolved path string `credentialPathMarkers` already produces
  (`e.Path`, `filepath.Clean`d) — no globs, no wildcards, no directory
  prefixes, no substring matching. A pattern loose enough to cover "any
  project's `.npmrc`" is loose enough to cover an attacker's `.npmrc`
  too; this feature does not offer that shape at all, rather than
  offering it with a warning label.
- **Scope: Rule 1 (credential-read) only.** Rule 2 (network egress) has
  no comparable "one specific known-good target" concept yet — its
  targets are bare IP:port, and a standalone MEDIUM finding isn't the
  noise problem this feature exists to fix. Extending allowlisting to
  Rule 2 is a separate, later decision, not built here.
- **Location and authorship: one flat file at the project root**
  (`.cordon-allowlist` — one absolute path per line, `#`-prefixed
  comments, blank lines ignored), read from inside `runChild` (already
  chdir'd into the project dir) before `syscallcapture.Run` launches the
  traced command. No Cordon-level or home-directory config, and no
  built-in default entries shipped with Cordon itself — every entry is
  an explicit, per-project, developer-authored decision, meant to be
  checked into the project's own version control so a change to it is a
  visible diff, not silent state. A global or built-in allowlist would
  mean Cordon's own authors — or nobody — deciding what's safe across
  every user's project, which is exactly the blanket trust this feature
  must not grant.
- **Content-blindness is inherited, not solved.** Allowlisting a path
  says "the file at this path was fine when I checked it," not "the file
  at this path is always fine." If a legitimately-allowlisted `.env`
  later has a real secret appended to it, Rule 1 stays silent for that
  path — a disclosed, accepted limitation of path-based trust (INTENT.md
  §1 best-effort), not something this mechanism claims to prevent.

**Named bypass risk this design is built against:** a package under
audit edits `.cordon-allowlist` — necessarily a read-write file inside
the project dir, since legitimate installs need a writable project tree
— as part of its own install, adding an entry for a path it's about to
read, defeating detection retroactively in the same run. Mitigated
structurally, not by policy: the allowlist is read exactly once,
synchronously, before the tracee's first instruction executes. By the
time the wrapped command could write to that file, Cordon has already
decided, for this run, what's allowlisted — a malicious edit can only
affect a *future* run, and only if the developer re-runs Cordon without
noticing the file changed, which version-controlling it makes visible as
an ordinary diff. This doesn't make the file tamper-proof; it makes
tampering *during the audited run itself* structurally inert.

**Secondary risk, addressed by the granularity constraint above:** a
developer authoring a convenience pattern ("just ignore all `.env`
files, they're always fine") instead of naming one reviewed file — which
would silently and permanently defeat Rule 1 for every matching path in
the project, including one a compromised dependency adds later. v1 has
no syntax capable of expressing this; only exact paths. Re-typing a new
exact path for every genuinely-reviewed file is deliberate friction, not
an oversight.
