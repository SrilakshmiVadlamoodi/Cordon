# env-path-forwarding

**Inherits:** INTENT.md §4 Phase 3 (Distribution — prerequisite for
`github-action`); [[sandbox-runner]] (`childEnv`/`roSystemDirs`, the
exact mechanism this slice extends); [[allowlist-mechanism]] (the
read-before-tracee-exists TOCTOU argument this slice reuses for a
different value)

**Why:** `childEnv` hardcodes `PATH` to a fixed system-directory set
(`defaultPath`, `run_linux.go:27`) and discards the caller's real `PATH`
entirely; `roSystemDirs` (`run_linux.go:43`) bind-mounts only `/bin /sbin
/lib /lib64 /usr /etc`. Anything the caller resolves via a `PATH` entry
outside that fixed set does not exist inside the sandbox at all. This
was a known, named gap (`sandbox.go:30-32`'s standing comment; DECISIONS.md
2026-09-04's `$npm_node_execpath` finding) but not yet a blocker for
anything Cordon shipped. It becomes one for `github-action`: the standard
way a real CI workflow gets a pinned Node version is `actions/setup-node`,
which installs into `$RUNNER_TOOL_CACHE` (typically under
`/opt/hostedtoolcache/...`) and prepends that directory to `PATH` — a
location outside every directory Cordon bind-mounts today. Without this
fix, `cordon run npm install` fails to resolve `npm`/`node` at all on the
default path through the Action, not as an edge case but as the common
case. Split into its own feature rather than built inline into
`github-action` because the fix lives entirely in `internal/sandbox`
(mount/env setup, the same layer `roSystemDirs`/`childEnv` already live
in) — bundling it with the Action's YAML/CI-output concerns would make
one feature responsible for two different layers, the same reasoning
DECISIONS.md 2026-09-04 used to split `syscall-capture-tree` out of
`syscall-capture`.

**Done:**
- [ ] A binary placed in a directory outside today's fixed `roSystemDirs`
      set, but present on the caller's `PATH` at invocation time, resolves
      and runs inside the sandbox — proves the actual gap closes, not
      just that the code compiles
- [ ] With the caller's `PATH` left at its own current default (nothing
      unusual on it), the wrapped command's behavior is unchanged from
      today: same `roSystemDirs` binds, same baseline resolvable set — no
      regression to the existing fixed-path behavior
- [ ] A realistic `actions/setup-node`-shaped case (a directory outside
      `/usr` added to `PATH`, holding a `node`-like binary) resolves and
      runs — the concrete scenario motivating this feature, not just a
      synthetic directory
- [ ] DECISIONS.md entry stating plainly that this widens the read-only
      surface visible inside the sandbox beyond the previous fixed
      allowlist (`roSystemDirs`) to include whatever the invoking
      caller's `PATH` names — an accepted, deliberate tradeoff, logged as
      one, not a silent side effect
- [ ] DECISIONS.md (or this doc) states explicitly *when* the caller's
      `PATH` is read relative to the tracee's first instruction, with a
      line-number citation, the same TOCTOU-shaped guarantee
      [[allowlist-mechanism]] gives for `.cordon-allowlist`

**Where the read happens, stated plainly (not left implicit):**
`sandbox.Run` (`sandbox.go`, the host-side, pre-namespace parent process)
is where `os.Getenv("PATH")` must be captured — at `Run`'s entry, before
`childConfig` is marshaled (`run_linux.go:80-87`) and long before
`cmd.Start()` (`run_linux.go:146`). At that point no namespace, no
re-exec'd child, no tracee, and no wrapped-command process exists yet at
all — this is strictly earlier than the allowlist's read-before-tracee
point (which happens inside the already-re-exec'd, already-namespaced
`runChild`, `run_linux.go:257`). The captured directory list crosses the
process boundary the same way `Command`/`ProjectDir`/`NewRoot` already do
today: as a field on `childConfig`, JSON-encoded into `childEnvVar`
before `cmd.Start()`. Consequence: the wrapped command cannot possibly
influence which `PATH` directories get bind-mounted for its own run —
by the time it (or anything it forks) executes for the first time, the
directory list was fixed before the sandbox process tree existed at all,
not merely before the tracee's first syscall.

**Constraints (slice-specific):**
- **`PATH` directories only, read-only bind-mounts — not general env
  passthrough.** Forwarding arbitrary environment variables is a
  separate, larger decision (env vars routinely carry secrets — API
  tokens, cloud credentials — and forwarding them into the sandboxed
  process's environment is exactly the kind of exposure INTENT.md §1's
  isolation boundary exists to prevent). This slice does not touch that;
  `childEnv` keeps synthesizing every other variable (`HOME`, `PWD`,
  `TERM`) exactly as it does today.
- **Additive to `defaultPath`, not a replacement.** The sandbox `PATH`
  becomes `defaultPath` plus the caller's extra directories (those not
  already covered by `roSystemDirs`), deduplicated, so today's baseline
  resolvable set never shrinks.
- **Missing or unreadable `PATH` directories are skipped silently**, the
  same as `roSystemDirs`' existing `os.Lstat` skip for e.g. missing
  `/lib64` on arm64 (`run_linux.go:324-326`) — a `PATH` entry that
  legitimately doesn't exist on the host is not an error condition.
- **Read-only, exactly like `roSystemDirs`.** No new write surface is
  introduced; this only widens what the sandboxed process can *see*, via
  the same bind-then-remount-read-only sequence already used for the
  existing system directories.
