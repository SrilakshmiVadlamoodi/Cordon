# credential-read-and-exfil

**Models:** The canonical self-propagating npm worm described in
INTENT.md §1: a `postinstall` script that reads the victim's SSH key (or
publish token) and POSTs it to an attacker-controlled endpoint.

**Behavior (all in one process, no child):**
- Opens `$HOME/.ssh/id_rsa`. The test harness plants a fake key there
  first; the sandbox maps `$HOME` to the project directory.
- Opens a `connect(2)` to `203.0.113.21:443` (TEST-NET-3, unroutable)
  and writes the key bytes. The connection fails in the sandbox's
  network namespace; the syscall is captured.

Single process, so both the `openat` and the `connect` are seen.

**Exercises:** Both rules and the escalation path — Rule 1 fires on the
key read, Rule 2 fires on the connection, and because both happened in
one run, the HIGH "possible credential exfiltration" correlation finding
is added.

**Expected report (top of output):**
- `[HIGH] Credential file read` naming the `.ssh/id_rsa` path.
- `[HIGH] Possible credential exfiltration` naming both the path and
  `203.0.113.21:443`.
- `[MEDIUM] Network connection` for `203.0.113.21:443`.

**What this fixture does not prove:** that Cordon caught an *actual*
exfiltration — the report itself says it cannot confirm data flowed from
the file to the socket, only that both happened. This fixture confirms
the report makes that correlation and states that limit plainly.
