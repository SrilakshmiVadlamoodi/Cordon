// Package syscallcapture ptrace-traces a single launched process and
// reports its openat/openat2, connect, and execve calls with arguments
// resolved to real paths and addresses (features/syscall-capture/intent.md).
//
// Scope for this slice is deliberately one process, not a process tree:
// see the "Scope split" note in that intent.md and DECISIONS.md
// 2026-09-04. features/syscall-capture-tree/intent.md is the named
// follow-up that widens tracing to forked/cloned descendants.
package syscallcapture

import "syscall"

// Config describes the one process to launch and trace.
type Config struct {
	// Argv0 is the resolved absolute path to the program to run.
	Argv0 string
	// Argv is its argv, Argv[0] conventionally the name as invoked.
	Argv []string
	// Envp is its environment.
	Envp []string
}

// Result is how the traced process ended.
type Result struct {
	// ExitCode is its exit status; meaningful only when Signal == 0.
	ExitCode int
	// Signal is the signal that killed it, or 0 if it exited normally.
	Signal syscall.Signal
	// UnobservedDescendants is the count of distinct forked thread-groups
	// (grouped by Tgid — a forked process with its own thread pool counts
	// once) that were kept alive so they don't ENOSYS but never traced:
	// the process-tree gap deferred to features/syscall-capture-tree.
	//
	// It is a rough figure, NOT a precise syscall-capture measurement.
	// Two reasons, both of which a reader should know before quoting it:
	//   - Lower bound. A task that exits before its /proc/<pid>/status
	//     can be read returns Tgid 0 and is skipped.
	//   - It counts every forked thread-group, including ones the wrapped
	//     program's language runtime forks for its own internal
	//     bookkeeping — not only ones the program's code launched. Go's
	//     runtime, for example, does a one-time clone(CLONE_PIDFD)
	//     support probe (a throwaway child) on the first os/exec call,
	//     and that child lands in this count. Whether a runtime does
	//     that, and how often, is version- and language-specific and is
	//     not something syscallcapture predicts or controls. On the
	//     current toolchain it is a stable +1 for a Go wrapped command
	//     that shells out; that is an observation, not a contract.
	//     Read this as "distinct processes we saw and did not trace",
	//     not "subprocesses the install launched".
	//
	// behaviorreport surfaces it in the report ("N other processes were
	// launched and NOT traced") so "what Cordon did not observe" is a
	// real per-run number, not a generic line (INTENT.md §1: best-effort,
	// and say so specifically). See DECISIONS.md 2026-09-05.
	UnobservedDescendants int
}

// Event is one captured syscall, with arguments resolved per
// features/syscall-capture/intent.md: fds become the real path the fd
// pointed at (via /proc/<pid>/fd/<n>, read *after* the call so failed
// opens don't get a bogus resolved path), not the raw argument string.
//
// Addr is a best-effort "ip:port" formatting of the raw sockaddr passed
// to connect, not a resolved hostname: turning a connect() target back
// into the name the program originally asked to resolve would require
// intercepting DNS/name resolution separately, which this syscall-level
// capture does not do. Documented gap, not silently promised.
type Event struct {
	Syscall string   // "openat", "connect", or "execve"
	Path    string   // openat, execve
	Argv    []string // execve only
	Addr    string   // connect only
}
