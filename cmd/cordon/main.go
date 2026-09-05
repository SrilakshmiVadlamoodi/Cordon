// Command cordon runs a command inside a rootless Linux sandbox. Later
// Phase 1 features add syscall capture and a behavior report on top; for
// now it is the sandbox-runner slice only (features/sandbox-runner).
package main

import (
	"fmt"
	"os"

	"github.com/SrilakshmiVadlamoodi/cordon/internal/sandbox"
	"github.com/SrilakshmiVadlamoodi/cordon/internal/syscallcapture"
)

func main() {
	// This binary can be re-exec'd as either of two in-process helpers,
	// nested one inside the other; each hook is a no-op unless its own
	// sentinel env var is set, and neither returns if it takes over.
	// Outer: sandbox.Run's in-namespace child (mounts, pivot_root, then
	// becomes PID 1 tracer/reaper — see runChild).
	sandbox.MaybeRunChild()
	// Inner: syscallcapture.Run's ptrace tracee helper (installs the
	// seccomp filter, then execve's into the real wrapped command).
	syscallcapture.MaybeRunTracee()
	os.Exit(run(os.Args[1:]))
}

// run is the CLI proper, split out so its exit code is testable.
func run(args []string) int {
	if len(args) < 2 || args[0] != "run" {
		fmt.Fprintln(os.Stderr, "usage: cordon run <command> [args...]")
		return 2
	}

	projectDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cordon:", err)
		return 1
	}

	res, err := sandbox.Run(sandbox.Spec{
		Command:    args[1:],
		ProjectDir: projectDir,
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "cordon:", err)
		return 1
	}

	// The behavior report goes to stderr, not stdout: the wrapped
	// command owns stdout (so `cordon run npm ci > deps.log` keeps npm's
	// output clean), and the report is Cordon's own diagnostic *about*
	// the run. intent.md says "stdout"; the deviation and its reasoning
	// are logged in DECISIONS.md 2026-09-05.
	if res.Report != "" {
		fmt.Fprint(os.Stderr, res.Report)
	}
	// res.ExitCode is -1 when the command died from a signal; os.Exit maps
	// that to 255. Faithful 128+signum semantics arrive with the init shim
	// (DECISIONS.md 2026-09-01).
	return res.ExitCode
}
