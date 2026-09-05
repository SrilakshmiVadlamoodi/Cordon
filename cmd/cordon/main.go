// Command cordon runs a command inside a rootless Linux sandbox. Later
// Phase 1 features add syscall capture and a behavior report on top; for
// now it is the sandbox-runner slice only (features/sandbox-runner).
package main

import (
	"fmt"
	"os"

	"github.com/SrilakshmiVadlamoodi/cordon/internal/sandbox"
)

func main() {
	// If this process was re-exec'd by sandbox.Run as the in-namespace
	// child, MaybeRunChild does the sandbox setup and never returns.
	sandbox.MaybeRunChild()
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
	// res.ExitCode is -1 when the command died from a signal; os.Exit maps
	// that to 255. Faithful 128+signum semantics arrive with the init shim
	// (DECISIONS.md 2026-09-01).
	return res.ExitCode
}
