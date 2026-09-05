// Package sandbox runs a single command inside rootless Linux namespaces:
// mount, PID, network and user. It is the confinement layer every other
// Cordon feature builds on (see features/sandbox-runner/intent.md and
// INTENT.md §3 Isolation layer).
//
// The public surface is deliberately tiny: build a [Spec], call [Run], read
// a [Result]. All namespace and filesystem setup is internal.
package sandbox

import "io"

// Spec describes one sandboxed execution.
type Spec struct {
	// Command is the argv of the program to run. Command[0] is resolved
	// against PATH inside the sandbox.
	Command []string

	// ProjectDir is an absolute host path made read-write inside the
	// sandbox and used as the working directory. Everything else on the
	// host filesystem is read-only or absent.
	ProjectDir string

	// Stdin, Stdout, Stderr are wired straight to the wrapped command. If
	// nil they are connected to the corresponding os.Std* stream.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Note: the wrapped command's environment is not caller-controllable yet.
// Run synthesizes a minimal sanitized environment (see childEnv in
// run_linux.go). A deliberate forwarding policy is a later concern.

// Result is the outcome of a sandboxed execution. It is only meaningful
// when [Run] returns a nil error.
type Result struct {
	// ExitCode is the wrapped command's exit status, or -1 if it was
	// terminated by a signal (reported over a side channel, since PID 1
	// cannot re-raise a signal on itself — see DECISIONS.md 2026-09-05).
	ExitCode int

	// Report is the rendered plain-text behavior report for this run. It
	// is generated in-namespace and handed back here as data — never
	// written to the wrapped command's stdout/stderr, which [Run] keeps
	// as an untouched pipe. The caller decides where it goes; cmd/cordon
	// prints it to stderr. Empty only when the run never started.
	Report string
}
