// Fixture: forks a detached child, does NOT wait for it, and exits
// immediately. The child sleeps briefly then writes a marker file into
// the project directory — an action that would be visible on the host
// (the project dir is bind-mounted read-write at the same path) IF the
// child survived long enough to complete it.
//
// It does not. Confirmed empirically (see
// testdata/corpus/delayed-process/group.md and DECISIONS.md): when
// runChild (PID 1 of the sandbox's PID namespace) exits right after this
// fixture's own process exits, the kernel immediately SIGKILLs every
// other process in that namespace (pid_namespaces(7)) — the detached
// child dies mid-sleep, and the marker file is never written. This
// fixture's assertion is on that absence, checked from outside the
// sandbox after waiting past the child's own sleep duration.
package main

import (
	"os"
	"os/exec"
)

func main() {
	dir, _ := os.Getwd() // the project directory
	_ = exec.Command("/bin/sh", "-c", "sleep 2 && date > "+dir+"/marker-file").Start()
	os.Exit(0)
}
