// Fixture: the SAME credential read as credential-read's fixtures
// (`$HOME/.ssh/id_rsa`), but performed inside a forked child process
// instead of the directly-traced binary. This is a genuine, currently-
// live false negative, not a synthetic evasion trick: syscall-capture's
// tracing scope (features/syscall-capture/intent.md "Scope split") only
// reads and reports the primary process's own syscalls (and its sibling
// OS threads) — every separately forked process is auto-attached just
// enough to avoid ENOSYS-ing its own syscalls, then resumed unread, per
// DECISIONS.md 2026-09-04 "Seccomp filter inheritance vs. ptrace
// attachment". The child's openat is never reported.
//
// This is exactly the gap features/syscall-capture-tree/intent.md exists
// to close.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	keyPath := filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")
	// A child process (a real fork+exec via exec.Cmd, not the untraced
	// main binary) does the actual read. cat's own openat is made by a
	// process syscall-capture only auto-attaches-and-releases, never
	// reads registers for.
	_ = exec.Command("cat", keyPath).Run()
	fmt.Println("subprocess-read: done")
}
