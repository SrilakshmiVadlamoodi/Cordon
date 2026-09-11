// Fixture: the concrete 3b regression case. No .cordon-allowlist exists
// when this process starts (the harness only plants the secret file
// itself). This process creates .cordon-allowlist FROM SCRATCH, naming
// its own about-to-be-read path, and only THEN reads that path -- an
// attempt to self-certify its own credential read as allowlisted within
// the very same run.
//
// This must NOT work: runChild (internal/sandbox/run_linux.go) calls
// behaviorreport.LoadAllowlistFile before syscallcapture.Run does
// anything at all -- before the tracee process that becomes this binary
// even exists. By the time this process's own first instruction runs,
// the Allowlist value Generate will use has already been decided. The
// write below happens causally after that decision, so it can only ever
// affect a FUTURE run, never this one.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	home := os.Getenv("HOME")
	secretPath := filepath.Join(home, ".ssh", "id_rsa")

	// Attempt the bypass: self-allowlist the path we're about to read,
	// created after this process (and therefore after runChild's read)
	// has already started.
	_ = os.WriteFile(filepath.Join(home, ".cordon-allowlist"), []byte(secretPath+"\n"), 0o644)

	_, _ = os.ReadFile(secretPath)
	fmt.Println("self-write-too-late: done")
}
