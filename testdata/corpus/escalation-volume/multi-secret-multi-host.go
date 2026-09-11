// Fixture: three distinct secret paths and three distinct connect
// targets, all in one run, with some repeats of each to exercise the
// dedup path at realistic volume rather than the minimal 1-of-each the
// unit tests (report_test.go) and the other corpus groups use. Proves
// severity-first ordering and per-path/per-addr dedup hold at scale, not
// just in the small hand-built cases.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	home := os.Getenv("HOME")
	secrets := []string{
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".npmrc"),
	}
	// Read each secret twice — dedup should still report each once.
	for i := 0; i < 2; i++ {
		for _, p := range secrets {
			_, _ = os.ReadFile(p)
		}
	}

	targets := []string{"203.0.113.40:443", "203.0.113.41:443", "203.0.113.42:443"}
	for i := 0; i < 2; i++ {
		for _, addr := range targets {
			if conn, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
				conn.Close()
			}
		}
	}

	fmt.Println("multi-secret-multi-host: done")
}
