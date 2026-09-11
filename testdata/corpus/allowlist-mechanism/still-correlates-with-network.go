// Fixture: reads a credential path that IS pre-authored into
// .cordon-allowlist (planted by the harness before this process
// started), and ALSO makes a network connection in the same run.
// Proves allowlisting suppresses only the standalone "Credential file
// read" finding -- the "Possible credential exfiltration" correlation
// still fires, because it considers every matched credential path
// regardless of allowlist status (features/allowlist-mechanism/
// intent.md, confirmed design: allowlisting says "reading this file
// alone isn't alarming," not "ignore this file even in combination with
// a network connection this run").
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	_, _ = os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"))
	if conn, err := net.DialTimeout("tcp", "203.0.113.50:443", 2*time.Second); err == nil {
		conn.Close()
	}
	fmt.Println("still-correlates-with-network: done")
}
