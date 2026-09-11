// Fixture: connections to several distinct hosts in one run, no
// credential access. Isolates dedup/multi-finding behavior for Rule 2
// from bare-connect.go's single-target case — proves each distinct
// address gets its own MEDIUM finding and none of them escalate, since
// there is no credential read in this run to correlate with.
//
// All three targets are TEST-NET-3 (RFC 5737, reserved/unroutable); the
// connect syscalls are what's captured, not success.
package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	for _, addr := range []string{
		"203.0.113.30:443",
		"203.0.113.31:443",
		"203.0.113.32:80",
	} {
		if conn, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
			conn.Close()
		}
	}
	fmt.Println("multi-host-connect: done")
}
