// Fixture: a single outbound network connection and nothing else — no
// credential read, no subprocess. Isolates "MEDIUM stays MEDIUM on its
// own", distinct from faux-node-gyp's combined network+subprocess case.
//
// The dial target is 203.0.113.7 (TEST-NET-3, RFC 5737 — reserved,
// unroutable). Inside the sandbox's network namespace the connect fails,
// but the connect(2) syscall is still made and captured — which is the
// whole point.
package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	conn, err := net.DialTimeout("tcp", "203.0.113.7:443", 2*time.Second)
	if err == nil {
		conn.Close()
	}
	fmt.Println("bare-network-connect: attempted one connection")
}
