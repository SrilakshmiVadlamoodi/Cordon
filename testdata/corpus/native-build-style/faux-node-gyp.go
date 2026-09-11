// Fixture: the observable footprint of a legitimate native build
// (node-gyp), minus an actual C toolchain — which this environment does
// not have, and which is not what is being tested anyway.
//
// It does the things node-gyp does that Cordon can see: many file opens
// under a build dir, one outbound connection (node-gyp downloads the
// Node headers), and a couple of child-process launches (node-gyp shells
// out to the compiler and linker). It does NOT touch any credential
// path — that omission is the point.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"net"
)

func main() {
	_ = os.MkdirAll("build", 0o755)

	// Probe for a bunch of build inputs, most of which won't exist —
	// exactly what a configure step does. Failed opens are still opens.
	for _, name := range []string{
		"binding.gyp", "package.json", "build/config.gypi",
		"build/Makefile", "src/addon.cc", "src/addon.h",
		"node_modules/.bin/node-gyp", "build/Release/.deps",
	} {
		_, _ = os.ReadFile(name)
	}

	// Write a couple of build outputs.
	for i := 0; i < 2; i++ {
		_ = os.WriteFile(filepath.Join("build", fmt.Sprintf("out-%d.o", i)), []byte("obj\n"), 0o644)
	}

	// Download the Node headers (203.0.113.11 — TEST-NET-3, unroutable;
	// the connect syscall is what matters, not that it succeeds).
	if conn, err := net.DialTimeout("tcp", "203.0.113.11:443", 2*time.Second); err == nil {
		conn.Close()
	}

	// Shell out to "the compiler" and "the linker" — two separate child
	// processes. Their own syscalls are not traced (process-tree gap);
	// they show up only in the report's unobserved-descendant count.
	for i := 0; i < 2; i++ {
		_ = exec.Command("/bin/true").Run()
	}

	fmt.Println("faux-node-gyp: build complete")
}
