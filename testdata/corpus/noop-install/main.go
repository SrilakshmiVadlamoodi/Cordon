// Fixture: a pure-JS package with no lifecycle side effects — the common
// case. Reads its own package.json (a file inside the project tree),
// prints a line, exits 0. No network, no subprocess, no credential path.
package main

import (
	"fmt"
	"os"
)

func main() {
	// A file that exists inside the project dir; the read is unremarkable.
	_, _ = os.ReadFile("package.json")
	fmt.Println("noop-install: nothing to do")
}
