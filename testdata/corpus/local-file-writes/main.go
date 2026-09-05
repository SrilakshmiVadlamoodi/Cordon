// Fixture: a package doing legitimate local work during install —
// reads and writes several files, all inside the project directory.
// No network, no subprocess, no credential path.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if err := os.MkdirAll("build", 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "local-file-writes:", err)
		os.Exit(1)
	}
	for i := 0; i < 3; i++ {
		p := filepath.Join("build", fmt.Sprintf("artifact-%d.txt", i))
		if err := os.WriteFile(p, []byte("generated\n"), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "local-file-writes:", err)
			os.Exit(1)
		}
		_, _ = os.ReadFile(p)
	}
	fmt.Println("local-file-writes: wrote build artifacts")
}
