// Fixture: reads a project's .env file directly (no subprocess, no
// network) — the same shape as credential-read's fixtures, but against
// a marker that was MISSING from credentialPathMarkers until the fix
// logged in DECISIONS.md 2026-09-11 ".env credential marker was
// missing". This fixture proves the fix, not a gap: it asserts a HIGH
// finding now fires, the same as any other marker in the list.
//
// .env is planted by the test harness at $HOME/.env (mapped to the
// project directory by the sandbox).
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	_, _ = os.ReadFile(filepath.Join(os.Getenv("HOME"), ".env"))
	fmt.Println("dotenv-read: done")
}
