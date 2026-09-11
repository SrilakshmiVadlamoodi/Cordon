// Fixture: opens a heuristic-confidence credential marker (.npmrc)
// BEFORE a definite-confidence one (id_rsa) -- the opposite of display
// order, so this proves the report's ordering is driven by confidence,
// not by which openat happened first. No network, no escalation
// involved: this isolates ordering within a plain multi-HIGH Rule 1
// result, the exact gap escalation-volume's multi-secret-multi-host
// fixture left open (it asserts all three HIGHs appear, not their
// relative order).
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	home := os.Getenv("HOME")
	_, _ = os.ReadFile(filepath.Join(home, ".npmrc"))         // heuristic -- opened first
	_, _ = os.ReadFile(filepath.Join(home, ".ssh", "id_rsa")) // definite -- opened second, must render first
	fmt.Println("definite-before-heuristic: done")
}
