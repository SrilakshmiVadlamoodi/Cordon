// Fixture: two distinct credential-shaped paths read in one run, no
// network. Isolates dedup/multi-finding ordering from the single-secret
// cases in this group — proves the rule reports each distinct secret
// once, not that reading more secrets escalates severity (there is no
// higher tier than HIGH to escalate to).
//
// Both files are planted by the test harness under $HOME (mapped to the
// project directory by the sandbox).
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	home := os.Getenv("HOME")
	_, _ = os.ReadFile(filepath.Join(home, ".ssh", "id_rsa"))
	_, _ = os.ReadFile(filepath.Join(home, ".aws", "credentials"))
	fmt.Println("multi-secret: done")
}
