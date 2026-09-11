// Fixture: reads two distinct credential paths. The harness plants a
// .cordon-allowlist containing an INVALID entry for one (a relative
// path) and a VALID entry for the other (an absolute, existing path).
// Proves fail-safe parsing: the invalid entry is dropped, not applied
// -- its path stays flagged exactly as if no entry existed -- while the
// valid entry still suppresses normally.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	home := os.Getenv("HOME")
	_, _ = os.ReadFile(filepath.Join(home, ".ssh", "id_rsa"))      // invalid (relative) entry -- stays flagged
	_, _ = os.ReadFile(filepath.Join(home, ".aws", "credentials")) // valid entry -- suppressed
	fmt.Println("malformed-entries-ignored: done")
}
