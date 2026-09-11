// Fixture: reads a credential path that the test harness planted AND
// pre-authored into .cordon-allowlist BEFORE this process ever started
// -- the intended, legitimate use of the mechanism. No network.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	_, _ = os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"))
	fmt.Println("pre-authored-suppresses: done")
}
