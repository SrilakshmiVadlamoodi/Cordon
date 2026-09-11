// Fixture: opens a generic file under $HOME/.config/ that is NOT
// gcloud's credentials.db — the one specific path under .config/ the
// rule matches. Proves the marker is that specific file, not "anything
// under .config/".
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	_, _ = os.ReadFile(filepath.Join(os.Getenv("HOME"), ".config", "some-tool", "settings.json"))
	fmt.Println("generic-config: done")
}
