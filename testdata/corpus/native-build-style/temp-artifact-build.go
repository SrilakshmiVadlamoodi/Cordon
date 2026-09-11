// Fixture: a second legitimate-native-build shape, distinct from
// faux-node-gyp's — heavier on scratch-file churn under /tmp (a real
// build's object files, lockfiles, staging), lighter on subprocess
// launches and no network call at all. Isolates whether high /tmp
// write/read volume alone can trip a finding — it must not, since
// nothing here is credential- or network-shaped.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	tmp := os.TempDir()
	for i := 0; i < 20; i++ {
		p := filepath.Join(tmp, fmt.Sprintf("build-artifact-%d.o", i))
		_ = os.WriteFile(p, []byte("obj\n"), 0o644)
		_, _ = os.ReadFile(p)
		_ = os.Remove(p)
	}
	fmt.Println("temp-artifact-build: done")
}
