// Fixture: a package that steals an npm publish token but does not send
// it over an observed network connection — it stages the token, or
// republishes itself through a mechanism Cordon does not watch.
//
// The .npmrc is planted by the test harness at $HOME/.npmrc; the sandbox
// maps $HOME to the project directory. No network, no child process.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	npmrc := filepath.Join(os.Getenv("HOME"), ".npmrc")
	_, _ = os.ReadFile(npmrc)
	fmt.Println("credential-read-no-network: done")
}
