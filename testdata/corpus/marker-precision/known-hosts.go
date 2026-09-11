// Fixture: opens $HOME/.ssh/known_hosts — a real file that lives right
// next to the id_rsa/id_ed25519/etc. markers the rule DOES match, but
// itself contains no private key material (just host public keys and
// fingerprints an SSH client uses to verify servers, not to
// authenticate itself). Proves the rule's markers are the specific
// private-key filenames, not "anything under .ssh/".
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	_, _ = os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	fmt.Println("known-hosts: done")
}
