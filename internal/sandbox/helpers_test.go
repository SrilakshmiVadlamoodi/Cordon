//go:build linux

package sandbox_test

import (
	"testing"

	"github.com/SrilakshmiVadlamoodi/cordon/internal/sandbox"
)

// requireUserNS skips the test when the kernel or distro policy forbids
// unprivileged user namespaces, so a CI failure points at the environment
// rather than at Cordon (INTENT.md §3 Platform). Delegates to
// sandbox.CheckUserNamespacesAvailableForTest so the test-skip condition
// and Run's own production-path error (run_linux.go's
// checkUserNamespacesAvailable) read the exact same two sysctls, via the
// exact same code, rather than two hand-copied checks that could silently
// drift apart from each other.
func requireUserNS(t *testing.T) {
	t.Helper()
	if err := sandbox.CheckUserNamespacesAvailableForTest(); err != nil {
		t.Skip(err.Error())
	}
}
