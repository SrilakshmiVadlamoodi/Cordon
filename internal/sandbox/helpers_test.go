//go:build linux

package sandbox_test

import (
	"os"
	"strings"
	"testing"
)

// requireUserNS skips the test when the kernel or distro policy forbids
// unprivileged user namespaces, so a CI failure points at the environment
// rather than at Cordon (INTENT.md §3 Platform).
func requireUserNS(t *testing.T) {
	t.Helper()

	// Older Debian/Ubuntu: a global on/off switch.
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(b)) == "0" {
			t.Skip("unprivileged user namespaces disabled (kernel.unprivileged_userns_clone=0)")
		}
	}
	// Ubuntu 23.10+/24.04: AppArmor gates unprivileged userns for
	// unconfined binaries even when the kernel supports it.
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			t.Skip("unprivileged user namespaces restricted by AppArmor (kernel.apparmor_restrict_unprivileged_userns=1)")
		}
	}
}
