//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckUserNamespacesAvailable exercises both documented restriction
// cases directly, via the injectable path vars, rather than relying on
// this dev machine happening to be restricted (it isn't — see
// helpers_test.go's requireUserNS, which never skips here). Without this,
// checkUserNamespacesAvailable's two error branches would be unverified
// code on exactly the path a real userns-restricted CI runner would hit.
func TestCheckUserNamespacesAvailable(t *testing.T) {
	origClone := unprivilegedUserNSClonePath
	origAppArmor := apparmorRestrictUnprivilegedUserNSPath
	t.Cleanup(func() {
		unprivilegedUserNSClonePath = origClone
		apparmorRestrictUnprivilegedUserNSPath = origAppArmor
	})

	writeFake := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "sysctl-fake")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	missingPath := func(t *testing.T) string {
		t.Helper()
		return filepath.Join(t.TempDir(), "does-not-exist")
	}

	t.Run("both unrestricted (missing files) is nil, matching an unpatched kernel", func(t *testing.T) {
		unprivilegedUserNSClonePath = missingPath(t)
		apparmorRestrictUnprivilegedUserNSPath = missingPath(t)
		if err := checkUserNamespacesAvailable(); err != nil {
			t.Fatalf("checkUserNamespacesAvailable() = %v, want nil", err)
		}
	})

	t.Run("unprivileged_userns_clone=0 is a clear, specific error", func(t *testing.T) {
		unprivilegedUserNSClonePath = writeFake(t, "0\n")
		apparmorRestrictUnprivilegedUserNSPath = missingPath(t)
		err := checkUserNamespacesAvailable()
		if err == nil {
			t.Fatal("checkUserNamespacesAvailable() = nil, want an error")
		}
		if !strings.Contains(err.Error(), "unprivileged_userns_clone=0") {
			t.Errorf("error %q does not name the specific sysctl and value", err.Error())
		}
	})

	t.Run("unprivileged_userns_clone=1 (unrestricted) does not trip the check", func(t *testing.T) {
		unprivilegedUserNSClonePath = writeFake(t, "1\n")
		apparmorRestrictUnprivilegedUserNSPath = missingPath(t)
		if err := checkUserNamespacesAvailable(); err != nil {
			t.Fatalf("checkUserNamespacesAvailable() = %v, want nil (1 means allowed)", err)
		}
	})

	t.Run("apparmor_restrict_unprivileged_userns=1 is a clear, specific error", func(t *testing.T) {
		unprivilegedUserNSClonePath = missingPath(t)
		apparmorRestrictUnprivilegedUserNSPath = writeFake(t, "1\n")
		err := checkUserNamespacesAvailable()
		if err == nil {
			t.Fatal("checkUserNamespacesAvailable() = nil, want an error")
		}
		if !strings.Contains(err.Error(), "apparmor_restrict_unprivileged_userns=1") {
			t.Errorf("error %q does not name the specific sysctl and value", err.Error())
		}
	})

	t.Run("apparmor_restrict_unprivileged_userns=0 (unrestricted) does not trip the check", func(t *testing.T) {
		unprivilegedUserNSClonePath = missingPath(t)
		apparmorRestrictUnprivilegedUserNSPath = writeFake(t, "0\n")
		if err := checkUserNamespacesAvailable(); err != nil {
			t.Fatalf("checkUserNamespacesAvailable() = %v, want nil (0 means unrestricted)", err)
		}
	})
}
