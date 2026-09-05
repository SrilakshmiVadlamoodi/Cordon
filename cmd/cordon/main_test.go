//go:build linux

package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireUserNS mirrors internal/sandbox's helper: skip rather than fail
// when the environment forbids unprivileged user namespaces.
func requireUserNS(t *testing.T) {
	t.Helper()
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(b)) == "0" {
			t.Skip("unprivileged user namespaces disabled")
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			t.Skip("unprivileged user namespaces restricted by AppArmor")
		}
	}
}

// buildCordon compiles the real binary so the test exercises the actual
// re-exec of /proc/self/exe, not the go-test harness.
func buildCordon(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "cordon")
	out, err := exec.Command("go", "build", "-o", bin,
		"github.com/SrilakshmiVadlamoodi/cordon/cmd/cordon").CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

func TestCLI_RunReportsExitCodeAndConfines(t *testing.T) {
	requireUserNS(t)

	bin := buildCordon(t)
	projectDir := t.TempDir()

	cmd := exec.Command(bin, "run", "/bin/sh", "-c", "pwd; id -u; exit 5")
	cmd.Dir = projectDir // the CLI uses the working directory as the project dir
	out, _ := cmd.Output()

	if ec := cmd.ProcessState.ExitCode(); ec != 5 {
		t.Fatalf("cordon exit = %d, want 5; output:\n%s", ec, out)
	}
	got := string(out)
	if !strings.Contains(got, projectDir+"\n") {
		t.Errorf("working dir inside sandbox is not the project dir\noutput:\n%s", got)
	}
	if !strings.Contains(got, "0\n") {
		t.Errorf("uid inside sandbox is not 0 (user-namespace mapping)\noutput:\n%s", got)
	}
}

func TestCLI_UsageWhenMisinvoked(t *testing.T) {
	bin := buildCordon(t)

	cmd := exec.Command(bin) // no args
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit, got success; output:\n%s", out)
	}
	if ec := cmd.ProcessState.ExitCode(); ec != 2 {
		t.Fatalf("exit = %d, want 2; output:\n%s", ec, out)
	}
	if !strings.Contains(string(out), "usage: cordon run") {
		t.Errorf("missing usage line; output:\n%s", out)
	}
}
