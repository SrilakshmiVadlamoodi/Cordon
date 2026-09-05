//go:build linux

package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildFixture compiles a testdata/corpus/<name> program into destDir and
// returns its path. destDir must be inside the project dir the run will
// use, so the binary is visible through the sandbox's bind mount.
func buildFixture(t *testing.T, name, destDir string) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata", "corpus", name))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(destDir, "fixture-"+name)
	out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Fatalf("building fixture %s: %v\n%s", name, err, out)
	}
	return bin
}

// runCorpusFixture runs one corpus fixture through the real cordon binary
// and returns just the behavior-report section of stdout.
func runCorpusFixture(t *testing.T, cordonBin, name string, plant func(projectDir string)) string {
	t.Helper()
	projectDir := t.TempDir()
	if plant != nil {
		plant(projectDir)
	}
	fixtureBin := buildFixture(t, name, projectDir)

	cmd := exec.Command(cordonBin, "run", fixtureBin)
	cmd.Dir = projectDir // cordon uses cwd as the project dir; sandbox maps $HOME to it
	out, _ := cmd.CombinedOutput()

	marker := "=== Cordon behavior report ==="
	i := strings.Index(string(out), marker)
	if i < 0 {
		t.Fatalf("%s: no behavior report in output:\n%s", name, out)
	}
	return string(out)[i:]
}

func plantSSHKey(projectDir string) {
	_ = os.MkdirAll(filepath.Join(projectDir, ".ssh"), 0o700)
	_ = os.WriteFile(filepath.Join(projectDir, ".ssh", "id_rsa"), []byte("FAKE-PRIVATE-KEY\n"), 0o600)
}

func plantNpmrc(projectDir string) {
	_ = os.WriteFile(filepath.Join(projectDir, ".npmrc"),
		[]byte("//registry.npmjs.org/:_authToken=FAKE-TOKEN\n"), 0o600)
}

func TestCorpus_BehaviorReport(t *testing.T) {
	requireUserNS(t)
	cordonBin := buildCordon(t)

	t.Run("noop-install: no findings", func(t *testing.T) {
		r := runCorpusFixture(t, cordonBin, "noop-install", nil)
		mustContain(t, r, "No findings.")
		mustNotContain(t, r, "[HIGH]")
		mustNotContain(t, r, "[MEDIUM]")
	})

	t.Run("local-file-writes: no high/medium", func(t *testing.T) {
		r := runCorpusFixture(t, cordonBin, "local-file-writes", nil)
		mustNotContain(t, r, "[HIGH]")
		mustNotContain(t, r, "[MEDIUM]")
	})

	t.Run("bare-network-connect: medium, not escalated", func(t *testing.T) {
		r := runCorpusFixture(t, cordonBin, "bare-network-connect", nil)
		mustContain(t, r, "[MEDIUM] Network connection")
		mustContain(t, r, "203.0.113.7:443")
		mustNotContain(t, r, "[HIGH]")
	})

	t.Run("faux-node-gyp: medium egress, no high, descendants reported", func(t *testing.T) {
		r := runCorpusFixture(t, cordonBin, "faux-node-gyp", nil)
		mustContain(t, r, "[MEDIUM] Network connection")
		mustContain(t, r, "203.0.113.11:443")
		mustNotContain(t, r, "[HIGH]")
		// The fixture launches 2 subprocesses; the reported count is
		// >= 2 (it also picks up the Go runtime's one-time pidfd probe
		// on first os/exec — see the fixture README and DECISIONS.md).
		if n := unobservedCount(t, r); n < 2 {
			t.Errorf("unobserved-descendant count = %d, want >= 2; report:\n%s", n, r)
		}
	})

	t.Run("credential-read-and-exfil: two highs at the top", func(t *testing.T) {
		r := runCorpusFixture(t, cordonBin, "credential-read-and-exfil", plantSSHKey)
		mustContain(t, r, "[HIGH] Credential file read")
		mustContain(t, r, "id_rsa")
		mustContain(t, r, "[HIGH] Possible credential exfiltration")
		mustContain(t, r, "203.0.113.21:443")
		// Highest severity first: the first finding line is a HIGH.
		if fi := strings.Index(r, "FINDINGS"); fi >= 0 {
			after := r[fi:]
			firstBracket := strings.Index(after, "[")
			if firstBracket < 0 || !strings.HasPrefix(after[firstBracket:], "[HIGH]") {
				t.Errorf("first finding is not HIGH; report:\n%s", r)
			}
		}
	})

	t.Run("credential-read-no-network: high, no exfil, no medium", func(t *testing.T) {
		r := runCorpusFixture(t, cordonBin, "credential-read-no-network", plantNpmrc)
		mustContain(t, r, "[HIGH] Credential file read")
		mustContain(t, r, ".npmrc")
		mustNotContain(t, r, "Possible credential exfiltration")
		mustNotContain(t, r, "[MEDIUM]")
	})
}

// unobservedCount pulls N out of the report's
// "N other process(es) were launched ... NOT traced" line, or -1 if the
// zero-case line is present instead.
func unobservedCount(t *testing.T, report string) int {
	t.Helper()
	const marker = " other process(es) were launched during this run and were NOT traced"
	i := strings.Index(report, marker)
	if i < 0 {
		if strings.Contains(report, "No separate processes were launched by the install this run") {
			return 0
		}
		t.Fatalf("report has neither the descendant-count line nor the zero-case line:\n%s", report)
	}
	// Walk back from the marker to the start of the number.
	j := i
	for j > 0 && report[j-1] >= '0' && report[j-1] <= '9' {
		j--
	}
	n := 0
	for _, c := range report[j:i] {
		n = n*10 + int(c-'0')
	}
	return n
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("report missing %q:\n%s", needle, haystack)
	}
}

func mustNotContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("report unexpectedly contains %q:\n%s", needle, haystack)
	}
}
