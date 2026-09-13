//go:build linux

package sandbox_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SrilakshmiVadlamoodi/cordon/internal/sandbox"
	"github.com/SrilakshmiVadlamoodi/cordon/internal/syscallcapture"
)

// TestMain routes the re-exec: when Run launches /proc/self/exe as the
// in-namespace child (and that child, in turn, launches it a second time
// as syscallcapture's ptrace tracee helper), the test binary is what
// actually runs each time, so it must give each layer its chance to take
// over before any test executes. See cmd/cordon/main.go for the same
// two-hook pattern in the real binary.
func TestMain(m *testing.M) {
	sandbox.MaybeRunChild()
	syscallcapture.MaybeRunTracee()
	os.Exit(m.Run())
}

func TestRun_PassesThroughExitCode(t *testing.T) {
	requireUserNS(t)

	res, err := sandbox.Run(sandbox.Spec{
		Command:    []string{"/bin/sh", "-c", "exit 42"},
		ProjectDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.ExitCode != 42 {
		t.Fatalf("ExitCode = %d, want 42", res.ExitCode)
	}
}

// TestRun_WrappedCommandSignalDeathReportsNegativeOne is the regression
// test for DECISIONS.md 2026-09-05 "PID 1 signal re-raise is silently
// dropped by the kernel": the exact repro from that entry, exercised
// through the real, public sandbox.Run API end-to-end (full namespace
// setup, real ptrace tracer, real PID 1) rather than as a lower-level
// unit test. Before that fix, this reported ExitCode 143 (the
// os.Exit(128+signal) fallback), not -1 — the earlier sandbox-runner
// tests only ever proved the wrapped command (PID 2) receives signals
// correctly; none of them exercised PID 1's own death *reporting*,
// which is exactly the gap that let this ship.
func TestRun_WrappedCommandSignalDeathReportsNegativeOne(t *testing.T) {
	requireUserNS(t)

	res, err := sandbox.Run(sandbox.Spec{
		Command:    []string{"/bin/sh", "-c", "kill -TERM $$"},
		ProjectDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.ExitCode != -1 {
		t.Fatalf("ExitCode = %d, want -1 (signal death)", res.ExitCode)
	}
}

// TestRun_NormalExitInSignalSentinelRangeIsNotMisreported guards the
// specific reason a sentinel exit code (e.g. 128+signal) was rejected in
// favor of the pipe-based report: a wrapped command's own, unrelated
// choice of exit code must never be misread as a signal death just
// because it happens to land in that numeric range.
func TestRun_NormalExitInSignalSentinelRangeIsNotMisreported(t *testing.T) {
	requireUserNS(t)

	res, err := sandbox.Run(sandbox.Spec{
		// 143 == 128+SIGTERM, the exact value a sentinel-exit-code
		// design would have used to mean "died from SIGTERM" — chosen
		// deliberately to prove this is a real, ordinary exit, not that.
		Command:    []string{"/bin/sh", "-c", "exit 143"},
		ProjectDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.ExitCode != 143 {
		t.Fatalf("ExitCode = %d, want 143 (a normal exit, not a misreported signal death)", res.ExitCode)
	}
}

func TestRun_PassesThroughStdoutAndStderrUnchanged(t *testing.T) {
	requireUserNS(t)

	// No trailing newlines, and bytes on both streams, so any wrapper that
	// buffered-and-reprinted or added framing would be caught.
	var out, errb bytes.Buffer
	res, err := sandbox.Run(sandbox.Spec{
		Command:    []string{"/bin/sh", "-c", "printf 'OUT-no-newline'; printf 'ERR-no-newline' >&2; exit 3"},
		ProjectDir: t.TempDir(),
		Stdout:     &out,
		Stderr:     &errb,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("ExitCode = %d, want 3", res.ExitCode)
	}
	if got := out.String(); got != "OUT-no-newline" {
		t.Fatalf("stdout = %q, want %q", got, "OUT-no-newline")
	}
	if got := errb.String(); got != "ERR-no-newline" {
		t.Fatalf("stderr = %q, want %q", got, "ERR-no-newline")
	}
}

func TestRun_RejectsEmptyCommand(t *testing.T) {
	_, err := sandbox.Run(sandbox.Spec{Command: nil, ProjectDir: t.TempDir()})
	if err == nil {
		t.Fatal("Run(empty Command) returned nil error, want a validation error")
	}
}

func TestRun_RejectsNonDirectoryProjectDir(t *testing.T) {
	_, err := sandbox.Run(sandbox.Spec{
		Command:    []string{"/bin/true"},
		ProjectDir: filepath.Join(t.TempDir(), "does-not-exist"),
	})
	if err == nil {
		t.Fatal("Run(nonexistent ProjectDir) returned nil error, want a validation error")
	}
}

func TestRun_CommandNotFoundExitsWith127(t *testing.T) {
	requireUserNS(t)

	res, err := sandbox.Run(sandbox.Spec{
		Command:    []string{"definitely-not-a-real-binary"},
		ProjectDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.ExitCode != 127 {
		t.Fatalf("ExitCode = %d, want 127 (command not found)", res.ExitCode)
	}
}

func TestRun_ChildIsInNewNamespaces(t *testing.T) {
	requireUserNS(t)

	// Each namespace is identified by the inode its /proc/self/ns/<x>
	// symlink points at. The child prints its own; every one must differ
	// from this test process's, i.e. the child is in a *new* namespace,
	// not merely "a" namespace.
	wantNS := []string{"user", "mnt", "pid", "net", "uts", "ipc"}
	script := `for ns in user mnt pid net uts ipc; do printf '%s=%s\n' "$ns" "$(readlink /proc/self/ns/$ns)"; done`

	var out bytes.Buffer
	res, err := sandbox.Run(sandbox.Spec{
		Command:    []string{"/bin/sh", "-c", script},
		ProjectDir: t.TempDir(),
		Stdout:     &out,
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Run: err=%v exit=%d output:\n%s", err, res.ExitCode, out.String())
	}

	child := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			child[k] = v
		}
	}
	for _, ns := range wantNS {
		self, e := os.Readlink("/proc/self/ns/" + ns)
		if e != nil {
			t.Skipf("cannot read this process's %s namespace: %v", ns, e)
		}
		got := child[ns]
		if got == "" {
			t.Fatalf("child reported no %s namespace; output:\n%s", ns, out.String())
		}
		if got == self {
			t.Fatalf("%s namespace not isolated: child and parent share %s", ns, self)
		}
	}
}

func TestRun_ProjectDirWritableAndHomeInvisible(t *testing.T) {
	requireUserNS(t)

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "existing.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A stand-in for the real home directory, holding a secret the wrapped
	// command must not be able to reach by any path.
	secretHome := t.TempDir()
	if err := os.MkdirAll(filepath.Join(secretHome, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	secretKey := filepath.Join(secretHome, ".ssh", "id_rsa")
	if err := os.WriteFile(secretKey, []byte("TOP-SECRET-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	script := strings.Join([]string{
		`printf 'PWD=%s\n' "$(pwd)"`,
		`printf 'HOME=%s\n' "$HOME"`,
		`cat existing.txt >/dev/null && echo READ_PROJECT_OK`,
		`echo written-by-sandbox > newfile.txt && echo WROTE_PROJECT_OK`,
		`cat "$HOME/.ssh/id_rsa" 2>/dev/null || echo HOME_SSH_BLOCKED`,
		`cat "` + secretKey + `" 2>/dev/null || echo ABS_SECRET_BLOCKED`,
		// Writes outside the project dir must fail, and specifically
		// because the filesystem is read-only. touch is a real program, so
		// its stderr (unlike a shell redirection error) flows through the
		// pipe where grep can inspect it.
		`touch /etc/cordon-probe 2>&1 | grep -q "Read-only file system" && echo ETC_WRITE_READONLY`,
		`touch /cordon-probe     2>&1 | grep -q "Read-only file system" && echo ROOT_WRITE_READONLY`,
	}, "\n")

	var out, errb bytes.Buffer
	res, err := sandbox.Run(sandbox.Spec{
		Command:    []string{"/bin/sh", "-c", script},
		ProjectDir: projectDir,
		Stdout:     &out,
		Stderr:     &errb,
	})
	if err != nil {
		t.Fatalf("Run error: %v\nstderr:\n%s", err, errb.String())
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", res.ExitCode, out.String(), errb.String())
	}

	got := out.String()
	mustContain := []string{
		"PWD=" + projectDir,
		"READ_PROJECT_OK",
		"WROTE_PROJECT_OK",
		"HOME_SSH_BLOCKED",
		"ABS_SECRET_BLOCKED",
		"ETC_WRITE_READONLY",
		"ROOT_WRITE_READONLY",
	}
	for _, want := range mustContain {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in sandbox output:\n%s", want, got)
		}
	}
	if strings.Contains(got, "TOP-SECRET-KEY") {
		t.Errorf("secret key contents leaked into sandbox output:\n%s", got)
	}
	if strings.Contains(got, "HOME="+secretHome) {
		t.Errorf("$HOME inside sandbox is the real home %q:\n%s", secretHome, got)
	}

	// The write that "succeeded" must have gone to the real project dir.
	if b, err := os.ReadFile(filepath.Join(projectDir, "newfile.txt")); err != nil {
		t.Errorf("project-dir write did not reach the host: %v", err)
	} else if strings.TrimSpace(string(b)) != "written-by-sandbox" {
		t.Errorf("project-dir file content = %q", b)
	}
	// The blocked write must not have touched the host /etc.
	if _, err := os.Stat("/etc/cordon-probe"); err == nil {
		t.Error("host /etc/cordon-probe exists — sandbox wrote outside the project dir")
		_ = os.Remove("/etc/cordon-probe")
	}
}

// pathForwardToolDir creates a directory holding one executable script, in a
// location that is (a) outside roSystemDirs and defaultPath, so it exercises
// the actual gap, and (b) NOT under /tmp — the sandbox mounts a fresh, empty
// tmpfs over /tmp (setupRootfs step 6) *after* the PATH-forwarding binds
// (step 3), so anything nested under /tmp would be shadowed by that later
// mount and this test would pass or fail for the wrong reason. /var/tmp is a
// distinct top-level directory the /tmp tmpfs mount never touches.
func pathForwardToolDir(t *testing.T, name, script string) string {
	t.Helper()
	const base = "/var/tmp"
	if _, err := os.Stat(base); err != nil {
		t.Skipf("no %s on this host: %v", base, err)
	}
	dir, err := os.MkdirTemp(base, "cordon-path-forward-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestRun_ForwardsCallerPathDirectoryOutsideSystemDirs is the direct proof
// for features/env-path-forwarding/intent.md's first Done item: a binary
// outside today's fixed roSystemDirs set, but on the caller's own PATH,
// resolves and runs inside the sandbox. Before this feature, Command[0]
// resolution (runChild's exec.LookPath against the sandbox PATH) could never
// find this binary at all — TestRun_CommandNotFoundExitsWith127 is the
// pre-existing proof of that failure mode for an unresolvable command.
func TestRun_ForwardsCallerPathDirectoryOutsideSystemDirs(t *testing.T) {
	requireUserNS(t)

	toolDir := pathForwardToolDir(t, "cordon-path-forward-probe", "#!/bin/sh\necho FORWARDED_TOOL_RAN\n")
	t.Setenv("PATH", toolDir+":"+os.Getenv("PATH"))

	var out bytes.Buffer
	res, err := sandbox.Run(sandbox.Spec{
		Command:    []string{"cordon-path-forward-probe"},
		ProjectDir: t.TempDir(),
		Stdout:     &out,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d, output:\n%s", res.ExitCode, out.String())
	}
	if !strings.Contains(out.String(), "FORWARDED_TOOL_RAN") {
		t.Fatalf("tool from forwarded PATH directory did not run; output:\n%s", out.String())
	}
}

// TestRun_ForkedChildResolvesToolFromForwardedPath is the setup-node-shaped
// scenario from features/env-path-forwarding/intent.md: not the top-level
// wrapped command itself, but a process *it forks* (the way `npm` forks
// `node`, or a postinstall script invokes `node` by bare name) resolving a
// tool via a PATH entry outside every directory Cordon bind-mounted before
// this feature — the actions/setup-node case that motivated it, where node
// lives under a CI tool-cache path outside /usr entirely.
func TestRun_ForkedChildResolvesToolFromForwardedPath(t *testing.T) {
	requireUserNS(t)

	toolDir := pathForwardToolDir(t, "node", "#!/bin/sh\necho NODE_RAN\n")
	t.Setenv("PATH", toolDir+":"+os.Getenv("PATH"))

	var out bytes.Buffer
	res, err := sandbox.Run(sandbox.Spec{
		// The wrapped command is /bin/sh (resolved via roSystemDirs,
		// unaffected by this feature); it, in turn, resolves "node" by bare
		// name against its own inherited PATH (childEnv's Envp) — the same
		// resolution shape a forked lifecycle script uses.
		Command:    []string{"/bin/sh", "-c", "node"},
		ProjectDir: t.TempDir(),
		Stdout:     &out,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d, output:\n%s", res.ExitCode, out.String())
	}
	if !strings.Contains(out.String(), "NODE_RAN") {
		t.Fatalf("forked child did not resolve tool via forwarded PATH; output:\n%s", out.String())
	}
}

// TestRun_DefaultPathResolutionUnaffected is the no-regression proof: with
// the caller's PATH left at whatever this test process already has (no
// unusual entries deliberately added), resolving a command by bare name
// against the sandbox's baseline PATH still works exactly as before this
// feature — additive forwarding must never shrink or reorder the existing
// resolvable set.
func TestRun_DefaultPathResolutionUnaffected(t *testing.T) {
	requireUserNS(t)

	var out bytes.Buffer
	res, err := sandbox.Run(sandbox.Spec{
		Command:    []string{"sh", "-c", "echo BASELINE_OK"},
		ProjectDir: t.TempDir(),
		Stdout:     &out,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d, output:\n%s", res.ExitCode, out.String())
	}
	if !strings.Contains(out.String(), "BASELINE_OK") {
		t.Fatalf("baseline bare-name PATH resolution regressed; output:\n%s", out.String())
	}
}

func TestRun_TmpIsWritableAndEphemeral(t *testing.T) {
	requireUserNS(t)

	// A file on the host /tmp that the sandbox must NOT see.
	hostFile, err := os.CreateTemp("/tmp", "cordon-host-tmp-")
	if err != nil {
		t.Fatal(err)
	}
	hostFile.Close()
	defer os.Remove(hostFile.Name())

	insidePath := "/tmp/cordon-write-probe"
	script := strings.Join([]string{
		`echo ok > ` + insidePath + ` && cat ` + insidePath, // /tmp is writable
		`test -e "` + hostFile.Name() + `" && echo HOST_TMP_VISIBLE || echo HOST_TMP_HIDDEN`,
	}, "\n")

	var out bytes.Buffer
	res, err := sandbox.Run(sandbox.Spec{
		Command:    []string{"/bin/sh", "-c", script},
		ProjectDir: t.TempDir(),
		Stdout:     &out,
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Run: err=%v exit=%d out=%q", err, res.ExitCode, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "ok") {
		t.Errorf("/tmp not writable inside sandbox; output=%q", got)
	}
	if !strings.Contains(got, "HOST_TMP_HIDDEN") {
		t.Errorf("host /tmp is visible inside sandbox; output=%q", got)
	}
	// Nothing the sandbox wrote to /tmp reaches the host.
	if _, err := os.Stat(insidePath); err == nil {
		t.Errorf("sandbox /tmp write leaked to host at %s", insidePath)
		_ = os.Remove(insidePath)
	}
}
