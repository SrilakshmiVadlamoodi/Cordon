//go:build linux

package syscallcapture_test

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/SrilakshmiVadlamoodi/cordon/internal/syscallcapture"
)

// helperEnvVar, when set, tells this same test binary to act as the
// traced program instead of running the test suite: open a known file
// and connect to a known address, then exit. Run needs a real external
// process to launch and ptrace, so the traced program has to be a
// distinct process — re-exec'ing this test binary is the same
// no-manual-fork idiom sandbox-runner's own tests already use for
// TestMain, applied to a purpose-built helper instead of the sandbox.
const helperEnvVar = "_CORDON_CAPTURE_TEST_HELPER"
const helperPathVar = helperEnvVar + "_PATH"
const helperAddrVar = helperEnvVar + "_ADDR"

// helperRelEnvVar selects a second helper mode: open a file by a
// *relative* path (cwd-relative, i.e. openat(AT_FDCWD, "name", ...) with
// a non-absolute pathname argument) instead of the absolute-path case
// above. This is what exercises handleOpenat's slow path — the
// PTRACE_SYSCALL exit-stop plus /proc/<pid>/fd readlink resolution —
// which the openat fast-path fix (DECISIONS.md 2026-09-04) left
// otherwise untested: real workloads observed so far never hit it (100%
// absolute paths, instrumented, not assumed), but the code is still
// live and security-relevant, so it needs its own direct test rather
// than relying on "nothing exercises it in practice."
const helperRelEnvVar = helperEnvVar + "_RELATIVE"
const helperRelDirVar = helperRelEnvVar + "_DIR"
const helperRelNameVar = helperRelEnvVar + "_NAME"

// helperThreadsEnvVar selects a third helper mode: open two different
// known files concurrently from two separate, runtime.LockOSThread'd
// goroutines. LockOSThread is the same primitive Run's own doc comments
// already cite for the reason ptrace state is per-OS-thread — a locked
// goroutine gets a dedicated OS thread for its lifetime, distinct from
// any other locked goroutine's, which is what deterministically forces
// real multi-threading here rather than hoping the scheduler happens to
// spread the two opens across threads on its own.
const helperThreadsEnvVar = helperEnvVar + "_THREADS"
const helperThreadsDirVar = helperThreadsEnvVar + "_DIR"

func TestMain(m *testing.M) {
	// If this process was re-exec'd by syscallcapture.Run as its own
	// tracee helper (installs the seccomp filter, then execve's into
	// whatever Argv0 names below), give it the chance to take over
	// before anything else runs.
	syscallcapture.MaybeRunTracee()

	if os.Getenv(helperThreadsEnvVar) != "" {
		runThreadsHelper()
		os.Exit(0)
	}
	if os.Getenv(helperRelEnvVar) != "" {
		runRelativeHelper()
		os.Exit(0)
	}
	if os.Getenv(helperEnvVar) != "" {
		runHelper()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runHelper is the traced program itself: exactly one openat (opening a
// known file) and exactly one connect (dialing a known address), nothing
// else that syscallcapture's filter would trap.
func runHelper() {
	f, err := os.Open(os.Getenv(helperPathVar))
	if err != nil {
		os.Exit(3)
	}
	f.Close()

	conn, err := net.Dial("tcp", os.Getenv(helperAddrVar))
	if err != nil {
		os.Exit(4)
	}
	conn.Close()
}

// runRelativeHelper chdirs into a known directory and opens a file by
// its bare (relative) name, so the openat it makes carries a
// non-absolute pathname argument — the one case handleOpenat's fast
// path explicitly declines to take.
func runRelativeHelper() {
	if err := os.Chdir(os.Getenv(helperRelDirVar)); err != nil {
		os.Exit(3)
	}
	f, err := os.Open(os.Getenv(helperRelNameVar)) // relative: no leading "/"
	if err != nil {
		os.Exit(4)
	}
	f.Close()
}

// threadHelperFiles are the two known files each of runThreadsHelper's
// two LockOSThread'd goroutines opens, one each.
var threadHelperFiles = []string{"thread-file-a", "thread-file-b"}

// runThreadsHelper opens two different known files concurrently from two
// separate OS threads (via runtime.LockOSThread), so the traced process
// makes openat calls from more than one Linux task while sharing a
// single Tgid — exactly the case the sibling-thread fix (DECISIONS.md
// 2026-09-04) exists for.
func runThreadsHelper() {
	dir := os.Getenv(helperThreadsDirVar)
	var wg sync.WaitGroup
	for _, name := range threadHelperFiles {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			f, err := os.Open(filepath.Join(dir, name))
			if err != nil {
				os.Exit(5)
			}
			f.Close()
		}(name)
	}
	wg.Wait()
}

// TestRun_CapturesOpenatAndConnect_ExactlyTwoEvents proves the capture
// engine reports exactly one openat for the known path and exactly one
// connect for the known address — no duplicates, nothing dropped.
//
// It does not assert on the *total* event count. The traced helper is
// this same Go test binary re-exec'd (see TestMain), and the Go runtime
// itself makes real openat calls before helper() ever runs — a THP size
// probe with no off-switch in the runtime source, plus (when the process
// runs inside a cgroup with a CPU quota, as it does in this sandboxed
// environment) GOMAXPROCS cgroup auto-detection reading
// /proc/<pid>/{cgroup,mountinfo} and /sys/fs/cgroup/.../cpu.max;
// GODEBUG=containermaxprocs=0 was tried against this Go 1.27 runtime and
// did not suppress it. Those are genuine syscalls the process actually
// made, correctly captured — proof the engine works, not a bug in it —
// so asserting a literal total of 2 would make this test flaky against
// runtime changes for a property this feature was never actually meant
// to guarantee. See DECISIONS.md and the Done checklist note in
// features/syscall-capture/intent.md.
func TestRun_CapturesOpenatAndConnect_ExactlyTwoEvents(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	knownPath := filepath.Join(t.TempDir(), "known-file")
	if err := os.WriteFile(knownPath, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	knownAddr := ln.Addr().String()

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	var events []syscallcapture.Event
	res, err := syscallcapture.Run(syscallcapture.Config{
		Argv0: self,
		Argv:  []string{self},
		Envp: []string{
			helperEnvVar + "=1",
			helperPathVar + "=" + knownPath,
			helperAddrVar + "=" + knownAddr,
		},
	}, func(e syscallcapture.Event) {
		events = append(events, e)
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.Signal != 0 {
		t.Fatalf("helper died by signal %v", res.Signal)
	}
	if res.ExitCode != 0 {
		t.Fatalf("helper exited %d, want 0", res.ExitCode)
	}

	var openCount, connectCount int
	for _, e := range events {
		switch {
		case e.Syscall == "openat" && e.Path == knownPath:
			openCount++
		case e.Syscall == "connect" && e.Addr == knownAddr:
			connectCount++
		}
	}
	if openCount != 1 {
		t.Errorf("openat events for %s = %d, want exactly 1 (events: %+v)", knownPath, openCount, events)
	}
	if connectCount != 1 {
		t.Errorf("connect events for %s = %d, want exactly 1 (events: %+v)", knownAddr, connectCount, events)
	}
}

// TestRun_CapturesOpenatViaRelativePath_ResolvesRealPath exercises
// handleOpenat's slow path directly: a relative-path openat must still
// be captured (not silently missed by the fast path's absolute-path
// check) and must still resolve to the real absolute path via the
// PTRACE_SYSCALL exit-stop + /proc/<pid>/fd readlink, not report the raw
// relative argument unresolved.
func TestRun_CapturesOpenatViaRelativePath_ResolvesRealPath(t *testing.T) {
	dir := t.TempDir()
	// Resolve symlinks defensively so the expected real path matches
	// exactly what readlink(/proc/<pid>/fd/<n>) returns — some temp-dir
	// setups place t.TempDir() under a symlinked base.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	const name = "relative-known-file"
	knownPath := filepath.Join(realDir, name)
	if err := os.WriteFile(knownPath, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	var events []syscallcapture.Event
	res, err := syscallcapture.Run(syscallcapture.Config{
		Argv0: self,
		Argv:  []string{self},
		Envp: []string{
			helperRelEnvVar + "=1",
			helperRelDirVar + "=" + realDir,
			helperRelNameVar + "=" + name,
		},
	}, func(e syscallcapture.Event) {
		events = append(events, e)
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.Signal != 0 {
		t.Fatalf("helper died by signal %v", res.Signal)
	}
	if res.ExitCode != 0 {
		t.Fatalf("helper exited %d, want 0", res.ExitCode)
	}

	var resolved, unresolved int
	for _, e := range events {
		if e.Syscall != "openat" {
			continue
		}
		switch e.Path {
		case knownPath:
			resolved++
		case name:
			// The fast path's signature: reports the raw argument
			// unresolved. Seeing this here would mean a relative-path
			// open wrongly took the fast path.
			unresolved++
		}
	}
	if unresolved != 0 {
		t.Errorf("openat event reported the raw relative path %q unresolved — "+
			"the relative-path fallback did not run exit-stop resolution", name)
	}
	if resolved != 1 {
		t.Fatalf("openat events resolved to %s = %d, want exactly 1 (events: %+v)", knownPath, resolved, events)
	}
}

// TestRun_CapturesOpenatFromSiblingOSThread is the regression test for
// DECISIONS.md 2026-09-04 "openat/connect/execve events from a traced
// process's other threads are silently dropped": a traced process that
// makes syscalls from more than one OS thread (same Tgid, different Tid
// — real Go programs like this test binary do this routinely, and so
// does Node.js via libuv's thread pool) must have events from *every*
// one of its threads captured, not just whichever one happens to be the
// thread-group leader. Before the fix, only one of the two opens below
// would have been reported — silently, with no error — because the
// dispatch loop only ever read the primary pid's own stops.
func TestRun_CapturesOpenatFromSiblingOSThread(t *testing.T) {
	dir := t.TempDir()
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	knownPaths := make(map[string]bool, len(threadHelperFiles))
	for _, name := range threadHelperFiles {
		p := filepath.Join(realDir, name)
		if err := os.WriteFile(p, []byte("hi"), 0o644); err != nil {
			t.Fatal(err)
		}
		knownPaths[p] = true
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	var events []syscallcapture.Event
	res, err := syscallcapture.Run(syscallcapture.Config{
		Argv0: self,
		Argv:  []string{self},
		Envp: []string{
			helperThreadsEnvVar + "=1",
			helperThreadsDirVar + "=" + realDir,
		},
	}, func(e syscallcapture.Event) {
		events = append(events, e)
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.Signal != 0 {
		t.Fatalf("helper died by signal %v", res.Signal)
	}
	if res.ExitCode != 0 {
		t.Fatalf("helper exited %d, want 0", res.ExitCode)
	}

	seen := map[string]int{}
	for _, e := range events {
		if e.Syscall == "openat" && knownPaths[e.Path] {
			seen[e.Path]++
		}
	}
	for p := range knownPaths {
		if seen[p] != 1 {
			t.Errorf("openat events for %s = %d, want exactly 1 (events: %+v)", p, seen[p], events)
		}
	}
}
