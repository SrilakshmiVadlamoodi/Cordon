//go:build linux && amd64

package syscallcapture

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// traceeEnvVar carries the JSON-encoded traceeConfig from Run into the
// re-exec'd /proc/self/exe tracee helper. Its presence is the sentinel
// MaybeRunTracee checks for — same idiom as sandbox.childEnvVar, one
// layer deeper: Run cannot inject code between the fork and the wrapped
// command's own exec (os/exec gives no such hook, and hand-rolling a
// fork() to get one is exactly what CLAUDE.md's "never fork manually"
// rule forbids), so instead a second, distinct re-exec of this same
// binary does the seccomp-filter install as ordinary post-exec Go code,
// then execve's into the real target itself. Seccomp filters are
// inherited across execve, so the filter installed here still applies
// once that final exec replaces this helper's image.
const traceeEnvVar = "_CORDON_TRACEE"

// tracedSyscalls is the exact set the seccomp-BPF filter traps via
// SECCOMP_RET_TRACE; everything else is SECCOMP_RET_ALLOW and never
// stops the tracee. This is what keeps overhead bounded to the ~3
// syscalls Cordon actually cares about instead of every syscall the
// wrapped command makes.
//
// Known gap: the filter does not check struct seccomp_data.arch, so it
// trusts the syscall-number namespace of whatever ABI the process is
// currently running under. A process that switches to a different
// syscall ABI mid-run (e.g. the x86-64 → i386 compat layer) could line
// up a traced number with an untraced syscall in the other ABI. Rootless
// namespaces here don't disable compat syscalls, so this is a real,
// documented, best-effort gap (INTENT.md §1), not a claimed guarantee.
var tracedSyscalls = []uint32{
	uint32(unix.SYS_OPENAT),
	uint32(unix.SYS_OPENAT2),
	uint32(unix.SYS_CONNECT),
	uint32(unix.SYS_EXECVE),
}

// traceeConfig is what the tracee helper needs to become the real
// wrapped command. It crosses the process boundary as JSON, same
// encoding choice as sandbox's childConfig.
type traceeConfig struct {
	Argv0 string
	Argv  []string
	Envp  []string
}

// Run launches cfg as a traced child, reports its openat/connect/execve
// calls to onEvent (which may be nil) as they happen, and blocks until
// it exits. The calling goroutine's OS thread becomes the ptrace tracer
// for the life of the call — ptrace is per-thread kernel state, so this
// requires runtime.LockOSThread (CLAUDE.md ground rule) and the thread
// is never unlocked afterward: by the time Run returns, the traced
// process is gone and there is nothing left to be a tracer of, so
// dedicating this thread for the remaining process lifetime costs
// nothing.
//
// Run is also this process's reaper for the duration of the call: any
// descendant that reparents here (e.g. an orphan the wrapped command
// backgrounds and then outlives) gets wait4'd so it cannot zombie. That
// reaping is unconditional — see the "Scope split" note in
// features/syscall-capture/intent.md — independent of the fact that only
// the one directly-launched child is actually traced this slice.
func Run(cfg Config, onEvent func(Event)) (Result, error) {
	runtime.LockOSThread()

	blob, err := json.Marshal(traceeConfig{Argv0: cfg.Argv0, Argv: cfg.Argv, Envp: cfg.Envp})
	if err != nil {
		return Result{}, fmt.Errorf("syscallcapture.Run: encoding tracee config: %w", err)
	}

	cmd := exec.Command("/proc/self/exe")
	cmd.Args = []string{"cordon-syscallcapture-tracee"}
	cmd.Env = []string{traceeEnvVar + "=" + string(blob)}
	// The tracee's stdio must be the real stdio the wrapped command sees
	// — os.Stdin/Stdout/Stderr are exactly that at this point in the
	// call chain (sandbox.runChild inherited them unchanged all the way
	// from sandbox.Run's Spec), and Cmd dup2's an *os.File directly with
	// no framing or buffering, matching what the old direct syscall.Exec
	// gave for free.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}

	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("syscallcapture.Run: starting tracee: %w", err)
	}
	pid := cmd.Process.Pid

	// PTRACE_TRACEME (set via SysProcAttr above) makes the kernel stop
	// the tracee with SIGTRAP right after its first execve — the exec
	// that starts *this* helper's own image — and before any of its Go
	// code runs. This is that stop.
	var ws syscall.WaitStatus
	if _, err := wait4Retry(pid, &ws, 0, nil); err != nil {
		return Result{}, fmt.Errorf("syscallcapture.Run: waiting for initial stop: %w", err)
	}
	if !ws.Stopped() {
		return Result{}, fmt.Errorf("syscallcapture.Run: tracee did not stop on launch (status %v)", ws)
	}

	// PTRACE_O_TRACEFORK/VFORK/CLONE do *not* extend event capture to the
	// process tree (that's features/syscall-capture-tree, deliberately
	// not built yet — DECISIONS.md 2026-09-04 "descendants must not
	// ENOSYS"). They exist purely so that when the seccomp filter below
	// — inherited by every descendant automatically, that part is not
	// optional — traps one of tracedSyscalls in a process we never
	// launched, a tracer is there to service it. Without a tracer
	// attached to that specific pid, SECCOMP_RET_TRACE doesn't skip
	// quietly: the kernel refuses to run the syscall at all and returns
	// -ENOSYS, which broke every external command (readlink, cat, grep)
	// any traced shell forked before this was added. Auto-attached
	// descendants are resumed immediately, unread and unreported, by the
	// wpid-not-yet-known branch in the loop below.
	opts := unix.PTRACE_O_TRACESECCOMP | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_EXITKILL |
		unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK | unix.PTRACE_O_TRACECLONE
	if err := syscall.PtraceSetOptions(pid, opts); err != nil {
		return Result{}, fmt.Errorf("syscallcapture.Run: PTRACE_SETOPTIONS: %w", err)
	}
	if err := syscall.PtraceCont(pid, 0); err != nil {
		return Result{}, fmt.Errorf("syscallcapture.Run: resuming tracee: %w", err)
	}

	// seenLaunchExec tracks whether we've passed the tracee helper's own
	// exec into the real wrapped command yet. That exec is captured by
	// the same seccomp filter as any other (it's a real execve, and the
	// filter has already been installed by then) — but it is Cordon's
	// own launch mechanics, not something the sandboxed program did, so
	// it is suppressed rather than reported. Everything after it is
	// genuine (e.g. a shell's `exec` builtin replacing itself again).
	seenLaunchExec := false
	// known tracks which pids/tids have already had their attach-stop
	// consumed. Every wpid we haven't seen yet is, by construction, a
	// just-auto-attached task reporting its first stop — either a new
	// forked process, or a new OS thread of a process we already know
	// about (see observed below for telling those apart).
	known := map[int]bool{pid: true}
	// observed tracks which known pids/tids actually get their syscalls
	// read and reported, vs. auto-attached-and-released only. A wpid
	// joins this set iff, at its first stop, its Tgid equals pid — i.e.
	// it is a sibling OS thread of the very process being traced, not a
	// separate forked process (see DECISIONS.md 2026-09-04 "openat/
	// connect/execve events from a traced process's other threads are
	// silently dropped"). pid is seeded here directly, with no /proc
	// read: it is the pid os/exec's own fork+exec returned for a freshly
	// created process, and a fresh process's PID always equals its own
	// Tgid — that identity holds for pid's entire lifetime regardless of
	// how many times it execve's (image replacement never changes
	// PID/TID/Tgid), so no read-based check is needed, or possible to
	// race, for the primary itself. Every *other* wpid's Tgid is read
	// from /proc/<wpid>/status once, at first sight — sameThreadGroup
	// defaults to "not a sibling thread" if that read fails (e.g. the
	// task already exited), which is the safe direction: a false
	// negative here just means "not observed," matching prior behavior;
	// a false positive would mean misattributing another process's
	// events, which this default rules out.
	observed := map[int]bool{pid: true}
	// unobservedTgids collects the distinct thread-group ids of every
	// task we auto-attach but never read — i.e. separate processes the
	// traced program forked (and their own threads, folded in by Tgid so
	// a forked process with its own thread pool counts once). Its size
	// becomes Result.UnobservedDescendants, which behaviorreport turns
	// into the report's "N other processes were launched and not traced"
	// line — a real, per-run statement of a real gap, not a generic
	// disclaimer.
	unobservedTgids := map[int]bool{}
	var result Result

	for {
		var ws syscall.WaitStatus
		wpid, err := wait4Retry(-1, &ws, 0, nil)
		if err != nil {
			return Result{}, fmt.Errorf("syscallcapture.Run: wait4: %w", err)
		}

		switch {
		case ws.Exited(), ws.Signaled():
			// This *is* wpid's own exit stop — wait4 reported WIFEXITED
			// or WIFSIGNALED for this specific pid/tid, meaning the
			// kernel will not reuse it until it's reaped (already done,
			// by this very wait4 call) and, eventually, PID-recycled.
			// Deleting here, at the exit stop itself rather than at some
			// later "done with its events" point, is what makes the
			// PID-reuse defense on observed correct: a later wpid
			// carrying a recycled number starts other than in either
			// map and is reclassified from scratch by its own Tgid, not
			// left holding a stale prior tenant's classification.
			delete(known, wpid)
			delete(observed, wpid)
			if wpid == pid {
				if ws.Exited() {
					result = Result{ExitCode: ws.ExitStatus()}
				} else {
					result = Result{Signal: ws.Signal()}
				}
				result.UnobservedDescendants = len(unobservedTgids)
				drainExitedDescendants()
				return result, nil
			}
			// A reparented/auto-attached descendant exited; reaping it
			// via wait4 above is all this slice owes it (attributing
			// events to it is features/syscall-capture-tree).

		case ws.Stopped():
			if !known[wpid] {
				// First stop for a new task (fork/vfork/clone auto-attach
				// delivers this as an ordinary signal-delivery-stop,
				// typically SIGSTOP or SIGTRAP — either way it must be
				// *swallowed*, not re-injected: re-delivering SIGSTOP
				// here would leave it group-stopped instead of running).
				// Set the same options so *its* descendants are
				// auto-attached too, classify it (sibling thread of the
				// traced process vs. a separate process — see observed's
				// doc comment), then let it run.
				known[wpid] = true
				_ = syscall.PtraceSetOptions(wpid, opts)
				switch tgid := threadGroupOf(wpid); {
				case tgid == pid:
					// A sibling OS thread of the traced process — observe
					// it exactly as the primary (DECISIONS.md 2026-09-04).
					observed[wpid] = true
				case tgid > 0:
					// A separate forked process (or one of its own
					// threads). Not traced this slice; recorded so the
					// report can say so. Note this counts *every* distinct
					// forked thread-group, including short-lived ones the
					// wrapped program's own runtime spawns for its own
					// reasons (e.g. Go's one-time clone(CLONE_PIDFD)
					// support probe on first os/exec) — the number is an
					// honest "processes we saw and did not trace", not a
					// curated "subprocesses you asked for".
					unobservedTgids[tgid] = true
				}
				_ = syscall.PtraceCont(wpid, 0)
				continue
			}

			sig := ws.StopSignal()
			switch {
			case sig == syscall.SIGTRAP && ws.TrapCause() == unix.PTRACE_EVENT_SECCOMP:
				if observed[wpid] {
					// wpid is either the primary or a sibling OS thread
					// of it (same Tgid) — read and report its syscall
					// exactly as the primary's own. No new identity
					// concept: Event carries no per-task field, so this
					// naturally folds into the same reporting the
					// primary's own syscalls already get, matching what
					// "the traced process" should mean in the first
					// place.
					handleSeccompStop(wpid, onEvent, &seenLaunchExec)
				} else {
					// A separate, unobserved process (or a thread of
					// one) — resume without reading it (see the
					// auto-attach comment above).
					_ = syscall.PtraceCont(wpid, 0)
				}
			case sig == syscall.SIGTRAP && ws.TrapCause() != 0:
				// PTRACE_EVENT_EXEC, or PTRACE_EVENT_FORK/VFORK/CLONE
				// arriving on the *parent* side of a fork this stop
				// belongs to — informational either way: the seccomp
				// stop already captured what mattered, and the new
				// child's own first stop (handled above) is what
				// actually needs a response.
				_ = syscall.PtraceCont(wpid, 0)
			case sig == syscall.SIGTRAP:
				_ = syscall.PtraceCont(wpid, 0)
			default:
				// A genuine signal delivery. Re-inject it so normal
				// signal semantics hold for every traced pid, not just
				// the primary one — for the primary tracee this is also
				// what makes faithful signal reporting possible at all:
				// it is PID 2, not PID 1, so unlike the direct-exec
				// design it replaced (DECISIONS.md 2026-09-01), it is
				// not immune to its own signals.
				_ = syscall.PtraceCont(wpid, int(sig))
			}
		}
	}
}

// drainExitedDescendants reaps any already-exited children without
// blocking, best-effort, once the traced process itself is accounted
// for. It does not wait for still-running descendants: when this
// process (PID 1 of its namespace) exits right after, the kernel tears
// down the whole PID namespace anyway.
func drainExitedDescendants() {
	for {
		var ws syscall.WaitStatus
		wpid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if err != nil || wpid <= 0 {
			return
		}
	}
}

// threadGroupOf reads wpid's own Tgid out of /proc, or returns 0 if that
// read fails (e.g. wpid already exited). Callers treat 0 as "unknown" and
// default it to the safe direction — see observed's doc comment in Run
// for why an unclassified task is "not a sibling thread" rather than the
// other way around, and Result.UnobservedDescendants' doc comment for
// why a 0 here makes the descendant count a lower bound.
func threadGroupOf(wpid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", wpid))
	if err != nil {
		return 0
	}
	const prefix = "Tgid:"
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		tgid, err := strconv.Atoi(strings.TrimSpace(line[len(prefix):]))
		if err != nil {
			return 0
		}
		return tgid
	}
	return 0
}

// handleSeccompStop reads the trapped syscall's number and arguments and
// dispatches to the per-syscall handler, each of which is responsible
// for resuming the tracee (via PtraceCont, or PtraceSyscall+PtraceCont
// for openat's exit-time fd resolution) before returning.
func handleSeccompStop(pid int, onEvent func(Event), seenLaunchExec *bool) {
	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		_ = syscall.PtraceCont(pid, 0)
		return
	}

	switch regs.Orig_rax {
	case uint64(unix.SYS_OPENAT), uint64(unix.SYS_OPENAT2):
		handleOpenat(pid, &regs, onEvent)
	case uint64(unix.SYS_CONNECT):
		handleConnect(pid, &regs, onEvent)
	case uint64(unix.SYS_EXECVE):
		handleExecve(pid, &regs, onEvent, seenLaunchExec)
	default:
		_ = syscall.PtraceCont(pid, 0)
	}
}

// handleOpenat resolves the "fds → real paths" half of the intent. In
// general the raw pathname argument can be relative, dirfd-relative, or
// point through a symlink, so the path that matters is read back from
// the fd openat actually returned, via /proc/<pid>/fd/<n> — which
// requires letting the syscall complete first, via PTRACE_SYSCALL (rather
// than PTRACE_CONT) from the seccomp stop, at the cost of a second
// ptrace round trip for this one call (every syscall in between still
// runs untraced either way).
//
// Fast path: an absolute rawPath needs none of that — there is no cwd or
// dirfd to resolve against, so the raw argument already is a real path,
// with one documented exception (DECISIONS.md, "openat fast path for
// absolute paths"): a symlink in the path, which the fast path reports
// unresolved rather than paying the exit-stop to canonicalize. Measured
// on a real install (69-package `express` + a forked postinstall): 100%
// of openat calls used absolute paths, and of the successful ones, 94.4%
// had raw == resolved already — the symlink case is real but rare, and
// every observed instance was OS/runtime plumbing (/proc/self/*,
// /etc/resolv.conf, glibc .so versioning), never a project file. This is
// not a new category of imprecision: a *failed* open already reports
// rawPath unmodified (no fd exists to resolve), so the fast path extends
// that same already-accepted behavior to the whole absolute-path case
// instead of paying for an exit-stop whose answer is usually already
// known from the entry args alone.
//
// This trades detection precision, not isolation: Event.Path only feeds
// the (best-effort, INTENT.md §1) behavior report — it has no bearing on
// what the mount/namespace sandbox actually confines. The hard boundary
// (isolation) is unchanged by this function; the soft one (how precisely
// an observed path gets reported) is what's being narrowed here.
func handleOpenat(pid int, regs *syscall.PtraceRegs, onEvent func(Event)) {
	rawPath, _ := readCString(pid, regs.Rsi)

	if len(rawPath) > 0 && rawPath[0] == '/' {
		if onEvent != nil {
			onEvent(Event{Syscall: "openat", Path: rawPath})
		}
		_ = syscall.PtraceCont(pid, 0)
		return
	}

	if err := syscall.PtraceSyscall(pid, 0); err != nil {
		_ = syscall.PtraceCont(pid, 0)
		return
	}
	var ws syscall.WaitStatus
	if _, err := wait4Retry(pid, &ws, 0, nil); err != nil {
		return
	}
	if !ws.Stopped() {
		// The tracee died mid-syscall (or exited); nothing left to
		// resume, and the outer loop's next wait4 will pick up its exit.
		if ws.Exited() || ws.Signaled() {
			// Re-deliver this status to the outer loop by not consuming
			// it silently: nothing to do here, the process is gone.
		}
		return
	}
	if ws.StopSignal() != syscall.SIGTRAP {
		// A real signal landed exactly between this syscall's entry and
		// exit. Re-inject it and skip fd resolution rather than eating
		// the signal — rare, but correctness on signal delivery matters
		// more than completeness of this one path resolution.
		if onEvent != nil {
			onEvent(Event{Syscall: "openat", Path: rawPath})
		}
		_ = syscall.PtraceCont(pid, int(ws.StopSignal()))
		return
	}

	var exitRegs syscall.PtraceRegs
	path := rawPath
	if err := syscall.PtraceGetRegs(pid, &exitRegs); err == nil {
		if fd := int64(exitRegs.Rax); fd >= 0 {
			if real, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd)); err == nil {
				path = real
			}
		}
		// fd < 0: the open failed (negative errno in Rax); rawPath is
		// the best we can report, per INTENT.md §1 — no fd to resolve.
	}
	if onEvent != nil {
		onEvent(Event{Syscall: "openat", Path: path})
	}
	_ = syscall.PtraceCont(pid, 0)
}

// handleConnect resolves the raw sockaddr argument into a best-effort
// "ip:port" string. No exit-stop is needed — connect's arguments are
// fully known at entry, unlike openat's fd.
func handleConnect(pid int, regs *syscall.PtraceRegs, onEvent func(Event)) {
	addrLen := regs.Rdx
	if addrLen > 128 {
		addrLen = 128 // sockaddr_in/in6 both fit well inside this
	}
	buf := readMem(pid, regs.Rsi, int(addrLen))
	if onEvent != nil {
		onEvent(Event{Syscall: "connect", Addr: formatSockaddr(buf)})
	}
	_ = syscall.PtraceCont(pid, 0)
}

// handleExecve reports every execve except the tracee helper's own first
// one (see seenLaunchExec's doc comment on Run).
func handleExecve(pid int, regs *syscall.PtraceRegs, onEvent func(Event), seenLaunchExec *bool) {
	path, _ := readCString(pid, regs.Rdi)
	if !*seenLaunchExec {
		*seenLaunchExec = true
	} else if onEvent != nil {
		onEvent(Event{Syscall: "execve", Path: path, Argv: readArgv(pid, regs.Rsi)})
	}
	_ = syscall.PtraceCont(pid, 0)
}

// installSeccompFilter installs the BPF program that traps exactly
// tracedSyscalls via SECCOMP_RET_TRACE and allows everything else. It
// must run in the tracee helper, after PTRACE_TRACEME has already taken
// effect (so this process is one the tracer will actually see stops
// from) and before the exec into the real wrapped command (so the
// filter — inherited across execve — is in place for that command's
// entire run).
func installSeccompFilter() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}

	n := len(tracedSyscalls)
	prog := make([]unix.SockFilter, 0, n+3)
	// Load the syscall number: struct seccomp_data{ int nr; ... }, nr at
	// offset 0.
	prog = append(prog, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0})
	// One comparison per traced syscall. jt jumps forward to the RET_TRACE
	// instruction (computed below); jf always falls through to the next
	// comparison, and the last one's fallthrough lands exactly on
	// RET_ALLOW, so no jf ever needs to be non-zero.
	for i, sc := range tracedSyscalls {
		prog = append(prog, unix.SockFilter{
			Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			Jt:   uint8(n - i),
			Jf:   0,
			K:    sc,
		})
	}
	prog = append(prog,
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_TRACE},
	)

	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, uintptr(unix.SECCOMP_MODE_FILTER), uintptr(unsafe.Pointer(&fprog)), 0, 0); err != nil {
		return fmt.Errorf("PR_SET_SECCOMP: %w", err)
	}
	return nil
}

// MaybeRunTracee takes over the process when it has been re-exec'd by
// Run as the tracee helper; otherwise it returns immediately. Every
// entrypoint that might be reached this way (main(), test TestMain
// funcs) must call it before doing anything else — same contract as
// sandbox.MaybeRunChild, one layer deeper in the re-exec chain.
func MaybeRunTracee() {
	blob := os.Getenv(traceeEnvVar)
	if blob == "" {
		return // ordinary process
	}
	os.Unsetenv(traceeEnvVar)

	var cfg traceeConfig
	if err := json.Unmarshal([]byte(blob), &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "cordon tracee: decoding config: %v\n", err)
		os.Exit(125)
	}

	if err := installSeccompFilter(); err != nil {
		fmt.Fprintf(os.Stderr, "cordon tracee: %v\n", err)
		os.Exit(125)
	}

	// This execve is itself one of tracedSyscalls, trapped by the filter
	// just installed, and reported to Run as the (suppressed) launch
	// exec. syscall.Exec replaces this process's image outright — no Go
	// code survives it — exactly like sandbox.runChild's old direct exec,
	// just moved one layer down.
	err := syscall.Exec(cfg.Argv0, cfg.Argv, cfg.Envp)
	fmt.Fprintf(os.Stderr, "cordon tracee: exec %s: %v\n", cfg.Argv0, err)
	os.Exit(126)
}

// wait4Retry wraps syscall.Wait4, retrying on EINTR — a tracer doing
// blocking waits is exactly the kind of long syscall a stray signal can
// interrupt.
func wait4Retry(pid int, ws *syscall.WaitStatus, options int, ru *syscall.Rusage) (int, error) {
	for {
		wpid, err := syscall.Wait4(pid, ws, options, ru)
		if err == syscall.EINTR {
			continue
		}
		return wpid, err
	}
}

// readMem reads up to n bytes at addr from the tracee's address space via
// /proc/<pid>/mem. Short reads and errors are tolerated (best-effort per
// INTENT.md §1) — the caller gets whatever bytes were read.
func readMem(pid int, addr uint64, n int) []byte {
	if addr == 0 || n <= 0 {
		return nil
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil
	}
	defer mem.Close()
	buf := make([]byte, n)
	read, _ := mem.ReadAt(buf, int64(addr))
	return buf[:read]
}

// readCString reads a NUL-terminated string from the tracee's address
// space starting at addr, capped at maxCStringLen to bound a runaway
// read against a corrupt or adversarial pointer.
const maxCStringLen = 4096

func readCString(pid int, addr uint64) (string, error) {
	if addr == 0 {
		return "", nil
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return "", err
	}
	defer mem.Close()

	const chunk = 256
	var out []byte
	tmp := make([]byte, chunk)
	off := int64(addr)
	for len(out) < maxCStringLen {
		n, err := mem.ReadAt(tmp, off)
		if n > 0 {
			if i := indexByte(tmp[:n], 0); i >= 0 {
				return string(append(out, tmp[:i]...)), nil
			}
			out = append(out, tmp[:n]...)
			off += int64(n)
		}
		if err != nil {
			break
		}
	}
	return string(out), nil
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// readArgv reads a NULL-terminated array of char* pointers (execve's
// argv) starting at addr, resolving each one via readCString. maxArgs
// bounds a runaway/corrupt array the same way maxCStringLen bounds a
// single string.
const maxArgs = 128

func readArgv(pid int, addr uint64) []string {
	if addr == 0 {
		return nil
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil
	}
	defer mem.Close()

	var argv []string
	ptrBuf := make([]byte, 8)
	for i := 0; i < maxArgs; i++ {
		if n, err := mem.ReadAt(ptrBuf, int64(addr)+int64(i)*8); n != 8 || err != nil {
			break
		}
		ptr := binary.LittleEndian.Uint64(ptrBuf)
		if ptr == 0 {
			break
		}
		s, err := readCString(pid, ptr)
		if err != nil {
			break
		}
		argv = append(argv, s)
	}
	return argv
}

// formatSockaddr turns a raw struct sockaddr_in/in6 into "ip:port" —
// best-effort per Event's doc comment, not a resolved hostname.
func formatSockaddr(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	family := binary.LittleEndian.Uint16(b[0:2])
	switch family {
	case unix.AF_INET:
		if len(b) < 8 {
			return ""
		}
		port := binary.BigEndian.Uint16(b[2:4])
		ip := net.IP(b[4:8])
		return fmt.Sprintf("%s:%d", ip.String(), port)
	case unix.AF_INET6:
		if len(b) < 28 {
			return ""
		}
		port := binary.BigEndian.Uint16(b[2:4])
		ip := net.IP(b[8:24])
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		return fmt.Sprintf("unknown-address-family-%d", family)
	}
}
