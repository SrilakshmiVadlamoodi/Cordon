//go:build linux

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/SrilakshmiVadlamoodi/cordon/internal/syscallcapture"
)

// childEnvVar carries the JSON-encoded childConfig from the parent Run call
// into the re-exec'd /proc/self/exe child. Its presence in the environment
// is the sentinel MaybeRunChild checks for.
const childEnvVar = "_CORDON_CHILD"

// defaultPath is the PATH handed to the wrapped command. The caller's own
// environment is not forwarded (see childEnv); a deliberate forwarding
// policy is a later concern.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// namespaceFlags is the set of namespaces the child is cloned into.
// CLONE_NEWUSER must ride in the same clone() as the rest: an unprivileged
// process only gains the namespace-scoped CAP_SYS_ADMIN that the other flags
// require by creating a user namespace first (DECISIONS.md 2026-09-01).
const namespaceFlags = syscall.CLONE_NEWUSER |
	syscall.CLONE_NEWNS |
	syscall.CLONE_NEWPID |
	syscall.CLONE_NEWNET |
	syscall.CLONE_NEWUTS |
	syscall.CLONE_NEWIPC

// roSystemDirs are bind-mounted read-only into the new root so the wrapped
// command can actually execute (shared libraries, the shell, coreutils,
// resolver config) without being able to modify the host.
var roSystemDirs = []string{"/bin", "/sbin", "/lib", "/lib64", "/usr", "/etc"}

// devNodes are the character devices a realistic build touches. Everything
// else under /dev is absent.
var devNodes = []string{"null", "zero", "full", "random", "urandom", "tty"}

// childConfig is everything the in-namespace child needs. It crosses the
// process boundary as JSON in childEnvVar.
type childConfig struct {
	Command    []string
	ProjectDir string
	NewRoot    string // empty mountpoint dir on the host; the child mounts a tmpfs here
}

// Run executes spec.Command inside a fresh set of Linux namespaces with an
// isolated root filesystem, and reports how it exited.
func Run(spec Spec) (Result, error) {
	if len(spec.Command) == 0 {
		return Result{}, errors.New("sandbox.Run: spec.Command is empty")
	}
	projectDir, err := filepath.Abs(spec.ProjectDir)
	if err != nil {
		return Result{}, fmt.Errorf("sandbox.Run: resolving project dir: %w", err)
	}
	if fi, statErr := os.Stat(projectDir); statErr != nil || !fi.IsDir() {
		return Result{}, fmt.Errorf("sandbox.Run: project dir %q is not an existing directory", projectDir)
	}

	// A bare mountpoint on the host for the child's new-root tmpfs. The
	// tmpfs itself lives only in the child's mount namespace; we just clean
	// up the empty directory afterwards.
	newRoot, err := os.MkdirTemp("", "cordon-root-")
	if err != nil {
		return Result{}, fmt.Errorf("sandbox.Run: creating newroot mountpoint: %w", err)
	}
	defer os.RemoveAll(newRoot)

	blob, err := json.Marshal(childConfig{
		Command:    spec.Command,
		ProjectDir: projectDir,
		NewRoot:    newRoot,
	})
	if err != nil {
		return Result{}, fmt.Errorf("sandbox.Run: encoding child config: %w", err)
	}

	// Re-exec ourselves. The child re-enters this binary, MaybeRunChild
	// sees the sentinel, and it takes over inside the new namespaces.
	cmd := exec.Command("/proc/self/exe")
	cmd.Args = []string{"cordon-sandbox-child"}
	cmd.Env = append(os.Environ(), childEnvVar+"="+string(blob))
	cmd.Stdin = orReader(spec.Stdin, os.Stdin)
	cmd.Stdout = orWriter(spec.Stdout, os.Stdout)
	cmd.Stderr = orWriter(spec.Stderr, os.Stderr)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: namespaceFlags,
		// Map our host UID/GID to root inside the new user namespace.
		// Because these are set, the runtime also writes
		// /proc/<pid>/setgroups = "deny" before gid_map, which the kernel
		// requires before an unprivileged process may write gid_map
		// (Linux 3.19+, CVE-2014-8989).
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}

	runErr := cmd.Run()

	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return Result{}, fmt.Errorf("sandbox.Run: missing wait status (run error: %v)", runErr)
	}
	if ws.Signaled() {
		return Result{ExitCode: -1}, nil
	}
	// A non-zero exit surfaces as *exec.ExitError; that is a normal Result,
	// not a Run failure. Anything else means we never launched the child.
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return Result{}, fmt.Errorf("sandbox.Run: launching sandbox child: %w", runErr)
		}
	}
	return Result{ExitCode: ws.ExitStatus()}, nil
}

// MaybeRunChild takes over the process when it has been re-exec'd as the
// in-namespace child; otherwise it returns immediately. main() and TestMain
// must call it before doing anything else.
func MaybeRunChild() {
	blob := os.Getenv(childEnvVar)
	if blob == "" {
		return // ordinary parent process
	}

	var cfg childConfig
	if err := json.Unmarshal([]byte(blob), &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "cordon child: decoding config: %v\n", err)
		os.Exit(125)
	}
	runChild(cfg) // never returns
}

// runChild executes inside the new namespaces: it builds the isolated root
// filesystem, then hands off to syscallcapture as PID 1 of the namespace.
//
// It used to end in a direct syscall.Exec of the wrapped command, making
// that command itself PID 1 — see DECISIONS.md 2026-09-01 for why that
// made signal delivery to it unreliable, and DECISIONS.md 2026-09-04 for
// why this changed and what it costs. This process now stays alive for
// the wrapped command's whole run: syscallcapture.Run launches it as a
// real child (PID 2) via ptrace's PTRACE_TRACEME, so runChild becomes its
// tracer and reaper rather than replacing itself with it.
func runChild(cfg childConfig) {
	// Keep the sentinel out of the wrapped command's environment.
	os.Unsetenv(childEnvVar)

	if err := setupRootfs(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "cordon child: sandbox setup: %v\n", err)
		os.Exit(125)
	}

	// Resolve the command against the sandbox PATH, not the parent's.
	os.Setenv("PATH", defaultPath)
	argv0, err := exec.LookPath(cfg.Command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cordon child: %v\n", err)
		os.Exit(127)
	}

	res, err := syscallcapture.Run(syscallcapture.Config{
		Argv0: argv0,
		Argv:  cfg.Command,
		Envp:  childEnv(cfg),
	}, nil) // no event consumer yet — behavior-report is a later feature
	if err != nil {
		fmt.Fprintf(os.Stderr, "cordon child: %v\n", err)
		os.Exit(125)
	}

	if res.Signal != 0 {
		// The wrapped command (PID 2, not PID 1 — unlike the old direct
		// exec, it is not immune to its own signals) died by signal.
		// Die by the same signal ourselves, as PID 1, so the outer
		// wait4 in sandbox.Run sees a faithful Signaled() status. We
		// never call signal.Notify for anything, so this signal's
		// default disposition (terminate) still applies to us.
		syscall.Kill(os.Getpid(), res.Signal)
		// Should not be reached for a genuinely fatal signal; fall back
		// to a conventional exit code rather than hang if it somehow is.
		os.Exit(128 + int(res.Signal))
	}
	os.Exit(res.ExitCode)
}

// setupRootfs constructs the sandbox root filesystem in the child's mount
// namespace and pivot_root's into it. Ordering matters throughout; see the
// step comments.
func setupRootfs(cfg childConfig) error {
	const oldRootName = ".oldroot"

	// 1. Make every mount in this namespace private, so nothing we do
	//    propagates back to the host. This is also a precondition for
	//    pivot_root, which refuses to operate on shared mounts.
	if err := mnt("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}

	// 2. A fresh tmpfs is the empty starting tree for the new root. It has
	//    to be a mount point in its own right for pivot_root to accept it.
	if err := mnt("tmpfs", cfg.NewRoot, "tmpfs", syscall.MS_NOSUID, "mode=0755"); err != nil {
		return fmt.Errorf("tmpfs on new root: %w", err)
	}

	// 3. Read-only binds of the host system directories. The RO flag is
	//    silently ignored on the initial bind and only takes effect on a
	//    follow-up MS_REMOUNT|MS_BIND (a documented kernel quirk).
	for _, dir := range roSystemDirs {
		if _, err := os.Lstat(dir); err != nil {
			continue // e.g. no /lib64 on arm64
		}
		target := filepath.Join(cfg.NewRoot, dir)
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		if err := mnt(dir, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			return fmt.Errorf("bind %s: %w", dir, err)
		}
		if err := mnt("", target, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_REC|syscall.MS_RDONLY, ""); err != nil {
			return fmt.Errorf("remount %s read-only: %w", dir, err)
		}
	}

	// 4. A private procfs for this PID + mount namespace.
	if err := os.MkdirAll(filepath.Join(cfg.NewRoot, "proc"), 0o555); err != nil {
		return err
	}
	if err := mnt("proc", filepath.Join(cfg.NewRoot, "proc"), "proc",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}

	// 5. Minimal /dev: a tmpfs holding only the character devices above,
	//    each bind-mounted from the host (mknod is not permitted in this
	//    user namespace).
	devDir := filepath.Join(cfg.NewRoot, "dev")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		return err
	}
	if err := mnt("tmpfs", devDir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NOEXEC, "mode=0755"); err != nil {
		return fmt.Errorf("tmpfs on /dev: %w", err)
	}
	for _, d := range devNodes {
		src := "/dev/" + d
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(devDir, d)
		f, err := os.OpenFile(dst, os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		_ = f.Close()
		if err := mnt(src, dst, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", src, err)
		}
	}

	// 6. A writable, ephemeral /tmp for the wrapped command's scratch use.
	tmpDir := filepath.Join(cfg.NewRoot, "tmp")
	if err := os.MkdirAll(tmpDir, 0o1777); err != nil {
		return err
	}
	if err := mnt("tmpfs", tmpDir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=1777"); err != nil {
		return fmt.Errorf("tmpfs on /tmp: %w", err)
	}

	// 7. The project directory, read-write, bind-mounted at the SAME
	//    absolute path it has on the host so captured paths stay meaningful.
	//    Done last so none of the fresh filesystems above can shadow it
	//    (e.g. a project dir that lives under /tmp).
	projTarget := filepath.Join(cfg.NewRoot, cfg.ProjectDir)
	if err := os.MkdirAll(projTarget, 0o755); err != nil {
		return err
	}
	if err := mnt(cfg.ProjectDir, projTarget, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind project dir: %w", err)
	}

	// 8. Enter the new root. put_old must sit underneath new_root.
	putOld := filepath.Join(cfg.NewRoot, oldRootName)
	if err := os.MkdirAll(putOld, 0o700); err != nil {
		return err
	}
	if err := syscall.PivotRoot(cfg.NewRoot, putOld); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := syscall.Chdir("/"); err != nil {
		return fmt.Errorf("chdir to new root: %w", err)
	}

	// 9. Detach the old root so the host filesystem is completely gone from
	//    this namespace, then remove the now-empty mountpoint.
	oldRoot := "/" + oldRootName
	if err := mnt("", oldRoot, "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make old root private: %w", err)
	}
	if err := syscall.Unmount(oldRoot, syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	if err := os.Remove(oldRoot); err != nil {
		return fmt.Errorf("remove old root mountpoint: %w", err)
	}

	// 10. Make the new root itself read-only. The submounts added above
	//     (project dir, /proc, /dev, /tmp) keep their own mount flags, so
	//     only the top-level tmpfs — anything the command might create
	//     directly under / — becomes non-writable.
	if err := mnt("", "/", "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID, "mode=0755"); err != nil {
		return fmt.Errorf("remount / read-only: %w", err)
	}

	// 11. Working directory = the project directory.
	if err := syscall.Chdir(cfg.ProjectDir); err != nil {
		return fmt.Errorf("chdir to project dir: %w", err)
	}
	return nil
}

// childEnv is the sanitized environment for the wrapped command. HOME points
// at the project directory: the real home is not mounted, and npm needs a
// writable HOME for its cache and .npmrc.
func childEnv(cfg childConfig) []string {
	env := []string{
		"PATH=" + defaultPath,
		"HOME=" + cfg.ProjectDir,
		"PWD=" + cfg.ProjectDir,
	}
	if term := os.Getenv("TERM"); term != "" {
		env = append(env, "TERM="+term)
	}
	return env
}

// mnt is a thin wrapper so mount call sites read as one line each.
func mnt(source, target, fstype string, flags uintptr, data string) error {
	return syscall.Mount(source, target, fstype, flags, data)
}

func orReader(r, def io.Reader) io.Reader {
	if r == nil {
		return def
	}
	return r
}

func orWriter(w, def io.Writer) io.Writer {
	if w == nil {
		return def
	}
	return w
}
