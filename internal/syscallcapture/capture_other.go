//go:build !linux

package syscallcapture

import "errors"

// errUnsupported is returned by Run on every non-Linux platform. Cordon is
// Linux-only by design (INTENT.md §3 Platform); this stub exists so the
// module still builds and `go vet` still runs on a non-Linux workstation
// (mirrors internal/sandbox/run_other.go).
var errUnsupported = errors.New("cordon: syscall capture requires Linux ptrace and seccomp")

func Run(Config, func(Event)) (Result, error) { return Result{}, errUnsupported }

// MaybeRunTracee is a no-op off Linux: there is no re-exec tracee mode.
func MaybeRunTracee() {}
