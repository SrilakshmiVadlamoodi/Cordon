//go:build !linux

package sandbox

import "errors"

// errUnsupported is returned by Run on every non-Linux platform. Cordon is
// Linux-only by design (INTENT.md §3 Platform); this stub exists so the
// module still builds and `go vet` still runs on a non-Linux workstation.
var errUnsupported = errors.New("cordon: the sandbox requires Linux namespaces")

func Run(Spec) (Result, error) { return Result{}, errUnsupported }

// MaybeRunChild is a no-op off Linux: there is no re-exec child mode.
func MaybeRunChild() {}
