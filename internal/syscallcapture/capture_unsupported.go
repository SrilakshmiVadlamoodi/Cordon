//go:build linux && !amd64

package syscallcapture

// This file exists to fail the *build*, deliberately, for any Linux
// architecture other than amd64 (arm64, 386, riscv64, ...).
//
// capture_linux.go's register access (Orig_rax, Rsi, Rax, Rdx, Rdi) is
// the amd64 layout of syscall.PtraceRegs; on arm64 that type is a
// completely different shape (Regs [31]uint64, Sp, Pc, Pstate — no
// named x86 registers at all), and the syscall-number/argument-register
// ABI a real port would need to read instead is also architecture
// -specific (see https://man7.org/linux/man-pages/man2/syscall.2.html's
// arm64 column). None of that is implemented.
//
// The alternative — widening capture_other.go's `!linux` tag to also
// cover `linux && !amd64`, so this compiles a working *binary* that
// just returns errUnsupported from Run at runtime — was considered and
// rejected (DECISIONS.md 2026-09-05 "arm64 build tag: fail the build,
// not the runtime"): a binary that builds cleanly but silently never
// captures anything is a worse failure mode for a security tool than
// refusing to build at all. Cross-compiling for an architecture this
// package doesn't support should fail loudly, here, not ship quietly
// and fail the user's actual goal later.
//
// cordonSyscallCaptureNotYetImplementedForThisLinuxArchitecture is not
// defined anywhere on purpose — Go has no `#error` directive, so an
// undefined-reference compile error naming a descriptive function is
// the standard idiom for a deliberate, readable build-time failure.
func init() {
	cordonSyscallCaptureNotYetImplementedForThisLinuxArchitecture()
}
