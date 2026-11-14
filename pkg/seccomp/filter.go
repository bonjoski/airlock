// Package seccomp provides pure-Go Seccomp-BPF compilation and syscall
// filtering for process confinement on Linux.
package seccomp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

// Common classic BPF constants (Linux kernel <linux/bpf_common.h>, <linux/filter.h>).
const (
	BPF_LD  = 0x00
	BPF_JMP = 0x05
	BPF_RET = 0x06

	BPF_W = 0x00

	BPF_ABS = 0x20

	BPF_JEQ = 0x10
	BPF_JGE = 0x30

	BPF_K = 0x00

	// x32 ABI syscall bit mask on x86_64 (<asm/unistd.h>)
	X32_SYSCALL_BIT = 0x40000000

	// Seccomp Return actions (<linux/seccomp.h>)
	SECCOMP_RET_KILL_PROCESS = 0x80000000
	SECCOMP_RET_ERRNO        = 0x00050000
	SECCOMP_RET_ALLOW        = 0x7fff0000

	// Linux errno
	EPERM = 1

	// Audit Architectures (<linux/audit.h>)
	AUDIT_ARCH_X86_64  = 0xc000003e // AUDIT_ARCH_X86_64
	AUDIT_ARCH_AARCH64 = 0xc00000b7 // AUDIT_ARCH_AARCH64

	// ioctl opcodes
	TIOCSTI = 0x5412 // Terminal injection opcode (V-05)

	// Offsets in struct seccomp_data (<linux/seccomp.h>)
	SeccompDataNrOffset   = 0
	SeccompDataArchOffset = 4
	SeccompDataArgsOffset = 16
)

// SockFilter represents an 8-byte classic BPF instruction (struct sock_filter).
type SockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// Stmt creates an unconditional BPF instruction.
func Stmt(code uint16, k uint32) SockFilter {
	return SockFilter{Code: code, Jt: 0, Jf: 0, K: k}
}

// Jump creates a conditional jump BPF instruction.
func Jump(code uint16, k uint32, jt, jf uint8) SockFilter {
	return SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// SyscallConfig maps architecture-specific syscall numbers for denied calls.
type SyscallConfig struct {
	AuditArch uint32
	IoctlNr   uint32
	Blocked   []uint32
}

// Filter defines the interface for seccomp BPF program synthesis.
type Filter interface {
	Compile(arch string) ([]byte, error)
	CompileInstructions(arch string) ([]SockFilter, error)
	WriteTo(w io.Writer, arch string) error
	CreateFilterFile(arch string) (*os.File, error)
	PruneSyscalls(syscalls []uint32)
}

// BPFFilter implements the Filter interface for process isolation.
type BPFFilter struct {
	extraBlocked  []uint32
	ioUringPolicy IoUringPolicy
}

// NewFilter creates a new seccomp BPF filter synthesizer with default fail-closed policies.
func NewFilter() *BPFFilter {
	return &BPFFilter{
		ioUringPolicy: IoUringPolicyBlockAll,
	}
}

// NewFilterWithBlocked creates a filter with additional pre-blocked syscalls.
func NewFilterWithBlocked(extra []uint32) *BPFFilter {
	return &BPFFilter{
		extraBlocked:  append([]uint32(nil), extra...),
		ioUringPolicy: IoUringPolicyBlockAll,
	}
}

// SetIoUringPolicy configures the policy for Linux io_uring syscalls (425, 426, 427).
func (f *BPFFilter) SetIoUringPolicy(policy IoUringPolicy) {
	f.ioUringPolicy = policy
}

// IoUringPolicy returns the current io_uring posture.
func (f *BPFFilter) IoUringPolicy() IoUringPolicy {
	return f.ioUringPolicy
}

// AddBlocked adds additional architecture-specific syscall numbers to the blocked set.
func (f *BPFFilter) AddBlocked(syscalls ...uint32) {
	f.extraBlocked = append(f.extraBlocked, syscalls...)
}

// PruneSyscalls blocks the specified syscall numbers in the synthesized BPF program.
func (f *BPFFilter) PruneSyscalls(syscalls []uint32) {
	f.AddBlocked(syscalls...)
}

// BlockedSyscalls returns a copy of dynamically blocked syscall numbers.
func (f *BPFFilter) BlockedSyscalls() []uint32 {
	res := make([]uint32, len(f.extraBlocked))
	copy(res, f.extraBlocked)
	return res
}

// GetSyscallConfig returns architecture-specific syscall numbers for Linux x86_64 or aarch64.
func GetSyscallConfig(arch string) (SyscallConfig, error) {
	switch arch {
	case "amd64", "x86_64":
		return SyscallConfig{
			AuditArch: AUDIT_ARCH_X86_64,
			IoctlNr:   16, // SYS_ioctl on x86_64
			Blocked: []uint32{
				425, // io_uring_setup
				426, // io_uring_enter
				427, // io_uring_register
				101, // ptrace
				310, // process_vm_readv
				311, // process_vm_writev
				250, // keyctl
				321, // bpf
				165, // mount
				246, // kexec_load
			},
		}, nil

	case "arm64", "aarch64":
		return SyscallConfig{
			AuditArch: AUDIT_ARCH_AARCH64,
			IoctlNr:   29, // SYS_ioctl on aarch64
			Blocked: []uint32{
				425, // io_uring_setup
				426, // io_uring_enter
				427, // io_uring_register
				117, // ptrace
				270, // process_vm_readv
				271, // process_vm_writev
				219, // keyctl
				280, // bpf
				40,  // mount
				104, // kexec_load
			},
		}, nil

	default:
		return SyscallConfig{}, fmt.Errorf("seccomp: unsupported architecture %q: %w", arch, errors.ErrUnsupported)
	}
}

// CompileInstructions synthesizes the BPF instructions for the target architecture.
func (f *BPFFilter) CompileInstructions(arch string) ([]SockFilter, error) {
	cfg, err := GetSyscallConfig(arch)
	if err != nil {
		return nil, fmt.Errorf("seccomp: failed to get syscall config: %w", err)
	}

	blocked := make([]uint32, 0, len(cfg.Blocked)+len(f.extraBlocked))
	seen := make(map[uint32]bool)
	for _, nr := range cfg.Blocked {
		// Under IoUringPolicyRestricted, io_uring_enter (426) and io_uring_register (427)
		// are not in the raw deny list (register is deeply inspected below).
		if f.ioUringPolicy == IoUringPolicyRestricted && (nr == SyscallIoUringEnter || nr == SyscallIoUringRegister) {
			continue
		}
		if !seen[nr] {
			blocked = append(blocked, nr)
			seen[nr] = true
		}
	}
	for _, nr := range f.extraBlocked {
		if !seen[nr] {
			blocked = append(blocked, nr)
			seen[nr] = true
		}
	}

	numBlocked := len(blocked)
	baseBlockedIdx := 4
	if cfg.AuditArch == AUDIT_ARCH_X86_64 {
		// Reserve 2 instructions to reject x32 ABI syscalls (nr >= 0x40000000)
		baseBlockedIdx = 6
	}

	// Calculate instruction layout based on policy
	var (
		idxIoctlCheck        int
		idxIoUringRegCheck   int
		idxAllowNormal       int
		idxLoadIoctlCmd      int
		idxCheckTiocsti      int
		idxAllowSafeIoctl    int
		idxLoadRegisterCmd   int
		idxCheckPersonality  int
		idxAllowSafeRegister int
		idxDeny              int
		totalInsts           int
	)

	if f.ioUringPolicy == IoUringPolicyRestricted {
		idxIoctlCheck = baseBlockedIdx + numBlocked
		idxIoUringRegCheck = idxIoctlCheck + 1
		idxAllowNormal = idxIoUringRegCheck + 1
		idxLoadIoctlCmd = idxAllowNormal + 1
		idxCheckTiocsti = idxLoadIoctlCmd + 1
		idxAllowSafeIoctl = idxCheckTiocsti + 1
		idxLoadRegisterCmd = idxAllowSafeIoctl + 1
		idxCheckPersonality = idxLoadRegisterCmd + 1
		idxAllowSafeRegister = idxCheckPersonality + 1
		idxDeny = idxAllowSafeRegister + 1
		totalInsts = idxDeny + 1
	} else {
		idxIoctlCheck = baseBlockedIdx + numBlocked
		idxAllowNormal = idxIoctlCheck + 1
		idxLoadIoctlCmd = idxAllowNormal + 1
		idxCheckTiocsti = idxLoadIoctlCmd + 1
		idxAllowSafeIoctl = idxCheckTiocsti + 1
		idxDeny = idxAllowSafeIoctl + 1
		totalInsts = idxDeny + 1
	}

	instructions := make([]SockFilter, 0, totalInsts)

	// 1. Verify architecture
	instructions = append(instructions,
		Stmt(BPF_LD|BPF_W|BPF_ABS, SeccompDataArchOffset),
		Jump(BPF_JMP|BPF_JEQ|BPF_K, cfg.AuditArch, 1, 0),
		Stmt(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
	)

	// 2. Load syscall number
	instructions = append(instructions,
		Stmt(BPF_LD|BPF_W|BPF_ABS, SeccompDataNrOffset),
	)

	// 2b. Reject x32 ABI syscalls on x86_64 (AIR-06: nr >= 0x40000000)
	if cfg.AuditArch == AUDIT_ARCH_X86_64 {
		instructions = append(instructions,
			Jump(BPF_JMP|BPF_JGE|BPF_K, X32_SYSCALL_BIT, 0, 1),
			Stmt(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
		)
	}

	// 3. Blocked syscalls check
	for i, syscallNr := range blocked {
		currIdx := baseBlockedIdx + i
		jt := uint8(idxDeny - currIdx - 1)
		instructions = append(instructions,
			Jump(BPF_JMP|BPF_JEQ|BPF_K, syscallNr, jt, 0),
		)
	}

	// 4. Ioctl syscall check
	jtIoctl := uint8(idxLoadIoctlCmd - idxIoctlCheck - 1)
	instructions = append(instructions,
		Jump(BPF_JMP|BPF_JEQ|BPF_K, cfg.IoctlNr, jtIoctl, 0),
	)

	// 4b. io_uring_register syscall check (only under IoUringPolicyRestricted)
	if f.ioUringPolicy == IoUringPolicyRestricted {
		jtIoUring := uint8(idxLoadRegisterCmd - idxIoUringRegCheck - 1)
		instructions = append(instructions,
			Jump(BPF_JMP|BPF_JEQ|BPF_K, SyscallIoUringRegister, jtIoUring, 0),
		)
	}

	// 5. Default allow for normal syscalls
	instructions = append(instructions,
		Stmt(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	)

	// 6. Ioctl deep inspection: load lower 32-bits of args[1] (ioctl cmd)
	instructions = append(instructions,
		Stmt(BPF_LD|BPF_W|BPF_ABS, SeccompDataArgsOffset+8),
	)

	// 7. Check if ioctl cmd is TIOCSTI
	jtTiocsti := uint8(idxDeny - idxCheckTiocsti - 1)
	instructions = append(instructions,
		Jump(BPF_JMP|BPF_JEQ|BPF_K, TIOCSTI, jtTiocsti, 0),
	)

	// 8. Safe ioctl allow
	instructions = append(instructions,
		Stmt(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	)

	// 9. io_uring_register deep inspection (only under IoUringPolicyRestricted)
	if f.ioUringPolicy == IoUringPolicyRestricted {
		// Load lower 32-bits of args[1] (register opcode)
		instructions = append(instructions,
			Stmt(BPF_LD|BPF_W|BPF_ABS, SeccompDataArgsOffset+8),
		)

		// Check if register opcode is IORING_REGISTER_PERSONALITY (9) -> deny
		jtPersonality := uint8(idxDeny - idxCheckPersonality - 1)
		instructions = append(instructions,
			Jump(BPF_JMP|BPF_JEQ|BPF_K, IORING_REGISTER_PERSONALITY, jtPersonality, 0),
		)

		// Safe io_uring_register opcode allow
		instructions = append(instructions,
			Stmt(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		)
	}

	// 10. Deny return
	instructions = append(instructions,
		Stmt(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
	)

	return instructions, nil
}

// Compile serializes the BPF instructions into raw little-endian binary bytes.
func (f *BPFFilter) Compile(arch string) ([]byte, error) {
	if arch == "" {
		arch = runtime.GOARCH
	}

	instructions, err := f.CompileInstructions(arch)
	if err != nil {
		return nil, fmt.Errorf("seccomp: compilation error: %w", err)
	}

	buf := new(bytes.Buffer)
	for _, inst := range instructions {
		if err := binary.Write(buf, binary.LittleEndian, inst.Code); err != nil {
			return nil, fmt.Errorf("seccomp: binary encode error: %w", err)
		}
		if err := binary.Write(buf, binary.LittleEndian, inst.Jt); err != nil {
			return nil, fmt.Errorf("seccomp: binary encode error: %w", err)
		}
		if err := binary.Write(buf, binary.LittleEndian, inst.Jf); err != nil {
			return nil, fmt.Errorf("seccomp: binary encode error: %w", err)
		}
		if err := binary.Write(buf, binary.LittleEndian, inst.K); err != nil {
			return nil, fmt.Errorf("seccomp: binary encode error: %w", err)
		}
	}

	return buf.Bytes(), nil
}

// WriteTo writes the serialized BPF program to the specified io.Writer.
func (f *BPFFilter) WriteTo(w io.Writer, arch string) error {
	data, err := f.Compile(arch)
	if err != nil {
		return fmt.Errorf("seccomp: compile failed: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("seccomp: write failed: %w", err)
	}

	return nil
}

// CreateFilterFile compiles and writes the BPF program into a temporary file
// suitable for passing as a file descriptor to Bubblewrap (--seccomp <FD>).
func (f *BPFFilter) CreateFilterFile(arch string) (*os.File, error) {
	tmpFile, err := os.CreateTemp("", "airlock-seccomp-*.bpf")
	if err != nil {
		return nil, fmt.Errorf("seccomp: failed to create temporary filter file: %w", err)
	}

	if err := f.WriteTo(tmpFile, arch); err != nil {
		_ = tmpFile.Close()
		if rmErr := os.Remove(tmpFile.Name()); rmErr != nil && !os.IsNotExist(rmErr) {
			return nil, fmt.Errorf("seccomp: write failed (%w) and cleanup error: %v", err, rmErr)
		}
		return nil, fmt.Errorf("seccomp: failed to write filter to temp file: %w", err)
	}

	// Rewind to beginning so reader reads from byte 0
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		_ = tmpFile.Close()
		if rmErr := os.Remove(tmpFile.Name()); rmErr != nil && !os.IsNotExist(rmErr) {
			return nil, fmt.Errorf("seccomp: seek failed (%w) and cleanup error: %v", err, rmErr)
		}
		return nil, fmt.Errorf("seccomp: failed to rewind filter file: %w", err)
	}

	return tmpFile, nil
}
