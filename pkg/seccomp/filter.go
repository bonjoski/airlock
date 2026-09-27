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

	BPF_K = 0x00

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
}

// BPFFilter implements the Filter interface for process isolation.
type BPFFilter struct{}

// NewFilter creates a new seccomp BPF filter synthesizer.
func NewFilter() *BPFFilter {
	return &BPFFilter{}
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

	// Calculate instruction layout
	// 0: Load arch
	// 1: JEQ AuditArch -> skip 1 (go to 3) else go to 2
	// 2: RET KILL
	// 3: Load NR
	// [4 .. 4+len(Blocked)-1]: Blocked syscall checks
	// [4+len(Blocked)]: JEQ IoctlNr -> jump to ioctl inspection
	// [4+len(Blocked)+1]: RET ALLOW (for non-blocked, non-ioctl syscalls)
	// [4+len(Blocked)+2]: Load args[1] (ioctl cmd)
	// [4+len(Blocked)+3]: JEQ TIOCSTI -> jump to deny
	// [4+len(Blocked)+4]: RET ALLOW (safe ioctl)
	// [4+len(Blocked)+5]: RET ERRNO (deny)

	numBlocked := len(cfg.Blocked)
	idxIoctlCheck := 4 + numBlocked
	idxAllowNonIoctl := idxIoctlCheck + 1
	idxLoadIoctlCmd := idxAllowNonIoctl + 1
	idxCheckTiocsti := idxLoadIoctlCmd + 1
	idxAllowSafeIoctl := idxCheckTiocsti + 1
	idxDeny := idxAllowSafeIoctl + 1

	totalInsts := idxDeny + 1
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

	// 3. Blocked syscalls check
	for i, syscallNr := range cfg.Blocked {
		currIdx := 4 + i
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

	// 9. Deny return
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
