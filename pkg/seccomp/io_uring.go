// Package seccomp provides pure-Go Seccomp-BPF compilation and syscall
// filtering for process confinement on Linux.
package seccomp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Linux io_uring syscall numbers (identical across x86_64, aarch64, riscv64).
const (
	SyscallIoUringSetup    uint32 = 425
	SyscallIoUringEnter    uint32 = 426
	SyscallIoUringRegister uint32 = 427
)

// Linux io_uring_register opcodes (<linux/io_uring.h>).
const (
	IORING_REGISTER_BUFFERS       uint32 = 0
	IORING_UNREGISTER_BUFFERS     uint32 = 1
	IORING_REGISTER_FILES         uint32 = 2
	IORING_UNREGISTER_FILES       uint32 = 3
	IORING_REGISTER_EVENTFD       uint32 = 4
	IORING_UNREGISTER_EVENTFD     uint32 = 5
	IORING_REGISTER_FILES_UPDATE  uint32 = 6
	IORING_REGISTER_EVENTFD_ASYNC uint32 = 7
	IORING_REGISTER_PROBE         uint32 = 8
	IORING_REGISTER_PERSONALITY   uint32 = 9  // BANNED: Personality registration elevation
	IORING_UNREGISTER_PERSONALITY uint32 = 10
	IORING_REGISTER_RESTRICTIONS  uint32 = 11
	IORING_REGISTER_ENABLE_RINGS  uint32 = 12
)

// Linux io_uring_restriction opcodes (<linux/io_uring.h>).
const (
	IORING_RESTRICTION_REGISTER_OP       uint16 = 0
	IORING_RESTRICTION_SQE_OP            uint16 = 1
	IORING_RESTRICTION_SQE_FLAGS_ALLOWED uint16 = 2
	IORING_RESTRICTION_SQE_FLAGS_REQUIRED uint16 = 3
)

// Linux io_uring SQE opcodes (<linux/io_uring.h>).
const (
	IORING_OP_NOP             uint8 = 0
	IORING_OP_READV           uint8 = 1
	IORING_OP_WRITEV          uint8 = 2
	IORING_OP_FSYNC           uint8 = 3
	IORING_OP_READ_FIXED      uint8 = 4
	IORING_OP_WRITE_FIXED     uint8 = 5
	IORING_OP_POLL_ADD        uint8 = 6
	IORING_OP_POLL_REMOVE     uint8 = 7
	IORING_OP_SYNC_FILE_RANGE uint8 = 8
	IORING_OP_SENDMSG         uint8 = 9  // BANNED: Socket network egress
	IORING_OP_RECVMSG         uint8 = 10 // BANNED: Socket network ingress
	IORING_OP_TIMEOUT         uint8 = 11
	IORING_OP_TIMEOUT_REMOVE  uint8 = 12
	IORING_OP_ACCEPT          uint8 = 13 // BANNED: Socket server accept
	IORING_OP_ASYNC_CANCEL    uint8 = 14
	IORING_OP_LINK_TIMEOUT    uint8 = 15
	IORING_OP_CONNECT         uint8 = 16 // BANNED: Socket network connect
	IORING_OP_FALLOCATE       uint8 = 17
	IORING_OP_OPENAT          uint8 = 18 // BANNED: Arbitrary file open
	IORING_OP_CLOSE           uint8 = 19
	IORING_OP_FILES_UPDATE    uint8 = 20
	IORING_OP_STATX           uint8 = 21
	IORING_OP_READ            uint8 = 22
	IORING_OP_WRITE           uint8 = 23
	IORING_OP_FADVISE         uint8 = 24
	IORING_OP_MADVISE         uint8 = 25
	IORING_OP_SEND            uint8 = 26 // BANNED: Socket send
	IORING_OP_RECV            uint8 = 27 // BANNED: Socket recv
	IORING_OP_OPENAT2         uint8 = 28 // BANNED: Extended open
	IORING_OP_EPOLL_CTL       uint8 = 29
	IORING_OP_SPLICE          uint8 = 30 // BANNED: Pipe splice
	IORING_OP_PROVIDE_BUFFERS uint8 = 31
	IORING_OP_REMOVE_BUFFERS  uint8 = 32
	IORING_OP_TEE             uint8 = 33 // BANNED: Pipe tee
	IORING_OP_SHUTDOWN        uint8 = 34
	IORING_OP_RENAMEAT        uint8 = 35 // BANNED: Filesystem rename
	IORING_OP_UNLINKAT        uint8 = 36 // BANNED: Filesystem unlink
	IORING_OP_MKDIRAT         uint8 = 37 // BANNED: Directory creation
	IORING_OP_SYMLINKAT       uint8 = 38 // BANNED: Symlink creation
	IORING_OP_LINKAT          uint8 = 39 // BANNED: Hardlink creation
)

// IoUringPolicy controls the seccomp posture regarding Linux io_uring syscalls.
type IoUringPolicy int

const (
	// IoUringPolicyBlockAll is the default fail-closed posture: all io_uring syscalls
	// (425 setup, 426 enter, 427 register) are denied with SECCOMP_RET_ERRNO(EPERM).
	// This matches ChromeOS, Android GKI, and hardened container profiles.
	IoUringPolicyBlockAll IoUringPolicy = iota

	// IoUringPolicyRestricted allows high-throughput asynchronous disk I/O on pre-initialized
	// rings by permitting io_uring_enter (426) and io_uring_register (427) while enforcing
	// deep BPF inspection that denies IORING_REGISTER_PERSONALITY (9) and keeping raw
	// sys_io_uring_setup (425) blocked.
	IoUringPolicyRestricted
)

// IoUringRestriction mirrors the 16-byte Linux kernel `struct io_uring_restriction`
// used with io_uring_register(fd, IORING_REGISTER_RESTRICTIONS, ptr, count).
type IoUringRestriction struct {
	Opcode   uint16    // IORING_RESTRICTION_*
	SubOp    uint8     // register_op, sqe_op, or sqe_flags
	Resv     uint8     // Reserved padding
	Resv2    [3]uint32 // Reserved padding
}

// Bytes serializes the 16-byte restriction into little-endian binary format.
func (r IoUringRestriction) Bytes() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, r.Opcode)
	_ = binary.Write(buf, binary.LittleEndian, r.SubOp)
	_ = binary.Write(buf, binary.LittleEndian, r.Resv)
	_ = binary.Write(buf, binary.LittleEndian, r.Resv2[0])
	_ = binary.Write(buf, binary.LittleEndian, r.Resv2[1])
	_ = binary.Write(buf, binary.LittleEndian, r.Resv2[2])
	return buf.Bytes()
}

// DefaultSafeSQEOpcodes returns the set of safe, high-throughput asynchronous disk I/O
// opcodes permitted under a restricted profile. Network and file-creation opcodes are strictly excluded.
func DefaultSafeSQEOpcodes() []uint8 {
	return []uint8{
		IORING_OP_NOP,
		IORING_OP_READV,
		IORING_OP_WRITEV,
		IORING_OP_FSYNC,
		IORING_OP_READ_FIXED,
		IORING_OP_WRITE_FIXED,
		IORING_OP_SYNC_FILE_RANGE,
		IORING_OP_READ,
		IORING_OP_WRITE,
		IORING_OP_FADVISE,
		IORING_OP_MADVISE,
		IORING_OP_CLOSE,
	}
}

// DefaultSafeRegisterOpcodes returns the permitted register opcodes for restricted rings.
// IORING_REGISTER_PERSONALITY is strictly excluded to prevent credential elevation.
func DefaultSafeRegisterOpcodes() []uint8 {
	return []uint8{
		uint8(IORING_REGISTER_BUFFERS),
		uint8(IORING_UNREGISTER_BUFFERS),
		uint8(IORING_REGISTER_FILES),
		uint8(IORING_UNREGISTER_FILES),
		uint8(IORING_REGISTER_EVENTFD),
		uint8(IORING_UNREGISTER_EVENTFD),
		uint8(IORING_REGISTER_PROBE),
		uint8(IORING_REGISTER_RESTRICTIONS),
		uint8(IORING_REGISTER_ENABLE_RINGS),
	}
}

// DefaultIoUringRestrictions constructs an immutable, hardened array of restrictions
// that seals an io_uring instance to safe asynchronous file I/O operations only.
func DefaultIoUringRestrictions() []IoUringRestriction {
	var restrictions []IoUringRestriction

	// 1. Allow safe SQE opcodes
	for _, op := range DefaultSafeSQEOpcodes() {
		restrictions = append(restrictions, IoUringRestriction{
			Opcode: IORING_RESTRICTION_SQE_OP,
			SubOp:  op,
		})
	}

	// 2. Allow safe register opcodes
	for _, regOp := range DefaultSafeRegisterOpcodes() {
		restrictions = append(restrictions, IoUringRestriction{
			Opcode: IORING_RESTRICTION_REGISTER_OP,
			SubOp:  regOp,
		})
	}

	// 3. Require 0 flags on SQEs
	restrictions = append(restrictions, IoUringRestriction{
		Opcode: IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
		SubOp:  0,
	})

	return restrictions
}

// BannedSQEOpcodes contains opcodes that must NEVER be allowed in sandbox execution.
var BannedSQEOpcodes = map[uint8]string{
	IORING_OP_SENDMSG:   "socket sendmsg (network egress)",
	IORING_OP_RECVMSG:   "socket recvmsg (network ingress)",
	IORING_OP_ACCEPT:    "socket accept (network server)",
	IORING_OP_CONNECT:   "socket connect (network egress)",
	IORING_OP_OPENAT:    "openat (arbitrary file open bypass)",
	IORING_OP_OPENAT2:   "openat2 (arbitrary file open bypass)",
	IORING_OP_SEND:      "socket send (network egress)",
	IORING_OP_RECV:      "socket recv (network ingress)",
	IORING_OP_SPLICE:    "splice (file descriptor redirection)",
	IORING_OP_TEE:       "tee (pipe duplication)",
	IORING_OP_RENAMEAT:  "renameat (filesystem mutation)",
	IORING_OP_UNLINKAT:  "unlinkat (file deletion)",
	IORING_OP_MKDIRAT:   "mkdirat (directory creation)",
	IORING_OP_SYMLINKAT: "symlinkat (symlink traversal vector)",
	IORING_OP_LINKAT:    "linkat (hardlink creation)",
}

// ValidateIoUringRestrictions performs a fail-closed adversarial audit of proposed restrictions.
// Returns an error if any banned SQE opcode or personality registration is permitted.
func ValidateIoUringRestrictions(restrictions []IoUringRestriction) error {
	if len(restrictions) == 0 {
		return errors.New("seccomp: empty io_uring restrictions list is fail-closed")
	}

	for _, r := range restrictions {
		switch r.Opcode {
		case IORING_RESTRICTION_SQE_OP:
			if reason, banned := BannedSQEOpcodes[r.SubOp]; banned {
				return fmt.Errorf("seccomp: disallowed io_uring SQE opcode %d: %s", r.SubOp, reason)
			}
		case IORING_RESTRICTION_REGISTER_OP:
			if uint32(r.SubOp) == IORING_REGISTER_PERSONALITY {
				return errors.New("seccomp: IORING_REGISTER_PERSONALITY is strictly forbidden (privilege elevation risk)")
			}
		case IORING_RESTRICTION_SQE_FLAGS_ALLOWED, IORING_RESTRICTION_SQE_FLAGS_REQUIRED:
			// Allowed flags checks
		default:
			return fmt.Errorf("seccomp: unknown restriction opcode %d", r.Opcode)
		}
	}

	return nil
}

// EncodeIoUringRestrictions serializes restrictions into binary format for passing to io_uring_register.
func EncodeIoUringRestrictions(restrictions []IoUringRestriction) ([]byte, error) {
	if err := ValidateIoUringRestrictions(restrictions); err != nil {
		return nil, fmt.Errorf("seccomp: cannot encode invalid restrictions: %w", err)
	}

	buf := new(bytes.Buffer)
	for _, r := range restrictions {
		buf.Write(r.Bytes())
	}
	return buf.Bytes(), nil
}
