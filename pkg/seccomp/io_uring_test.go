package seccomp

import (
	"testing"
)

func TestIoUring_DefaultPolicyBlockAll(t *testing.T) {
	filter := NewFilter()
	if filter.IoUringPolicy() != IoUringPolicyBlockAll {
		t.Fatalf("expected default policy to be IoUringPolicyBlockAll, got %v", filter.IoUringPolicy())
	}

	insts, err := filter.CompileInstructions("amd64")
	if err != nil {
		t.Fatalf("CompileInstructions(amd64) failed: %v", err)
	}

	vm := &bpfVM{instructions: insts}

	// Verify all 3 io_uring syscalls are denied by default with EPERM
	ioUringSyscalls := []uint32{
		SyscallIoUringSetup,
		SyscallIoUringEnter,
		SyscallIoUringRegister,
	}

	for _, nr := range ioUringSyscalls {
		res := vm.run(seccompDataSim{
			nr:   int32(nr),
			arch: AUDIT_ARCH_X86_64,
		})
		if res != SECCOMP_RET_ERRNO|EPERM {
			t.Errorf("io_uring syscall %d was not denied with EPERM under default policy, got 0x%x", nr, res)
		}
	}
}

func TestIoUring_RestrictedPolicy(t *testing.T) {
	for _, arch := range []struct {
		name      string
		auditArch uint32
	}{
		{"amd64", AUDIT_ARCH_X86_64},
		{"arm64", AUDIT_ARCH_AARCH64},
	} {
		t.Run(arch.name, func(t *testing.T) {
			filter := NewFilter()
			filter.SetIoUringPolicy(IoUringPolicyRestricted)

			if filter.IoUringPolicy() != IoUringPolicyRestricted {
				t.Fatalf("expected policy to be IoUringPolicyRestricted, got %v", filter.IoUringPolicy())
			}

			insts, err := filter.CompileInstructions(arch.name)
			if err != nil {
				t.Fatalf("CompileInstructions(%s) failed: %v", arch.name, err)
			}

			vm := &bpfVM{instructions: insts}

			// 1. Raw io_uring_setup (425) must remain BLOCKED (preventing unauthorized ring setup)
			resSetup := vm.run(seccompDataSim{
				nr:   int32(SyscallIoUringSetup),
				arch: arch.auditArch,
			})
			if resSetup != SECCOMP_RET_ERRNO|EPERM {
				t.Errorf("expected sys_io_uring_setup to remain EPERM under restricted policy, got 0x%x", resSetup)
			}

			// 2. io_uring_enter (426) must be ALLOWED for event submission/completion
			resEnter := vm.run(seccompDataSim{
				nr:   int32(SyscallIoUringEnter),
				arch: arch.auditArch,
			})
			if resEnter != SECCOMP_RET_ALLOW {
				t.Errorf("expected io_uring_enter to be allowed under restricted policy, got 0x%x", resEnter)
			}

			// 3. io_uring_register (427) with safe opcode (e.g., IORING_REGISTER_BUFFERS = 0) must be ALLOWED
			resRegisterSafe := vm.run(seccompDataSim{
				nr:   int32(SyscallIoUringRegister),
				arch: arch.auditArch,
				args: [6]uint64{3, uint64(IORING_REGISTER_BUFFERS), 0, 0, 0, 0},
			})
			if resRegisterSafe != SECCOMP_RET_ALLOW {
				t.Errorf("expected io_uring_register with safe opcode to be allowed, got 0x%x", resRegisterSafe)
			}

			// 4. io_uring_register (427) with IORING_REGISTER_PERSONALITY (9) must be DENIED (EPERM)
			resRegisterPersonality := vm.run(seccompDataSim{
				nr:   int32(SyscallIoUringRegister),
				arch: arch.auditArch,
				args: [6]uint64{3, uint64(IORING_REGISTER_PERSONALITY), 0, 0, 0, 0},
			})
			if resRegisterPersonality != SECCOMP_RET_ERRNO|EPERM {
				t.Errorf("expected io_uring_register(IORING_REGISTER_PERSONALITY) to be denied with EPERM, got 0x%x", resRegisterPersonality)
			}

			// 5. Normal syscalls (e.g. read = 0 on x86_64, 63 on aarch64) must be ALLOWED
			normalNr := int32(0)
			if arch.name == "arm64" {
				normalNr = 63 // SYS_read on aarch64
			}
			resNormal := vm.run(seccompDataSim{
				nr:   normalNr,
				arch: arch.auditArch,
			})
			if resNormal != SECCOMP_RET_ALLOW {
				t.Errorf("expected normal syscall %d to be allowed, got 0x%x", normalNr, resNormal)
			}

			// 6. TIOCSTI ioctl must remain DENIED
			ioctlNr := int32(16)
			if arch.name == "arm64" {
				ioctlNr = 29
			}
			resIoctl := vm.run(seccompDataSim{
				nr:   ioctlNr,
				arch: arch.auditArch,
				args: [6]uint64{0, TIOCSTI, 0, 0, 0, 0},
			})
			if resIoctl != SECCOMP_RET_ERRNO|EPERM {
				t.Errorf("expected TIOCSTI ioctl to be denied, got 0x%x", resIoctl)
			}
		})
	}
}

func TestIoUring_RestrictionsValidation(t *testing.T) {
	// 1. Default safe restrictions must validate cleanly
	defaults := DefaultIoUringRestrictions()
	if err := ValidateIoUringRestrictions(defaults); err != nil {
		t.Fatalf("DefaultIoUringRestrictions failed validation: %v", err)
	}

	// 2. Empty list must fail closed
	if err := ValidateIoUringRestrictions(nil); err == nil {
		t.Error("expected error for empty restrictions list, got nil")
	}

	// 3. Banned SQE opcodes must fail validation
	bannedOpcodes := []uint8{
		IORING_OP_OPENAT,
		IORING_OP_OPENAT2,
		IORING_OP_CONNECT,
		IORING_OP_ACCEPT,
		IORING_OP_SENDMSG,
		IORING_OP_RECVMSG,
		IORING_OP_SPLICE,
		IORING_OP_TEE,
		IORING_OP_UNLINKAT,
		IORING_OP_RENAMEAT,
		IORING_OP_MKDIRAT,
	}

	for _, op := range bannedOpcodes {
		malicious := []IoUringRestriction{
			{Opcode: IORING_RESTRICTION_SQE_OP, SubOp: op},
		}
		if err := ValidateIoUringRestrictions(malicious); err == nil {
			t.Errorf("expected validation failure for banned opcode %d, got nil", op)
		}
	}

	// 4. IORING_REGISTER_PERSONALITY must fail validation
	personalityMalicious := []IoUringRestriction{
		{Opcode: IORING_RESTRICTION_REGISTER_OP, SubOp: uint8(IORING_REGISTER_PERSONALITY)},
	}
	if err := ValidateIoUringRestrictions(personalityMalicious); err == nil {
		t.Error("expected validation failure for IORING_REGISTER_PERSONALITY, got nil")
	}
}

func TestIoUring_EncodeRestrictions(t *testing.T) {
	defaults := DefaultIoUringRestrictions()
	encoded, err := EncodeIoUringRestrictions(defaults)
	if err != nil {
		t.Fatalf("EncodeIoUringRestrictions failed: %v", err)
	}

	expectedLen := len(defaults) * 16 // 16 bytes per struct io_uring_restriction
	if len(encoded) != expectedLen {
		t.Fatalf("expected encoded length %d, got %d", expectedLen, len(encoded))
	}
}
