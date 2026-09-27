package seccomp

import (
	"encoding/binary"
	"os"
	"testing"
)

// bpfVM is a lightweight classic BPF emulator for verifying seccomp filter logic in tests.
type bpfVM struct {
	instructions []SockFilter
}

type seccompDataSim struct {
	nr   int32
	arch uint32
	args [6]uint64
}

func (sim *seccompDataSim) read32(offset uint32) uint32 {
	switch {
	case offset == SeccompDataNrOffset:
		return uint32(sim.nr)
	case offset == SeccompDataArchOffset:
		return sim.arch
	case offset >= SeccompDataArgsOffset && offset < SeccompDataArgsOffset+48:
		argIdx := (offset - SeccompDataArgsOffset) / 8
		isHigh := (offset-SeccompDataArgsOffset)%8 >= 4
		val := sim.args[argIdx]
		if isHigh {
			return uint32(val >> 32)
		}
		return uint32(val & 0xffffffff)
	default:
		return 0
	}
}

func (vm *bpfVM) run(data seccompDataSim) uint32 {
	var a uint32
	pc := 0

	for pc < len(vm.instructions) {
		inst := vm.instructions[pc]
		pc++

		switch inst.Code {
		case BPF_LD | BPF_W | BPF_ABS:
			a = data.read32(inst.K)
		case BPF_JMP | BPF_JEQ | BPF_K:
			if a == inst.K {
				pc += int(inst.Jt)
			} else {
				pc += int(inst.Jf)
			}
		case BPF_RET | BPF_K:
			return inst.K
		default:
			panic("unsupported BPF instruction in test emulator")
		}
	}

	return 0
}

func TestFilter_Compile_Amd64(t *testing.T) {
	filter := NewFilter()
	data, err := filter.Compile("amd64")
	if err != nil {
		t.Fatalf("Compile(amd64) failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Compile(amd64) returned empty bytecode")
	}

	if len(data)%8 != 0 {
		t.Fatalf("Bytecode length %d is not a multiple of 8 (sock_filter size)", len(data))
	}
}

func TestFilter_Compile_Arm64(t *testing.T) {
	filter := NewFilter()
	data, err := filter.Compile("arm64")
	if err != nil {
		t.Fatalf("Compile(arm64) failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Compile(arm64) returned empty bytecode")
	}

	if len(data)%8 != 0 {
		t.Fatalf("Bytecode length %d is not a multiple of 8 (sock_filter size)", len(data))
	}
}

func TestFilter_UnsupportedArch(t *testing.T) {
	filter := NewFilter()
	_, err := filter.Compile("mips")
	if err == nil {
		t.Fatal("Expected error for unsupported architecture 'mips', got nil")
	}
}

func TestFilter_Simulation_Amd64(t *testing.T) {
	filter := NewFilter()
	instructions, err := filter.CompileInstructions("amd64")
	if err != nil {
		t.Fatalf("CompileInstructions failed: %v", err)
	}

	vm := &bpfVM{instructions: instructions}

	// 1. Architecture mismatch -> KILL
	mismatchData := seccompDataSim{
		arch: AUDIT_ARCH_AARCH64, // wrong arch for amd64 filter
		nr:   0,                  // read
	}
	if ret := vm.run(mismatchData); ret != SECCOMP_RET_KILL_PROCESS {
		t.Errorf("Expected SECCOMP_RET_KILL_PROCESS on arch mismatch, got 0x%x", ret)
	}

	// 2. Normal allowed syscalls (read, write, getpid) -> ALLOW
	allowedSyscalls := []int32{0 /* read */, 1 /* write */, 39 /* getpid */}
	for _, nr := range allowedSyscalls {
		d := seccompDataSim{
			arch: AUDIT_ARCH_X86_64,
			nr:   nr,
		}
		if ret := vm.run(d); ret != SECCOMP_RET_ALLOW {
			t.Errorf("Expected syscall %d to be allowed, got 0x%x", nr, ret)
		}
	}

	// 3. Blocked syscalls -> ERRNO EPERM
	cfg, _ := GetSyscallConfig("amd64")
	for _, blockedNr := range cfg.Blocked {
		d := seccompDataSim{
			arch: AUDIT_ARCH_X86_64,
			nr:   int32(blockedNr),
		}
		expected := uint32(SECCOMP_RET_ERRNO | EPERM)
		if ret := vm.run(d); ret != expected {
			t.Errorf("Expected blocked syscall %d to return 0x%x, got 0x%x", blockedNr, expected, ret)
		}
	}

	// 4. Safe ioctl (e.g. TCGETS = 0x5401) -> ALLOW
	safeIoctl := seccompDataSim{
		arch: AUDIT_ARCH_X86_64,
		nr:   int32(cfg.IoctlNr),
		args: [6]uint64{0, 0x5401 /* TCGETS */, 0, 0, 0, 0},
	}
	if ret := vm.run(safeIoctl); ret != SECCOMP_RET_ALLOW {
		t.Errorf("Expected safe ioctl to be allowed, got 0x%x", ret)
	}

	// 5. Malicious ioctl (TIOCSTI = 0x5412) -> ERRNO EPERM
	maliciousIoctl := seccompDataSim{
		arch: AUDIT_ARCH_X86_64,
		nr:   int32(cfg.IoctlNr),
		args: [6]uint64{0, TIOCSTI, 0, 0, 0, 0},
	}
	expectedDeny := uint32(SECCOMP_RET_ERRNO | EPERM)
	if ret := vm.run(maliciousIoctl); ret != expectedDeny {
		t.Errorf("Expected TIOCSTI ioctl to be denied with 0x%x, got 0x%x", expectedDeny, ret)
	}
}

func TestFilter_Simulation_Arm64(t *testing.T) {
	filter := NewFilter()
	instructions, err := filter.CompileInstructions("arm64")
	if err != nil {
		t.Fatalf("CompileInstructions failed: %v", err)
	}

	vm := &bpfVM{instructions: instructions}

	// 1. Architecture mismatch -> KILL
	mismatchData := seccompDataSim{
		arch: AUDIT_ARCH_X86_64, // wrong arch for arm64 filter
		nr:   63,                // read on arm64
	}
	if ret := vm.run(mismatchData); ret != SECCOMP_RET_KILL_PROCESS {
		t.Errorf("Expected SECCOMP_RET_KILL_PROCESS on arch mismatch, got 0x%x", ret)
	}

	// 2. Normal allowed syscalls (read=63, write=64, getpid=172 on arm64) -> ALLOW
	allowedSyscalls := []int32{63, 64, 172}
	for _, nr := range allowedSyscalls {
		d := seccompDataSim{
			arch: AUDIT_ARCH_AARCH64,
			nr:   nr,
		}
		if ret := vm.run(d); ret != SECCOMP_RET_ALLOW {
			t.Errorf("Expected arm64 syscall %d to be allowed, got 0x%x", nr, ret)
		}
	}

	// 3. Blocked syscalls -> ERRNO EPERM
	cfg, _ := GetSyscallConfig("arm64")
	for _, blockedNr := range cfg.Blocked {
		d := seccompDataSim{
			arch: AUDIT_ARCH_AARCH64,
			nr:   int32(blockedNr),
		}
		expected := uint32(SECCOMP_RET_ERRNO | EPERM)
		if ret := vm.run(d); ret != expected {
			t.Errorf("Expected blocked arm64 syscall %d to return 0x%x, got 0x%x", blockedNr, expected, ret)
		}
	}

	// 4. Safe ioctl -> ALLOW
	safeIoctl := seccompDataSim{
		arch: AUDIT_ARCH_AARCH64,
		nr:   int32(cfg.IoctlNr),
		args: [6]uint64{0, 0x5401, 0, 0, 0, 0},
	}
	if ret := vm.run(safeIoctl); ret != SECCOMP_RET_ALLOW {
		t.Errorf("Expected safe ioctl to be allowed on arm64, got 0x%x", ret)
	}

	// 5. Malicious ioctl (TIOCSTI) -> ERRNO EPERM
	maliciousIoctl := seccompDataSim{
		arch: AUDIT_ARCH_AARCH64,
		nr:   int32(cfg.IoctlNr),
		args: [6]uint64{0, TIOCSTI, 0, 0, 0, 0},
	}
	expectedDeny := uint32(SECCOMP_RET_ERRNO | EPERM)
	if ret := vm.run(maliciousIoctl); ret != expectedDeny {
		t.Errorf("Expected TIOCSTI ioctl to be denied on arm64 with 0x%x, got 0x%x", expectedDeny, ret)
	}
}

func TestFilter_CreateFilterFile(t *testing.T) {
	filter := NewFilter()
	file, err := filter.CreateFilterFile("amd64")
	if err != nil {
		t.Fatalf("CreateFilterFile failed: %v", err)
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()

	stat, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if stat.Size() == 0 || stat.Size()%8 != 0 {
		t.Errorf("Filter file size %d invalid", stat.Size())
	}

	// Read and verify first instruction is BPF_LD | BPF_W | BPF_ABS
	buf := make([]byte, 8)
	if _, err := file.Read(buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	code := binary.LittleEndian.Uint16(buf[0:2])
	if code != (BPF_LD | BPF_W | BPF_ABS) {
		t.Errorf("First instruction code 0x%x, expected 0x%x", code, BPF_LD|BPF_W|BPF_ABS)
	}
}
