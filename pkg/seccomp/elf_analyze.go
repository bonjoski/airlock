// Package seccomp provides pure-Go Seccomp-BPF compilation and syscall
// filtering for process confinement on Linux.
package seccomp

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// NetworkSyscallsAmd64 lists the 14 core Linux x86_64 networking syscall numbers
// that are pruned (blocked) when a binary does not require network access.
var NetworkSyscallsAmd64 = []uint32{
	41, // SYS_SOCKET
	42, // SYS_CONNECT
	43, // SYS_ACCEPT
	44, // SYS_SENDTO
	45, // SYS_RECVFROM
	46, // SYS_SENDMSG
	47, // SYS_RECVMSG
	48, // SYS_SHUTDOWN
	49, // SYS_BIND
	50, // SYS_LISTEN
	51, // SYS_GETSOCKNAME
	52, // SYS_GETPEERNAME
	53, // SYS_SOCKETPAIR
	54, // SYS_SETSOCKOPT
}

// NetworkSyscallsArm64 lists the 14 core Linux aarch64 networking syscall numbers
// that are pruned (blocked) when a binary does not require network access.
var NetworkSyscallsArm64 = []uint32{
	198, // SYS_SOCKET
	199, // SYS_SOCKETPAIR
	200, // SYS_BIND
	201, // SYS_LISTEN
	202, // SYS_ACCEPT
	203, // SYS_CONNECT
	204, // SYS_GETSOCKNAME
	205, // SYS_GETPEERNAME
	206, // SYS_SENDTO
	207, // SYS_RECVFROM
	208, // SYS_SETSOCKOPT
	210, // SYS_SHUTDOWN
	211, // SYS_SENDMSG
	212, // SYS_RECVMSG
}

// NetworkSymbols is the set of known libc networking functions used to identify
// if a dynamic or unstripped static binary performs network operations.
var NetworkSymbols = map[string]struct{}{
	"socket":           {},
	"socketpair":       {},
	"bind":             {},
	"listen":           {},
	"accept":           {},
	"accept4":          {},
	"connect":          {},
	"getsockname":      {},
	"getpeername":      {},
	"send":             {},
	"sendto":           {},
	"sendmsg":          {},
	"sendmmsg":         {},
	"recv":             {},
	"recvfrom":         {},
	"recvmsg":          {},
	"recvmmsg":         {},
	"setsockopt":       {},
	"getsockopt":       {},
	"shutdown":         {},
	"getaddrinfo":      {},
	"freeaddrinfo":     {},
	"getnameinfo":      {},
	"gethostbyname":    {},
	"gethostbyname_r":  {},
	"gethostbyname2":   {},
	"gethostbyname2_r": {},
	"gethostbyaddr":    {},
	"gethostbyaddr_r":  {},
	"res_init":         {},
	"res_query":        {},
	"res_search":       {},
	"inet_addr":        {},
	"inet_aton":        {},
	"inet_ntoa":        {},
	"inet_pton":        {},
	"inet_ntop":        {},
	"getservbyname":    {},
	"getservbyport":    {},
	"getprotobyname":   {},
	"getprotobynumber": {},
	"getifaddrs":       {},
	"freeifaddrs":      {},
	"dn_expand":        {},
}

// isNetworkSymbol reports whether a symbol name corresponds to a networking operation.
// It checks standard libc function names as well as Go runtime/stdlib network symbols.
func isNetworkSymbol(sym string) bool {
	clean := strings.TrimSpace(sym)
	if clean == "" {
		return false
	}
	if _, ok := NetworkSymbols[clean]; ok {
		return true
	}

	lower := strings.ToLower(clean)
	// Check for Go stdlib networking symbols in statically linked Go ELFs
	if strings.HasPrefix(lower, "syscall.socket") ||
		strings.HasPrefix(lower, "syscall.connect") ||
		strings.HasPrefix(lower, "syscall.bind") ||
		strings.HasPrefix(lower, "syscall.listen") ||
		strings.HasPrefix(lower, "syscall.accept") ||
		strings.HasPrefix(lower, "syscall.getaddrinfo") ||
		strings.HasPrefix(lower, "net.") ||
		strings.HasPrefix(lower, "crypto/tls.") {
		return true
	}

	return false
}

// NetworkSyscalls returns the architecture-specific network syscall numbers.
func NetworkSyscalls(arch string) ([]uint32, error) {
	switch arch {
	case "amd64", "x86_64":
		ret := make([]uint32, len(NetworkSyscallsAmd64))
		copy(ret, NetworkSyscallsAmd64)
		return ret, nil
	case "arm64", "aarch64":
		ret := make([]uint32, len(NetworkSyscallsArm64))
		copy(ret, NetworkSyscallsArm64)
		return ret, nil
	default:
		return nil, fmt.Errorf("seccomp: unsupported architecture %q for network syscalls: %w", arch, errors.ErrUnsupported)
	}
}

// ELFAnalysisResult captures the static analysis findings for an ELF binary.
type ELFAnalysisResult struct {
	Path              string
	IsELF             bool
	IsDynamic         bool
	IsStatic          bool
	IsStripped        bool
	HasNetworkSymbols bool
	DetectedSymbols   []string
	Prunable          bool
	PrunedSyscallNrs  []uint32
}

// AnalyzeELF inspects an executable binary using standard library debug/elf to determine
// whether network-related dynamic or static symbols are present.
//
// Fail-Closed Security Model:
//   - If the target is not an ELF binary (e.g. script, Mach-O), Prunable is false.
//   - If the target is a statically linked binary with stripped symbols (.symtab missing),
//     Prunable is false because direct raw syscalls or static networking cannot be ruled out.
//   - Prunable is true ONLY if the binary is verified to have symbols and none match networking.
func AnalyzeELF(path string, arch string) (*ELFAnalysisResult, error) {
	if arch == "" {
		arch = runtime.GOARCH
	}

	res := &ELFAnalysisResult{
		Path: path,
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("seccomp: failed to open binary for ELF inspection: %w", err)
	}
	defer file.Close()

	elfFile, err := elf.NewFile(file)
	if err != nil {
		// Not an ELF binary (e.g. script, Mach-O, PE). Fail closed by not pruning.
		res.IsELF = false
		res.Prunable = false
		return res, nil
	}
	defer elfFile.Close()

	res.IsELF = true

	// Check if dynamically linked
	hasInterp := elfFile.Section(".interp") != nil
	imported, _ := elfFile.ImportedSymbols()
	dynSyms, _ := elfFile.DynamicSymbols()

	if hasInterp || len(imported) > 0 || len(dynSyms) > 0 {
		res.IsDynamic = true
		res.IsStatic = false

		detected := make(map[string]struct{})

		for _, imp := range imported {
			symName := strings.TrimSpace(imp.Name)
			if isNetworkSymbol(symName) {
				detected[symName] = struct{}{}
			}
		}

		for _, dyn := range dynSyms {
			symName := strings.TrimSpace(dyn.Name)
			if isNetworkSymbol(symName) {
				detected[symName] = struct{}{}
			}
		}

		for sym := range detected {
			res.DetectedSymbols = append(res.DetectedSymbols, sym)
		}

		if len(res.DetectedSymbols) > 0 {
			res.HasNetworkSymbols = true
			res.Prunable = false
		} else {
			res.HasNetworkSymbols = false
			res.Prunable = true
		}
	} else {
		// Statically linked binary
		res.IsStatic = true
		res.IsDynamic = false

		symtab := elfFile.Section(".symtab")
		if symtab == nil {
			// Statically linked and stripped! Fail-closed: cannot verify absence of networking.
			res.IsStripped = true
			res.Prunable = false
			return res, nil
		}

		syms, err := elfFile.Symbols()
		if err != nil || len(syms) == 0 {
			res.IsStripped = true
			res.Prunable = false
			return res, nil
		}

		detected := make(map[string]struct{})
		for _, sym := range syms {
			symName := strings.TrimSpace(sym.Name)
			if isNetworkSymbol(symName) {
				detected[symName] = struct{}{}
			}
		}

		for sym := range detected {
			res.DetectedSymbols = append(res.DetectedSymbols, sym)
		}

		if len(res.DetectedSymbols) > 0 {
			res.HasNetworkSymbols = true
			res.Prunable = false
		} else {
			res.HasNetworkSymbols = false
			res.Prunable = true
		}
	}

	if res.Prunable {
		syscalls, err := NetworkSyscalls(arch)
		if err == nil {
			res.PrunedSyscallNrs = syscalls
		}
	}

	return res, nil
}
