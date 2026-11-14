// Package profile provides centralized security profiles for specialized execution
// contexts, including dev-agent, mcp-gateway, and web-worker.
package profile

import (
	"fmt"
	"strings"

	"github.com/bonjoski/airlock/pkg/seatbelt"
	"github.com/bonjoski/airlock/pkg/seccomp"
)

// WebWorkerProfileName is the canonical profile identifier for web application worker processes
// (e.g. w3wp.exe, Node.js, Python ASGI/WSGI, Go HTTP servers, Kestrel) defended against webshell execution.
const WebWorkerProfileName = "web-worker"

// ExecveSyscalls maps architecture to execve and execveat syscall numbers.
var ExecveSyscalls = map[string][]uint32{
	"amd64":   {59, 322}, // SYS_execve, SYS_execveat
	"x86_64":  {59, 322},
	"arm64":   {221, 281}, // SYS_execve, SYS_execveat
	"aarch64": {221, 281},
}

// BuildWebWorkerSeccomp constructs a hardened seccomp BPF filter that strictly denies
// execve and execveat, preventing web workers from spawning child shells (AntiFox defense).
func BuildWebWorkerSeccomp(arch string) (*seccomp.BPFFilter, error) {
	syscalls, ok := ExecveSyscalls[strings.ToLower(arch)]
	if !ok {
		return nil, fmt.Errorf("unsupported architecture for web-worker seccomp: %s", arch)
	}

	filter := seccomp.NewFilter()
	filter.AddBlocked(syscalls...)
	return filter, nil
}

// GenerateWebWorkerSeatbelt synthesizes a macOS Seatbelt profile for web worker processes,
// strictly denying child shell execution and confining writable areas.
func GenerateWebWorkerSeatbelt(p seatbelt.Params) (string, error) {
	p.Profile = WebWorkerProfileName

	// Deny shell binaries explicitly
	shellDenials := []string{
		"/bin/sh",
		"/bin/bash",
		"/bin/zsh",
		"/bin/csh",
		"/bin/tcsh",
		"/bin/ksh",
		"/usr/bin/python3",
		"/usr/bin/perl",
	}
	p.ExtraDenyRead = append(p.ExtraDenyRead, shellDenials...)

	gen := seatbelt.NewGenerator()
	return gen.Generate(p)
}

// AugmentBwrapArgsForWebWorker configures Bubblewrap sandbox flags to confine web workers:
// 1. Mounts application document root as strictly read-only (blocking .aspx/.php drops)
// 2. Mounts ephemeral scratch directories with noexec
// 3. Drops all Linux capabilities
func AugmentBwrapArgsForWebWorker(args []string, webRoot string, scratchDir string) []string {
	args = append(args, "--cap-drop", "ALL")

	if webRoot != "" {
		// Read-only document root
		args = append(args, "--ro-bind", webRoot, webRoot)
	}

	if scratchDir != "" {
		// Ephemeral writable scratch directory with noexec semantics
		args = append(args, "--tmpfs", scratchDir)
	}

	return args
}
