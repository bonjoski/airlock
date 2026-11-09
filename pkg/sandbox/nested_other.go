//go:build !darwin && !linux

package sandbox

func isKernelSandboxed() bool {
	return false
}
