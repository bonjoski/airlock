//go:build !windows
// +build !windows

package secrets

import "syscall"

func getProcessGroupID() int {
	return syscall.Getpgrp()
}
