//go:build windows
// +build windows

package secrets

import "os"

func getProcessGroupID() int {
	return os.Getpid()
}
