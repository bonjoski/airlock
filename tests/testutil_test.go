package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PlatformCmd adapts Unix-style commands (/bin/sh, /bin/echo, /bin/cat, echo)
// to platform-appropriate commands on Windows (cmd.exe /c ...) while preserving
// the arguments on POSIX systems.
func PlatformCmd(args ...string) []string {
	if len(args) == 0 {
		return args
	}

	if runtime.GOOS != "windows" {
		return args
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "/bin/sh", "/bin/bash", "sh", "bash":
		if len(rest) >= 2 && rest[0] == "-c" {
			return append([]string{"cmd.exe", "/c"}, rest[1:]...)
		}
		return append([]string{"cmd.exe", "/c"}, rest...)

	case "/bin/echo", "echo":
		return append([]string{"cmd.exe", "/c", "echo"}, rest...)

	case "/bin/cat", "cat":
		return append([]string{"cmd.exe", "/c", "type"}, rest...)

	case "/bin/true", "/usr/bin/true":
		return []string{"cmd.exe", "/c", "exit 0"}

	default:
		return args
	}
}

// PlatformCmdString converts a shell command line for platform execution.
// For example, "/bin/cat /path/to/file" becomes "cmd.exe /c type C:\path\to\file" on Windows.
func PlatformCmdString(cmdStr string) string {
	if runtime.GOOS != "windows" {
		return cmdStr
	}

	fields := strings.Fields(cmdStr)
	adapted := PlatformCmd(fields...)
	return strings.Join(adapted, " ")
}

// PlatformPath converts a path to a slash-normalized format that is safe for JSON payloads
// and valid across both POSIX and Windows filesystems without escape corruption.
func PlatformPath(p string) string {
	return filepath.ToSlash(filepath.Clean(p))
}

// PlatformPathList joins directory paths using the OS-specific PATH separator (: on Unix, ; on Windows).
func PlatformPathList(dirs ...string) string {
	return strings.Join(dirs, string(os.PathListSeparator))
}

// JSONRPCRequest serializes a JSON-RPC 2.0 tool/method request with automatic JSON escaping,
// preventing path backslash syntax corruption on Windows.
func JSONRPCRequest(id any, method string, params any) []byte {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	return b
}

// JSONRPCToolCall generates a tools/call request payload safely.
func JSONRPCToolCall(id any, toolName string, arguments map[string]interface{}) []byte {
	return JSONRPCRequest(id, "tools/call", map[string]interface{}{
		"name":      toolName,
		"arguments": arguments,
	})
}
