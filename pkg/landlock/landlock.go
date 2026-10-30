// Package landlock provides pure-Go Linux Landlock LSM confinement primitives
// for restricting filesystem and network capabilities in unprivileged processes.
package landlock

import (
	"errors"
	"path/filepath"
	"strings"
)

// Linux Landlock syscall numbers (Linux 5.13+)
const (
	SysLandlockCreateRuleset = 444
	SysLandlockAddRule       = 445
	SysLandlockRestrictSelf  = 446
)

// Landlock rule types (<linux/landlock.h>)
const (
	RuleTypePathBeneath = 1
)

// Landlock create_ruleset flags
const (
	CreateRulesetVersion = 1 << 0
)

// Landlock Access FS flags (<linux/landlock.h>)
const (
	AccessFSExecute    = 1 << 0
	AccessFSWriteFile  = 1 << 1
	AccessFSReadFile   = 1 << 2
	AccessFSReadDir    = 1 << 3
	AccessFSRemoveDir  = 1 << 4
	AccessFSRemoveFile = 1 << 5
	AccessFSMakeChar   = 1 << 6
	AccessFSMakeDir    = 1 << 7
	AccessFSMakeReg    = 1 << 8
	AccessFSMakeSock   = 1 << 9
	AccessFSMakeFifo   = 1 << 10
	AccessFSMakeBlock  = 1 << 11
	AccessFSMakeSym    = 1 << 12
	AccessFSRefer      = 1 << 13
	AccessFSTruncate   = 1 << 14
	AccessFSIoctlDev   = 1 << 15

	AccessFSRead  = AccessFSExecute | AccessFSReadFile | AccessFSReadDir
	AccessFSWrite = AccessFSWriteFile | AccessFSRemoveDir | AccessFSRemoveFile |
		AccessFSMakeChar | AccessFSMakeDir | AccessFSMakeReg | AccessFSMakeSock |
		AccessFSMakeFifo | AccessFSMakeBlock | AccessFSMakeSym | AccessFSRefer | AccessFSTruncate
	AccessFSAll = AccessFSRead | AccessFSWrite
)

var (
	// ErrLandlockNotSupported indicates that the running kernel does not support Landlock.
	ErrLandlockNotSupported = errors.New("landlock: LSM is not supported on this kernel or platform")
)

// RulesetAttr is struct landlock_ruleset_attr (<linux/landlock.h>).
type RulesetAttr struct {
	HandledAccessFS uint64
}

// PathBeneathAttr is struct landlock_path_beneath_attr (<linux/landlock.h>).
type PathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
}

// PathRule associates a filesystem path with permitted Landlock access flags.
type PathRule struct {
	Path   string
	Access uint64
}

// Ruleset defines the Landlock LSM policy for process isolation.
type Ruleset struct {
	HandledAccessFS uint64
	Rules           []PathRule
	DenyPaths       []string
}

// Config specifies input directories for synthesizing a Landlock ruleset.
type Config struct {
	WorkspaceRoot   string
	ScratchDir      string
	UserHome        string
	ExtraAllowRead  []string
	ExtraAllowWrite []string
	ExtraDenyRead   []string
}

// DevAgentDefaultDenyPaths lists credentials and secrets forbidden in dev-agent profile.
var DevAgentDefaultDenyPaths = []string{
	"~/.ssh",
	"~/.aws",
	"~/.gnupg",
	"~/.kube",
	"~/.config/gh",
	"~/.config/gcloud",
	"/var/run/docker.sock",
	".env",
	".env.*",
}

// BuildDevAgentRuleset synthesizes a fail-closed Landlock policy for the dev-agent profile.
// In Landlock's model, any path not explicitly granted access is denied by the kernel.
// Host secrets (~/.ssh, ~/.aws, etc.) are omitted from all rule allowances.
func BuildDevAgentRuleset(cfg Config) *Ruleset {
	rs := &Ruleset{
		HandledAccessFS: AccessFSAll,
		DenyPaths:       append([]string(nil), DevAgentDefaultDenyPaths...),
	}

	// 1. System toolchains and runtime paths (Read-Only)
	systemDirs := []string{
		"/usr",
		"/lib",
		"/lib64",
		"/bin",
		"/sbin",
		"/opt",
		"/etc",
	}
	for _, sys := range systemDirs {
		rs.Rules = append(rs.Rules, PathRule{
			Path:   sys,
			Access: AccessFSRead,
		})
	}

	// 2. User toolchains (Read-Only)
	if cfg.UserHome != "" {
		toolchains := []string{
			filepath.Join(cfg.UserHome, ".cargo", "bin"),
			filepath.Join(cfg.UserHome, ".rustup"),
			filepath.Join(cfg.UserHome, "go", "bin"),
			filepath.Join(cfg.UserHome, ".nvm"),
			filepath.Join(cfg.UserHome, ".fnm"),
			filepath.Join(cfg.UserHome, ".pyenv"),
			filepath.Join(cfg.UserHome, ".local", "bin"),
		}
		for _, tc := range toolchains {
			rs.Rules = append(rs.Rules, PathRule{
				Path:   tc,
				Access: AccessFSRead,
			})
		}
	}

	// 3. Workspace Root (Read-Write)
	if cfg.WorkspaceRoot != "" {
		rs.Rules = append(rs.Rules, PathRule{
			Path:   cfg.WorkspaceRoot,
			Access: AccessFSAll,
		})
	}

	// 4. Ephemeral Scratch Directory & Temp (Read-Write)
	if cfg.ScratchDir != "" {
		rs.Rules = append(rs.Rules, PathRule{
			Path:   cfg.ScratchDir,
			Access: AccessFSAll,
		})
	}
	rs.Rules = append(rs.Rules, PathRule{
		Path:   "/tmp",
		Access: AccessFSAll,
	})

	// 5. Extra allowances
	for _, p := range cfg.ExtraAllowRead {
		cleaned := strings.TrimSpace(p)
		if cleaned != "" {
			rs.Rules = append(rs.Rules, PathRule{
				Path:   cleaned,
				Access: AccessFSRead,
			})
		}
	}
	for _, p := range cfg.ExtraAllowWrite {
		cleaned := strings.TrimSpace(p)
		if cleaned != "" {
			rs.Rules = append(rs.Rules, PathRule{
				Path:   cleaned,
				Access: AccessFSAll,
			})
		}
	}

	return rs
}
