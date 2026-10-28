package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/redact"
)

// Runner defines a clean in-process execution interface for Airlock confinement.
// It allows callers like Aegisbox and Fabrial to invoke Airlock without shelling out.
type Runner interface {
	Execute(ctx context.Context, cmd []string, opts SandboxOpts) (*ExecResult, error)
}

// ExecResult encapsulates structured execution results and telemetry from a sandboxed process.
type ExecResult struct {
	ExitCode       int      `json:"exit_code"`
	Stdout         string   `json:"stdout"`
	Stderr         string   `json:"stderr"`
	DurationMs     int64    `json:"duration_ms"`
	Airgap         bool     `json:"airgap"`
	AllowedDomains []string `json:"allowed_domains"`
	Error          string   `json:"error,omitempty"`
}

// Success returns true if the execution completed with exit code 0 and no error.
func (r *ExecResult) Success() bool {
	return r != nil && r.ExitCode == 0 && r.Error == ""
}

// DefaultRunner implements the Runner interface.
type DefaultRunner struct{}

// NewRunner creates a new in-process Airlock Runner.
func NewRunner() Runner {
	return &DefaultRunner{}
}

// Execute executes a command inside the Airlock sandbox in-process.
func (r *DefaultRunner) Execute(ctx context.Context, cmd []string, opts SandboxOpts) (*ExecResult, error) {
	if len(cmd) == 0 {
		return nil, errors.New("sandbox: no command specified for execution")
	}

	start := time.Now()

	workspaceRoot := opts.WorkspaceRoot
	if workspaceRoot == "" {
		cwd, err := os.Getwd()
		if err == nil {
			workspaceRoot = FindWorkspaceRoot(cwd)
		}
	}

	// 1. Resolve Profile and Policy Configuration
	var loadedCfg *config.Config
	if opts.Profile != "" {
		prof, err := config.GetBuiltinProfile(opts.Profile)
		if err != nil {
			return &ExecResult{
				ExitCode:   1,
				Error:      err.Error(),
				DurationMs: time.Since(start).Milliseconds(),
			}, err
		}
		loadedCfg = prof
		// If profile is agent and no secrets explicitly specified, auto-lease common agent credentials
		if strings.EqualFold(opts.Profile, config.ProfileAgent) && len(opts.LeasedSecrets) == 0 {
			opts.LeasedSecrets = append(opts.LeasedSecrets, config.AgentDefaultSecrets...)
		}
	}

	if opts.ConfigPath != "" {
		cfg, err := config.LoadFromFile(opts.ConfigPath)
		if err != nil {
			return &ExecResult{
				ExitCode:   1,
				Error:      fmt.Sprintf("error loading config %q: %v", opts.ConfigPath, err),
				DurationMs: time.Since(start).Milliseconds(),
			}, err
		}
		if loadedCfg != nil {
			loadedCfg = config.MergeProfiles(loadedCfg, cfg)
		} else {
			loadedCfg = cfg
		}
	} else if workspaceRoot != "" {
		if _, cfg, _, err := config.DiscoverConfigWithIssues(workspaceRoot); err == nil && cfg != nil {
			if loadedCfg != nil {
				loadedCfg = config.MergeProfiles(loadedCfg, cfg)
			} else {
				loadedCfg = cfg
			}
		}
	}

	// 2. Synthesize Effective Sandbox Options
	effectiveOpts := opts
	effectiveOpts.WorkspaceRoot = workspaceRoot

	workingDir := opts.WorkingDir
	if workingDir == "" {
		if cwd, err := os.Getwd(); err == nil {
			workingDir = cwd
		} else {
			workingDir = workspaceRoot
		}
	}
	if resolved, err := filepath.EvalSymlinks(workingDir); err == nil {
		workingDir = resolved
	}
	effectiveOpts.WorkingDir = workingDir

	if loadedCfg != nil {
		config.SanitizeAndEnforceGuardrails(loadedCfg)

		if loadedCfg.Network.Airgap && !effectiveOpts.AllowDirectNet {
			effectiveOpts.Airgap = true
		}
		effectiveOpts.AllowedDomains = mergeUniqueStrings(effectiveOpts.AllowedDomains, loadedCfg.Network.AllowDomains)
		effectiveOpts.KeepEnv = mergeUniqueStrings(effectiveOpts.KeepEnv, loadedCfg.Env.Allow)
		effectiveOpts.DenyEnv = mergeUniqueStrings(effectiveOpts.DenyEnv, loadedCfg.Env.Deny)
		effectiveOpts.ExtraAllowRead = mergeUniqueStrings(effectiveOpts.ExtraAllowRead, loadedCfg.Filesystem.AllowRead)
		effectiveOpts.ExtraAllowWrite = mergeUniqueStrings(effectiveOpts.ExtraAllowWrite, loadedCfg.Filesystem.AllowWrite)
		effectiveOpts.ExtraDenyRead = mergeUniqueStrings(effectiveOpts.ExtraDenyRead, loadedCfg.Filesystem.DenyRead)
		effectiveOpts.ExtraDenyWrite = mergeUniqueStrings(effectiveOpts.ExtraDenyWrite, loadedCfg.Filesystem.DenyWrite)

		if loadedCfg.Vetting.Enable {
			effectiveOpts.VetEnabled = true
		}
		if loadedCfg.Vetting.Strict {
			effectiveOpts.VetStrict = true
		}
		effectiveOpts.IgnoredVetRules = mergeUniqueStrings(effectiveOpts.IgnoredVetRules, loadedCfg.Vetting.IgnoredRules)
	}

	// 3. Setup Captured / Streamed Output
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	if opts.Stdout != nil {
		effectiveOpts.Stdout = io.MultiWriter(&stdoutBuf, opts.Stdout)
	} else {
		effectiveOpts.Stdout = &stdoutBuf
	}

	if opts.Stderr != nil {
		effectiveOpts.Stderr = io.MultiWriter(&stderrBuf, opts.Stderr)
	} else {
		effectiveOpts.Stderr = &stderrBuf
	}

	// 4. Construct Sandbox Confinement Engine
	eng, err := NewEngine(effectiveOpts)
	if err != nil {
		res := &ExecResult{
			ExitCode:       1,
			Error:          fmt.Sprintf("sandbox: engine initialization error: %v", err),
			DurationMs:     time.Since(start).Milliseconds(),
			Airgap:         effectiveOpts.Airgap,
			AllowedDomains: effectiveOpts.AllowedDomains,
		}
		return res, err
	}

	// 5. Execute Command Inside Confinement Boundary
	exitCode, execErr := eng.Execute(ctx, cmd)
	duration := time.Since(start)

	res := &ExecResult{
		ExitCode:       exitCode,
		Stdout:         redact.RedactString(stdoutBuf.String()),
		Stderr:         redact.RedactString(stderrBuf.String()),
		DurationMs:     duration.Milliseconds(),
		Airgap:         effectiveOpts.Airgap,
		AllowedDomains: effectiveOpts.AllowedDomains,
	}
	if execErr != nil {
		res.Error = execErr.Error()
	}

	return res, execErr
}

// Execute runs a command inside the Airlock sandbox using the default in-process Runner.
func Execute(ctx context.Context, cmd []string, opts SandboxOpts) (*ExecResult, error) {
	return NewRunner().Execute(ctx, cmd, opts)
}

func mergeUniqueStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var res []string
	for _, v := range a {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			res = append(res, v)
		}
	}
	for _, v := range b {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			res = append(res, v)
		}
	}
	return res
}
