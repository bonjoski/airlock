package doctor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/shim"
)

// FixStatus describes the outcome of an individual remediation action.
type FixStatus string

const (
	FixRepaired FixStatus = "REPAIRED"
	FixSkipped  FixStatus = "SKIPPED"
	FixFailed   FixStatus = "FAILED"
)

// FixAction records an individual auto-remediation step taken.
type FixAction struct {
	ID      string    `json:"id"`
	Title   string    `json:"title"`
	Status  FixStatus `json:"status"`
	Details string    `json:"details,omitempty"`
}

// FixReport summarizes all auto-remediation actions executed by AutoFix.
type FixReport struct {
	Actions  []FixAction `json:"actions"`
	Repaired int         `json:"repaired"`
	Skipped  int         `json:"skipped"`
	Failed   int         `json:"failed"`
}

// AutoFix executes automated remediations for diagnostic findings:
// 1. Safely removes $HOME/.airlock/bin/airlock shadowing Homebrew.
// 2. Uninstalls orphan shims where host binaries are missing from $PATH.
// 3. Generates baseline airlock.yaml declarative policy if missing from workspace.
// 4. Ensures scratch and cache directories exist with strict 0700 private permissions.
func AutoFix(ctx context.Context, opts Options) (*FixReport, error) {
	if opts.WorkspaceRoot == "" {
		if cwd, err := os.Getwd(); err == nil {
			opts.WorkspaceRoot = cwd
		}
	}
	if opts.HomeDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			opts.HomeDir = home
		}
	}
	if opts.PathEnv == "" {
		opts.PathEnv = os.Getenv("PATH")
	}
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}
	if opts.ShimDir == "" && opts.HomeDir != "" {
		opts.ShimDir = filepath.Join(opts.HomeDir, ".airlock", "bin")
	}

	report := &FixReport{
		Actions: make([]FixAction, 0, 4),
	}

	// 1. Remove shadowed airlock binary from shim directory
	act1 := autoFixShadowedAirlock(opts)
	report.Actions = append(report.Actions, act1)

	// 2. Clean up orphan shims
	act2 := autoFixOrphanShims(opts)
	report.Actions = append(report.Actions, act2)

	// 3. Ensure baseline declarative policy
	act3 := autoFixDeclarativeConfig(opts)
	report.Actions = append(report.Actions, act3)

	// 4. Ensure scratch/cache directories with 0700 permissions
	act4 := autoFixStoragePermissions(opts)
	report.Actions = append(report.Actions, act4)

	for _, a := range report.Actions {
		switch a.Status {
		case FixRepaired:
			report.Repaired++
		case FixSkipped:
			report.Skipped++
		case FixFailed:
			report.Failed++
		}
	}

	return report, nil
}

// autoFixShadowedAirlock safely removes $HOME/.airlock/bin/airlock if it exists.
func autoFixShadowedAirlock(opts Options) FixAction {
	action := FixAction{
		ID:    "shims-shadowing-airlock",
		Title: "Remove shadowed airlock executable from shim directory",
	}

	shimDir := opts.ShimDir
	if shimDir == "" && opts.HomeDir != "" {
		shimDir = filepath.Join(opts.HomeDir, ".airlock", "bin")
	}
	if shimDir == "" {
		action.Status = FixSkipped
		action.Details = "Shim directory cannot be determined"
		return action
	}

	cleanShimDir := filepath.Clean(shimDir)
	candidates := []string{"airlock"}
	if opts.GOOS == "windows" {
		candidates = append(candidates, "airlock.exe")
	}

	var removed []string
	var failures []string

	for _, name := range candidates {
		targetPath := filepath.Join(cleanShimDir, name)
		cleanTarget := filepath.Clean(targetPath)

		// Adversarial check: verify path does not escape cleanShimDir
		if filepath.Dir(cleanTarget) != cleanShimDir {
			failures = append(failures, fmt.Sprintf("Path traversal rejected for %s", targetPath))
			continue
		}

		fi, err := os.Lstat(cleanTarget)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			failures = append(failures, fmt.Sprintf("Failed to stat %s: %v", cleanTarget, err))
			continue
		}

		if fi.IsDir() {
			failures = append(failures, fmt.Sprintf("%s is a directory, refusing to delete", cleanTarget))
			continue
		}

		// Verify regular file or symlink
		if !fi.Mode().IsRegular() && (fi.Mode()&os.ModeSymlink == 0) {
			failures = append(failures, fmt.Sprintf("%s is a special device/socket/fifo, refusing to delete", cleanTarget))
			continue
		}

		// Safely remove file/symlink (os.Remove unlinks symlinks without following)
		if err := os.Remove(cleanTarget); err != nil {
			failures = append(failures, fmt.Sprintf("Failed to remove %s: %v", cleanTarget, err))
			continue
		}

		removed = append(removed, cleanTarget)
	}

	if len(failures) > 0 {
		action.Status = FixFailed
		action.Details = strings.Join(failures, "; ")
		return action
	}

	if len(removed) > 0 {
		action.Status = FixRepaired
		action.Details = fmt.Sprintf("Safely removed shadowed airlock executable: %s", strings.Join(removed, ", "))
		return action
	}

	action.Status = FixSkipped
	action.Details = "No shadowed airlock binary present in shim directory"
	return action
}

// autoFixOrphanShims cleans up active shims whose host binaries are not found on $PATH.
func autoFixOrphanShims(opts Options) FixAction {
	action := FixAction{
		ID:    "shims-orphan-cleanup",
		Title: "Clean up orphan toolchain shims",
	}

	shimDir := opts.ShimDir
	if shimDir == "" && opts.HomeDir != "" {
		shimDir = filepath.Join(opts.HomeDir, ".airlock", "bin")
	}
	if shimDir == "" {
		action.Status = FixSkipped
		action.Details = "Shim directory cannot be determined"
		return action
	}

	pathVar := opts.PathEnv
	if pathVar == "" {
		pathVar = os.Getenv("PATH")
	}

	mgr := shim.NewManager()
	shims, err := mgr.ListWithPath(shimDir, pathVar)
	if err != nil {
		action.Status = FixFailed
		action.Details = fmt.Sprintf("Failed to list shims in %s: %v", shimDir, err)
		return action
	}

	var orphanTools []string
	for _, s := range shims {
		if s.Installed && s.TargetHostBinary == "" {
			orphanTools = append(orphanTools, s.Tool)
		}
	}

	if len(orphanTools) == 0 {
		action.Status = FixSkipped
		action.Details = "All active shims have valid host binaries on $PATH"
		return action
	}

	var removed []string
	var failures []string

	for _, tool := range orphanTools {
		if err := mgr.UninstallTool(shimDir, tool); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", tool, err))
		} else {
			removed = append(removed, tool)
		}
	}

	if len(failures) > 0 {
		action.Status = FixFailed
		action.Details = fmt.Sprintf("Failed to uninstall some orphan shims: %s", strings.Join(failures, "; "))
		return action
	}

	action.Status = FixRepaired
	action.Details = fmt.Sprintf("Uninstalled %d orphan shim(s) missing host binaries: %s", len(removed), strings.Join(removed, ", "))
	return action
}

// autoFixDeclarativeConfig generates baseline airlock.yaml if neither airlock.yaml nor .airlockrc exists.
func autoFixDeclarativeConfig(opts Options) FixAction {
	action := FixAction{
		ID:    "config-airlock-yaml",
		Title: "Generate baseline workspace declarative policy (airlock.yaml)",
	}

	wsRoot := opts.WorkspaceRoot
	if wsRoot == "" {
		if cwd, err := os.Getwd(); err == nil {
			wsRoot = cwd
		}
	}
	if wsRoot == "" {
		action.Status = FixSkipped
		action.Details = "Workspace root cannot be determined"
		return action
	}

	// Check if any policy file exists in wsRoot
	for _, name := range config.ConfigFileNames {
		p := filepath.Join(wsRoot, name)
		if fi, err := os.Lstat(p); err == nil && !fi.IsDir() {
			action.Status = FixSkipped
			action.Details = fmt.Sprintf("Declarative policy already present (%s)", name)
			return action
		}
	}

	targetPath := filepath.Join(wsRoot, "airlock.yaml")
	cleanTarget := filepath.Clean(targetPath)
	cleanWs := filepath.Clean(wsRoot)

	// Path safety
	if filepath.Dir(cleanTarget) != cleanWs {
		action.Status = FixFailed
		action.Details = fmt.Sprintf("Path traversal rejected for target %s", targetPath)
		return action
	}

	projType := config.DetectProjectType(wsRoot)
	content := config.GenerateTemplate(projType)

	// O_CREATE | O_EXCL ensures non-destructive atomic creation (fails if file or symlink exists)
	f, err := os.OpenFile(cleanTarget, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		action.Status = FixFailed
		action.Details = fmt.Sprintf("Failed to create %s: %v", cleanTarget, err)
		return action
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString(content); err != nil {
		action.Status = FixFailed
		action.Details = fmt.Sprintf("Failed to write to %s: %v", cleanTarget, err)
		return action
	}

	action.Status = FixRepaired
	action.Details = fmt.Sprintf("Generated baseline airlock.yaml (%s profile) in %s", projType, wsRoot)
	return action
}

// autoFixStoragePermissions ensures scratch and cache directories exist with 0700 permissions.
func autoFixStoragePermissions(opts Options) FixAction {
	action := FixAction{
		ID:    "storage-scratch-dirs",
		Title: "Ensure scratch and cache directories exist with 0700 permissions",
	}

	homeDir := opts.HomeDir
	if homeDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			homeDir = home
		}
	}
	if homeDir == "" {
		action.Status = FixSkipped
		action.Details = "Home directory cannot be determined"
		return action
	}

	airlockBase := filepath.Join(homeDir, ".airlock")
	targetDirs := []string{
		filepath.Join(airlockBase, "scratch"),
		filepath.Join(airlockBase, "cache"),
	}
	if opts.ScratchBase != "" && opts.ScratchBase != "/tmp" && opts.ScratchBase != os.TempDir() {
		targetDirs = append(targetDirs, opts.ScratchBase)
	}

	var repaired []string
	var skipped []string
	var failures []string

	for _, dir := range targetDirs {
		cleanDir := filepath.Clean(dir)

		fi, err := os.Lstat(cleanDir)
		if err != nil {
			if os.IsNotExist(err) {
				// Directory does not exist: create with 0700
				if err := os.MkdirAll(cleanDir, 0700); err != nil {
					failures = append(failures, fmt.Sprintf("Failed to create %s: %v", cleanDir, err))
					continue
				}
				if runtime.GOOS != "windows" {
					if chmodErr := os.Chmod(cleanDir, 0700); chmodErr != nil {
						failures = append(failures, fmt.Sprintf("Failed to chmod %s: %v", cleanDir, chmodErr))
						continue
					}
				}
				repaired = append(repaired, fmt.Sprintf("Created %s (0700)", cleanDir))
				continue
			}
			failures = append(failures, fmt.Sprintf("Failed to stat %s: %v", cleanDir, err))
			continue
		}

		// Symlink safety: if directory is a symlink, do NOT follow or chmod target!
		if fi.Mode()&os.ModeSymlink != 0 {
			// Insecure symlink detected in place of scratch/cache directory
			if err := os.Remove(cleanDir); err != nil {
				failures = append(failures, fmt.Sprintf("Failed to remove insecure symlink %s: %v", cleanDir, err))
				continue
			}
			if err := os.Mkdir(cleanDir, 0700); err != nil {
				failures = append(failures, fmt.Sprintf("Failed to recreate private directory %s: %v", cleanDir, err))
				continue
			}
			if runtime.GOOS != "windows" {
				if chmodErr := os.Chmod(cleanDir, 0700); chmodErr != nil {
					failures = append(failures, fmt.Sprintf("Failed to chmod recreated directory %s: %v", cleanDir, chmodErr))
					continue
				}
			}
			repaired = append(repaired, fmt.Sprintf("Replaced insecure symlink at %s with private directory (0700)", cleanDir))
			continue
		}

		if !fi.IsDir() {
			failures = append(failures, fmt.Sprintf("%s exists but is not a directory", cleanDir))
			continue
		}

		// Directory exists: check permissions
		if runtime.GOOS != "windows" {
			currentPerm := fi.Mode().Perm()
			if currentPerm != 0700 {
				if err := os.Chmod(cleanDir, 0700); err != nil {
					failures = append(failures, fmt.Sprintf("Failed to set 0700 on %s: %v", cleanDir, err))
					continue
				}
				repaired = append(repaired, fmt.Sprintf("Updated permissions on %s to 0700 (was %04o)", cleanDir, currentPerm))
			} else {
				skipped = append(skipped, fmt.Sprintf("%s already exists with 0700 permissions", cleanDir))
			}
		} else {
			skipped = append(skipped, fmt.Sprintf("%s already exists", cleanDir))
		}
	}

	if len(failures) > 0 {
		action.Status = FixFailed
		action.Details = strings.Join(failures, "; ")
		return action
	}

	if len(repaired) > 0 {
		action.Status = FixRepaired
		action.Details = strings.Join(repaired, "; ")
		return action
	}

	action.Status = FixSkipped
	action.Details = strings.Join(skipped, "; ")
	return action
}

// FormatTerminal generates an ANSI styled summary table of auto-remediation actions.
func (r *FixReport) FormatTerminal(useColor bool) string {
	var sb strings.Builder
	sb.WriteString("Airlock Doctor — Auto-Remediation Summary\n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("%-10s  %-24s  %s\n", "STATUS", "ID", "DETAILS"))
	sb.WriteString(fmt.Sprintf("%-10s  %-24s  %s\n", "----------", "------------------------", "------------------------------------------------"))

	for _, act := range r.Actions {
		tag := string(act.Status)
		padTag := fmt.Sprintf("%-10s", tag)
		if useColor {
			switch act.Status {
			case FixRepaired:
				padTag = "\033[32m" + padTag + "\033[0m"
			case FixSkipped:
				padTag = "\033[33m" + padTag + "\033[0m"
			case FixFailed:
				padTag = "\033[31m" + padTag + "\033[0m"
			}
		}
		sb.WriteString(fmt.Sprintf("%s  %-24s  %s\n", padTag, act.ID, act.Details))
	}

	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Remediations: %d repaired, %d skipped, %d failed\n", r.Repaired, r.Skipped, r.Failed))
	return sb.String()
}
