package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrArchivePathEscape indicates an archive extraction path or target attempts to escape
// its confined destination or workspace root (Zip-Slip / GHSA-qh76-45cr-8xrc).
var ErrArchivePathEscape = errors.New("sandbox: archive path escape blocked (Zip-Slip confinement)")

var archiveCommandNames = map[string]bool{
	"7z":           true,
	"7za":          true,
	"7zz":          true,
	"7zr":          true,
	"sevenz":       true,
	"sevenz-rust":  true,
	"sevenz-rust2": true,
	"tar":          true,
	"gtar":         true,
	"bsdtar":       true,
	"unzip":        true,
	"unrar":        true,
	"rar":          true,
	"cpio":         true,
	"pax":          true,
}

// ValidateArchiveEntryPath enforces strict Zip-Slip confinement for a single archive entry
// name against destRoot (mitigating GHSA-qh76-45cr-8xrc / sevenz-rust2 dest.join(entry.name())
// traversal and symlink escapes). Returns the canonical confined path on success.
func ValidateArchiveEntryPath(destRoot, entryName string) (string, error) {
	if strings.TrimSpace(destRoot) == "" {
		return "", fmt.Errorf("%w: empty destination root", ErrArchivePathEscape)
	}
	if entryName == "" {
		return "", fmt.Errorf("%w: empty archive entry name", ErrArchivePathEscape)
	}
	if strings.ContainsRune(entryName, 0) {
		return "", fmt.Errorf("%w: NUL byte in archive entry %q", ErrArchivePathEscape, entryName)
	}

	// Reject Windows drive-letter roots (e.g. C:\foo, C:foo), UNC prefixes, and leading slashes
	if len(entryName) >= 2 && entryName[1] == ':' {
		return "", fmt.Errorf("%w: drive-qualified archive entry %q", ErrArchivePathEscape, entryName)
	}
	if strings.HasPrefix(entryName, "/") || strings.HasPrefix(entryName, "\\") {
		return "", fmt.Errorf("%w: absolute archive entry %q", ErrArchivePathEscape, entryName)
	}

	// Normalize both POSIX and Windows separators to detect cross-platform Zip-Slip payloads
	normalized := strings.ReplaceAll(entryName, "\\", "/")
	for _, seg := range strings.Split(normalized, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: parent traversal segment in archive entry %q", ErrArchivePathEscape, entryName)
		}
		lowerSeg := strings.ToLower(seg)
		if strings.Contains(lowerSeg, "%2e%2e") || strings.Contains(lowerSeg, "%2e.") || strings.Contains(lowerSeg, ".%2e") {
			return "", fmt.Errorf("%w: encoded traversal segment in archive entry %q", ErrArchivePathEscape, entryName)
		}
	}

	absRoot, err := filepath.Abs(destRoot)
	if err != nil {
		return "", fmt.Errorf("%w: cannot resolve destination root: %v", ErrArchivePathEscape, err)
	}
	realRoot, err := resolveDeepestAncestor(absRoot)
	if err != nil {
		return "", fmt.Errorf("%w: cannot canonicalize destination root: %v", ErrArchivePathEscape, err)
	}

	relClean := filepath.Clean(filepath.FromSlash(normalized))
	if relClean == ".." || strings.HasPrefix(relClean, ".."+string(filepath.Separator)) || filepath.IsAbs(relClean) {
		return "", fmt.Errorf("%w: lexical escape in archive entry %q", ErrArchivePathEscape, entryName)
	}

	candidate := filepath.Join(realRoot, relClean)
	realCandidate, err := resolveDeepestAncestor(candidate)
	if err != nil {
		return "", fmt.Errorf("%w: cannot canonicalize archive entry target %q: %v", ErrArchivePathEscape, entryName, err)
	}

	if !isSubpath(realRoot, realCandidate) {
		return "", fmt.Errorf("%w: resolved path %q escapes destination root %q", ErrArchivePathEscape, realCandidate, realRoot)
	}

	return realCandidate, nil
}

// ValidateArchiveCommandConfinement performs a pre-flight fail-closed confinement audit on
// archive extraction invocations executed through Airlock, ensuring mutual validation with
// Fabrial's dynamic tier escalation boundary (GHSA-qh76-45cr-8xrc).
func ValidateArchiveCommandConfinement(workspaceRoot, workingDir string, cmdArgs []string) error {
	if len(cmdArgs) == 0 || strings.TrimSpace(workspaceRoot) == "" {
		return nil
	}

	toolIdx, tool := unwrapArchiveTool(cmdArgs)
	if tool == "" {
		return nil
	}

	baseDir := workingDir
	if baseDir == "" {
		baseDir = workspaceRoot
	}

	absRoot, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return fmt.Errorf("%w: cannot resolve workspace root: %v", ErrArchivePathEscape, err)
	}
	realRoot, err := resolveDeepestAncestor(absRoot)
	if err != nil {
		return fmt.Errorf("%w: cannot canonicalize workspace root: %v", ErrArchivePathEscape, err)
	}

	args := cmdArgs[toolIdx+1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		lower := strings.ToLower(arg)

		// 1. Block archive flags that intentionally bypass relative-path or symlink confinement
		if arg == "-P" || lower == "--absolute-names" ||
			lower == "--keep-directory-symlink" || lower == "-spe" ||
			lower == "-snl" || lower == "-snh" {
			return fmt.Errorf("%w: unsafe archive flag %q is forbidden for %s", ErrArchivePathEscape, arg, tool)
		}

		// 2. Check explicit extraction destination flags (-o<dir>, -C <dir>, --directory=<dir>, -d <dir>)
		var destTarget string
		switch {
		case strings.HasPrefix(lower, "-o") && len(arg) > 2 && strings.HasPrefix(tool, "7z"):
			destTarget = arg[2:]
		case strings.HasPrefix(lower, "--directory="):
			destTarget = arg[len("--directory="):]
		case (arg == "-C" || arg == "--directory" || arg == "-d") && i+1 < len(args):
			destTarget = args[i+1]
			i++
		}

		if destTarget != "" {
			if err := validateWorkspaceDestination(realRoot, baseDir, destTarget); err != nil {
				return err
			}
			continue
		}

		// 3. Reject NUL bytes or parent traversal segments inside archive path arguments
		if strings.ContainsRune(arg, 0) {
			return fmt.Errorf("%w: NUL byte in %s argument", ErrArchivePathEscape, tool)
		}
		if hasTraversalSegment(arg) {
			return fmt.Errorf("%w: traversal sequence in %s argument %q", ErrArchivePathEscape, tool, arg)
		}
	}

	return nil
}

func unwrapArchiveTool(cmdArgs []string) (int, string) {
	wrappers := map[string]bool{
		"env":     true,
		"command": true,
		"nohup":   true,
		"nice":    true,
		"stdbuf":  true,
		"timeout": true,
	}

	for i := 0; i < len(cmdArgs); i++ {
		tok := strings.TrimSpace(cmdArgs[i])
		if tok == "" {
			continue
		}
		// Skip env VAR=VAL assignments
		if strings.Contains(tok, "=") && !strings.HasPrefix(tok, "-") && !strings.ContainsAny(tok, "/\\") {
			continue
		}
		if strings.HasPrefix(tok, "-") {
			continue
		}

		base := strings.ToLower(filepath.Base(strings.ReplaceAll(tok, "\\", "/")))
		base = strings.TrimSuffix(base, ".exe")
		if wrappers[base] {
			continue
		}
		if archiveCommandNames[base] {
			return i, base
		}
		return -1, ""
	}
	return -1, ""
}

func validateWorkspaceDestination(realRoot, baseDir, destTarget string) error {
	if strings.ContainsRune(destTarget, 0) {
		return fmt.Errorf("%w: NUL byte in archive destination", ErrArchivePathEscape)
	}
	if hasTraversalSegment(destTarget) {
		return fmt.Errorf("%w: traversal sequence in archive destination %q", ErrArchivePathEscape, destTarget)
	}

	var candidate string
	if filepath.IsAbs(destTarget) || strings.HasPrefix(destTarget, "/") || strings.HasPrefix(destTarget, "\\") || (len(destTarget) >= 2 && destTarget[1] == ':') {
		candidate = filepath.Clean(destTarget)
	} else {
		candidate = filepath.Join(baseDir, filepath.FromSlash(strings.ReplaceAll(destTarget, "\\", "/")))
	}

	absCand, err := filepath.Abs(candidate)
	if err != nil {
		return fmt.Errorf("%w: cannot resolve archive destination %q: %v", ErrArchivePathEscape, destTarget, err)
	}
	realCand, err := resolveDeepestAncestor(absCand)
	if err != nil {
		return fmt.Errorf("%w: cannot canonicalize archive destination %q: %v", ErrArchivePathEscape, destTarget, err)
	}
	if !isSubpath(realRoot, realCand) {
		return fmt.Errorf("%w: extraction target %q resolves outside workspace root %q", ErrArchivePathEscape, realCand, realRoot)
	}
	return nil
}

func hasTraversalSegment(s string) bool {
	norm := strings.ReplaceAll(s, "\\", "/")
	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return true
		}
		lower := strings.ToLower(seg)
		if strings.Contains(lower, "%2e%2e") || strings.Contains(lower, "%2e.") || strings.Contains(lower, ".%2e") {
			return true
		}
	}
	return false
}

// resolveDeepestAncestor resolves symlinks on the deepest existing ancestor of p and
// re-appends the remaining non-existent path components.
func resolveDeepestAncestor(p string) (string, error) {
	cleaned := filepath.Clean(p)
	var tail []string
	curr := cleaned

	for {
		resolved, err := filepath.EvalSymlinks(curr)
		if err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			return cleaned, nil
		}
		tail = append(tail, filepath.Base(curr))
		curr = parent
	}
}

func isSubpath(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}
