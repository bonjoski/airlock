package vet

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/bonjoski/airlock/pkg/config"
)

// SirenExitCode is the fail-closed exit code emitted by `airlock vet --strict`
// when any Siren sandbox misconfiguration anti-pattern is detected (RFC-2026-11-27-67).
const SirenExitCode = 30

// SirenFinding describes a single sandbox misconfiguration anti-pattern discovered
// by static post-compilation linting of Seatbelt SBPL, Landlock, or declarative policy.
type SirenFinding struct {
	RuleID         string `json:"rule_id"`   // e.g. "AIRLOCK-SIREN-001"
	Severity       string `json:"severity"`  // "critical", "high"
	Location       string `json:"location"`
	Summary        string `json:"summary"`
	RemediationCmd string `json:"remediation_cmd"`
}

// VetProfileStrict lints a declarative Airlock config and/or compiled sandbox profile
// (Seatbelt SBPL, Landlock ruleset summary, or bwrap/seccomp policy directives) against
// Siren sandbox misconfiguration anti-patterns (RFC-2026-11-27-67).
//
// Linting operates on the post-compilation canonical S-expression AST (comments stripped,
// whitespace normalized) so SBPL comment or whitespace tricks cannot evade detection.
func VetProfileStrict(cfg *config.Config, compiledSBPLOrLandlock string) ([]SirenFinding, error) {
	var findings []SirenFinding
	seen := make(map[string]bool)
	addFinding := func(f SirenFinding) {
		key := f.RuleID + "|" + f.Location + "|" + f.Summary
		if !seen[key] {
			seen[key] = true
			findings = append(findings, f)
		}
	}

	// 1. Declarative config checks
	if cfg != nil {
		lintConfigStrict(cfg, addFinding)
	}

	// 2. Compiled profile / SBPL / Landlock / seccomp checks
	trimmed := strings.TrimSpace(compiledSBPLOrLandlock)
	if trimmed != "" {
		if looksLikeSBPL(trimmed) {
			exprs, err := parseSExprs(trimmed)
			if err != nil {
				return nil, fmt.Errorf("vet: malformed compiled SBPL profile (fail-closed): %w", err)
			}
			lintSBPLAST(cfg, exprs, addFinding)
		} else {
			lintLandlockText(trimmed, addFinding)
		}

		// Cross-cutting directive checks (relative PATH, seccomp io_uring/x32, fail-open flags)
		lintCompiledDirectives(trimmed, addFinding)
	}

	return findings, nil
}

func lintConfigStrict(cfg *config.Config, add func(SirenFinding)) {
	// AIRLOCK-SIREN-006: Fail-open / non-strict mode or ignored vetting rules
	switch strings.ToLower(strings.TrimSpace(string(cfg.Mode))) {
	case string(config.ModePermissive), string(config.ModeAudit):
		add(SirenFinding{
			RuleID:         "AIRLOCK-SIREN-006",
			Severity:       "critical",
			Location:       "config.mode",
			Summary:        fmt.Sprintf("Fail-open execution mode %q weakens kernel confinement boundaries", cfg.Mode),
			RemediationCmd: "airlock init --force",
		})
	}
	if len(cfg.Vetting.IgnoredRules) > 0 {
		add(SirenFinding{
			RuleID:         "AIRLOCK-SIREN-006",
			Severity:       "high",
			Location:       "config.vetting.ignored_rules",
			Summary:        fmt.Sprintf("Vetting rules suppressed (%d ignored); strict mode prohibits rule bypasses", len(cfg.Vetting.IgnoredRules)),
			RemediationCmd: "airlock config validate",
		})
	}

	// AIRLOCK-SIREN-002: Forbidden host credential or root filesystem allows
	for _, p := range cfg.Filesystem.AllowRead {
		clean := strings.TrimSpace(p)
		if clean == "/" || clean == "/*" || clean == "~" || clean == "$HOME" {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-001",
				Severity:       "critical",
				Location:       "config.filesystem.allow_read",
				Summary:        fmt.Sprintf("Unbounded broad read allowance %q exposes host credentials", p),
				RemediationCmd: "airlock config validate",
			})
			continue
		}
		if config.IsForbiddenPath(clean) {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-002",
				Severity:       "critical",
				Location:       "config.filesystem.allow_read",
				Summary:        fmt.Sprintf("Config grants read access to protected credential/socket path %q", p),
				RemediationCmd: "airlock config validate",
			})
		}
	}
	for _, p := range cfg.Filesystem.AllowWrite {
		clean := strings.TrimSpace(p)
		if clean == "/" || clean == "/*" || clean == "~" || clean == "$HOME" {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-001",
				Severity:       "critical",
				Location:       "config.filesystem.allow_write",
				Summary:        fmt.Sprintf("Unbounded broad write allowance %q allows host persistence", p),
				RemediationCmd: "airlock config validate",
			})
			continue
		}
		if config.IsForbiddenPath(clean) {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-002",
				Severity:       "critical",
				Location:       "config.filesystem.allow_write",
				Summary:        fmt.Sprintf("Config grants write access to protected path %q", p),
				RemediationCmd: "airlock config validate",
			})
		}
	}

	// AIRLOCK-SIREN-003: Wildcard or metadata/RFC1918 egress allowlist entries
	for _, dom := range cfg.Network.AllowDomains {
		d := strings.TrimSpace(dom)
		if d == "" || d == "*" || d == "*.*" || !config.IsValidDomainRule(d) {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-003",
				Severity:       "critical",
				Location:       "config.network.allow_domains",
				Summary:        fmt.Sprintf("Wildcard or invalid egress domain rule %q bypasses allowlist confinement", dom),
				RemediationCmd: "airlock config validate",
			})
			continue
		}
		if isPrivateOrMetadataHost(d) {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-003",
				Severity:       "critical",
				Location:       "config.network.allow_domains",
				Summary:        fmt.Sprintf("Egress allowlist permits private/RFC1918 or cloud metadata address %q", dom),
				RemediationCmd: "airlock config validate",
			})
		}
	}

	// AIRLOCK-SIREN-004: Relative PATH or dynamic linker/runtime smuggling in env.allow
	for _, rawEnv := range cfg.Env.Allow {
		trimmed := strings.TrimSpace(rawEnv)
		if trimmed == "" {
			continue
		}
		key := trimmed
		val := ""
		hasVal := false
		if idx := strings.Index(trimmed, "="); idx != -1 {
			key = strings.TrimSpace(trimmed[:idx])
			val = trimmed[idx+1:]
			hasVal = true
		}
		upper := strings.ToUpper(key)
		if config.IsForbiddenEnv(upper) || upper == "PYTHONPATH" || upper == "NODE_OPTIONS" || upper == "LD_LIBRARY_PATH" {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-004",
				Severity:       "high",
				Location:       "config.env.allow",
				Summary:        fmt.Sprintf("Environment allowlist exposes dangerous injection variable %q", key),
				RemediationCmd: "airlock config validate",
			})
		}
		if upper == "PATH" && hasVal && hasRelativePathEntry(val) {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-004",
				Severity:       "high",
				Location:       "config.env.allow",
				Summary:        fmt.Sprintf("Relative or empty PATH segment detected (%q), enabling binary shadowing", val),
				RemediationCmd: "airlock run --profile untrusted-agent -- <cmd>",
			})
		}
	}
}

// --- S-expression AST parser for Apple Seatbelt SBPL ---

type sExpr struct {
	isList bool
	atom   string
	isStr  bool
	list   []sExpr
}

func (e sExpr) flattenStrings() []string {
	if !e.isList {
		return []string{e.atom}
	}
	var out []string
	for _, child := range e.list {
		out = append(out, child.flattenStrings()...)
	}
	return out
}

func (e sExpr) canonicalText() string {
	if !e.isList {
		if e.isStr {
			return `"` + e.atom + `"`
		}
		return e.atom
	}
	parts := make([]string, len(e.list))
	for i, c := range e.list {
		parts[i] = c.canonicalText()
	}
	return "(" + strings.Join(parts, " ") + ")"
}

type sbplToken struct {
	kind  string // "(", ")", "atom", "string"
	value string
}

func tokenizeSBPL(input string) ([]sbplToken, error) {
	var tokens []sbplToken
	runes := []rune(input)
	n := len(runes)
	i := 0

	for i < n {
		r := runes[i]

		// Skip any whitespace (ASCII or Unicode)
		if unicode.IsSpace(r) {
			i++
			continue
		}

		// Strip SBPL line comments starting with ';'
		if r == ';' {
			for i < n && runes[i] != '\n' {
				i++
			}
			continue
		}

		if r == '(' {
			tokens = append(tokens, sbplToken{kind: "(", value: "("})
			i++
			continue
		}
		if r == ')' {
			tokens = append(tokens, sbplToken{kind: ")", value: ")"})
			i++
			continue
		}

		// SBPL regex literal #"..."
		if r == '#' && i+1 < n && runes[i+1] == '"' {
			i += 2
			var sb strings.Builder
			closed := false
			for i < n {
				c := runes[i]
				if c == '\\' && i+1 < n {
					sb.WriteRune(c)
					sb.WriteRune(runes[i+1])
					i += 2
					continue
				}
				if c == '"' {
					closed = true
					i++
					break
				}
				sb.WriteRune(c)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated SBPL regex literal")
			}
			tokens = append(tokens, sbplToken{kind: "string", value: sb.String()})
			continue
		}

		// Double-quoted string literal "..."
		if r == '"' {
			i++
			var sb strings.Builder
			closed := false
			for i < n {
				c := runes[i]
				if c == '\\' && i+1 < n {
					sb.WriteRune(runes[i+1])
					i += 2
					continue
				}
				if c == '"' {
					closed = true
					i++
					break
				}
				sb.WriteRune(c)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated SBPL string literal")
			}
			tokens = append(tokens, sbplToken{kind: "string", value: sb.String()})
			continue
		}

		// Atom token
		start := i
		for i < n && !unicode.IsSpace(runes[i]) && runes[i] != '(' && runes[i] != ')' && runes[i] != ';' && runes[i] != '"' {
			i++
		}
		tokens = append(tokens, sbplToken{kind: "atom", value: string(runes[start:i])})
	}

	return tokens, nil
}

func parseSExprs(input string) ([]sExpr, error) {
	tokens, err := tokenizeSBPL(input)
	if err != nil {
		return nil, err
	}
	pos := 0
	var exprs []sExpr
	for pos < len(tokens) {
		e, nextPos, err := parseOneSExpr(tokens, pos)
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, e)
		pos = nextPos
	}
	return exprs, nil
}

func parseOneSExpr(tokens []sbplToken, pos int) (sExpr, int, error) {
	if pos >= len(tokens) {
		return sExpr{}, pos, fmt.Errorf("unexpected end of SBPL input")
	}
	tok := tokens[pos]
	switch tok.kind {
	case ")":
		return sExpr{}, pos, fmt.Errorf("unexpected closing parenthesis in SBPL")
	case "atom":
		return sExpr{isList: false, atom: tok.value}, pos + 1, nil
	case "string":
		return sExpr{isList: false, atom: tok.value, isStr: true}, pos + 1, nil
	case "(":
		pos++
		var items []sExpr
		for pos < len(tokens) && tokens[pos].kind != ")" {
			child, nextPos, err := parseOneSExpr(tokens, pos)
			if err != nil {
				return sExpr{}, pos, err
			}
			items = append(items, child)
			pos = nextPos
		}
		if pos >= len(tokens) || tokens[pos].kind != ")" {
			return sExpr{}, pos, fmt.Errorf("unclosed parenthesis in SBPL")
		}
		return sExpr{isList: true, list: items}, pos + 1, nil
	default:
		return sExpr{}, pos, fmt.Errorf("unknown token kind %q", tok.kind)
	}
}

func looksLikeSBPL(s string) bool {
	// Strip comments and check if S-expressions with SBPL directives are present
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		clean := strings.TrimSpace(line)
		if clean == "" || strings.HasPrefix(clean, ";") {
			continue
		}
		if strings.HasPrefix(clean, "(") {
			return true
		}
	}
	return strings.Contains(s, "(version 1)") || strings.Contains(s, "(deny ") || strings.Contains(s, "(allow ")
}

func lintSBPLAST(cfg *config.Config, exprs []sExpr, add func(SirenFinding)) {
	hasDenyDefault := false
	hasAllowDefault := false

	lastBroadFileReadIdx := -1
	lastBroadFileWriteIdx := -1
	hasAnyFileWriteAllow := false

	// Required credential/socket targets that MUST have effective high-precedence denials
	type credTarget struct {
		name     string
		patterns []string
	}
	requiredCreds := []credTarget{
		{name: "~/.ssh", patterns: []string{"/.ssh", `\.ssh`, "ssh|aws", "(ssh|"}},
		{name: "~/.aws", patterns: []string{"/.aws", `\.aws`, "|aws|"}},
		{name: "/var/run/docker.sock", patterns: []string{"docker.sock"}},
	}

	lastDenyIdx := make(map[string]int, len(requiredCreds))
	lastExplicitAllowIdx := make(map[string]int, len(requiredCreds))
	for _, ct := range requiredCreds {
		lastDenyIdx[ct.name] = -1
		lastExplicitAllowIdx[ct.name] = -1
	}

	lastGitWriteDenyIdx := -1
	lastGitWriteAllowIdx := -1

	for idx, expr := range exprs {
		if !expr.isList || len(expr.list) < 2 {
			continue
		}
		if expr.list[0].isList {
			continue
		}
		head := strings.ToLower(expr.list[0].atom)
		if head != "allow" && head != "deny" {
			continue
		}

		var actions []string
		var predicates []sExpr
		for _, item := range expr.list[1:] {
			if !item.isList && !item.isStr {
				actions = append(actions, strings.ToLower(item.atom))
			} else {
				predicates = append(predicates, item)
			}
		}

		hasAction := func(targets ...string) bool {
			for _, a := range actions {
				for _, t := range targets {
					if a == t {
						return true
					}
				}
			}
			return false
		}

		// Default rule detection
		if hasAction("default") {
			if head == "deny" {
				hasDenyDefault = true
			} else {
				hasAllowDefault = true
			}
			continue
		}

		predText := strings.ToLower(joinPredicates(predicates))

		// File-read checks
		coversRead := hasAction("file-read*", "file-read-data", "file*")
		coversWrite := hasAction("file-write*", "file-write-data", "file*")

		if head == "allow" && coversRead {
			if len(predicates) == 0 {
				lastBroadFileReadIdx = idx
			} else {
				for _, ct := range requiredCreds {
					if matchesAnyPattern(predText, ct.patterns) {
						lastExplicitAllowIdx[ct.name] = idx
					}
				}
			}
		}

		if head == "deny" && coversRead {
			for _, ct := range requiredCreds {
				if matchesAnyPattern(predText, ct.patterns) {
					lastDenyIdx[ct.name] = idx
				}
			}
		}

		// File-write checks
		if head == "allow" && coversWrite {
			hasAnyFileWriteAllow = true
			if len(predicates) == 0 {
				lastBroadFileWriteIdx = idx
			} else if strings.Contains(predText, "/.git") || strings.Contains(predText, `\.git`) {
				lastGitWriteAllowIdx = idx
			}
		}
		if head == "deny" && coversWrite {
			if strings.Contains(predText, "/.git") || strings.Contains(predText, `\.git`) {
				lastGitWriteDenyIdx = idx
			}
		}

		// Network egress checks
		coversNet := hasAction("network*", "network-outbound")
		if head == "allow" && coversNet {
			if len(predicates) == 0 {
				add(SirenFinding{
					RuleID:         "AIRLOCK-SIREN-003",
					Severity:       "critical",
					Location:       fmt.Sprintf("sbpl.form[%d]", idx),
					Summary:        fmt.Sprintf("Unrestricted wildcard network egress (%s) permits arbitrary exfiltration", expr.canonicalText()),
					RemediationCmd: "airlock run --profile untrusted-agent --allow-egress api.anthropic.com -- <cmd>",
				})
			} else if hasWildcardNetworkTarget(predicates) {
				if cfg == nil || cfg.Network.Airgap || len(cfg.Network.AllowDomains) == 0 {
					sev := "high"
					if cfg != nil && cfg.Network.Airgap {
						sev = "critical"
					}
					add(SirenFinding{
						RuleID:         "AIRLOCK-SIREN-003",
						Severity:       sev,
						Location:       fmt.Sprintf("sbpl.form[%d]", idx),
						Summary:        "Wildcard outbound network rule detected without explicit domain allowlist",
						RemediationCmd: "airlock run --profile untrusted-agent --allow-egress api.anthropic.com -- <cmd>",
					})
				}
			}
		}
	}

	if hasAllowDefault {
		add(SirenFinding{
			RuleID:         "AIRLOCK-SIREN-006",
			Severity:       "critical",
			Location:       "sbpl.default",
			Summary:        "Fail-open SBPL policy uses (allow default) instead of (deny default)",
			RemediationCmd: "airlock init --force",
		})
	} else if !hasDenyDefault {
		add(SirenFinding{
			RuleID:         "AIRLOCK-SIREN-001",
			Severity:       "critical",
			Location:       "sbpl.default",
			Summary:        "Compiled SBPL profile is missing mandatory (deny default) fail-closed baseline",
			RemediationCmd: "airlock init --force",
		})
	}

	if lastBroadFileWriteIdx >= 0 {
		add(SirenFinding{
			RuleID:         "AIRLOCK-SIREN-001",
			Severity:       "critical",
			Location:       fmt.Sprintf("sbpl.form[%d]", lastBroadFileWriteIdx),
			Summary:        "Broad unbounded (allow file-write*) permits host-wide filesystem tampering",
			RemediationCmd: "airlock run --profile untrusted-agent -- <cmd>",
		})
	}

	// Verify credential denies exist and win over any broad (allow file-read*)
	broadReadUncovered := false
	for _, ct := range requiredCreds {
		denyPos := lastDenyIdx[ct.name]
		allowPos := lastExplicitAllowIdx[ct.name]
		if denyPos < 0 {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-002",
				Severity:       "critical",
				Location:       "sbpl.filesystem",
				Summary:        fmt.Sprintf("Compiled SBPL profile is missing explicit read/write denial for %s", ct.name),
				RemediationCmd: "airlock run --profile untrusted-agent -- <cmd>",
			})
			if lastBroadFileReadIdx >= 0 {
				broadReadUncovered = true
			}
		} else if lastBroadFileReadIdx > denyPos || allowPos > denyPos {
			broadReadUncovered = true
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-001",
				Severity:       "critical",
				Location:       "sbpl.filesystem",
				Summary:        fmt.Sprintf("Broad or explicit file-read* allow overrides denial for %s (last-match-wins escape)", ct.name),
				RemediationCmd: "airlock run --profile untrusted-agent -- <cmd>",
			})
		}
	}
	if broadReadUncovered && lastBroadFileReadIdx >= 0 {
		add(SirenFinding{
			RuleID:         "AIRLOCK-SIREN-001",
			Severity:       "critical",
			Location:       fmt.Sprintf("sbpl.form[%d]", lastBroadFileReadIdx),
			Summary:        "Broad (allow file-read*) present without complete high-precedence credential denials after it",
			RemediationCmd: "airlock run --profile untrusted-agent -- <cmd>",
		})
	}

	// Verify .git write protection when file-write* is allowed
	if hasAnyFileWriteAllow && (lastGitWriteDenyIdx < 0 || lastGitWriteAllowIdx > lastGitWriteDenyIdx || lastBroadFileWriteIdx > lastGitWriteDenyIdx) {
		add(SirenFinding{
			RuleID:         "AIRLOCK-SIREN-007",
			Severity:       "high",
			Location:       "sbpl.workspace",
			Summary:        "Compiled SBPL profile permits workspace writes without high-precedence .git write protection",
			RemediationCmd: "airlock run --profile untrusted-agent -- <cmd>",
		})
	}
}

func joinPredicates(preds []sExpr) string {
	var parts []string
	for _, p := range preds {
		parts = append(parts, p.canonicalText())
	}
	return strings.Join(parts, " ")
}

func matchesAnyPattern(text string, patterns []string) bool {
	for _, pat := range patterns {
		if strings.Contains(text, pat) {
			return true
		}
	}
	return false
}

func hasWildcardNetworkTarget(preds []sExpr) bool {
	for _, p := range preds {
		for _, tok := range p.flattenStrings() {
			lower := strings.ToLower(strings.TrimSpace(tok))
			if lower == "*" || strings.HasPrefix(lower, "*:") || lower == "0.0.0.0:*" || lower == "::/0" {
				return true
			}
		}
	}
	return false
}

func lintLandlockText(text string, add func(SirenFinding)) {
	lower := strings.ToLower(text)
	// Strip '#' comments line by line
	var cleanLines []string
	for _, line := range strings.Split(lower, "\n") {
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			cleanLines = append(cleanLines, line)
		}
	}
	cleaned := strings.Join(cleanLines, "\n")

	if strings.Contains(cleaned, "allow_fs=/") || strings.Contains(cleaned, "allow_read=/") || strings.Contains(cleaned, "path_beneath:/") {
		add(SirenFinding{
			RuleID:         "AIRLOCK-SIREN-001",
			Severity:       "critical",
			Location:       "landlock.rules",
			Summary:        "Landlock ruleset grants root filesystem (/) access, bypassing credential isolation",
			RemediationCmd: "airlock run --profile untrusted-agent -- <cmd>",
		})
	}

	for _, sensitive := range []string{".ssh", ".aws", "docker.sock"} {
		for _, line := range cleanLines {
			if (strings.Contains(line, "allow") || strings.Contains(line, "path_beneath")) && strings.Contains(line, sensitive) && !strings.Contains(line, "deny") {
				add(SirenFinding{
					RuleID:         "AIRLOCK-SIREN-002",
					Severity:       "critical",
					Location:       "landlock.rules",
					Summary:        fmt.Sprintf("Landlock/bwrap profile explicitly allows protected path %q", sensitive),
					RemediationCmd: "airlock run --profile untrusted-agent -- <cmd>",
				})
			}
		}
	}
}

func lintCompiledDirectives(raw string, add func(SirenFinding)) {
	// Strip comment-only markers cleanly while preserving values
	lower := strings.ToLower(raw)

	// AIRLOCK-SIREN-005: Disabled seccomp io_uring / x32 ABI guards
	seccompPatterns := []string{
		"seccomp=disabled",
		"seccomp: disabled",
		"seccomp=off",
		"seccomp: false",
		"disable_seccomp",
		"--no-seccomp",
		"io_uring=allow",
		"io_uring: allow",
		"allow_io_uring",
		"seccomp_io_uring: false",
		"x32=allow",
		"x32_abi=allow",
		"allow_x32",
		"seccomp_x32: false",
	}
	normalized := collapseWhitespace(lower)
	for _, pat := range seccompPatterns {
		if strings.Contains(normalized, pat) {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-005",
				Severity:       "critical",
				Location:       "profile.seccomp",
				Summary:        fmt.Sprintf("Seccomp io_uring/x32 ABI guard disabled (%q)", pat),
				RemediationCmd: "airlock doctor",
			})
			break
		}
	}

	// AIRLOCK-SIREN-006: Fail-open / degraded execution markers
	degradedPatterns := []string{
		"--allow-degraded-local",
		"allow_degraded_local",
		"allow-degraded-local",
		"fail_open",
		"fail-open",
		"degraded=true",
		"degraded: true",
		"mode: permissive",
		"mode: audit",
	}
	for _, pat := range degradedPatterns {
		if strings.Contains(normalized, pat) {
			add(SirenFinding{
				RuleID:         "AIRLOCK-SIREN-006",
				Severity:       "critical",
				Location:       "profile.degraded",
				Summary:        fmt.Sprintf("Fail-open or degraded sandbox execution setting detected (%q)", pat),
				RemediationCmd: "airlock init --force",
			})
			break
		}
	}

	// AIRLOCK-SIREN-004: Relative PATH entries in compiled env/bwrap args
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idx := strings.Index(trimmed, "PATH="); idx != -1 {
			// Ensure we matched PATH= and not GOPATH= or PYTHONPATH=
			if idx == 0 || !isIdentChar(trimmed[idx-1]) {
				rest := trimmed[idx+len("PATH="):]
				pathVal := extractDirectiveValue(rest)
				if hasRelativePathEntry(pathVal) {
					add(SirenFinding{
						RuleID:         "AIRLOCK-SIREN-004",
						Severity:       "high",
						Location:       "profile.env.PATH",
						Summary:        fmt.Sprintf("Relative PATH entry detected (%q), enabling binary shadowing", pathVal),
						RemediationCmd: "airlock run --profile untrusted-agent -- <cmd>",
					})
				}
			}
		}
		if strings.Contains(trimmed, "--setenv PATH ") {
			idx := strings.Index(trimmed, "--setenv PATH ")
			rest := strings.TrimSpace(trimmed[idx+len("--setenv PATH "):])
			pathVal := extractDirectiveValue(rest)
			if hasRelativePathEntry(pathVal) {
				add(SirenFinding{
					RuleID:         "AIRLOCK-SIREN-004",
					Severity:       "high",
					Location:       "profile.bwrap.PATH",
					Summary:        fmt.Sprintf("Relative PATH entry passed to bwrap (%q), enabling binary shadowing", pathVal),
					RemediationCmd: "airlock run --profile untrusted-agent -- <cmd>",
				})
			}
		}
	}
}

func isIdentChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}

func extractDirectiveValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') {
		q := s[0]
		if end := strings.IndexByte(s[1:], q); end != -1 {
			return s[1 : 1+end]
		}
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func hasRelativePathEntry(pathVal string) bool {
	if pathVal == "" {
		return false
	}
	segments := strings.Split(pathVal, ":")
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." || strings.HasPrefix(seg, "./") || strings.HasPrefix(seg, "../") || !filepath.IsAbs(seg) {
			return true
		}
	}
	return false
}

func isPrivateOrMetadataHost(raw string) bool {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if idx := strings.LastIndex(host, ":"); idx != -1 && strings.Count(host, ":") == 1 {
		host = host[:idx]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	unmapped := addr.Unmap()
	return unmapped.IsPrivate() ||
		unmapped.IsLoopback() ||
		unmapped.IsLinkLocalUnicast() ||
		unmapped.IsLinkLocalMulticast() ||
		unmapped.IsUnspecified() ||
		unmapped.IsMulticast()
}
