// Package vet provides pre-execution static analysis and heuristic inspection.
package vet

import (
	"strings"
)

// KnownMaliciousPackages contains historical malicious/typosquatted packages identified across registries.
var KnownMaliciousPackages = map[string]string{
	"crossenv":                "npm malicious package masquerading as cross-env",
	"colorama-v2":             "PyPI supply chain attack targeting colorama",
	"reqeusts":                "PyPI typosquat targeting requests",
	"python3-dateutil":        "PyPI typosquat targeting python-dateutil",
	"nodetest1":               "npm credential exfiltration test vector",
	"discord.js-api":          "npm token stealer masquerading as discord.js",
	"nobles-curves":           "npm typosquat targeting @noble/curves",
	"flatmap-stream":          "npm backdoor targeting bitcore-wallet-client",
	"event-stream-v2":         "npm hijacked package clone",
	"babelcli":                "npm typosquat targeting babel-cli",
	"cross-env.js":            "npm typosquat targeting cross-env",
	"d3.js":                   "npm typosquat targeting d3",
	"fabric-js":               "npm typosquat targeting fabric",
	"gruntcli":                "npm typosquat targeting grunt-cli",
	"http-proxy.js":           "npm typosquat targeting http-proxy",
	"jquerry":                 "npm typosquat targeting jquery",
	"mariadb-node":            "npm typosquat targeting mariadb",
	"mongose":                 "npm typosquat targeting mongoose",
	"mssql-node":              "npm typosquat targeting mssql",
	"mysqljs":                 "npm typosquat targeting mysql",
	"node-fabric":             "npm typosquat targeting fabric",
	"node-opencv":             "npm typosquat targeting opencv",
	"node-openssl":            "npm typosquat targeting openssl",
	"node-sqlite":             "npm typosquat targeting sqlite3",
	"node-tkinter":            "npm typosquat targeting tkinter",
	"nodemailer-js":           "npm typosquat targeting nodemailer",
	"noderequest":             "npm typosquat targeting request",
	"open-cv":                 "npm typosquat targeting opencv",
	"openssl-js":              "npm typosquat targeting openssl",
	"puppeteer-extra-stealth": "npm typosquat targeting puppeteer-extra-plugin-stealth",
	"shadow-socks":            "npm typosquat targeting shadowsocks",
	"sqlite.js":               "npm typosquat targeting sqlite3",
	"sqlserver":               "npm typosquat targeting tedious / mssql",
	"urllib4":                 "PyPI typosquat targeting urllib3",
	"crypto-js-node":          "npm typosquat targeting crypto-js",
	"chalk-v2":                "npm typosquat targeting chalk",
}

// HighProfilePackages are the top most downloaded libraries across npm, PyPI, and Crates.io
var HighProfilePackages = []string{
	// npm
	"lodash", "express", "react", "react-dom", "axios", "chalk", "commander",
	"vue", "angular", "next", "typescript", "webpack", "debug", "moment",
	"async", "bluebird", "dotenv", "ws", "redux", "socket.io", "rxjs",
	"yargs", "body-parser", "mongoose", "postcss", "eslint", "prettier",

	// PyPI
	"requests", "urllib3", "numpy", "pandas", "flask", "django", "scipy",
	"pytest", "cryptography", "colorama", "pydantic", "torch", "boto3",
	"pillow", "setuptools", "wheel", "pyyaml", "certifi", "six", "click",

	// Cargo / Crates.io
	"serde", "tokio", "syn", "rand", "clap", "anyhow", "tracing",
	"hyper", "reqwest", "futures", "log", "bytes", "regex", "itertools",
}

// LevenshteinDistance computes the minimum edit distance between two strings.
func LevenshteinDistance(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	l1, l2 := len(r1), len(r2)

	if l1 == 0 {
		return l2
	}
	if l2 == 0 {
		return l1
	}

	prev := make([]int, l2+1)
	curr := make([]int, l2+1)

	for j := 0; j <= l2; j++ {
		prev[j] = j
	}

	for i := 1; i <= l1; i++ {
		curr[0] = i
		for j := 1; j <= l2; j++ {
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			curr[j] = min(
				curr[j-1]+1,    // insertion
				prev[j]+1,      // deletion
				prev[j-1]+cost, // substitution
			)
		}
		copy(prev, curr)
	}

	return curr[l2]
}

func min(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// ExtractPackageNames parses target package names from CLI installation arguments.
func ExtractPackageNames(cmdArgs []string) []string {
	if len(cmdArgs) == 0 {
		return nil
	}

	tool := filepathBase(cmdArgs[0])
	var pkgs []string
	inInstallMode := false

	for i := 1; i < len(cmdArgs); i++ {
		arg := cmdArgs[i]

		// Skip options / flags
		if strings.HasPrefix(arg, "-") {
			continue
		}

		// Mode check
		switch tool {
		case "npm", "pnpm", "yarn", "bun":
			if arg == "install" || arg == "i" || arg == "add" {
				inInstallMode = true
				continue
			}
		case "pip", "pip3", "uv":
			if arg == "install" || arg == "add" {
				inInstallMode = true
				continue
			}
		case "cargo":
			if arg == "add" {
				inInstallMode = true
				continue
			}
		default:
			if arg == "install" || arg == "add" {
				inInstallMode = true
				continue
			}
		}

		if inInstallMode {
			// Strip version constraints, e.g. express@4.18.2 or requests==2.31.0
			clean := cleanPackageName(arg)
			if clean != "" && !strings.HasPrefix(clean, ".") && !strings.HasPrefix(clean, "/") {
				pkgs = append(pkgs, clean)
			}
		}
	}

	return pkgs
}

func filepathBase(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

func cleanPackageName(pkg string) string {
	// Strip scope if needed or normalize
	clean := pkg

	// Handle npm scope e.g. @org/foo -> foo or full
	if strings.Contains(clean, "==") {
		clean = strings.Split(clean, "==")[0]
	} else if strings.Contains(clean, ">=") {
		clean = strings.Split(clean, ">=")[0]
	} else if strings.Contains(clean, "<=") {
		clean = strings.Split(clean, "<=")[0]
	} else if strings.Contains(clean, "@") && !strings.HasPrefix(clean, "@") {
		clean = strings.Split(clean, "@")[0]
	}

	return strings.TrimSpace(strings.ToLower(clean))
}

// CheckTyposquatting returns findings if the package name is a known malicious package or typosquat.
func CheckTyposquatting(pkgName string) (isKnownMalicious bool, reason string, isSquat bool, target string) {
	pkgNorm := strings.ToLower(strings.TrimSpace(pkgName))
	if pkgNorm == "" {
		return false, "", false, ""
	}

	// 1. Direct match on known malicious/hijacked package database
	if desc, ok := KnownMaliciousPackages[pkgNorm]; ok {
		return true, desc, false, ""
	}

	// 2. Proximity check against high-profile ecosystem packages
	for _, popular := range HighProfilePackages {
		if pkgNorm == popular {
			// Exact match to benign popular package
			continue
		}

		dist := LevenshteinDistance(pkgNorm, popular)

		// Distance 1 match on names >= 4 chars, or Distance 2 on names >= 8 chars
		if (dist == 1 && len(popular) >= 4) || (dist == 2 && len(popular) >= 8 && len(pkgNorm) >= 8) {
			return false, "", true, popular
		}
	}

	return false, "", false, ""
}
