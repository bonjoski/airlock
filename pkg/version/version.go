// Package version defines the single source of truth for the Airlock project version,
// build commit hash, and build timestamp.
package version

var (
	// Version is the current semantic version of Airlock.
	Version = "0.6.0"

	// Commit is the git commit SHA injected at build time via -ldflags.
	Commit = "unknown"

	// BuildTime is the ISO-8601/RFC-3339 build timestamp injected at build time via -ldflags.
	BuildTime = "unknown"
)
