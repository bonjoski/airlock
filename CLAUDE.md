# Claude Code Guidelines for `airlock`


## Build & Test Commands
- **Build Binary:** `go build -o bin/airlock ./cmd/airlock`
- **Build MCP Server:** `go build -o bin/airlock-mcp ./cmd/airlock-mcp`
- **Unit Tests:** `go test -v ./...`
- **Adversarial Tests:** `go test -v ./tests/adversarial_phase3_test.go ./tests/sec31_extended_threats_test.go`
- **Linter:** `golangci-lint run`
- **Diagnostics:** `./bin/airlock doctor`

## Code Style & Architectural Invariants
- Sub-15ms cold start: zero VM, zero background daemon.
- Native kernel containment: Apple Seatbelt on macOS, Landlock LSM & seccomp on Linux.
- Quarantine sensitive developer files: `~/.ssh`, `~/.aws`, `~/.gnupg`, Keychains.
- Fail closed: return exit code 126 if kernel containment fails.
- No dynamic linker smuggling: strip `LD_PRELOAD` and `DYLD_INSERT_LIBRARIES`.

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
