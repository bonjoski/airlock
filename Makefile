# Airlock Makefile
# Minimalist Workstation Sandbox for Untrusted Package Installs & Agentic Loops

SHELL := /bin/bash
BINARY_NAME := airlock
LEGACY_ALIAS := boxpkg
BIN_DIR := bin
DIST_DIR := dist
MAIN_PKG := ./cmd/airlock
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.5.0")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildTime=$(BUILD_TIME)

# Tool paths
GOLANGCI_LINT := $(shell which golangci-lint 2>/dev/null)
GOVULNCHECK := $(shell which govulncheck 2>/dev/null)

.PHONY: all
all: fmt vet lint vulncheck test build ## Run format, vet, lint, vulncheck, test, and build

.PHONY: help
help: ## Display this help screen
	@echo "Airlock Build & Development Automation"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the optimized release binary in ./bin/airlock and bin/airlock-mcp
	@mkdir -p $(BIN_DIR)
	@echo "==> Building $(BINARY_NAME) $(VERSION)..."
	go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) $(MAIN_PKG)
	@ln -sf $(BINARY_NAME) $(BIN_DIR)/$(LEGACY_ALIAS)
	@echo "==> Building airlock-mcp $(VERSION)..."
	go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/airlock-mcp ./cmd/airlock-mcp
	@echo "==> Binaries built: $(BIN_DIR)/$(BINARY_NAME), $(BIN_DIR)/airlock-mcp"

.PHONY: build-debug
build-debug: ## Build unoptimized debug binary with symbols
	@mkdir -p $(BIN_DIR)
	@echo "==> Building debug $(BINARY_NAME)..."
	go build -race -o $(BIN_DIR)/$(BINARY_NAME)-debug $(MAIN_PKG)
	go build -race -o $(BIN_DIR)/airlock-mcp-debug ./cmd/airlock-mcp
	@echo "==> Debug binaries built in $(BIN_DIR)/"

.PHONY: cross-compile
cross-compile: ## Cross-compile release binaries for Darwin and Linux (amd64, arm64)
	@mkdir -p $(DIST_DIR)
	@echo "==> Cross-compiling $(BINARY_NAME) & airlock-mcp $(VERSION)..."
	@echo "    -> darwin/arm64"
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)_darwin_arm64 $(MAIN_PKG)
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/airlock-mcp_darwin_arm64 ./cmd/airlock-mcp
	@echo "    -> darwin/amd64"
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)_darwin_amd64 $(MAIN_PKG)
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/airlock-mcp_darwin_amd64 ./cmd/airlock-mcp
	@echo "    -> linux/arm64"
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)_linux_arm64 $(MAIN_PKG)
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/airlock-mcp_linux_arm64 ./cmd/airlock-mcp
	@echo "    -> linux/amd64"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)_linux_amd64 $(MAIN_PKG)
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/airlock-mcp_linux_amd64 ./cmd/airlock-mcp
	@echo "==> Cross-compilation complete in $(DIST_DIR)/"

.PHONY: package
package: cross-compile ## Package release tarballs and generate sha256 checksums in dist/
	@echo "==> Packaging release tarballs..."
	@for target in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do \
		tar_dir=$(DIST_DIR)/pkg_$$target; \
		rm -rf $$tar_dir; \
		mkdir -p $$tar_dir; \
		cp $(DIST_DIR)/$(BINARY_NAME)_$$target $$tar_dir/$(BINARY_NAME); \
		cp $(DIST_DIR)/airlock-mcp_$$target $$tar_dir/airlock-mcp; \
		ln -sf $(BINARY_NAME) $$tar_dir/$(LEGACY_ALIAS); \
		[ -f README.md ] && cp README.md $$tar_dir/ || true; \
		[ -f LICENSE ] && cp LICENSE $$tar_dir/ || true; \
		tar -czf $(DIST_DIR)/$(BINARY_NAME)_$${target}.tar.gz -C $$tar_dir .; \
		rm -rf $$tar_dir; \
	done
	@echo "==> Generating SHA256 checksums..."
	@(cd $(DIST_DIR) && shasum -a 256 $(BINARY_NAME)_*.tar.gz > checksums.txt)
	@echo "==> Packages ready in $(DIST_DIR)/:"
	@ls -lh $(DIST_DIR)/$(BINARY_NAME)_*.tar.gz $(DIST_DIR)/checksums.txt

.PHONY: test
test: ## Run all unit and integration tests
	@echo "==> Running tests..."
	go test -v ./...

.PHONY: test-race
test-race: ## Run all tests with Go race detector enabled
	@echo "==> Running tests with race detector..."
	go test -v -race ./...

.PHONY: test-sec
test-sec: ## Run adversarial security integration tests (SEC-01 through SEC-18)
	@echo "==> Running security verification test battery..."
	go test -v ./tests/...

.PHONY: test-install
test-install: ## Run install.sh script integration test suite
	@echo "==> Running installer integration test suite..."
	./tests/install_test.sh

.PHONY: coverage
coverage: ## Run tests and generate HTML coverage report
	@mkdir -p $(DIST_DIR)
	@echo "==> Calculating test coverage..."
	go test -coverprofile=$(DIST_DIR)/coverage.out ./...
	go tool cover -html=$(DIST_DIR)/coverage.out -o $(DIST_DIR)/coverage.html
	@echo "==> Coverage report generated at $(DIST_DIR)/coverage.html"

.PHONY: bench
bench: ## Run performance latency benchmarks
	@echo "==> Running benchmarks..."
	go test -bench=. -benchmem ./...

.PHONY: vulncheck
vulncheck: ## Run official Go vulnerability checker (govulncheck)
	@echo "==> Running govulncheck..."
	@if [ -n "$(GOVULNCHECK)" ]; then \
		govulncheck ./... ; \
	else \
		echo "govulncheck not installed. Installing via 'go install golang.org/x/vuln/cmd/govulncheck@latest'..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest ; \
		$$(go env GOPATH)/bin/govulncheck ./... ; \
	fi

.PHONY: lint
lint: ## Run linter (golangci-lint or go vet fallback)
	@echo "==> Running linter..."
	@if [ -n "$(GOLANGCI_LINT)" ]; then \
		golangci-lint run ./... ; \
	else \
		echo "golangci-lint not found in PATH; running go vet fallback..."; \
		go vet ./... ; \
	fi

.PHONY: vet
vet: ## Run standard go vet analysis
	@echo "==> Running go vet..."
	go vet ./...

.PHONY: fmt
fmt: ## Format all Go source files
	@echo "==> Formatting code..."
	gofmt -s -w .

.PHONY: fmt-check
fmt-check: ## Check code formatting without writing changes
	@echo "==> Checking code format..."
	@test -z "$$(gofmt -s -l . | tee /dev/stderr)" || (echo "Format check failed. Run 'make fmt' to fix." && exit 1)

.PHONY: tidy
tidy: ## Ensure go.mod and go.sum are cleanly synced
	@echo "==> Tidying go.mod..."
	go mod tidy

.PHONY: install
install: build ## Install airlock binary to $(GOPATH)/bin or $(GOBIN)
	@echo "==> Installing $(BINARY_NAME)..."
	go install -ldflags="$(LDFLAGS)" $(MAIN_PKG)
	@echo "==> Installed to $$(go env GOPATH)/bin/$(BINARY_NAME)"

.PHONY: shims-install
shims-install: build ## Install transparent package manager shims in ~/.airlock/bin
	@echo "==> Installing transparent shell shims..."
	./$(BIN_DIR)/$(BINARY_NAME) shim install

.PHONY: shims-uninstall
shims-uninstall: build ## Remove transparent package manager shims from ~/.airlock/bin
	@echo "==> Uninstalling transparent shell shims..."
	./$(BIN_DIR)/$(BINARY_NAME) shim uninstall

.PHONY: clean
clean: ## Remove compiled binaries, coverage profiles, and test artifacts
	@echo "==> Cleaning build artifacts..."
	@rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out coverage.html
	@echo "==> Clean complete."
