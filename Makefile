# Airlock Makefile
# Minimalist Workstation Sandbox for Untrusted Package Installs & Agentic Loops

SHELL := /bin/bash
BINARY_NAME := airlock
LEGACY_ALIAS := boxpkg
BIN_DIR := bin
DIST_DIR := dist
MAIN_PKG := ./cmd/airlock
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
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
build: ## Build the optimized release binary in ./bin/airlock (and symlink bin/boxpkg)
	@mkdir -p $(BIN_DIR)
	@echo "==> Building $(BINARY_NAME) $(VERSION)..."
	go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) $(MAIN_PKG)
	@ln -sf $(BINARY_NAME) $(BIN_DIR)/$(LEGACY_ALIAS)
	@echo "==> Binary built: $(BIN_DIR)/$(BINARY_NAME) (aliased as $(BIN_DIR)/$(LEGACY_ALIAS))"

.PHONY: build-debug
build-debug: ## Build unoptimized debug binary with symbols
	@mkdir -p $(BIN_DIR)
	@echo "==> Building debug $(BINARY_NAME)..."
	go build -race -o $(BIN_DIR)/$(BINARY_NAME)-debug $(MAIN_PKG)
	@echo "==> Debug binary built: $(BIN_DIR)/$(BINARY_NAME)-debug"

.PHONY: test
test: ## Run all unit and integration tests
	@echo "==> Running tests..."
	go test -v ./...

.PHONY: test-race
test-race: ## Run all tests with Go race detector enabled
	@echo "==> Running tests with race detector..."
	go test -v -race ./...

.PHONY: test-sec
test-sec: ## Run adversarial security integration tests (SEC-01 through SEC-12)
	@echo "==> Running security verification test battery..."
	go test -v ./tests/...

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
