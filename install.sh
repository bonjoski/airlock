#!/usr/bin/env sh
# Airlock Standalone Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/bonjoski/airlock/main/install.sh | sh
#
# Environment variables:
#   AIRLOCK_VERSION     Version to install (e.g. "v1.0.0", default: latest)
#   AIRLOCK_INSTALL_DIR Target directory (default: "$HOME/.airlock/bin")
#   NO_SHIMS            Set to 1 to skip automatic shim installation
#   DRY_RUN             Set to 1 to simulate installation without modifying system

set -eu

REPO="bonjoski/airlock"
DEFAULT_VERSION="v0.6.0"

# Color helpers (disabled if not connected to a terminal)
if [ -t 1 ]; then
    RED="\033[0;31m"
    GREEN="\033[0;32m"
    BLUE="\033[0;34m"
    YELLOW="\033[0;33m"
    BOLD="\033[1m"
    RESET="\033[0m"
else
    RED=""
    GREEN=""
    BLUE=""
    YELLOW=""
    BOLD=""
    RESET=""
fi

log_info() {
    printf "${BLUE}==>${RESET} ${BOLD}%s${RESET}\n" "$1"
}

log_success() {
    printf "${GREEN}==>${RESET} ${BOLD}%s${RESET}\n" "$1"
}

log_warn() {
    printf "${YELLOW}WARNING:${RESET} %s\n" "$1"
}

log_error() {
    printf "${RED}ERROR:${RESET} %s\n" "$1" >&2
}

# Parse CLI flags
VERSION="${AIRLOCK_VERSION:-}"
INSTALL_DIR="${AIRLOCK_INSTALL_DIR:-}"
INSTALL_SHIMS=1
DRY_RUN="${DRY_RUN:-0}"

if [ "${NO_SHIMS:-0}" = "1" ]; then
    INSTALL_SHIMS=0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -d|--dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --no-shims)
            INSTALL_SHIMS=0
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            cat <<EOF
Airlock Universal Installer

Usage:
  install.sh [options]

Options:
  -v, --version <tag>   Install specific version (default: latest release)
  -d, --dir <path>      Install directory (default: ~/.airlock/bin)
      --no-shims        Skip installing package manager shims
      --dry-run         Print steps without modifying files
  -h, --help            Show this help message

Environment Variables:
  AIRLOCK_VERSION       Same as --version
  AIRLOCK_INSTALL_DIR   Same as --dir
  NO_SHIMS=1            Same as --no-shims
EOF
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Detect OS
OS_RAW="$(uname -s)"
case "$OS_RAW" in
    Darwin*)
        OS="darwin"
        ;;
    Linux*)
        OS="linux"
        ;;
    *)
        log_error "Unsupported operating system: $OS_RAW. Airlock currently supports macOS (Darwin) and Linux."
        exit 1
        ;;
esac

# Detect Architecture
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    arm64|aarch64)
        ARCH="arm64"
        ;;
    *)
        log_error "Unsupported architecture: $ARCH_RAW. Airlock supports amd64 and arm64."
        exit 1
        ;;
esac

# Default install directory
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="$HOME/.airlock/bin"
fi

# Helper for HTTP download
download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        log_error "Neither curl nor wget is available. Please install curl or wget."
        exit 1
    fi
}

# Resolve latest release version if not specified
if [ -z "$VERSION" ]; then
    log_info "Fetching latest release version..."
    LATEST_JSON=""
    if command -v curl >/dev/null 2>&1; then
        LATEST_JSON="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || true)"
    elif command -v wget >/dev/null 2>&1; then
        LATEST_JSON="$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || true)"
    fi

    if [ -n "$LATEST_JSON" ]; then
        VERSION="$(printf "%s" "$LATEST_JSON" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)"
    fi

    if [ -z "$VERSION" ]; then
        VERSION="$DEFAULT_VERSION"
    fi
fi

# Ensure version has 'v' prefix for release URL
case "$VERSION" in
    v*) ;;
    *) VERSION="v${VERSION}" ;;
esac

TARBALL_NAME="airlock_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL_NAME}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

log_info "Installing Airlock ${VERSION} for ${OS}/${ARCH} into ${INSTALL_DIR}..."

if [ "$DRY_RUN" = "1" ]; then
    log_info "[DRY-RUN] Would download: ${DOWNLOAD_URL}"
    log_info "[DRY-RUN] Would download: ${CHECKSUMS_URL}"
    log_info "[DRY-RUN] Would verify SHA256 checksum for ${TARBALL_NAME}"
    log_info "[DRY-RUN] Would extract binary into ${INSTALL_DIR}/airlock"
    if [ "$INSTALL_SHIMS" = "1" ]; then
        log_info "[DRY-RUN] Would run: ${INSTALL_DIR}/airlock shim install"
    fi
    log_success "Dry run complete."
    exit 0
fi

# Create scratch temporary directory
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'airlock-install')"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

log_info "Downloading ${TARBALL_NAME}..."
download "$DOWNLOAD_URL" "${TMP_DIR}/${TARBALL_NAME}"

log_info "Downloading checksums.txt..."
download "$CHECKSUMS_URL" "${TMP_DIR}/checksums.txt"

# Verify Sigstore Cosign keyless provenance if cosign is installed
if command -v cosign >/dev/null 2>&1; then
    BUNDLE_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt.bundle"
    log_info "Downloading Sigstore Cosign verification bundle..."
    if download "$BUNDLE_URL" "${TMP_DIR}/checksums.txt.bundle" 2>/dev/null; then
        log_info "Verifying keyless signature via Sigstore / Rekor transparency log..."
        if cosign verify-blob \
            --bundle "${TMP_DIR}/checksums.txt.bundle" \
            --certificate-identity-regexp "^https://github.com/${REPO}/" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "${TMP_DIR}/checksums.txt" >/dev/null 2>&1; then
            log_success "Cryptographic provenance verified with Sigstore Cosign (keyless OIDC)! 🔏"
        else
            log_warn "Sigstore Cosign signature verification failed for checksums.txt. Proceeding with SHA256 validation."
        fi
    fi
fi

# Verify SHA256 checksum
log_info "Verifying cryptographic checksum..."
EXPECTED_HASH="$(grep "${TARBALL_NAME}" "${TMP_DIR}/checksums.txt" | awk '{print $1}')"

if [ -z "$EXPECTED_HASH" ]; then
    log_error "Could not find checksum for ${TARBALL_NAME} in checksums.txt"
    exit 1
fi

ACTUAL_HASH=""
if command -v shasum >/dev/null 2>&1; then
    ACTUAL_HASH="$(shasum -a 256 "${TMP_DIR}/${TARBALL_NAME}" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_HASH="$(sha256sum "${TMP_DIR}/${TARBALL_NAME}" | awk '{print $1}')"
else
    log_warn "Neither shasum nor sha256sum available. Skipping checksum validation."
fi

if [ -n "$ACTUAL_HASH" ]; then
    if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
        log_error "Checksum verification failed!"
        log_error "Expected: $EXPECTED_HASH"
        log_error "Actual:   $ACTUAL_HASH"
        exit 1
    fi
    log_success "Checksum verified: ${ACTUAL_HASH}"
fi

# Extract and install binary
mkdir -p "$INSTALL_DIR"
tar -xzf "${TMP_DIR}/${TARBALL_NAME}" -C "$TMP_DIR"

if [ ! -f "${TMP_DIR}/airlock" ]; then
    log_error "Archive did not contain 'airlock' executable binary."
    exit 1
fi

mv "${TMP_DIR}/airlock" "${INSTALL_DIR}/airlock"
chmod 755 "${INSTALL_DIR}/airlock"

if [ -f "${TMP_DIR}/airlock-mcp" ]; then
    mv "${TMP_DIR}/airlock-mcp" "${INSTALL_DIR}/airlock-mcp"
    chmod 755 "${INSTALL_DIR}/airlock-mcp"
fi

log_success "Airlock binary installed successfully to ${INSTALL_DIR}/airlock"

# Install package manager shims if requested
if [ "$INSTALL_SHIMS" = "1" ]; then
    log_info "Configuring transparent package manager shims (npm, pip, cargo, uv, bun)..."
    "${INSTALL_DIR}/airlock" shim install --target "$INSTALL_DIR" || log_warn "Failed to configure shims automatically."
fi

# Check PATH setup
PATH_CONFIGURED=0
case ":${PATH}:" in
    *:"${INSTALL_DIR}":*)
        PATH_CONFIGURED=1
        ;;
esac

printf "\n"
log_success "Airlock ${VERSION} installation complete! 🛡️"
printf "\n"

if [ "$PATH_CONFIGURED" = "0" ]; then
    printf "${BOLD}To use Airlock and transparent package manager shims, add this to your shell profile:${RESET}\n"
    printf "  export PATH=\"%s:\$PATH\"\n\n" "$INSTALL_DIR"
    
    DETECTED_SHELL="$(basename "${SHELL:-sh}")"
    case "$DETECTED_SHELL" in
        zsh)
            printf "Run: ${BLUE}echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc && source ~/.zshrc${RESET}\n\n" "$INSTALL_DIR"
            ;;
        bash)
            printf "Run: ${BLUE}echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc && source ~/.bashrc${RESET}\n\n" "$INSTALL_DIR"
            ;;
        *)
            printf "Run: ${BLUE}echo 'export PATH=\"%s:\$PATH\"' >> ~/.profile${RESET}\n\n" "$INSTALL_DIR"
            ;;
    esac
fi

printf "Quick Start:\n"
printf "  • Run untrusted command in sandbox:   ${BLUE}airlock run -- npm install${RESET}\n"
printf "  • Direct shorthand:                   ${BLUE}airlock npm install${RESET}\n"
printf "  • Offline airgap isolation:           ${BLUE}airlock --airgap pip install .${RESET}\n"
printf "  • Verify status & installed shims:   ${BLUE}airlock shim list${RESET}\n\n"
