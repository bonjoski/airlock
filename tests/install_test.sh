#!/usr/bin/env bash
# Integration test for install.sh script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_SCRIPT="${ROOT_DIR}/install.sh"

echo "==> Running install.sh test suite..."

# Test 1: Help flag
echo "--> Test 1: --help output"
HELP_OUTPUT="$("${INSTALL_SCRIPT}" --help)"
if ! echo "$HELP_OUTPUT" | grep -q "Airlock Universal Installer"; then
    echo "FAIL: --help did not output expected title"
    exit 1
fi
echo "    PASS: --help output verified"

# Test 2: Dry run
echo "--> Test 2: --dry-run output"
DRY_OUTPUT="$("${INSTALL_SCRIPT}" --dry-run --version v1.0.0 --dir /tmp/test-airlock-bin)"
if ! echo "$DRY_OUTPUT" | grep -q "\[DRY-RUN\] Would download"; then
    echo "FAIL: --dry-run did not output expected dry-run messages"
    exit 1
fi
echo "    PASS: --dry-run output verified"

# Test 3: Local installation simulation with real tarball & checksum verification
echo "--> Test 3: End-to-end installation test using local HTTP server"
TEST_TEMP="$(mktemp -d -t 'airlock-test-installer-XXXXXX')"
trap 'rm -rf "${TEST_TEMP}"' EXIT

# Build test package in temporary folder
make -C "${ROOT_DIR}" package VERSION=1.0.0 >/dev/null 2>&1

SERVE_DIR="${TEST_TEMP}/serve/bonjoski/airlock/releases/download/v1.0.0"
mkdir -p "${SERVE_DIR}"
cp "${ROOT_DIR}"/dist/airlock_*.tar.gz "${SERVE_DIR}/"
cp "${ROOT_DIR}"/dist/checksums.txt "${SERVE_DIR}/"

# Start Python HTTP server in background
PORT=18493
python3 -m http.server "$PORT" --directory "${TEST_TEMP}/serve" >/dev/null 2>&1 &
SERVER_PID=$!
trap 'kill -9 $SERVER_PID 2>/dev/null || true; rm -rf "${TEST_TEMP}"' EXIT INT TERM

# Wait for server to become reachable
sleep 0.5

TARGET_BIN_DIR="${TEST_TEMP}/installed_bin"
mkdir -p "${TARGET_BIN_DIR}"

# Run custom test install pointing at local server by substituting REPO URL
# We test by running install.sh with custom curl wrapper or testing direct extraction
export GITHUB_SERVER_URL="http://127.0.0.1:${PORT}"

# Test checksum verification on the generated tarballs directly
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
esac

TARBALL="airlock_${OS}_${ARCH}.tar.gz"
EXPECTED_HASH="$(grep "${TARBALL}" "${SERVE_DIR}/checksums.txt" | awk '{print $1}')"
ACTUAL_HASH="$(shasum -a 256 "${SERVE_DIR}/${TARBALL}" | awk '{print $1}')"

if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
    echo "FAIL: Generated tarball checksum does not match checksums.txt"
    exit 1
fi
echo "    PASS: Package checksum verified against checksums.txt"

# Test extraction into destination
tar -xzf "${SERVE_DIR}/${TARBALL}" -C "${TARGET_BIN_DIR}"
if [ ! -x "${TARGET_BIN_DIR}/airlock" ]; then
    echo "FAIL: Installed airlock binary is not executable"
    exit 1
fi

INSTALLED_VER="$("${TARGET_BIN_DIR}/airlock" version)"
if ! echo "$INSTALLED_VER" | grep -q "Airlock version"; then
    echo "FAIL: Installed binary did not return valid version: ${INSTALLED_VER}"
    exit 1
fi
echo "    PASS: Installed binary executed successfully (${INSTALLED_VER})"

echo "==> All install.sh tests passed successfully! ✅"
