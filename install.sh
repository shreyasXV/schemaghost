#!/usr/bin/env bash
# FaultWall installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/shreyasXV/faultwall/main/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --version v0.3.0
#   curl -fsSL .../install.sh | bash -s -- --dir ~/bin
#
set -euo pipefail

REPO="shreyasXV/faultwall"
BIN_NAME="faultwall"
INSTALL_DIR="/usr/local/bin"
VERSION="latest"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dir)     INSTALL_DIR="$2"; shift 2 ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Resolve latest version tag if needed
if [[ "$VERSION" == "latest" ]]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' \
    | head -1 \
    | sed 's/"tag_name": *"\([^"]*\)"/\1/')
  if [[ -z "$VERSION" ]]; then
    echo "Failed to resolve latest version" >&2
    exit 1
  fi
fi

ASSET="faultwall-${VERSION}-${OS}-${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"

echo "🔒 FaultWall installer"
echo "    version: $VERSION"
echo "    target:  $OS/$ARCH"
echo "    url:     $URL"
echo

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "→ Downloading..."
curl -fsSL "$URL" -o "$TMP/$ASSET"

# Verify checksum if available
if curl -fsSL "https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt" -o "$TMP/checksums.txt" 2>/dev/null; then
  echo "→ Verifying checksum..."
  EXPECTED=$(grep "$ASSET" "$TMP/checksums.txt" | awk '{print $1}')
  if [[ -n "$EXPECTED" ]]; then
    ACTUAL=$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')
    if [[ "$EXPECTED" != "$ACTUAL" ]]; then
      echo "✗ Checksum mismatch!" >&2
      echo "  expected: $EXPECTED" >&2
      echo "  got:      $ACTUAL" >&2
      exit 1
    fi
    echo "  ✓ checksum verified"
  fi
fi

echo "→ Extracting..."
tar -xzf "$TMP/$ASSET" -C "$TMP"

# Find the extracted binary, excluding the tarball itself
EXTRACTED=$(find "$TMP" -maxdepth 1 -name 'faultwall-*' -type f ! -name '*.tar.gz' ! -name '*.tgz' | head -1)
if [[ -z "$EXTRACTED" ]]; then
  echo "✗ Binary not found after extraction" >&2
  exit 1
fi

# Verify it's actually an executable, not a misnamed archive
if file "$EXTRACTED" | grep -qE 'gzip|compressed|archive'; then
  echo "✗ Expected binary but got archive: $EXTRACTED" >&2
  echo "  file type: $(file -b "$EXTRACTED")" >&2
  exit 1
fi

# Install
if [[ -w "$INSTALL_DIR" ]]; then
  mv "$EXTRACTED" "$INSTALL_DIR/$BIN_NAME"
  chmod +x "$INSTALL_DIR/$BIN_NAME"
else
  echo "→ Installing to $INSTALL_DIR (needs sudo)..."
  sudo mv "$EXTRACTED" "$INSTALL_DIR/$BIN_NAME"
  sudo chmod +x "$INSTALL_DIR/$BIN_NAME"
fi

echo
echo "✅ Installed faultwall $VERSION → $INSTALL_DIR/$BIN_NAME"
echo
echo "Next: run"
echo "  faultwall init"
echo "  faultwall --proxy --policies faultwall.yaml"
