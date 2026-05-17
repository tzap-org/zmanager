#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: scripts/generate-package-metadata.sh <tag> <release-base-url> <SHA256SUMS> [out-dir]" >&2
  exit 2
fi

TAG=$1
RELEASE_BASE_URL=${2%/}
CHECKSUMS=$3
OUT_DIR=${4:-dist/package-metadata}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_DIR="$ROOT/packaging"
VERSION=${TAG#v}
RELEASE_DATE=${ZMANAGER_RELEASE_DATE:-$(date -u +%F)}

TARGET_AARCH64_APPLE_DARWIN="aarch64-apple-darwin"
TARGET_X86_64_APPLE_DARWIN="x86_64-apple-darwin"
TARGET_AARCH64_UNKNOWN_LINUX_GNU="aarch64-unknown-linux-gnu"
TARGET_X86_64_UNKNOWN_LINUX_GNU="x86_64-unknown-linux-gnu"
TARGET_AARCH64_PC_WINDOWS_MSVC="aarch64-pc-windows-msvc"
TARGET_X86_64_PC_WINDOWS_MSVC="x86_64-pc-windows-msvc"

ASSET_AARCH64_APPLE_DARWIN="zm-$TARGET_AARCH64_APPLE_DARWIN.tar.gz"
ASSET_X86_64_APPLE_DARWIN="zm-$TARGET_X86_64_APPLE_DARWIN.tar.gz"
ASSET_AARCH64_UNKNOWN_LINUX_GNU="zm-$TARGET_AARCH64_UNKNOWN_LINUX_GNU.tar.gz"
ASSET_X86_64_UNKNOWN_LINUX_GNU="zm-$TARGET_X86_64_UNKNOWN_LINUX_GNU.tar.gz"
ASSET_AARCH64_PC_WINDOWS_MSVC="zm-$TARGET_AARCH64_PC_WINDOWS_MSVC.zip"
ASSET_X86_64_PC_WINDOWS_MSVC="zm-$TARGET_X86_64_PC_WINDOWS_MSVC.zip"

checksum_for() {
  local asset=$1
  awk -v asset="$asset" '
    {
      path = $2
      sub(/^.*\//, "", path)
      if (path == asset) {
        print $1
        found = 1
      }
    }
    END {
      if (!found) {
        exit 1
      }
    }
  ' "$CHECKSUMS" || {
    echo "missing checksum for $asset in $CHECKSUMS" >&2
    exit 1
  }
}

sed_escape() {
  printf '%s' "$1" | sed 's/[&|\\]/\\&/g'
}

render_template() {
  local template=$1
  local destination=$2
  mkdir -p "$(dirname "$destination")"

  sed \
    -e "s|__TAG__|$(sed_escape "$TAG")|g" \
    -e "s|__PACKAGE_VERSION__|$(sed_escape "$VERSION")|g" \
    -e "s|__RELEASE_DATE__|$(sed_escape "$RELEASE_DATE")|g" \
    -e "s|__RELEASE_BASE_URL__|$(sed_escape "$RELEASE_BASE_URL")|g" \
    -e "s|__SHA_AARCH64_APPLE_DARWIN__|$SHA_AARCH64_APPLE_DARWIN|g" \
    -e "s|__SHA_X86_64_APPLE_DARWIN__|$SHA_X86_64_APPLE_DARWIN|g" \
    -e "s|__SHA_AARCH64_UNKNOWN_LINUX_GNU__|$SHA_AARCH64_UNKNOWN_LINUX_GNU|g" \
    -e "s|__SHA_X86_64_UNKNOWN_LINUX_GNU__|$SHA_X86_64_UNKNOWN_LINUX_GNU|g" \
    -e "s|__SHA_AARCH64_PC_WINDOWS_MSVC__|$SHA_AARCH64_PC_WINDOWS_MSVC|g" \
    -e "s|__SHA_X86_64_PC_WINDOWS_MSVC__|$SHA_X86_64_PC_WINDOWS_MSVC|g" \
    "$template" > "$destination"
}

SHA_AARCH64_APPLE_DARWIN=$(checksum_for "$ASSET_AARCH64_APPLE_DARWIN")
SHA_X86_64_APPLE_DARWIN=$(checksum_for "$ASSET_X86_64_APPLE_DARWIN")
SHA_AARCH64_UNKNOWN_LINUX_GNU=$(checksum_for "$ASSET_AARCH64_UNKNOWN_LINUX_GNU")
SHA_X86_64_UNKNOWN_LINUX_GNU=$(checksum_for "$ASSET_X86_64_UNKNOWN_LINUX_GNU")
SHA_AARCH64_PC_WINDOWS_MSVC=$(checksum_for "$ASSET_AARCH64_PC_WINDOWS_MSVC")
SHA_X86_64_PC_WINDOWS_MSVC=$(checksum_for "$ASSET_X86_64_PC_WINDOWS_MSVC")

HOMEBREW_OUT="$OUT_DIR/homebrew/Formula/zmanager.rb"
WINGET_OUT="$OUT_DIR/winget/FrankManZhu.ZManagerCLI/$VERSION"

render_template "$TEMPLATE_DIR/homebrew/zmanager.rb.template" "$HOMEBREW_OUT"
render_template \
  "$TEMPLATE_DIR/winget/FrankManZhu.ZManagerCLI.yaml.template" \
  "$WINGET_OUT/FrankManZhu.ZManagerCLI.yaml"
render_template \
  "$TEMPLATE_DIR/winget/FrankManZhu.ZManagerCLI.locale.en-US.yaml.template" \
  "$WINGET_OUT/FrankManZhu.ZManagerCLI.locale.en-US.yaml"
render_template \
  "$TEMPLATE_DIR/winget/FrankManZhu.ZManagerCLI.installer.yaml.template" \
  "$WINGET_OUT/FrankManZhu.ZManagerCLI.installer.yaml"

echo "$HOMEBREW_OUT"
echo "$WINGET_OUT"
