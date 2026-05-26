#!/usr/bin/env bash
set -euo pipefail

ZIG_VERSION=0.16.0
ZIG_BASE_URL="https://ziglang.org/download/$ZIG_VERSION"
INSTALL_DIR=${1:-/opt/zig}

case "$(uname -m)" in
  x86_64)
    ZIG_ARCHIVE="zig-x86_64-linux-$ZIG_VERSION.tar.xz"
    ZIG_SHA256="70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00"
    ;;
  aarch64|arm64)
    ZIG_ARCHIVE="zig-aarch64-linux-$ZIG_VERSION.tar.xz"
    ZIG_SHA256="ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17"
    ;;
  *)
    echo "unsupported Linux architecture for Zig install: $(uname -m)" >&2
    exit 1
    ;;
esac

if command -v zig >/dev/null 2>&1; then
  zig version
  exit 0
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zmanager-zig.XXXXXX")"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

curl -fsSLo "$TMP_DIR/$ZIG_ARCHIVE" "$ZIG_BASE_URL/$ZIG_ARCHIVE"
echo "$ZIG_SHA256  $TMP_DIR/$ZIG_ARCHIVE" | sha256sum -c -

mkdir -p "$INSTALL_DIR"
tar -C "$INSTALL_DIR" --strip-components=1 -xf "$TMP_DIR/$ZIG_ARCHIVE"
"$INSTALL_DIR/zig" version
