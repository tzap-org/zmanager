#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: scripts/package-release.sh <target-triple> [out-dir]" >&2
  exit 2
fi

TARGET=$1
OUT_DIR=${2:-dist}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE="zm-$TARGET.tar.gz"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/zmanager-release.XXXXXX")"

cleanup() {
  rm -rf "$STAGE"
}
trap cleanup EXIT

cd "$ROOT"
mkdir -p "$OUT_DIR"

cargo build --locked --release --target "$TARGET" -p zmanager-cli --bin zm

cp "target/$TARGET/release/zm" "$STAGE/zm"
cp README.md LICENSE THIRD_PARTY_NOTICES.md "$STAGE/"

tar -C "$STAGE" -czf "$OUT_DIR/$ARCHIVE" zm README.md LICENSE THIRD_PARTY_NOTICES.md

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$OUT_DIR/$ARCHIVE" > "$OUT_DIR/$ARCHIVE.sha256"
else
  sha256sum "$OUT_DIR/$ARCHIVE" > "$OUT_DIR/$ARCHIVE.sha256"
fi

echo "$OUT_DIR/$ARCHIVE"
