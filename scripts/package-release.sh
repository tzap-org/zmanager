#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: scripts/package-release.sh <target-triple> [out-dir]" >&2
  exit 2
fi

TARGET=$1
OUT_DIR=${2:-dist}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/zmanager-release.XXXXXX")"

cleanup() {
  rm -rf "$STAGE"
}
trap cleanup EXIT

cd "$ROOT"
mkdir -p "$OUT_DIR"
OUT_ABS="$(cd "$OUT_DIR" && pwd)"

if [[ "$TARGET" == *windows* ]]; then
  BINARY="zm.exe"
  ARCHIVE="zm-$TARGET.zip"
else
  BINARY="zm"
  ARCHIVE="zm-$TARGET.tar.gz"
fi

cargo build --locked --release --target "$TARGET" -p zmanager-cli --bin zm

cp "target/$TARGET/release/$BINARY" "$STAGE/$BINARY"
cp README.md LICENSE THIRD_PARTY_NOTICES.md "$STAGE/"

if [[ "$TARGET" == *windows* ]]; then
  (cd "$STAGE" && zip -q -9 "$OUT_ABS/$ARCHIVE" "$BINARY" README.md LICENSE THIRD_PARTY_NOTICES.md)
else
  tar -C "$STAGE" -czf "$OUT_ABS/$ARCHIVE" "$BINARY" README.md LICENSE THIRD_PARTY_NOTICES.md
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$OUT_ABS/$ARCHIVE" > "$OUT_ABS/$ARCHIVE.sha256"
else
  sha256sum "$OUT_ABS/$ARCHIVE" > "$OUT_ABS/$ARCHIVE.sha256"
fi

echo "$OUT_DIR/$ARCHIVE"
