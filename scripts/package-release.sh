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
cp README.md LICENSE NOTICE "$STAGE/"
PYTHON_BIN=${PYTHON:-}
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN=python
  else
    echo "python3 or python is required to generate third-party notices" >&2
    exit 1
  fi
fi
"$PYTHON_BIN" scripts/generate-third-party-notices.py \
  --out-notices "$STAGE/THIRD_PARTY_NOTICES.md" \
  --license-dir "$STAGE/third-party-licenses" >/dev/null
mkdir -p "$STAGE/completions"
cp completions/zm.bash completions/_zm completions/zm.fish "$STAGE/completions/"
mkdir -p "$STAGE/man/man1"
cp docs/man/zm.1 "$STAGE/man/man1/"

if [[ "$TARGET" == *windows* ]]; then
  (cd "$STAGE" && zip -q -9 -r "$OUT_ABS/$ARCHIVE" "$BINARY" README.md LICENSE NOTICE THIRD_PARTY_NOTICES.md third-party-licenses completions man)
else
  tar -C "$STAGE" -czf "$OUT_ABS/$ARCHIVE" "$BINARY" README.md LICENSE NOTICE THIRD_PARTY_NOTICES.md third-party-licenses completions man
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$OUT_ABS/$ARCHIVE" > "$OUT_ABS/$ARCHIVE.sha256"
else
  sha256sum "$OUT_ABS/$ARCHIVE" > "$OUT_ABS/$ARCHIVE.sha256"
fi

scripts/inspect-runtime-deps.sh "$TARGET" "$OUT_ABS" >/dev/null

echo "$OUT_DIR/$ARCHIVE"
