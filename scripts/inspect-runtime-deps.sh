#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: scripts/inspect-runtime-deps.sh <target-triple> [out-dir]" >&2
  exit 2
fi

TARGET=$1
OUT_DIR=${2:-dist}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$ROOT/target/$TARGET/release/zm"
if [[ "$OUT_DIR" = /* ]]; then
  OUT_PATH="$OUT_DIR"
else
  OUT_PATH="$ROOT/$OUT_DIR"
fi
REPORT="$OUT_PATH/zm-$TARGET.deps.txt"

if [[ ! -x "$BINARY" ]]; then
  echo "runtime dependency inspection failed: missing executable $BINARY" >&2
  exit 1
fi

mkdir -p "$(dirname "$REPORT")"

{
  echo "target: $TARGET"
  echo "binary: target/$TARGET/release/zm"
  echo "generated_at_utc: $(date -u +%FT%TZ)"
  echo
  if [[ "$TARGET" == *apple-darwin ]]; then
    echo "tool: otool -L"
    echo
    otool -L "$BINARY"
  elif [[ "$TARGET" == *linux-musl ]]; then
    echo "tool: file + readelf -d"
    echo
    if ! command -v readelf >/dev/null 2>&1; then
      echo "readelf is required to verify static Linux release artifacts" >&2
      exit 1
    fi
    file "$BINARY"
    echo
    if readelf -d "$BINARY" 2>/dev/null | grep -q '(NEEDED)'; then
      readelf -d "$BINARY"
      echo "static Linux runtime dependency inspection failed: dynamic dependencies were found" >&2
      exit 1
    fi
    echo "no ELF NEEDED entries"
  elif [[ "$TARGET" == *linux* ]]; then
    echo "tool: ldd"
    echo
    ldd "$BINARY"
  else
    echo "unsupported target for Unix runtime dependency inspection: $TARGET" >&2
    exit 2
  fi
} > "$REPORT"

echo "$REPORT"
