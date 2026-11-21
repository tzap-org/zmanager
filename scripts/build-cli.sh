#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "$TARGET" ]]; then
  echo "could not determine the Rust host target" >&2
  exit 1
fi

OPENSSL_DIR="$(python3 "$ROOT/scripts/build-openssl.py" "$TARGET")"
export OPENSSL_DIR OPENSSL_STATIC=1 OPENSSL_NO_VENDOR=1

cargo build --release -p zmanager-cli --bin zm "$@"

echo "Built $ROOT/target/release/zm"
