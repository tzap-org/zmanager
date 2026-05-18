#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

missing=()

require_tool() {
  local tool=$1
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
}

require_any_tool() {
  local label=$1
  shift
  local tool
  for tool in "$@"; do
    if command -v "$tool" >/dev/null 2>&1; then
      return 0
    fi
  done
  missing+=("$label")
}

for tool in \
  brotli \
  bzip2 \
  bsdtar \
  dpkg-deb \
  gcab \
  gzip \
  lz4 \
  lzip \
  lzop \
  lrzip \
  mkisofs \
  rar \
  rpmbuild \
  uncompress \
  unzip \
  xz \
  zip \
  zstd
do
  require_tool "$tool"
done

require_any_tool "7zz or 7z" 7zz 7z

if [ "${#missing[@]}" -ne 0 ]; then
  printf 'missing release compatibility tools:\n' >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi

cargo test -p zmanager-cli --test compat_formats_cli -- --nocapture
