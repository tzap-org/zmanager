#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVES="$ROOT/fixtures/archives"
MANIFEST="$ARCHIVES/manifest.tsv"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zmanager-fixtures.XXXXXX")"
SRC="$WORK/payload"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$ARCHIVES"
rm -f "$ARCHIVES"/basic.zip \
  "$ARCHIVES"/basic.7z \
  "$ARCHIVES"/basic.tar.gz \
  "$ARCHIVES"/basic.tar.xz \
  "$ARCHIVES"/basic.tar.zst \
  "$ARCHIVES"/basic.cpio \
  "$ARCHIVES"/basic.xar \
  "$ARCHIVES"/basic.iso \
  "$ARCHIVES"/basic.deb

mkdir -p "$SRC/nested/empty-dir"
mkdir -p "$SRC/dir with spaces"
mkdir -p "$SRC/unicode"

printf 'Z-Manager fixture payload\n' > "$SRC/README.txt"
printf 'nested fixture file\n' > "$SRC/nested/file.txt"
printf 'spaces in path\n' > "$SRC/dir with spaces/file with spaces.txt"
printf 'unicode path fixture\n' > "$SRC/unicode/こんにちは.txt"

if ln -s "../README.txt" "$SRC/nested/readme-link.txt" 2>/dev/null; then
  :
fi

(
  cd "$ROOT"
  cargo run -p zmanager-cli -- zip-create "$SRC" "$ARCHIVES/basic.zip" deflate
  cargo run -p zmanager-cli -- source-small "$SRC" "$ARCHIVES/basic.7z" solid
  cargo run -p zmanager-cli -- source-fast "$SRC" "$ARCHIVES/basic.tar.zst" 1
)

bsdtar -czf "$ARCHIVES/basic.tar.gz" -C "$WORK" payload
bsdtar -cJf "$ARCHIVES/basic.tar.xz" -C "$WORK" payload
bsdtar --format=cpio -cf "$ARCHIVES/basic.cpio" -C "$WORK" payload

(
  cd "$WORK"
  xar -cf "$ARCHIVES/basic.xar" payload
)

ISO_SRC="$WORK/iso-payload"
mkdir -p "$ISO_SRC/nested/empty-dir"
mkdir -p "$ISO_SRC/dir with spaces"
mkdir -p "$ISO_SRC/unicode"
cp "$SRC/README.txt" "$ISO_SRC/README.txt"
cp "$SRC/nested/file.txt" "$ISO_SRC/nested/file.txt"
cp "$SRC/dir with spaces/file with spaces.txt" "$ISO_SRC/dir with spaces/file with spaces.txt"
cp "$SRC/unicode/こんにちは.txt" "$ISO_SRC/unicode/こんにちは.txt"
hdiutil makehybrid -iso -joliet -o "$ARCHIVES/basic.iso" "$ISO_SRC" >/dev/null

DEB="$WORK/deb"
mkdir -p "$DEB/control" "$DEB/data/usr/share/zmanager-fixture"
printf '2.0\n' > "$DEB/debian-binary"
cat > "$DEB/control/control" <<'CONTROL'
Package: zmanager-fixture
Version: 0.1.0
Architecture: all
Maintainer: Z-Manager <fixtures@example.invalid>
Description: Small archive fixture for Z-Manager compatibility tests
CONTROL
cp "$SRC/README.txt" "$DEB/data/usr/share/zmanager-fixture/README.txt"
bsdtar -czf "$DEB/control.tar.gz" -C "$DEB/control" control
bsdtar -cJf "$DEB/data.tar.xz" -C "$DEB/data" .
bsdtar --format=ar -cf "$ARCHIVES/basic.deb" -C "$DEB" debian-binary control.tar.gz data.tar.xz

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    echo "missing SHA-256 tool; install shasum or sha256sum" >&2
    exit 1
  fi
}

append_manifest() {
  local filename="$1"
  local format="$2"
  local extract="$3"
  local password="$4"
  local notes="$5"
  local checksum
  checksum="$(sha256_file "$ARCHIVES/$filename")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$filename" "$format" "$extract" "$password" "$checksum" "$notes" >> "$MANIFEST"
}

printf '# filename\tformat\textract\tpassword\tsha256\tnotes\n' > "$MANIFEST"
append_manifest "basic.zip" "ZIP" "true" "" "ZIP Deflate fixture created by Z-Manager"
append_manifest "basic.7z" "7Z" "true" "" "7Z LZMA2 solid fixture created by Z-Manager"
append_manifest "basic.tar.gz" "TAR.GZ" "true" "" "Tar fixture compressed with gzip"
append_manifest "basic.tar.xz" "TAR.XZ" "true" "" "Tar fixture compressed with xz"
append_manifest "basic.tar.zst" "TAR.ZST" "true" "" "Tar fixture compressed with zstd"
append_manifest "basic.cpio" "CPIO" "true" "" "CPIO fixture created by bsdtar"
append_manifest "basic.xar" "XAR" "true" "" "XAR fixture created by macOS xar"
append_manifest "basic.iso" "ISO" "true" "" "ISO fixture created by hdiutil makehybrid"
append_manifest "basic.deb" "DEB" "true" "" "Debian ar package fixture"

echo "Generated fixtures in $ARCHIVES"
