#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: scripts/package-deb.sh <target-triple> [out-dir]" >&2
  exit 2
fi

readonly TARGET=$1
readonly OUT_DIR=${2:-dist}
readonly PACKAGE_NAME="zmanager-cli"
readonly BINARY_NAME="zm"
readonly PACKAGE_REVISION="1"
readonly PACKAGE_SECTION="utils"
readonly PACKAGE_PRIORITY="optional"
readonly DEBIAN_STANDARDS_VERSION="4.6.2"
readonly MAINTAINER="Tzap Org <frankmanzhu@users.noreply.github.com>"
readonly HOMEPAGE="https://github.com/tzap-org/zmanager"
readonly DESCRIPTION_SHORT="Universal file archiver"
readonly DESCRIPTION_LONG="ZManager CLI provides high-performance compression, safe extraction, and seamless handling of ZIP, 7z, TAR.ZST, TZAP, RAR, and many other archive formats."
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly STAGE="$(mktemp -d "${TMPDIR:-/tmp}/zmanager-deb.XXXXXX")"
readonly SHLIBS_WORK="$(mktemp -d "${TMPDIR:-/tmp}/zmanager-shlibs.XXXXXX")"

cleanup() {
  rm -rf "$STAGE" "$SHLIBS_WORK"
}
trap cleanup EXIT
chmod 0755 "$STAGE"

debian_arch_for_target() {
  case "$1" in
    x86_64-unknown-linux-gnu) echo "amd64" ;;
    aarch64-unknown-linux-gnu) echo "arm64" ;;
    *)
      echo "unsupported Debian target: $1" >&2
      exit 2
      ;;
  esac
}

workspace_version() {
  awk '
    /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^version = / {
      gsub(/"/, "", $3)
      print $3
      found = 1
      exit
    }
    END {
      if (!found) {
        exit 1
      }
    }
  ' Cargo.toml
}

python_bin() {
  if [[ -n "${PYTHON:-}" ]]; then
    echo "$PYTHON"
  elif command -v python3 >/dev/null 2>&1; then
    echo "python3"
  elif command -v python >/dev/null 2>&1; then
    echo "python"
  else
    echo "python3 or python is required to generate third-party notices" >&2
    exit 1
  fi
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required to build Debian packages" >&2
    exit 1
  fi
}

shlibs_depends_for() {
  local binary=$1
  local package_binary="debian/$PACKAGE_NAME/usr/bin/$BINARY_NAME"
  mkdir -p "$SHLIBS_WORK/debian/$PACKAGE_NAME/DEBIAN"
  install -D -m 0755 "$binary" "$SHLIBS_WORK/$package_binary"
  cat > "$SHLIBS_WORK/debian/control" <<CONTROL
Source: $PACKAGE_NAME
Section: $PACKAGE_SECTION
Priority: $PACKAGE_PRIORITY
Maintainer: $MAINTAINER
Standards-Version: $DEBIAN_STANDARDS_VERSION

Package: $PACKAGE_NAME
Architecture: any
Depends: \${shlibs:Depends}
Description: $DESCRIPTION_SHORT
 $DESCRIPTION_LONG
CONTROL

  (
    cd "$SHLIBS_WORK"
    dpkg-shlibdeps -O "$package_binary"
  ) | sed -n 's/^shlibs:Depends=//p'
}

write_control_file() {
  local deb_arch=$1
  local deb_version=$2
  local depends=$3
  local installed_size=$4

  mkdir -p "$STAGE/DEBIAN"
  cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: $PACKAGE_NAME
Version: $deb_version
Section: $PACKAGE_SECTION
Priority: $PACKAGE_PRIORITY
Architecture: $deb_arch
Maintainer: $MAINTAINER
Installed-Size: $installed_size
Depends: $depends
Homepage: $HOMEPAGE
Description: $DESCRIPTION_SHORT
 $DESCRIPTION_LONG
CONTROL
}

write_copyright_file() {
  local doc_dir=$1
  cat > "$doc_dir/copyright" <<'COPYRIGHT'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: ZManager CLI
Source: https://github.com/tzap-org/zmanager

Files: *
Copyright: 2026 Frank Zhu
License: Apache-2.0
 Licensed under the Apache License, Version 2.0.
 .
 On Debian systems, the full text of the Apache License 2.0 is available in
 /usr/share/common-licenses/Apache-2.0.
 .
 Bundled third-party notices are installed in
 /usr/share/doc/zmanager-cli/THIRD_PARTY_NOTICES.md and copied license files
 are installed under /usr/share/doc/zmanager-cli/third-party-licenses/.
COPYRIGHT
}

write_changelog_file() {
  local doc_dir=$1
  local deb_version=$2
  local changelog_date=${ZMANAGER_DEB_DATE:-$(date -u -R)}

  cat > "$doc_dir/changelog.Debian" <<CHANGELOG
$PACKAGE_NAME ($deb_version) unstable; urgency=medium

  * Release ZManager CLI $VERSION.

 -- $MAINTAINER  $changelog_date
CHANGELOG
  gzip -9 -n "$doc_dir/changelog.Debian"
}

cd "$ROOT"
readonly DEB_ARCH="$(debian_arch_for_target "$TARGET")"
readonly VERSION="$(workspace_version)"
readonly DEB_VERSION="${VERSION}-${PACKAGE_REVISION}"
readonly DEB_FILE="${PACKAGE_NAME}_${DEB_VERSION}_${DEB_ARCH}.deb"
readonly OUT_ABS="$(mkdir -p "$OUT_DIR" && cd "$OUT_DIR" && pwd)"

require_tool dpkg-deb
require_tool dpkg-shlibdeps
require_tool gzip
readonly PYTHON_BIN="$(python_bin)"

cargo build --locked --release --target "$TARGET" -p zmanager-cli --bin "$BINARY_NAME"

install -D -m 0755 "target/$TARGET/release/$BINARY_NAME" "$STAGE/usr/bin/$BINARY_NAME"

readonly DOC_DIR="$STAGE/usr/share/doc/$PACKAGE_NAME"
install -D -m 0644 README.md "$DOC_DIR/README.md"
"$PYTHON_BIN" scripts/generate-third-party-notices.py \
  --out-notices "$DOC_DIR/THIRD_PARTY_NOTICES.md" \
  --license-dir "$DOC_DIR/third-party-licenses" >/dev/null
write_copyright_file "$DOC_DIR"
write_changelog_file "$DOC_DIR" "$DEB_VERSION"

mkdir -p "$STAGE/usr/share/man/man1"
gzip -9 -n -c docs/man/zm.1 > "$STAGE/usr/share/man/man1/zm.1.gz"

install -D -m 0644 completions/zm.bash "$STAGE/usr/share/bash-completion/completions/zm"
install -D -m 0644 completions/_zm "$STAGE/usr/share/zsh/vendor-completions/_zm"
install -D -m 0644 completions/zm.fish "$STAGE/usr/share/fish/vendor_completions.d/zm.fish"

readonly SHLIBS_DEPENDS="$(shlibs_depends_for "$STAGE/usr/bin/$BINARY_NAME")"
if [[ -z "$SHLIBS_DEPENDS" ]]; then
  echo "dpkg-shlibdeps did not report runtime dependencies for $BINARY_NAME" >&2
  exit 1
fi

readonly INSTALLED_SIZE="$(du -sk "$STAGE/usr" | awk '{print $1}')"
write_control_file "$DEB_ARCH" "$DEB_VERSION" "$SHLIBS_DEPENDS" "$INSTALLED_SIZE"

dpkg-deb --build --root-owner-group "$STAGE" "$OUT_ABS/$DEB_FILE" >/dev/null

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$OUT_ABS/$DEB_FILE" > "$OUT_ABS/$DEB_FILE.sha256"
else
  sha256sum "$OUT_ABS/$DEB_FILE" > "$OUT_ABS/$DEB_FILE.sha256"
fi

echo "$OUT_DIR/$DEB_FILE"
