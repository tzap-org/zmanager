#!/bin/sh
set -eu

REPO_URL="${ZMANAGER_REPO_URL:-https://github.com/frankmanzhu/zmanager}"
VERSION="${ZMANAGER_VERSION:-latest}"
INSTALL_DIR="${ZMANAGER_INSTALL_DIR:-$HOME/.local/bin}"
TMPDIR="${TMPDIR:-/tmp}"

say() {
  printf '%s\n' "$*"
}

fail() {
  printf 'zmanager install: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || return 1
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin)
      case "$arch" in
        arm64) printf 'aarch64-apple-darwin' ;;
        x86_64) printf 'x86_64-apple-darwin' ;;
        *) return 1 ;;
      esac
      ;;
    Linux)
      case "$arch" in
        x86_64) printf 'x86_64-unknown-linux-gnu' ;;
        aarch64|arm64) printf 'aarch64-unknown-linux-gnu' ;;
        *) return 1 ;;
      esac
      ;;
    *)
      return 1
      ;;
  esac
}

sha256_file() {
  if need shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif need sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  else
    fail "need shasum or sha256sum to verify release downloads"
  fi
}

install_binary() {
  src="$1"
  mkdir -p "$INSTALL_DIR"
  cp "$src" "$INSTALL_DIR/zm"
  chmod 0755 "$INSTALL_DIR/zm"
}

download_release() {
  target="$1"
  asset="zm-$target.tar.gz"

  if [ "$VERSION" = "latest" ]; then
    base="$REPO_URL/releases/latest/download"
  else
    base="$REPO_URL/releases/download/$VERSION"
  fi

  need curl || fail "curl is required"

  say "Downloading $asset from $base"
  curl -fsSL "$base/$asset" -o "$asset" || return 1
  curl -fsSL "$base/SHA256SUMS" -o SHA256SUMS || return 1

  expected="$(grep "  $asset\$" SHA256SUMS | awk '{print $1}')"
  [ -n "$expected" ] || fail "SHA256SUMS does not contain $asset"

  actual="$(sha256_file "$asset")"
  [ "$actual" = "$expected" ] || fail "checksum mismatch for $asset"

  tar -xzf "$asset"
  [ -x zm ] || fail "release archive did not contain executable zm"
  install_binary zm
}

build_from_source() {
  need git || fail "git is required for source install"
  need cargo || fail "Rust/Cargo is required for source install"

  say "Building zm from source"
  git clone --depth 1 "$REPO_URL.git" source

  if [ "$VERSION" != "latest" ]; then
    (
      cd source
      git fetch --depth 1 origin "refs/tags/$VERSION:refs/tags/$VERSION"
      git checkout "$VERSION"
    )
  fi

  (
    cd source
    cargo build --locked --release -p zmanager-cli --bin zm
  )

  install_binary source/target/release/zm
}

target="$(detect_target)" || fail "unsupported platform: $(uname -s) $(uname -m)"
work="$(mktemp -d "$TMPDIR/zmanager-install.XXXXXX")"

cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

cd "$work"

if ! download_release "$target"; then
  say "No matching release asset found; falling back to source build"
  build_from_source
fi

say "Installed zm to $INSTALL_DIR/zm"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "Add $INSTALL_DIR to PATH to run zm without a full path." ;;
esac
