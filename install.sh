#!/bin/sh
set -eu

REPO_URL="${ZMANAGER_REPO_URL:-https://github.com/tzap-org/zmanager}"
VERSION="${ZMANAGER_VERSION:-latest}"
INSTALL_DIR="${ZMANAGER_INSTALL_DIR:-$HOME/.local/bin}"
TMPDIR="${TMPDIR:-/tmp}"
install_stage=""

# Default: the offline signer. --full installs the enrollment-capable build;
# `zm --version` reports which flavor.
FULL=0
# --preview installs from the latest successful Package Preview CI run
# instead of a release, for developers testing packages before release.
PREVIEW=0

usage() {
  cat <<'EOF'
zmanager install script

Usage: sh install.sh [--full] [--preview]

Options:
  --full      install the full build (online identity and enrollment features)
  --preview   install from the latest successful Package Preview CI run
              instead of a release (requires the gh CLI; set
              ZMANAGER_RUN_ID to install a specific run)
  --help      show this help

With a piped install, pass the flags after sh -s --:
  curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sh -s -- --full
  curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sh -s -- --preview
EOF
}

for arg in "$@"; do
  case "$arg" in
    --full) FULL=1 ;;
    --preview) PREVIEW=1 ;;
    --help | -h) usage; exit 0 ;;
    *)
      printf 'zmanager install: unknown argument: %s\n' "$arg" >&2
      usage >&2
      exit 1
      ;;
  esac
done

say() {
  printf '%s\n' "$*"
}

fail() {
  printf 'zmanager install: %s\n' "$*" >&2
  exit 1
}

fail_install_permission() {
  printf 'zmanager install: cannot write to %s\n' "$INSTALL_DIR" >&2
  printf 'Try a user-writable install directory, or rerun with sudo:\n' >&2
  if [ "$VERSION" = "latest" ]; then
    printf '  curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sudo env ZMANAGER_INSTALL_DIR="%s" sh\n' "$INSTALL_DIR" >&2
  else
    printf '  curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sudo env ZMANAGER_VERSION="%s" ZMANAGER_INSTALL_DIR="%s" sh\n' "$VERSION" "$INSTALL_DIR" >&2
  fi
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
        x86_64) printf 'x86_64-unknown-linux-musl' ;;
        aarch64|arm64) printf 'aarch64-unknown-linux-musl' ;;
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
  mkdir -p "$INSTALL_DIR" || fail "could not create install directory $INSTALL_DIR"
  [ -w "$INSTALL_DIR" ] || fail_install_permission
  [ ! -d "$INSTALL_DIR/zm" ] || fail "install destination $INSTALL_DIR/zm is a directory"
  install_stage="$(mktemp "$INSTALL_DIR/.zm-install.XXXXXX")" \
    || fail "could not stage the replacement executable in $INSTALL_DIR"
  cp "$src" "$install_stage" || fail "could not copy the replacement executable; the existing installation was preserved"
  chmod 0755 "$install_stage" || fail "could not mark the replacement executable as executable"
  mv -f "$install_stage" "$INSTALL_DIR/zm" || fail "could not replace $INSTALL_DIR/zm"
  install_stage=""
}

print_path_hint() {
  shell_name="$(basename "${SHELL:-sh}")"
  case "$shell_name" in
    fish)
      say "Add zm to PATH for future fish sessions:"
      say "  fish_add_path \"$INSTALL_DIR\""
      ;;
    zsh)
      say "Add zm to PATH for future zsh sessions:"
      say "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.zshrc"
      say "  export PATH=\"$INSTALL_DIR:\$PATH\""
      ;;
    bash)
      say "Add zm to PATH for future bash sessions:"
      say "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc"
      say "  export PATH=\"$INSTALL_DIR:\$PATH\""
      ;;
    *)
      say "Add zm to PATH for future shell sessions:"
      say "  export PATH=\"$INSTALL_DIR:\$PATH\""
      ;;
  esac
}

print_success() {
  installed="$INSTALL_DIR/zm"
  version="$("$installed" --version 2>/dev/null || printf 'zm')"

  say ""
  say "ZManager CLI installed"
  say "  Binary:  $installed"
  say "  Version: $version"
  say ""

  case ":$PATH:" in
    *":$INSTALL_DIR:"*)
      say "Try it:"
      say "  zm healthcheck"
      ;;
    *)
      say "Try it now:"
      say "  \"$installed\" healthcheck"
      say ""
      print_path_hint
      ;;
  esac
}

download_release() {
  target="$1"
  if [ "$FULL" = "1" ]; then
    asset="zm-full-$target.tar.gz"
    binary="zm-full"
  else
    asset="zm-$target.tar.gz"
    binary="zm"
  fi

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
  [ -x "$binary" ] || fail "release archive did not contain executable $binary"
  install_binary "$binary"
}

# Install from the Package Preview CI instead of a release. The preview
# workflow (package-preview.yml) uploads each build as a GitHub Actions
# artifact named zm-preview-<target>-full / zm-preview-<target>-offline,
# containing the normal release tarball plus its .sha256 sidecar.
download_preview() {
  target="$1"
  if [ "$FULL" = "1" ]; then
    artifact="zm-preview-$target-full"
    archive="zm-full-$target.tar.gz"
    binary="zm-full"
  else
    artifact="zm-preview-$target-offline"
    archive="zm-$target.tar.gz"
    binary="zm"
  fi

  need gh || fail "preview installs require the gh CLI (https://cli.github.com/)"

  run_id="${ZMANAGER_RUN_ID:-}"
  if [ -z "$run_id" ]; then
    say "Finding the latest successful Package Preview run"
    run_id="$(gh run list --repo "$REPO_URL" --workflow package-preview.yml --status success --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)"
    [ -n "$run_id" ] || fail "could not find a Package Preview run; run the package-preview workflow, or set ZMANAGER_RUN_ID"
  fi

  say "Downloading artifact $artifact from run $run_id"
  gh run download "$run_id" --repo "$REPO_URL" -n "$artifact" -D "$PWD" \
    || fail "artifact $artifact not found in run $run_id"

  [ -f "$archive" ] || fail "artifact did not contain $archive"
  [ -f "$archive.sha256" ] || fail "artifact did not contain $archive.sha256"
  expected="$(awk '{print $1}' "$archive.sha256")"
  actual="$(sha256_file "$archive")"
  [ "$actual" = "$expected" ] || fail "checksum mismatch for $archive"

  tar -xzf "$archive"
  [ -x "$binary" ] || fail "release archive did not contain executable $binary"
  install_binary "$binary"
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
    if [ "$FULL" = "1" ]; then
      cargo build --locked --release -p zmanager-cli --bin zm --features tzap-online
    else
      cargo build --locked --release -p zmanager-cli --bin zm
    fi
  )

  install_binary source/target/release/zm
}

target="$(detect_target)" || fail "unsupported platform: $(uname -s) $(uname -m)"
work="$(mktemp -d "$TMPDIR/zmanager-install.XXXXXX")"

cleanup() {
  if [ -n "$install_stage" ]; then
    rm -f "$install_stage"
  fi
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$work"

if [ "$PREVIEW" = "1" ]; then
  # Preview installs never fall back to a source build: the point of a
  # preview is testing the packaged CI artifact.
  download_preview "$target"
elif ! download_release "$target"; then
  say "No matching release asset found; falling back to source build"
  build_from_source
fi

print_success
