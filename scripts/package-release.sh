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

configure_static_linux_target() {
  case "$TARGET" in
    *-unknown-linux-musl)
      local musl_abi
      case "$TARGET" in
        x86_64-unknown-linux-musl)
          musl_abi=x86_64-linux-musl
          ;;
        aarch64-unknown-linux-musl)
          musl_abi=aarch64-linux-musl
          ;;
        *)
          echo "unsupported static Linux target: $TARGET" >&2
          exit 1
          ;;
      esac

      if ! command -v zig >/dev/null 2>&1; then
        echo "zig is required to build static Linux release artifacts for $TARGET" >&2
        exit 1
      fi

      local target_env=${TARGET//-/_}
      local target_env_upper=${target_env^^}
      local tool_dir="$ROOT/target/zmanager-tools/$TARGET"
      local zig_cc="$tool_dir/zig-cc"
      local zig_cxx="$tool_dir/zig-cxx"
      local zig_ar="$tool_dir/zig-ar"
      mkdir -p "$tool_dir"

      cat > "$zig_cc" <<EOF
#!/usr/bin/env bash
args=()
skip_next=false
for arg in "\$@"; do
  if [[ "\$skip_next" == true ]]; then
    skip_next=false
    continue
  fi
  case "\$arg" in
    --target=*|-target=*)
      continue
      ;;
    --target|-target)
      skip_next=true
      continue
      ;;
  esac
  args+=("\$arg")
done
exec zig cc -target $musl_abi -w "\${args[@]}"
EOF
      cat > "$zig_cxx" <<EOF
#!/usr/bin/env bash
args=()
skip_next=false
for arg in "\$@"; do
  if [[ "\$skip_next" == true ]]; then
    skip_next=false
    continue
  fi
  case "\$arg" in
    --target=*|-target=*)
      continue
      ;;
    --target|-target)
      skip_next=true
      continue
      ;;
  esac
  args+=("\$arg")
done
exec zig c++ -target $musl_abi -w "\${args[@]}"
EOF
      cat > "$zig_ar" <<'EOF'
#!/usr/bin/env bash
exec zig ar "$@"
EOF
      chmod +x "$zig_cc" "$zig_cxx" "$zig_ar"

      export "CC_${target_env}=$zig_cc"
      export "CXX_${target_env}=$zig_cxx"
      export "AR_${target_env}=$zig_ar"
      export "CXXSTDLIB_${target_env}=c++"
      export "CARGO_TARGET_${target_env_upper}_LINKER=$zig_cc"
      local rustflags_env="CARGO_TARGET_${target_env_upper}_RUSTFLAGS"
      local rustflags="${!rustflags_env:-}"
      export "$rustflags_env=${rustflags:+$rustflags }-C link-self-contained=no"
      ;;
  esac
}

if [[ "$TARGET" == *windows* ]]; then
  BINARY="zm.exe"
  ARCHIVE="zm-$TARGET.zip"
else
  BINARY="zm"
  ARCHIVE="zm-$TARGET.tar.gz"
fi

configure_static_linux_target
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
cp completions/zm.bash completions/_zm completions/zm.fish completions/zm.ps1 "$STAGE/completions/"
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
