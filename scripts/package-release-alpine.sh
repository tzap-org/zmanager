#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: scripts/package-release-alpine.sh <target-triple> [out-dir]" >&2
  exit 2
fi

TARGET=$1
OUT_DIR=${2:-dist}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=${ZM_ALPINE_RUST_IMAGE:-rust:1-alpine3.22}

case "$TARGET" in
  aarch64-unknown-linux-musl)
    PLATFORM=linux/arm64
    ;;
  x86_64-unknown-linux-musl)
    PLATFORM=linux/amd64
    ;;
  *)
    echo "Alpine packaging supports only aarch64- and x86_64-unknown-linux-musl" >&2
    exit 2
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for Alpine musl packaging" >&2
  exit 1
fi

cd "$ROOT"
mkdir -p "$OUT_DIR"

# zmanager-core path-depends on the forensic-vfs-engine sibling, which in turn
# path-depends on the udf-forensic and ntfs-forensic siblings. zmanager-ffi also
# path-depends on the localsend-rs sibling. From the container's /workspace
# checkout those resolve to the mount points below, so all four must be mounted.
LOCALSEND_DIR="$ROOT/../localsend-rs"
FVE_DIR="$ROOT/../forensic-vfs-engine"
UDF_DIR="$ROOT/../udf-forensic"
NTFS_DIR="$ROOT/../ntfs-forensic"
for d in "$LOCALSEND_DIR" "$FVE_DIR" "$UDF_DIR" "$NTFS_DIR"; do
  if [ ! -d "$d" ]; then
    echo "sibling directory not found at $d — clone it first" >&2
    exit 1
  fi
done

docker run --rm \
  --platform "$PLATFORM" \
  -v "$ROOT:/workspace" \
  -v "$(cd "$LOCALSEND_DIR" && pwd):/localsend-rs" \
  -v "$(cd "$FVE_DIR" && pwd):/forensic-vfs-engine" \
  -v "$(cd "$UDF_DIR" && pwd):/udf-forensic" \
  -v "$(cd "$NTFS_DIR" && pwd):/ntfs-forensic" \
  -w /workspace \
  -e TARGET="$TARGET" \
  -e OUT_DIR="$OUT_DIR" \
  -e CARGO_HOME=/workspace/target/alpine-cargo \
  -e CARGO_TARGET_DIR=/workspace/target \
  -e HOST_UID="$(id -u)" \
  -e HOST_GID="$(id -g)" \
  -e ZM_USE_SYSTEM_MUSL_TOOLCHAIN=1 \
  "$IMAGE" \
  /bin/sh -c '
    set -eu
    # git is required: the workspace .cargo/config.toml sets
    # net.git-fetch-with-cli, so cargo shells out to the git CLI for the
    # dpp/forensic-vfs-engine git dependencies.
    #
    # xz-dev/xz-static provide the system liblzma used by the native LZMA
    # decoder in the static link.
    apk add --no-cache \
      bash \
      binutils \
      git \
      build-base \
      clang20-libclang \
      cmake \
      file \
      linux-headers \
      perl \
      pkgconf \
      python3 \
      zlib-dev zlib-static \
      bzip2-dev bzip2-static \
      xz-dev xz-static \
      zstd-dev zstd-static \
      lz4-dev lz4-static \
      expat-dev expat-static \
      nettle-dev nettle-static

    # The container runs /bin/sh (busybox ash) — use POSIX export, not bash-only declare
    TARGET_ENV=${TARGET//-/_}
    TARGET_ENV_UPPER=$(printf '%s' "$TARGET_ENV" | tr '[:lower:]' '[:upper:]')
    export "CC_${TARGET_ENV}=cc"
    export "CXX_${TARGET_ENV}=c++"
    export "AR_${TARGET_ENV}=ar"
    export "CARGO_TARGET_${TARGET_ENV_UPPER}_LINKER=cc"

    scripts/package-release.sh "$TARGET" "$OUT_DIR"

    chown -R "$HOST_UID:$HOST_GID" "$OUT_DIR" "target/$TARGET" 2>/dev/null || true
  '
