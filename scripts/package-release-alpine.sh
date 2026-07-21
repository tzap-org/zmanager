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

if [[ "$TARGET" != "aarch64-unknown-linux-musl" ]]; then
  echo "Alpine packaging is currently supported only for aarch64-unknown-linux-musl" >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for Alpine musl packaging" >&2
  exit 1
fi

cd "$ROOT"
mkdir -p "$OUT_DIR"

TZAP_DIR="$ROOT/../tzap"
if [ ! -d "$TZAP_DIR" ]; then
  echo "tzap directory not found at $TZAP_DIR — clone it first" >&2
  exit 1
fi

docker run --rm \
  --platform linux/arm64 \
  -v "$ROOT:/workspace" \
  -v "$(cd "$TZAP_DIR" && pwd):/tzap" \
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
    apk add --no-cache \
      bash \
      binutils \
      build-base \
      cmake \
      file \
      linux-headers \
      perl \
      pkgconf \
      python3

    export CC_aarch64_unknown_linux_musl=cc
    export CXX_aarch64_unknown_linux_musl=c++
    export AR_aarch64_unknown_linux_musl=ar
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=cc

    scripts/package-release.sh "$TARGET" "$OUT_DIR"

    chown -R "$HOST_UID:$HOST_GID" "$OUT_DIR" "target/$TARGET" 2>/dev/null || true
  '
