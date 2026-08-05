#!/usr/bin/env bash
# Builds the zmanager-ffi static library for the iOS simulator (arm64 + x86_64).
# Used by zmanager-mobile's Xcode build phase; the zmanager repo owns the build.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOS_BUILD_DIR="$ROOT/dist/ios"
TOOLCHAIN_DIR="$IOS_BUILD_DIR/cmake"
SIM_ARM_TARGET="aarch64-apple-ios-sim"
SIM_X86_TARGET="x86_64-apple-ios"
LIB_NAME="libzmanager_ffi.a"
SIM_LIB="$IOS_BUILD_DIR/libzmanager_ffi_sim.a"
PROFILE_DIR="debug"
CARGO_PROFILE_ARGS=()

if [[ "${CONFIGURATION:-Debug}" == "Release" ]]; then
  PROFILE_DIR="release"
  CARGO_PROFILE_ARGS=(--release)
fi

export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"
unset ARCHS CURRENT_ARCH VALID_ARCHS IPHONESIMULATOR_DEPLOYMENT_TARGET

SIMULATOR_SDK_PATH="$(xcrun --sdk iphonesimulator --show-sdk-path)"
DEPENDENCY_TOOLCHAIN="$TOOLCHAIN_DIR/ios-simulator-dependencies.cmake"

mkdir -p "$TOOLCHAIN_DIR"
cat > "$DEPENDENCY_TOOLCHAIN" <<EOF
set(CMAKE_IGNORE_PREFIX_PATH "/opt/homebrew;/usr/local" CACHE STRING "" FORCE)
set(CMAKE_DISABLE_FIND_PACKAGE_LZ4 TRUE CACHE BOOL "" FORCE)
set(CMAKE_DISABLE_FIND_PACKAGE_LibLZMA TRUE CACHE BOOL "" FORCE)
set(CMAKE_DISABLE_FIND_PACKAGE_ZSTD TRUE CACHE BOOL "" FORCE)
set(LIBXML2_INCLUDE_DIR "$SIMULATOR_SDK_PATH/usr/include/libxml2" CACHE PATH "" FORCE)
EOF

cargo_rustc_simulator_staticlib() {
  local target="$1"
  local arch="$2"

  CMAKE_OSX_ARCHITECTURES="$arch" \
    CMAKE_OSX_DEPLOYMENT_TARGET="$IPHONEOS_DEPLOYMENT_TARGET" \
    CMAKE_OSX_SYSROOT="$SIMULATOR_SDK_PATH" \
    CMAKE_TOOLCHAIN_FILE="$DEPENDENCY_TOOLCHAIN" \
    BINDGEN_EXTRA_CLANG_ARGS="--target=$arch-apple-ios-simulator -isysroot $SIMULATOR_SDK_PATH" \
    PKG_CONFIG_ALLOW_CROSS=1 \
    PKG_CONFIG_LIBDIR="$SIMULATOR_SDK_PATH/usr/lib/pkgconfig" \
    PKG_CONFIG_PATH="" \
    cargo rustc \
      --manifest-path "$ROOT/Cargo.toml" \
      -p zmanager-ffi \
      --target "$target" \
      "${CARGO_PROFILE_ARGS[@]}" \
      --lib \
      --crate-type staticlib
}

rustup target add "$SIM_ARM_TARGET" "$SIM_X86_TARGET" >/dev/null

cargo_rustc_simulator_staticlib "$SIM_ARM_TARGET" "arm64"
cargo_rustc_simulator_staticlib "$SIM_X86_TARGET" "x86_64"

mkdir -p "$IOS_BUILD_DIR"
lipo -create \
  "$ROOT/target/$SIM_ARM_TARGET/$PROFILE_DIR/$LIB_NAME" \
  "$ROOT/target/$SIM_X86_TARGET/$PROFILE_DIR/$LIB_NAME" \
  -output "$SIM_LIB"

echo "Built $SIM_LIB"
