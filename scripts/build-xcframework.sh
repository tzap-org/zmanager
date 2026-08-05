#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$ROOT/crates/zmanager-ffi"
DIST="$ROOT/dist/swift"
FFI_NAME="zmanagerFFI"
XCFRAMEWORK_DIR="$DIST/$FFI_NAME.xcframework"

echo "Building zmanager-ffi for macOS..."
cd "$CRATE_DIR"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
cargo build --release

echo "Cleaning previous Swift package artifacts..."
rm -rf "$DIST"

echo "Generating Swift bindings..."
mkdir -p "$DIST/Sources/ZManagerFFI"
mkdir -p "$DIST/Headers"
cargo run --bin uniffi-bindgen generate --library "$ROOT/target/release/libzmanager_ffi.dylib" --language swift --out-dir "$DIST/Sources/ZManagerFFI"

echo "Moving C headers out of Swift source directory..."
mv "$DIST/Sources/ZManagerFFI/"*.h "$DIST/Headers/"
mv "$DIST/Sources/ZManagerFFI/"*.modulemap "$DIST/Headers/module.modulemap"

echo "Creating XCFramework..."
xcodebuild -create-xcframework \
    -library "$ROOT/target/release/libzmanager_ffi.a" \
    -headers "$DIST/Headers" \
    -output "$XCFRAMEWORK_DIR"

echo "Successfully built Swift package artifacts to $DIST"
