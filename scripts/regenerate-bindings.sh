#!/usr/bin/env bash
# Regenerates the Swift and Kotlin UniFFI bindings for downstream consumers:
#   - Swift: this repo's SPM package (dist/swift)
#   - Kotlin + Swift: the zmanager-mobile repo (checked-in generated files)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$ROOT/crates/zmanager-ffi"
UDL_FILE="$CRATE_DIR/src/zmanager_ffi.udl"
CONFIG_FILE="$CRATE_DIR/uniffi/uniffi.toml"

MOBILE_ROOT="${ZMANAGER_MOBILE_ROOT:-$ROOT/../zmanager-mobile}"
ANDROID_GENERATED_DIR="$MOBILE_ROOT/android/app/src/main/java"
IOS_GENERATED_DIR="$MOBILE_ROOT/ios/ZManagerMobile/ZManagerMobile/Bridge/Generated"

echo "Regenerating Swift package bindings for zmanager..."
bash "$ROOT/scripts/build-xcframework.sh"

if [[ -d "$MOBILE_ROOT" ]]; then
  echo "Regenerating mobile bindings in $MOBILE_ROOT..."
  (
    cd "$CRATE_DIR"
    cargo run --bin uniffi-bindgen generate \
      --language kotlin \
      --out-dir "$ANDROID_GENERATED_DIR" \
      --config "$CONFIG_FILE" \
      --no-format \
      "$UDL_FILE"
    cargo run --bin uniffi-bindgen generate \
      --language swift \
      --out-dir "$IOS_GENERATED_DIR" \
      --no-format \
      "$UDL_FILE"
  )
  echo "Mobile bindings regenerated: $ANDROID_GENERATED_DIR/org/tzap/zmanager/mobile/bridge/generated/zmanager.kt, $IOS_GENERATED_DIR"
else
  echo "Skipping mobile bindings: $MOBILE_ROOT not found (set ZMANAGER_MOBILE_ROOT to override)."
fi
