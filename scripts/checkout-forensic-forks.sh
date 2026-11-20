#!/usr/bin/env bash
set -euo pipefail

# Compatibility entry point. The release lock now catalogs every sibling
# input; local calls preserve current checkouts and release callers pass
# ZMANAGER_BUILD_MODE=release to select exact pinned commits.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${ZMANAGER_BUILD_MODE:-local}"
exec bash "$root/scripts/prepare-sibling-inputs.sh" --mode "$mode" "$@"
