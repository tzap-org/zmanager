#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${ZMANAGER_BUILD_MODE:-local}"
lockfile=""
while (($#)); do
  case "$1" in
    --mode) mode="${2:?missing mode}"; shift ;;
    --lockfile) lockfile="${2:?missing lockfile}"; shift ;;
    -h|--help) echo "Usage: scripts/ensure-sibling-repos.sh [--mode local|snapshot|release] [--lockfile PATH]"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
args=(--mode "$mode")
[[ -n "$lockfile" ]] && args+=(--lockfile "$lockfile")
bash "$root/scripts/prepare-sibling-inputs.sh" "${args[@]}"
