#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: scripts/checkout-forensic-forks.sh [sibling-parent-directory]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT=${1:-"$ROOT/.."}
mkdir -p "$PARENT"
PARENT="$(cd "$PARENT" && pwd)"

while read -r checkout repository revision extra; do
  checkout=${checkout%$'\r'}
  revision=${revision%$'\r'}
  [[ -z "$checkout" || "$checkout" == \#* ]] && continue
  if [[ -n "$extra" || ! "$checkout" =~ ^[a-z0-9][a-z0-9.-]*$ || ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
    echo "invalid forensic fork pin for $checkout" >&2
    exit 1
  fi

  destination="$PARENT/$checkout"
  if [[ ! -e "$destination" ]]; then
    git clone --no-checkout "$repository" "$destination"
    git -C "$destination" checkout --detach "$revision"
  fi
  # Existing development checkouts are never reset or switched silently.
  if [[ "$(git -C "$destination" rev-parse HEAD)" != "$revision" ]]; then
    echo "$destination must be checked out at $revision; existing work was preserved" >&2
    exit 1
  fi
done < "$ROOT/forensic-forks.lock"
