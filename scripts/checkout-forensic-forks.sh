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

ensure_checkout() {
  local checkout=$1
  local repository=$2
  local revision=$3
  local destination="$PARENT/$checkout"
  local current
  local previous

  if [[ ! -e "$destination" ]]; then
    git clone --no-checkout "$repository" "$destination"
    git -C "$destination" checkout --detach "$revision"
    return
  fi

  if ! git -C "$destination" rev-parse --git-dir >/dev/null 2>&1; then
    echo "$destination exists but is not a Git checkout; existing files were preserved" >&2
    exit 1
  fi

  current=$(git -C "$destination" rev-parse HEAD)
  if [[ -n "$(git -C "$destination" status --porcelain)" ]]; then
    echo "$destination has local changes and cannot be verified against pinned revision $revision; existing work was preserved" >&2
    exit 1
  fi
  if [[ "$current" == "$revision" ]]; then
    echo "$checkout is at pinned revision ${revision:0:7}"
    return
  fi
  previous=$current

  if ! git -C "$destination" cat-file -e "$revision^{commit}" 2>/dev/null; then
    git -C "$destination" fetch --no-tags "$repository" "$revision"
  fi
  if ! git -C "$destination" cat-file -e "$revision^{commit}" 2>/dev/null; then
    echo "could not fetch pinned revision $revision for $destination" >&2
    exit 1
  fi

  if git -C "$destination" merge-base --is-ancestor HEAD "$revision"; then
    if git -C "$destination" symbolic-ref -q HEAD >/dev/null 2>&1; then
      git -C "$destination" merge --ff-only "$revision"
    else
      git -C "$destination" checkout --detach "$revision"
    fi
  elif git -C "$destination" merge-base --is-ancestor "$revision" HEAD; then
    echo "$destination is ahead of pinned revision $revision; refusing to rewind it" >&2
    exit 1
  else
    echo "$destination has diverged from pinned revision $revision; existing history was preserved" >&2
    exit 1
  fi

  current=$(git -C "$destination" rev-parse HEAD)
  if [[ "$current" != "$revision" ]]; then
    echo "failed to advance $destination to pinned revision $revision" >&2
    exit 1
  fi
  echo "Advanced $checkout from ${previous:0:7} to pinned revision ${revision:0:7}"
}

while read -r checkout repository revision extra; do
  checkout=${checkout%$'\r'}
  revision=${revision%$'\r'}
  [[ -z "$checkout" || "$checkout" == \#* ]] && continue
  if [[ -n "$extra" || ! "$checkout" =~ ^[a-z0-9][a-z0-9.-]*$ || ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
    echo "invalid forensic fork pin for $checkout" >&2
    exit 1
  fi
  ensure_checkout "$checkout" "$repository" "$revision"
done < "$ROOT/forensic-forks.lock"

if [[ ! -f "$ROOT/forensic-vfs-engine-rev.txt" ]]; then
  echo "missing forensic-vfs-engine-rev.txt pin" >&2
  exit 1
fi
IFS= read -r revision < "$ROOT/forensic-vfs-engine-rev.txt" || true
revision=${revision%$'\r'}
if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid forensic-vfs-engine revision pin" >&2
  exit 1
fi
ensure_checkout "forensic-vfs-engine" "https://github.com/frankmanzhu/forensic-vfs-engine.git" "$revision"
