#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
parent="${ZMANAGER_SIBLING_PARENT_DIR:-$(dirname "$root")}"
mode="${1:-verify}"
lock="$root/release-build-inputs.lock"
usage() { echo "Usage: scripts/release-gate.sh prepare|verify|verify-build"; }
case "$mode" in prepare|verify|verify-build) ;; -h|--help) usage; exit 0 ;; *) usage >&2; exit 2 ;; esac
lock_entry() { awk -v wanted="$1" '$1 == wanted { print $2 " " $4; found=1 } END { if (!found) exit 1 }' "$lock"; }
package_lock_version() {
  awk -v wanted="$1" '$0 == "[[package]]" { in_package=0 } $0 == "name = \"" wanted "\"" { in_package=1; next } in_package && /^version = / { gsub(/"/, "", $3); print $3; exit }' "$2"
}
require_tagged_commit() {
  local name="$1" dir="$parent/$1" url sha tags
  read -r url sha <<< "$(lock_entry "$name")" || { echo "Release lock is missing $name" >&2; return 1; }
  git -C "$dir" fetch --tags --no-recurse-submodules origin
  tags="$(git -C "$dir" tag --points-at "$sha" --list 'v*')"
  [[ -n "$tags" ]] || { echo "$name commit $sha has no v* release tag" >&2; return 1; }
  printf '%s release tag(s): %s (%s)\n' "$name" "$(printf '%s' "$tags" | tr '\n' ' ')" "$sha"
}
verify_release_order() { require_tagged_commit tzap; }
verify_tzap_resolution() {
  local sha tag version package resolved
  read -r _ sha <<< "$(lock_entry tzap)"
  version="$(package_lock_version tzap-core "$root/Cargo.lock")"
  [[ -n "$version" ]] || { echo "Cargo.lock is missing tzap-core" >&2; return 1; }
  tag="v$version"
  [[ "$(git -C "$parent/tzap" rev-parse -q --verify "refs/tags/$tag^{commit}" 2>/dev/null || true)" == "$sha" ]] || { echo "TZAP lock commit $sha must have release tag $tag" >&2; return 1; }
  for package in tzap-core tzap-plugin-keywrap tzap-plugin-signing; do
    resolved="$(awk -v wanted="$package" '$0 == "[[package]]" { in_package=0 } $0 == "name = \"" wanted "\"" { in_package=1; next } in_package && /^version = / { gsub(/"/, "", $3); print $3; exit }' "$root/Cargo.lock")"
    [[ "$resolved" == "$version" ]] || { echo "$package resolves to ${resolved:-<missing>} in Cargo.lock, but released TZAP $tag is required" >&2; return 1; }
  done
  echo "Cargo.lock resolves all released TZAP crates at $version ($tag)."
}
verify_product_release_tag() {
  local tag="${ZMANAGER_RELEASE_TAG:-}" tag_commit product_commit expected_version resolved package
  [[ -n "$tag" ]] || return 0
  if [[ "${ZMANAGER_NOTARIZATION_TEST:-false}" != "true" ]]; then
    tag_commit="$(git -C "$root" rev-parse -q --verify "refs/tags/$tag^{commit}" 2>/dev/null || true)"
    product_commit="$(git -C "$root" rev-parse HEAD)"
    [[ -n "$tag_commit" && "$tag_commit" == "$product_commit" ]] || { echo "Product checkout $product_commit does not match release tag $tag" >&2; return 1; }
  fi
  expected_version="${tag#v}"
  for package in zmanager-core zmanager-tzap-hosted zmanager-localsend; do
    resolved="$(awk -v wanted="$package" '$0 == "[[package]]" { in_package=0 } $0 == "name = \"" wanted "\"" { in_package=1; next } in_package && /^version = / { gsub(/"/, "", $3); print $3; exit }' "$root/Cargo.lock")"
    [[ "$resolved" == "$expected_version" ]] || { echo "$package resolves to ${resolved:-<missing>}; expected product release $tag" >&2; return 1; }
  done
  echo "ZManager checkout and Cargo package versions match release tag $tag."
}
case "$mode" in
  prepare)
    bash "$root/scripts/check-sibling-repos.sh" --strict
    bash "$root/scripts/update-release-build-inputs.sh" --write
    verify_release_order
    verify_tzap_resolution
    echo "Review, commit, and push release-build-inputs.lock, then run scripts/release-gate.sh verify before tagging ZManager."
    ;;
  verify)
    bash "$root/scripts/check-sibling-repos.sh" --strict
    bash "$root/scripts/update-release-build-inputs.sh" --check
    git -C "$root" diff --quiet HEAD -- release-build-inputs.lock || { echo "release-build-inputs.lock must be committed and pushed before tagging" >&2; exit 1; }
    verify_release_order
    verify_tzap_resolution
    echo "Release inputs are clean, current, pushed, and ready for the ZManager release tag."
    ;;
  verify-build)
    root_dirty="$(git -C "$root" status --porcelain=v1 --untracked-files=all)"
    [[ -z "$root_dirty" ]] || { printf 'Product checkout is dirty:\n%s\n' "$root_dirty" >&2; exit 1; }
    while read -r name url branch sha extra; do
      [[ -z "${name:-}" || "$name" == \#* ]] && continue
      sha="${sha%$'\r'}"
      dir="$parent/$name"
      actual="$(git -C "$dir" rev-parse HEAD)"
      origin="$(git -C "$dir" remote get-url origin)"
      [[ "$actual" == "$sha" ]] || { echo "$name is at $actual, expected locked commit $sha" >&2; exit 1; }
      [[ "${origin%.git}" == "${url%.git}" ]] || { echo "$name origin differs from the release lock" >&2; exit 1; }
      [[ -z "$(git -C "$dir" status --porcelain=v1 --untracked-files=all)" ]] || { echo "$name checkout is dirty" >&2; exit 1; }
    done < "$lock"
    verify_release_order
    verify_tzap_resolution
    verify_product_release_tag
    echo "Tagged ZManager build inputs match the committed release lock."
    ;;
esac
