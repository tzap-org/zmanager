#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
parent="${ZMANAGER_SIBLING_PARENT_DIR:-$(dirname "$root")}"
mode="${ZMANAGER_BUILD_MODE:-local}"
catalog="${ZMANAGER_BUILD_INPUTS_LOCK:-$root/release-build-inputs.lock}"
report="$root/target/build-inputs-report.tsv"
resolve_output=""
usage() { echo "Usage: scripts/prepare-sibling-inputs.sh [--mode local|snapshot|release] [--lockfile PATH] [--report PATH] | --resolve-ci PATH"; }
while (($#)); do
  case "$1" in
    --mode) mode="${2:?missing mode}"; shift ;;
    --lockfile) catalog="${2:?missing lockfile}"; shift ;;
    --report) report="${2:?missing report path}"; shift ;;
    --resolve-ci) resolve_output="${2:?missing output path}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
if [[ "$catalog" != /* && ! "$catalog" =~ ^[A-Za-z]:[\\/] ]]; then catalog="$root/$catalog"; fi
[[ -f "$catalog" ]] || { echo "Missing sibling catalog: $catalog" >&2; exit 1; }
normalize_url() { printf '%s' "${1%/}" | sed -E 's/\.git$//' | tr '[:upper:]' '[:lower:]'; }
valid_entry() { [[ -z "$5" && "$1" =~ ^[a-z0-9][a-z0-9.-]*$ && "$2" =~ ^https?:// && "$3" =~ ^[A-Za-z0-9._/-]+$ && "$4" =~ ^[0-9a-f]{40}$ ]]; }
if [[ -n "$resolve_output" ]]; then
  mkdir -p "$(dirname "$resolve_output")"; tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
  printf '# CI snapshot captured by scripts/prepare-sibling-inputs.sh --resolve-ci.\n# checkout-name canonical-url integration-branch resolved-commit-sha\n' > "$tmp"
  while read -r name url branch ignored extra; do
    [[ -z "${name:-}" || "$name" == \#* ]] && continue
    if [[ -n "${extra:-}" || ! "$name" =~ ^[a-z0-9][a-z0-9.-]*$ || ! "$url" =~ ^https?:// || ! "$branch" =~ ^[A-Za-z0-9._/-]+$ ]]; then echo "Invalid sibling catalog entry: $name $url ${branch:-}" >&2; exit 1; fi
    sha="$(git ls-remote --exit-code --refs "$url" "refs/heads/$branch" | awk 'NR==1 {print $1}')"
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Could not resolve $name branch $branch at $url" >&2; exit 1; }
    printf '%s %s %s %s\n' "$name" "$url" "$branch" "$sha" >> "$tmp"
  done < "$catalog"
  mv "$tmp" "$resolve_output"; trap - EXIT; echo "Captured CI sibling snapshot: $resolve_output"; exit 0
fi
[[ "$mode" == local || "$mode" == snapshot || "$mode" == release ]] || { echo "Invalid mode: $mode" >&2; exit 2; }
if [[ "$mode" == release && "$catalog" != "$root/release-build-inputs.lock" ]]; then echo "Release mode must use the committed release-build-inputs.lock" >&2; exit 2; fi
if [[ "$mode" == snapshot && "$catalog" == "$root/release-build-inputs.lock" ]]; then echo "Snapshot mode requires a CI snapshot lock via --lockfile" >&2; exit 2; fi
mkdir -p "$(dirname "$report")"; release_tag="${ZMANAGER_RELEASE_TAG:-${GITHUB_REF_NAME:-}}"; printf 'name\trepository\tintegration_branch\tcheckout_branch\tcommit\tstate\tmode\trelease_tag\n' > "$report"
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  desktop_branch="$(git -C "$root" branch --show-current 2>/dev/null || true)"
  desktop_sha="$(git -C "$root" rev-parse HEAD)"
  desktop_dirty="$(git -C "$root" status --porcelain=v1 --untracked-files=all)"
  desktop_origin="$(git -C "$root" remote get-url origin 2>/dev/null || true)"
else
  [[ "$mode" != local && "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || {
    echo "$root is not a Git checkout; CI snapshot metadata is unavailable" >&2; exit 1;
  }
  # Container jobs may receive the checked-out files without the host's .git
  # directory. GitHub's event metadata still identifies the exact clean input.
  desktop_branch=""
  desktop_sha="$GITHUB_SHA"
  desktop_dirty=""
  desktop_origin="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}"
fi
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(basename "$root")" "$desktop_origin" "-" "${desktop_branch:-DETACHED}" "$desktop_sha" "$([[ -n "$desktop_dirty" ]] && echo dirty || echo clean)" "$mode" "$release_tag" >> "$report"
while read -r name url branch sha extra; do
  [[ -z "${name:-}" || "$name" == \#* ]] && continue
  valid_entry "$name" "$url" "$branch" "$sha" "${extra:-}" || { echo "Invalid sibling input entry: $name $url ${branch:-} ${sha:-}" >&2; exit 1; }
  dir="$parent/$name"
  if [[ ! -e "$dir" ]]; then
    if [[ "$mode" == local ]]; then git clone --single-branch --depth 1 --branch "$branch" "$url" "$dir"; else git clone "$url" "$dir"; fi
  fi
  git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "$dir exists but is not a Git checkout" >&2; exit 1; }
  origin="$(git -C "$dir" remote get-url origin 2>/dev/null || true)"
  [[ -n "$origin" && "$(normalize_url "$origin")" == "$(normalize_url "$url")" ]] || { echo "$name origin mismatch: expected $url, found ${origin:-<missing>}" >&2; exit 1; }
  expected=""; [[ "$mode" == release || "$mode" == snapshot ]] && expected="$sha"
  if [[ -n "$expected" ]]; then
    dirty="$(git -C "$dir" status --porcelain=v1 --untracked-files=all)"; [[ -z "$dirty" ]] || { echo "$name has local changes; preserving work instead of checking out $expected" >&2; exit 1; }
    if ! git -C "$dir" cat-file -e "$expected^{commit}" 2>/dev/null; then git -C "$dir" fetch --no-tags origin "$expected"; fi
    git -C "$dir" cat-file -e "$expected^{commit}" 2>/dev/null || { echo "$name commit unavailable: $expected" >&2; exit 1; }
    git -C "$dir" checkout --detach "$expected"; actual="$expected"
  else
    actual="$(git -C "$dir" rev-parse HEAD)"
  fi
  dirty="$(git -C "$dir" status --porcelain=v1 --untracked-files=all)"; state=clean; [[ -n "$dirty" ]] && state=dirty
  branch_actual="$(git -C "$dir" branch --show-current 2>/dev/null || true)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$url" "$branch" "${branch_actual:-DETACHED}" "$actual" "$state" "$mode" "$release_tag" >> "$report"
  printf '[%s] %s %s %s\n' "$state" "$name" "${actual:0:12}" "${branch_actual:-detached}"
done < "$catalog"
echo "Build input report: $report"
