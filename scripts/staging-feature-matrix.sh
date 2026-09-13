#!/usr/bin/env bash
# Run the supported Rust feature matrix, then the hosted runtime checks against
# staging. This is intentionally a staging-only entry point: production must
# never be used as a test endpoint.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_URL="${ZM_STAGING_BASE_URL:-https://staging.tzap.org}"
ENV_FILE="${ZM_STAGING_ENV_FILE:-}"

fail() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

case "$BASE_URL" in
	"https://staging.tzap.org"|"https://staging.tzap.org/"|"https://staging.tzap.org/"*) ;;
	*) fail "feature-matrix tests are restricted to https://staging.tzap.org (got: $BASE_URL)" ;;
esac

for command_name in cargo curl; do
	command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done
[[ -n "$ENV_FILE" ]] || fail "ZM_STAGING_ENV_FILE must point to the staging credential environment file"
[[ -f "$ENV_FILE" ]] || fail "staging environment file not found: $ENV_FILE"

CURL_TIMEOUT_ARGS=(--connect-timeout 10 --max-time 30)

run_profile() {
	local label="$1"
	shift
	printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$label"
	(cd "$REPO_ROOT" && cargo "$@")
}

run_profile "core default tests" test -p zmanager-core --all-targets
run_profile "CLI reduced-profile tests" test -p zmanager-cli --no-default-features --all-targets
run_profile "CLI hosted-feature tests" test -p zmanager-cli --features tzap-online --all-targets
run_profile "FFI reduced-profile tests" test -p zmanager-ffi --no-default-features --all-targets
run_profile "FFI LocalSend tests" test -p zmanager-ffi --features localsend --all-targets
run_profile "FFI all-feature tests" test -p zmanager-ffi --all-features --all-targets
run_profile "workspace all-feature compile check" check --workspace --all-targets --all-features

printf '\n[%s] staging health preflight\n' "$(date '+%H:%M:%S')"
curl "${CURL_TIMEOUT_ARGS[@]}" --fail --silent --show-error "$BASE_URL/actuator/health" >/dev/null

"$SCRIPT_DIR/staging-integration.sh" --env-file "$ENV_FILE" --base-url "$BASE_URL"
