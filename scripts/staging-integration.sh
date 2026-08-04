#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_ROOT_CERT="$REPO_ROOT/crates/zmanager-core/src/trust/tzap-staging-root-ca-2026.pem"

ENV_FILE="${ZM_STAGING_ENV_FILE:-}"
BASE_URL="${ZM_STAGING_BASE_URL:-https://staging.tzap.org}"
ROOT_CERT="${ZM_STAGING_ROOT_CERT:-$DEFAULT_ROOT_CERT}"
KEEP_ARTIFACTS=false
RUN_ORGANIZATION=true

usage() {
	cat <<'EOF'
Usage: scripts/staging-integration.sh --env-file PATH [options]

Runs destructive-to-staging (but not production) integration coverage for:
  - two email/password logins through native PKCE handoff
  - personal certificate enrollment and server chain validation
  - signed document offline and live-status validation
  - organization creation, approval-pending enrollment, approval, and retry
  - signed RecipientWrap TZAP creation for two contacts
  - RootAuth verification plus decrypt/test/extract as both recipients

Options:
  --env-file PATH       File defining STAGING_TEST_RECIPIENT_{1,2}_{EMAIL,PASSWORD}
  --base-url URL        Staging API URL (default: https://staging.tzap.org)
  --root-cert PATH      Explicit staging root certificate
  --skip-organization   Skip the organization approval workflow
  --keep-artifacts      Keep the mode-0700 temporary state directory

Optional registration coverage:
  Set STAGING_REGISTRATION_EMAIL and STAGING_REGISTRATION_PASSWORD. The script
  starts registration and prompts for the emailed code. For a non-interactive
  harness that returns a dev code, set STAGING_REGISTRATION_CODE instead.

The run creates persistent staging users/certificates/organizations as needed.
It never prints passwords, session tokens, PKCE verifiers, or private keys.
EOF
}

fail() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

log() {
	printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--env-file)
			ENV_FILE="${2:?--env-file requires a path}"
			shift 2
			;;
		--base-url)
			BASE_URL="${2:?--base-url requires a URL}"
			shift 2
			;;
		--root-cert)
			ROOT_CERT="${2:?--root-cert requires a path}"
			shift 2
			;;
		--skip-organization)
			RUN_ORGANIZATION=false
			shift
			;;
		--keep-artifacts)
			KEEP_ARTIFACTS=true
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*) fail "unknown option: $1" ;;
	esac
done

for command_name in cargo curl jq openssl cmp; do
	command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done
[[ -n "$ENV_FILE" ]] || fail "--env-file is required"
[[ -f "$ENV_FILE" ]] || fail "environment file not found: $ENV_FILE"
[[ -f "$ROOT_CERT" ]] || fail "staging root certificate not found: $ROOT_CERT"

# shellcheck disable=SC1090
source "$ENV_FILE"

for variable_name in \
	STAGING_TEST_RECIPIENT_1_EMAIL \
	STAGING_TEST_RECIPIENT_1_PASSWORD \
	STAGING_TEST_RECIPIENT_2_EMAIL \
	STAGING_TEST_RECIPIENT_2_PASSWORD; do
	[[ -n "${!variable_name:-}" ]] || fail "$variable_name is missing from $ENV_FILE"
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zmanager-staging-integration.XXXXXX")"
chmod 700 "$WORK_DIR"
cleanup() {
	if [[ "$KEEP_ARTIFACTS" == true ]]; then
		printf '\nArtifacts retained at %s\n' "$WORK_DIR"
	else
		rm -rf -- "$WORK_DIR"
	fi
}
trap cleanup EXIT

ZM="$REPO_ROOT/target/debug/zm"

post_json() {
	local path="$1" body="$2" token="${3:-}" response_file status
	response_file="$(mktemp "$WORK_DIR/response.XXXXXX")"
	if [[ -n "$token" ]]; then
		status="$(curl --silent --show-error --output "$response_file" --write-out '%{http_code}' \
			-H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
			--data "$body" "$BASE_URL$path")"
	else
		status="$(curl --silent --show-error --output "$response_file" --write-out '%{http_code}' \
			-H 'Content-Type: application/json' --data "$body" "$BASE_URL$path")"
	fi
	if [[ "$status" != 2* ]]; then
		jq '{error, message, denial_reason, support_reference}' "$response_file" >&2 2>/dev/null || true
		fail "POST $path returned HTTP $status"
	fi
	cat "$response_file"
}

native_auth_begin() {
	local state_dir="$1"
	mkdir -p "$state_dir"
	"$ZM" auth login --state-dir "$state_dir" --environment staging \
		--auth-base-url "$BASE_URL" --account-base-url "$BASE_URL" --json
}

pkce_challenge() {
	local verifier="$1"
	printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A |
		tr '+/' '-_' | tr -d '='
}

complete_native_handoff() {
	local state_dir="$1" state="$2" handoff_code="$3"
	"$ZM" auth callback --state-dir "$state_dir" --state "$state" \
		--handoff-code "$handoff_code" --auth-base-url "$BASE_URL" --json >/dev/null
}

login_user() {
	local state_dir="$1" email="$2" password="$3" launch state verifier challenge login
	launch="$(native_auth_begin "$state_dir")"
	state="$(jq -er '.state' <<<"$launch")"
	verifier="$(jq -er '.pkce_verifier' "$state_dir/auth-pending.json")"
	challenge="$(pkce_challenge "$verifier")"
	login="$(post_json /v1/login/email "$(jq -nc \
		--arg email "$email" --arg password "$password" --arg state "$state" --arg challenge "$challenge" \
		'{email:$email,password:$password,client_id:"zmanager-cli",redirect_uri:"tzap://auth/callback",state:$state,code_challenge:$challenge,code_challenge_method:"S256"}')")"
	complete_native_handoff "$state_dir" "$state" "$(jq -er '.handoff_code' <<<"$login")"
}

register_user_if_requested() {
	local email="${STAGING_REGISTRATION_EMAIL:-}" password="${STAGING_REGISTRATION_PASSWORD:-}"
	[[ -n "$email" || -n "$password" ]] || return 0
	[[ -n "$email" && -n "$password" ]] || fail "both STAGING_REGISTRATION_EMAIL and STAGING_REGISTRATION_PASSWORD are required"
	local state_dir="$WORK_DIR/registered" launch state verifier challenge started code completed
	log "Registering the optional staging user"
	launch="$(native_auth_begin "$state_dir")"
	state="$(jq -er '.state' <<<"$launch")"
	verifier="$(jq -er '.pkce_verifier' "$state_dir/auth-pending.json")"
	challenge="$(pkce_challenge "$verifier")"
	started="$(post_json /v1/signup/email/register/start "$(jq -nc \
		--arg email "$email" --arg challenge "$challenge" \
		'{client_id:"zmanager-cli",email:$email,redirect_uri:"tzap://auth/callback",code_challenge:$challenge,code_challenge_method:"S256"}')")"
	code="${STAGING_REGISTRATION_CODE:-$(jq -r '.dev_verification_code // empty' <<<"$started")}" 
	if [[ -z "$code" ]]; then
		[[ -t 0 ]] || fail "registration code was emailed; rerun interactively or set STAGING_REGISTRATION_CODE"
		read -r -p "Verification code sent to $email: " code
	fi
	completed="$(post_json /v1/signup/email/register/verify "$(jq -nc \
		--arg verification_id "$(jq -er '.verification_id' <<<"$started")" \
		--arg code "$code" --arg verifier "$verifier" --arg password "$password" \
		'{verification_id:$verification_id,code:$code,code_verifier:$verifier,password:$password}')")"
	complete_native_handoff "$state_dir" "$state" "$(jq -er '.handoff_code' <<<"$completed")"
	"$ZM" auth status --state-dir "$state_dir" --json | jq -e '.authenticated == true' >/dev/null
	log "Optional registration and native handoff passed"
}

session_token() {
	jq -er '.sessions.default.access_token' "$1/auth-session.json"
}

enroll_personal() {
	local state_dir="$1" output="$2"
	"$ZM" cert enroll --state-dir "$state_dir" --service-base-url "$BASE_URL" \
		--trusted-root-cert "$ROOT_CERT" --requested-validity-seconds 7776000 --json > "$output"
	jq -er '.certificate.certificate_id' "$output"
}

decode_recipient_key() {
	local state_dir="$1" key_id="$2" output="$3" encoded padded padding
	encoded="$(jq -er --arg id "$key_id" \
		'.recipient_encryption_keys[] | select(.key_id == $id) | .private_key_der' \
		"$state_dir/default.identity.json")"
	padding=$(( (4 - ${#encoded} % 4) % 4 ))
	padded="$encoded"
	while (( padding > 0 )); do
		padded="${padded}="
		padding=$((padding - 1))
	done
	printf '%s' "$padded" | tr '_-' '/+' | openssl base64 -d -A > "$output"
	chmod 600 "$output"
}

log "Building the staging-test CLI"
(cd "$REPO_ROOT" && cargo build -p zmanager-cli)

log "Checking staging health and distributed trust material"
curl --fail --silent --show-error "$BASE_URL/actuator/health" | jq -e '.status == "UP"' >/dev/null
root_sha="sha256:$(openssl x509 -in "$ROOT_CERT" -outform DER | openssl dgst -sha256 -hex | awk '{print $2}')"
curl --fail --silent --show-error "$BASE_URL/v1/trust/roots" |
	jq -e --arg root "$root_sha" 'any(.[]; .certificateFingerprint == $root and .status == "active")' >/dev/null
curl --fail --silent --show-error "$BASE_URL/v1/trust/intermediates" |
	jq -e 'any(.[]; .status == "active" and .scope == "platform")' >/dev/null

register_user_if_requested

STATE_1="$WORK_DIR/recipient-1"
STATE_2="$WORK_DIR/recipient-2"
log "Logging in both staging recipients through PKCE handoff"
login_user "$STATE_1" "$STAGING_TEST_RECIPIENT_1_EMAIL" "$STAGING_TEST_RECIPIENT_1_PASSWORD"
login_user "$STATE_2" "$STAGING_TEST_RECIPIENT_2_EMAIL" "$STAGING_TEST_RECIPIENT_2_PASSWORD"
"$ZM" auth status --state-dir "$STATE_1" --json | jq -e '.authenticated == true and .expired == false' >/dev/null
"$ZM" auth status --state-dir "$STATE_2" --json | jq -e '.authenticated == true and .expired == false' >/dev/null

log "Enrolling and locally validating two personal certificates"
CERT_1="$(enroll_personal "$STATE_1" "$WORK_DIR/enroll-1.json")"
CERT_2="$(enroll_personal "$STATE_2" "$WORK_DIR/enroll-2.json")"
CERT_1_SHA="$(jq -er '.certificate.certificate_sha256' "$WORK_DIR/enroll-1.json")"
CERT_2_SHA="$(jq -er '.certificate.certificate_sha256' "$WORK_DIR/enroll-2.json")"
"$ZM" cert list --state-dir "$STATE_1" --json | jq -e --arg id "$CERT_1" 'any(.certificates[]; .certificate_id == $id)' >/dev/null
"$ZM" cert list --state-dir "$STATE_2" --json | jq -e --arg id "$CERT_2" 'any(.certificates[]; .certificate_id == $id)' >/dev/null

log "Signing a document and validating it offline and with live status"
printf '%s\n' '{"tzap_payload_version":1,"title":"Staging integration document","amount":42}' > "$WORK_DIR/document.json"
"$ZM" sign "$WORK_DIR/document.json" --state-dir "$STATE_1" --certificate-id "$CERT_1" \
	--output "$WORK_DIR/document-envelope.json" --json >/dev/null
"$ZM" verify "$WORK_DIR/document-envelope.json" --custom-trust-root-cert "$ROOT_CERT" --json |
	jq -e '.state == "cryptographically_intact_offline"' >/dev/null
curl --fail --silent --show-error "$BASE_URL/v1/status/certificates/by-fingerprint/$CERT_1_SHA" > "$WORK_DIR/status-1.json"
"$ZM" verify "$WORK_DIR/document-envelope.json" --custom-trust-root-cert "$ROOT_CERT" \
	--status-response "$WORK_DIR/status-1.json" --json | jq -e '.state == "valid_now"' >/dev/null

if [[ "$RUN_ORGANIZATION" == true ]]; then
	log "Creating an organization and exercising approval-pending enrollment"
	TOKEN_1="$(session_token "$STATE_1")"
	ORG="$(post_json /v1/orgs "$(jq -nc --arg name "ZManager staging $(date -u '+%Y%m%dT%H%M%SZ')" '{name:$name}')" "$TOKEN_1")"
	ORG_ID="$(jq -er '.org_id' <<<"$ORG")"
	set +e
	"$ZM" cert enroll --state-dir "$STATE_1" --service-base-url "$BASE_URL" \
		--trusted-root-cert "$ROOT_CERT" --org-id "$ORG_ID" --requested-validity-seconds 7776000 \
		--json > "$WORK_DIR/org-pending.out" 2> "$WORK_DIR/org-pending.err"
	pending_exit=$?
	set -e
	[[ "$pending_exit" -ne 0 ]] || fail "organization enrollment unexpectedly bypassed device approval"
	rg_pattern='device_linkage_pending|organization_device_approval_pending'
	{ grep -Eq "$rg_pattern" "$WORK_DIR/org-pending.out" || grep -Eq "$rg_pattern" "$WORK_DIR/org-pending.err"; } ||
		fail "organization enrollment did not report approval pending"
	ORG_KEY_ID="$(jq -er --arg label "Hosted TZAP enrollment signing key (org:$ORG_ID)" \
		'.device_signing_keys[] | select(.label == $label) | .key_id' "$STATE_1/default.identity.json")"
	DEVICES="$(curl --fail --silent --show-error -H "Authorization: Bearer $TOKEN_1" "$BASE_URL/v1/orgs/$ORG_ID/devices")"
	ORG_DEVICE_ID="$(jq -er --arg key "$ORG_KEY_ID" '.[] | select(.device_public_key_fingerprint == $key) | .organization_device_id' <<<"$DEVICES")"
	post_json "/v1/orgs/$ORG_ID/devices/$ORG_DEVICE_ID/approve" '{}' "$TOKEN_1" >/dev/null
	"$ZM" cert enroll --state-dir "$STATE_1" --service-base-url "$BASE_URL" \
		--trusted-root-cert "$ROOT_CERT" --org-id "$ORG_ID" --requested-validity-seconds 7776000 \
		--json > "$WORK_DIR/org-enroll.json"
	ORG_CERT="$(jq -er '.certificate.certificate_id' "$WORK_DIR/org-enroll.json")"
	jq -e --arg org "$ORG_ID" '.certificate.public_org_id == $org' "$WORK_DIR/org-enroll.json" >/dev/null
	jq -e --arg key "$ORG_KEY_ID" \
		'([.device_signing_keys[] | select(.key_id == $key)] | length) == 1 and any(.enrolled_certificates[]; .signing_key_id == $key)' \
		"$STATE_1/default.identity.json" >/dev/null
	"$ZM" sign "$WORK_DIR/document.json" --state-dir "$STATE_1" --certificate-id "$ORG_CERT" \
		--output "$WORK_DIR/org-document-envelope.json" --json >/dev/null
	"$ZM" verify "$WORK_DIR/org-document-envelope.json" --custom-trust-root-cert "$ROOT_CERT" --json |
		jq -e '.state == "cryptographically_intact_offline"' >/dev/null
	"$ZM" cert list --state-dir "$STATE_1" --json |
		jq -e --arg id "$ORG_CERT" --arg org "$ORG_ID" \
		'any(.certificates[]; .certificate_id == $id and .public_org_id == $org)' >/dev/null
fi

log "Creating contact cards and a signed two-recipient TZAP"
KEY_1="$("$ZM" contact keygen --state-dir "$STATE_1" --label 'Staging recipient one' --json | jq -er '.recipient_key_id')"
KEY_2="$("$ZM" contact keygen --state-dir "$STATE_2" --label 'Staging recipient two' --json | jq -er '.recipient_key_id')"
"$ZM" contact export --state-dir "$STATE_1" --recipient-key-id "$KEY_1" --certificate-id "$CERT_1" \
	--display-name 'Staging Recipient One' --output "$WORK_DIR/contact-1.json" --json >/dev/null
"$ZM" contact export --state-dir "$STATE_2" --recipient-key-id "$KEY_2" --certificate-id "$CERT_2" \
	--display-name 'Staging Recipient Two' --output "$WORK_DIR/contact-2.json" --json >/dev/null
CONTACT_1="$("$ZM" contact import "$WORK_DIR/contact-1.json" --state-dir "$STATE_1" --accept \
	--custom-trust-root-cert "$ROOT_CERT" --json | jq -er '.contact.contact_id')"
CONTACT_2="$("$ZM" contact import "$WORK_DIR/contact-2.json" --state-dir "$STATE_1" --accept \
	--custom-trust-root-cert "$ROOT_CERT" --json | jq -er '.contact.contact_id')"
mkdir -p "$WORK_DIR/payload"
printf 'signed multi-recipient staging payload\n' > "$WORK_DIR/payload/message.txt"
"$ZM" share "$WORK_DIR/multi-recipient.tzap" "$WORK_DIR/payload" --state-dir "$STATE_1" \
	--contact "$CONTACT_1" --contact "$CONTACT_2" --certificate-id "$CERT_1" --json |
	jq -e '.recipients == 2 and .signed == true' >/dev/null

decode_recipient_key "$STATE_1" "$KEY_1" "$WORK_DIR/recipient-1.key.der"
decode_recipient_key "$STATE_2" "$KEY_2" "$WORK_DIR/recipient-2.key.der"
"$ZM" test "$WORK_DIR/multi-recipient.tzap" --public-no-key --trusted-ca-cert "$ROOT_CERT" --json |
	jq -e '.root_auth.authenticator == "x509" and .root_auth.trust_anchor_subject != null' >/dev/null
for recipient_number in 1 2; do
	"$ZM" test "$WORK_DIR/multi-recipient.tzap" \
		--recipient-key "$WORK_DIR/recipient-$recipient_number.key.der" --trusted-ca-cert "$ROOT_CERT" --json |
		jq -e '.root_auth.authenticator == "x509" and .root_auth.trust_anchor_subject != null and .tested_entries > 0' >/dev/null
	mkdir -p "$WORK_DIR/extracted-$recipient_number"
	"$ZM" extract "$WORK_DIR/multi-recipient.tzap" --recipient-key "$WORK_DIR/recipient-$recipient_number.key.der" \
		-C "$WORK_DIR/extracted-$recipient_number" --json >/dev/null
	cmp "$WORK_DIR/payload/message.txt" "$WORK_DIR/extracted-$recipient_number/payload/message.txt"
done

log "STAGING INTEGRATION PASSED"
printf 'personal_certificate_1=%s\n' "$CERT_1"
printf 'personal_certificate_2=%s\n' "$CERT_2"
printf 'personal_certificate_1_sha256=%s\n' "$CERT_1_SHA"
printf 'personal_certificate_2_sha256=%s\n' "$CERT_2_SHA"
if [[ "$RUN_ORGANIZATION" == true ]]; then
	printf 'organization_id=%s\norganization_certificate=%s\n' "$ORG_ID" "$ORG_CERT"
fi
