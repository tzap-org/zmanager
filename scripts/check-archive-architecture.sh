#!/usr/bin/env bash
set -euo pipefail

# Deletion guard for CLEAN-002/CLEAN-703. This intentionally checks production
# consumers only; backend internals and focused adapter tests may use backend
# implementation names behind the engine seam.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
desktop_root="${repo_root}/../zmanager-desktop/src-tauri/src"
mobile_root="${repo_root}/../zmanager-mobile"
gui_root="${repo_root}/../zmanager-gui"
failed=0

# Prints "start end" line ranges for every inline `#[cfg(test)]` item in a file.
# The glob filters below drop whole test files, but production modules carry
# their unit tests inline; those are tests too and must not trip these guards.
#
# Brace counting is deliberately avoided: braces inside string literals (any
# `format!("{}")`) desynchronise a naive depth counter. rustfmt puts the closing
# brace of a top-level item in column 0, so the region runs from the attribute
# to the next line that is exactly `}`.
cfg_test_ranges() {
    awk '
    /^#\[cfg\(test\)\]/ && !inblock {
        pending = 1
        start = NR
        next
    }
    pending && /^[[:space:]]*#\[/ { next }          # further attributes on the same item
    pending {
        pending = 0
        if (index($0, "{") > 0) { inblock = 1; next }
        print start, NR                             # single-line item, e.g. `use ...;`
        next
    }
    inblock && /^\}/ {
        print start, NR
        inblock = 0
    }
    END { if (inblock) print start, NR }            # test module runs to EOF
    ' "$1"
}

# Reads `file:line:text` matches and drops the ones inside inline test code.
drop_inline_test_matches() {
    local match file lineno start end suppressed
    while IFS= read -r match; do
        [[ -z "${match}" ]] && continue
        file="${match%%:*}"
        lineno="${match#*:}"
        lineno="${lineno%%:*}"
        if [[ ! -f "${file}" || ! "${lineno}" =~ ^[0-9]+$ ]]; then
            printf '%s\n' "${match}"
            continue
        fi
        suppressed=0
        while read -r start end; do
            if (( lineno >= start && lineno <= end )); then
                suppressed=1
                break
            fi
        done < <(cfg_test_ranges "${file}")
        (( suppressed )) || printf '%s\n' "${match}"
    done
}

check_absent() {
    local label="$1"
    local pattern="$2"
    shift 2
    local hits
    hits="$(rg -n --no-heading --with-filename --glob '*.rs' --glob '!**/tests/**' --glob '!**/*tests.rs' --glob '!**/tests.rs' "$pattern" "$@" 2>/dev/null | drop_inline_test_matches || true)"
    if [[ -n "${hits}" ]]; then
        printf '%s\n' "${hits}"
        printf 'FAIL: %s\n' "$label" >&2
        failed=1
    fi
}

check_absent_any_file() {
    local label="$1"
    local pattern="$2"
    shift 2
    if rg -n "$pattern" "$@"; then
        printf 'FAIL: %s\n' "$label" >&2
        failed=1
    fi
}

check_absent "backend execution/types still cross a product seam" \
    'zmanager_core::(apple_archive_backend|raw_stream_backend|sevenz_backend|tar_gz_backend|tar_zst_backend|tzap_backend|zip_backend|rar_backend)::' \
    "${repo_root}/crates/zmanager-cli/src" "${repo_root}/crates/zmanager-ffi/src" "${desktop_root}"
check_absent "legacy backend-shaped extraction job remains" \
    'run_(zip|tar_zst|apple_archive|7z|rar|raw_stream|tzap)_extract_job' \
    "${repo_root}/crates" "${desktop_root}"
check_absent "dead archive compatibility branch remains" 'cfg\(any\)' "${repo_root}/crates" "${desktop_root}"
check_absent "factory-only read session wrapper remains" 'FactoryBackedReadAdapterSession' "${repo_root}/crates/zmanager-core/src"
check_absent "deleted TZAP backend compatibility alias remains" 'tzap_backend' "${repo_root}/crates" "${desktop_root}"
check_absent "native adapters bypass the session context" 'archive: &DetectedArchive|open_options: &OpenOptions' "${repo_root}/crates/zmanager-core/src/engine/adapters/native.rs"
check_absent "native adapters reopen a path outside the cursor factory" 'File::open\(path\)' "${repo_root}/crates/zmanager-core/src/engine/adapters/native.rs"
check_absent "selected native operations reinterpret engine IDs as archive indexes" 'entry_id\.0' "${repo_root}/crates/zmanager-core/src/engine/adapters/native.rs" "${repo_root}/crates/zmanager-core/src/engine/adapters/zip.rs"
check_absent "selected native operations hard-code synthetic adapter IDs" 'entry_id[[:space:]]*!=[[:space:]]*EntryId\(' "${repo_root}/crates/zmanager-core/src/engine/adapters/native.rs" "${repo_root}/crates/zmanager-core/src/engine/adapters/zip.rs"
check_absent "hosted TZAP is imported through offline core" \
    'zmanager_core::(auth_client|certificate_lifecycle|enrollment_client|local_tzap_service|status_client|tzap_service|tzap_service_auth)::' \
    "${repo_root}/crates/zmanager-cli/src" "${repo_root}/crates/zmanager-ffi/src" "${desktop_root}"
check_absent "hidden backend test support crosses a production seam" \
    'zmanager_core::backend_test_support::' \
    "${repo_root}/crates/zmanager-cli/src" "${repo_root}/crates/zmanager-ffi/src" "${repo_root}/crates/zmanager-tzap-hosted/src" "${desktop_root}"
check_absent "core exports backend modules publicly" \
    '^pub mod [a-z0-9_]+_backend' \
    "${repo_root}/crates/zmanager-core/src/lib.rs"
check_absent "core exposes adapter implementation modules publicly" \
    '^pub mod adapters$' \
    "${repo_root}/crates/zmanager-core/src/engine/mod.rs"
check_absent "adapter descriptors allocate leaked metadata" \
    'Box::leak\(Box::new\(AdapterDescriptor' \
    "${repo_root}/crates/zmanager-core/src/engine"
check_absent "production code masks dead code" \
    '#\[allow\(dead_code\)\]' \
    --glob '!test_support.rs' \
    "${repo_root}/crates/zmanager-core/src" "${repo_root}/crates/zmanager-cli/src"
check_absent "adapter error mapping bypasses the shared disposition rule" \
    'SessionDisposition::Unusable' \
    --glob '!mod.rs' \
    "${repo_root}/crates/zmanager-core/src/engine/adapters"

if [[ -d "${mobile_root}" ]]; then
    check_absent_any_file "mobile bridge scripts still request the removed auth feature" \
        '(--features[[:space:]]+auth|features[[:space:]]+auth)' \
        "${mobile_root}/scripts" "${mobile_root}/docs"
fi

if [[ -d "${gui_root}" ]]; then
    check_absent_any_file "GUI documentation references the deleted TZAP backend module" \
        'tzap_backend\.rs' \
        "${gui_root}/docs" "${gui_root}/steps"
fi

for hosted_path in \
    "${repo_root}/crates/zmanager-core/src/auth/auth_client.rs" \
    "${repo_root}/crates/zmanager-core/src/auth/certificate_lifecycle.rs" \
    "${repo_root}/crates/zmanager-core/src/auth/enrollment_client.rs" \
    "${repo_root}/crates/zmanager-core/src/auth/http_client.rs" \
    "${repo_root}/crates/zmanager-core/src/auth/local_tzap_service.rs" \
    "${repo_root}/crates/zmanager-core/src/auth/status_client.rs" \
    "${repo_root}/crates/zmanager-core/src/auth/tzap_service.rs" \
    "${repo_root}/crates/zmanager-core/src/auth/tzap_service_auth.rs" \
    "${repo_root}/crates/zmanager-core/src/wire_profile.rs"; do
    if [[ -e "$hosted_path" ]]; then
        printf 'FAIL: hosted implementation remains in offline core: %s\n' "$hosted_path" >&2
        failed=1
    fi
done

if [[ "$failed" -ne 0 ]]; then
    exit 1
fi
printf 'archive architecture deletion audit passed\n'
