#!/usr/bin/env bash
# Verify that every supported artifact profile remains native-only.

set -euo pipefail

for package in zmanager-core zmanager-cli zmanager-ffi; do
    for profile in default no-default-features; do
        if [[ "$profile" == "no-default-features" ]]; then
            graph=$(cargo tree -e normal -p "$package" --no-default-features)
        else
            graph=$(cargo tree -e normal -p "$package")
        fi
        forbidden='libarchive|bsdtar'
        # CLI defaults are offline too. FFI defaults include LocalSend's HTTP
        # transport; its reduced profile must exclude that transport entirely.
        if [[ "$package" == "zmanager-cli" || "$package" == "zmanager-core" || "$profile" == "no-default-features" ]]; then
            forbidden+='|reqwest'
        fi
        if grep -Eiq "$forbidden" <<<"$graph"; then
            echo "$package $profile still contains a forbidden hosted/backend runtime dependency" >&2
            exit 1
        fi
    done
done

cargo check -p zmanager-core --no-default-features --all-targets
cargo check -p zmanager-cli --no-default-features --all-targets
cargo check -p zmanager-ffi --no-default-features --all-targets
