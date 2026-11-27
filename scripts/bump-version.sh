#!/usr/bin/env bash
set -euo pipefail

# Ensure script is run from project root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <new-version> <stable-tzap-version> (e.g. 2.3.1 0.3.1)"
    exit 1
fi

NEW_VERSION="${1#v}"
TZAP_VERSION="${2#v}"

if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: release version '$NEW_VERSION' must be stable SemVer without a prerelease suffix."
    exit 1
fi

if ! [[ "$TZAP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: TZAP version '$TZAP_VERSION' must be stable SemVer without a prerelease suffix."
    exit 1
fi

OLD_VERSION=$(grep -E '^version = ' Cargo.toml | head -1 | cut -d '"' -f 2)

echo "==> Bumping workspace version from ${OLD_VERSION} to ${NEW_VERSION}..."

# Stable releases must consume the matching published TZAP set. Development
# manifests intentionally require the sibling's 0.3.1-dev packages.
python3 - "$TZAP_VERSION" <<'PY'
from pathlib import Path
import re
import sys

version = sys.argv[1]
for path in (
    Path("crates/zmanager-core/Cargo.toml"),
    Path("crates/zmanager-ffi/Cargo.toml"),
    Path("fuzz/Cargo.toml"),
):
    text = path.read_text()
    updated, count = re.subn(
        r'(?m)^(tzap-(?:core|plugin-keywrap|plugin-signing)\s*=\s*)"[^\"]+"',
        lambda match: f'{match.group(1)}"={version}"',
        text,
    )
    if count == 0:
        raise SystemExit(f"No TZAP dependencies found in {path}")
    path.write_text(updated)
PY

# Update root Cargo.toml [workspace.package] version
sed -i.bak -E "s/^version = \"${OLD_VERSION}\"/version = \"${NEW_VERSION}\"/" Cargo.toml
rm -f Cargo.toml.bak

# Update internal dependency version strings for inter-crate paths in Cargo.toml
sed -i.bak -E "s/(zmanager-[a-z-]+ = \{[^}]*version = \")[^\"]+(\"[^}]*\})/\1${NEW_VERSION}\2/g" Cargo.toml
rm -f Cargo.toml.bak

# Update version references with strict anchors to prevent unintended replacements

if [ -f README.md ]; then
    sed -i.bak -E "s/(\`zm )[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?( \(full\)\`)/\1${NEW_VERSION}\3/g" README.md
    sed -i.bak -E "s/(\`zm )[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?( \(offline\)\`)/\1${NEW_VERSION}\3/g" README.md
    rm -f README.md.bak
fi

if [ -f docs/INSTALL.md ]; then
    sed -i.bak -E "s/(\`zm )[0-9]+\.[0-9]+\.[0-9]+( \(full\)\`)/\1${NEW_VERSION}\2/g" docs/INSTALL.md
    sed -i.bak -E "s/(\`zm )[0-9]+\.[0-9]+\.[0-9]+( \(offline\)\`)/\1${NEW_VERSION}\2/g" docs/INSTALL.md
    sed -i.bak -E "s/(TzapOrg\.ZManagerCLI\\\\)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" docs/INSTALL.md
    sed -i.bak -E "s/(ZMANAGER_VERSION=v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" docs/INSTALL.md
    sed -i.bak -E "s/(releases\/download\/v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" docs/INSTALL.md
    sed -i.bak -E "s/^([[:space:]]*)v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?[[:space:]]*\\\\/\1v${NEW_VERSION} \\\\/g" docs/INSTALL.md
    rm -f docs/INSTALL.md.bak
fi

if [ -f RELEASE.md ]; then
    sed -i.bak -E "s/(git tag v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" RELEASE.md
    sed -i.bak -E "s/^([[:space:]]*)v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?[[:space:]]*\\\\/\1v${NEW_VERSION} \\\\/g" RELEASE.md
    sed -i.bak -E "s/(releases\/download\/v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" RELEASE.md
    sed -i.bak -E "s/(TzapOrg\.ZManagerCLI\\\\)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" RELEASE.md
    sed -i.bak -E "s/(release-notes\/)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" RELEASE.md
    sed -i.bak -E "s/(\`v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\` GitHub release)/\1${NEW_VERSION}\3/g" RELEASE.md
    rm -f RELEASE.md.bak
fi

if [ -f crates/zmanager-cli/tests/help_cli.rs ]; then
    sed -i.bak -E "s/(zm )[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?( \(full, test\))/\1${NEW_VERSION}\3/g" crates/zmanager-cli/tests/help_cli.rs
    sed -i.bak -E "s/(assert_eq!\(env!\(\"CARGO_PKG_VERSION\"\), \")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\"\);)/\1${NEW_VERSION}\3/g" crates/zmanager-cli/tests/help_cli.rs
    rm -f crates/zmanager-cli/tests/help_cli.rs.bak
fi

# Generate Cargo.lock files against the selected stable TZAP crates. The local
# development patch otherwise replaces registry package identities with paths.
CONFIG_BACKUP=$(mktemp)
FUZZ_MANIFEST_BACKUP=$(mktemp)
cp .cargo/config.toml "$CONFIG_BACKUP"
cp fuzz/Cargo.toml "$FUZZ_MANIFEST_BACKUP"
restore_cargo_config() {
    cp "$CONFIG_BACKUP" .cargo/config.toml
    cp "$FUZZ_MANIFEST_BACKUP" fuzz/Cargo.toml
    rm -f "$CONFIG_BACKUP"
    rm -f "$FUZZ_MANIFEST_BACKUP"
}
trap restore_cargo_config EXIT
python3 -c 'from pathlib import Path; p=Path(".cargo/config.toml"); s=p.read_text(); marker="[patch.crates-io]"; assert marker in s; p.write_text(s.split(marker, 1)[0].rstrip() + "\n")'
python3 -c 'from pathlib import Path; import re; p=Path("fuzz/Cargo.toml"); s=p.read_text(); s, n=re.subn(r"(?m)^tzap-(?:core|plugin-keywrap|plugin-signing)\s*=\s*\{[^\n]*\}\n", "", s); assert n == 3, f"expected three TZAP patches in fuzz manifest, found {n}"; p.write_text(s)'

echo "==> Updating root Cargo.lock..."
cargo check --workspace

echo "==> Updating fuzz/Cargo.lock..."
cargo check --manifest-path fuzz/Cargo.toml

echo "==> Verifying --locked compatibility..."
cargo check --workspace --locked
cargo check --manifest-path fuzz/Cargo.toml --locked

echo "Successfully prepared workspace ${NEW_VERSION} with stable TZAP ${TZAP_VERSION}!"
