# CLI Release

## GitHub Remote

The standalone CLI repository is expected to use:

```sh
git remote add origin https://github.com/tzap-org/zmanager.git
```

The Homebrew tap should live in a separate repository named
`homebrew-zmanager`:

```sh
https://github.com/tzap-org/homebrew-zmanager.git
```

That naming lets users run `brew install tzap-org/zmanager/zmanager`.

## Native OpenSSL

The package scripts build and statically link OpenSSL 3.5.9 with TZAP's
upstream RSA-PSS provider alias patch. `scripts/build-openssl.py` verifies the
source and patch checksums and caches the patched libraries by target. It needs
Python 3, Perl, Git, and the native build tools for the selected target.

For a direct Unix Cargo build using that same version, use the published TZAP
lockfile with the development override temporarily removed, then run:

```sh
target="$(rustc -vV | sed -n 's/^host: //p')"
OPENSSL_DIR="$(python3 scripts/build-openssl.py "$target")"
export OPENSSL_DIR OPENSSL_STATIC=1 OPENSSL_NO_VENDOR=1
cargo build --locked -p zmanager-cli --bin zm
```

The environment override selects these native libraries for the published
TZAP crates as well. Bare Cargo builds use the vendored source selected by
those crates unless an external OpenSSL installation is configured.

## Release Checklist

1. Run:

   ```sh
   cargo test --workspace
   cargo clippy --workspace --all-targets
   cargo fmt --check
   ```

2. Run the tool-dependent compatibility suite on a fully provisioned validation
   machine:

   ```sh
   scripts/release-compatibility-check.sh
   ```

   This check intentionally fails instead of skipping when creator tools such
   as RARLab `rar`, 7-Zip, `bsdtar`, `zstd`, and package builders are missing.

3. Tag the CLI repository:

   ```sh
   git tag v2.2.1
   git push origin main --tags
   ```

4. Confirm the release workflow generated:

   ```text
   release-artifacts/SHA256SUMS
   release-artifacts/zm-<target>.deps.txt
   release-artifacts/package-metadata/homebrew/Formula/zmanager.rb
   release-artifacts/package-metadata/winget/TzapOrg.ZManagerCLI/<version>/
   ```

   To regenerate locally from downloaded artifacts:

   ```sh
   scripts/generate-package-metadata.sh \
     v2.2.1 \
     https://github.com/tzap-org/zmanager/releases/download/v2.2.1 \
     dist/SHA256SUMS \
     dist/package-metadata
   ```

5. Copy the generated Homebrew formula to the tap repository at
   `Formula/zmanager.rb`.

6. Validate the tap:

   ```sh
   brew audit --strict --formula Formula/zmanager.rb
   brew install Formula/zmanager.rb
   brew test zmanager
   ```

7. Validate the generated WinGet manifests:

   ```powershell
   winget validate .\dist\package-metadata\winget\TzapOrg.ZManagerCLI\2.2.1
   ```

8. Validate the Linux static tarballs on Ubuntu 22.04 and 24.04:

   ```sh
   tar -xzf ./dist/zm-x86_64-unknown-linux-musl.tar.gz
   ./zm --version
   ./zm doctor
   grep -q "no ELF NEEDED entries" ./dist/zm-x86_64-unknown-linux-musl.deps.txt
   ```

The Homebrew formula and WinGet manifests are generated from `SHA256SUMS`;
do not hand-edit release asset hashes.

## Release Notes

Use [docs/release-notes/2.2.1.md](docs/release-notes/2.2.1.md) as the release
notes source for the `v2.2.1` GitHub release. Update the versioned file first
when preparing a later release.
