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

Before tagging, refresh and verify every controlled repository and sibling:

```sh
bash scripts/release-gate.sh prepare
git diff -- release-build-inputs.lock
bash scripts/release-gate.sh verify
```

Release TZAP before ZManager. The ZManager lock records the released TZAP
source snapshot and all sibling checkout commits. Commit the reviewed lock
before creating the ZManager release tag. Package workflows consume that lock
without updating it.

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
   git tag v2.3.0
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
     v2.3.0 \
     https://github.com/tzap-org/zmanager/releases/download/v2.3.0 \
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
   winget validate .\dist\package-metadata\winget\TzapOrg.ZManagerCLI\2.3.0
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

## macOS CLI signing and notarization

Tagged releases sign both macOS CLI executables (`zm` and `zm-full`) with a
Developer ID Application identity and submit them to Apple in a ZIP. Packaging
does not wait for Apple: it saves the submission IDs and signed archives, then
stages the complete release as a GitHub draft with generated release notes.
The `Publish notarized draft releases` workflow checks drafts every 20 minutes.
It publishes a draft only after both Apple submissions are accepted, the
downloaded archive checksums and signed code hashes match the recorded values,
and Gatekeeper accepts each executable with a quarantine attribute. You can
also run that workflow manually for a single tag while investigating a
submission. Configure these repository Actions secrets:

- `APPLE_DEVELOPER_ID_P12_BASE64`
- `APPLE_DEVELOPER_ID_P12_PASSWORD`
- `APPLE_API_KEY_BASE64`
- `APPLE_API_KEY_ID`
- `APPLE_API_ISSUER_ID`

The signing job imports the P12 into a temporary runner keychain and removes
the keychain and API key file when signing finishes. To validate the
credentials without creating a draft, run the `Release` workflow manually with
the release tag and `notarization_test` enabled. This test confirms upload and
records the submission ID; Apple acceptance happens asynchronously. A tagged
push uses the normal draft-release path.

Apple issues a notarization ticket for each standalone CLI binary, but tickets
cannot be stapled directly to standalone binaries. Gatekeeper retrieves the
ticket online when it evaluates the downloaded executable; see
[Apple's notarization workflow documentation](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

## Release Notes

Use [docs/release-notes/2.3.0.md](docs/release-notes/2.3.0.md) as the release
notes source for the `v2.3.0` GitHub release.
