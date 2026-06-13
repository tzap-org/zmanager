# CLI Release

## GitHub Remote

The standalone CLI repository is expected to use:

```sh
git remote add origin https://github.com/frankmanzhu/zmanager.git
```

The Homebrew tap should live in a separate repository named
`homebrew-zmanager`:

```sh
https://github.com/frankmanzhu/homebrew-zmanager.git
```

That naming lets users run `brew install frankmanzhu/zmanager/zmanager`.

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
   git tag v1.0.4
   git push origin main --tags
   ```

4. Confirm the release workflow generated:

   ```text
   release-artifacts/SHA256SUMS
   release-artifacts/zm-<target>.deps.txt
   release-artifacts/package-metadata/homebrew/Formula/zmanager.rb
   release-artifacts/package-metadata/winget/FrankZhu.ZManagerCLI/<version>/
   ```

   To regenerate locally from downloaded artifacts:

   ```sh
   scripts/generate-package-metadata.sh \
     v1.0.4 \
     https://github.com/frankmanzhu/zmanager/releases/download/v1.0.4 \
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
   winget validate .\dist\package-metadata\winget\FrankZhu.ZManagerCLI\1.0.4
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

Use [docs/release-notes/1.0.4.md](docs/release-notes/1.0.4.md) as the release
notes source for the `v1.0.4` GitHub release. Update the versioned file first
when preparing a later release.
