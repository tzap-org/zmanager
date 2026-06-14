# Installing ZManager CLI

This document covers the CLI-first distribution paths for `zm`. Release
artifacts are built by GitHub Actions and published with a
top-level `SHA256SUMS` file.

## Direct Downloads

Download the archive for your platform from the GitHub release:

| Platform | Asset |
| --- | --- |
| macOS Apple Silicon | `zm-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `zm-x86_64-apple-darwin.tar.gz` |
| Linux ARM64 | `zm-aarch64-unknown-linux-musl.tar.gz` |
| Linux x86_64 | `zm-x86_64-unknown-linux-musl.tar.gz` |
| Windows ARM64 | `zm-aarch64-pc-windows-msvc.zip` |
| Windows x64 | `zm-x86_64-pc-windows-msvc.zip` |

Verify checksums before installing.

Unix:

```sh
curl -LO https://github.com/tzap-org/zmanager/releases/download/v1.0.3/SHA256SUMS
curl -LO https://github.com/tzap-org/zmanager/releases/download/v1.0.3/zm-aarch64-apple-darwin.tar.gz
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Linux without `shasum`:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

Windows PowerShell:

```powershell
$asset = "zm-x86_64-pc-windows-msvc.zip"
$expected = (Select-String -Path .\SHA256SUMS -Pattern $asset).Line.Split(" ")[0]
$actual = (Get-FileHash -Algorithm SHA256 .\$asset).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "checksum mismatch for $asset" }
```

After verification, extract the archive and place `zm` or `zm.exe` on `PATH`.
The release archive also includes `LICENSE`, `NOTICE`, shell completions under
`completions/`, and the manual page under `man/man1/`. Third-party notices are
included in `THIRD_PARTY_NOTICES.md`, with copied license files under
`third-party-licenses/`.

## Shell Completions

The release archives include bash, zsh, fish, and PowerShell completions.
Unix package managers install bash, zsh, and fish completions into their
standard completion directories.

For manual bash setup without extra shell packages:

```sh
source <(zm completions bash)
```

For zsh or fish manual setup:

```sh
mkdir -p ~/.zfunc
zm completions zsh > ~/.zfunc/_zm

mkdir -p ~/.config/fish/completions
zm completions fish > ~/.config/fish/completions/zm.fish
```

Homebrew installs the static bash completion at
`$(brew --prefix)/etc/bash_completion.d/zm`. Bash users can source that file
directly or use `source <(zm completions bash)`.

PowerShell users can dot-source the generated completer from their profile or
current session:

```powershell
zm completions powershell > zm.ps1
. .\zm.ps1
```

## Linux Direct Install

Linux release archives are statically linked musl builds. They are intended to
run as a single executable without installing extra runtime packages.

```sh
curl -LO https://github.com/tzap-org/zmanager/releases/download/v1.0.3/SHA256SUMS
curl -LO https://github.com/tzap-org/zmanager/releases/download/v1.0.3/zm-x86_64-unknown-linux-musl.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf zm-x86_64-unknown-linux-musl.tar.gz
./zm --version
```

Use `zm-aarch64-unknown-linux-musl.tar.gz` on ARM64 systems.

## Install Script

macOS and Linux users can install the latest matching release into
`$HOME/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sh
```

Set `ZMANAGER_VERSION` and `ZMANAGER_INSTALL_DIR` to pin a version or install
elsewhere:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh \
  | ZMANAGER_VERSION=v1.0.3 ZMANAGER_INSTALL_DIR=/usr/local/bin sh
```

If no matching binary exists, the installer falls back to building from source.

## Homebrew

The Homebrew tap repository should be named `homebrew-zmanager`. After the
generated formula is copied to the tap, users install with:

```sh
brew install tzap-org/zmanager/zmanager
```

The release workflow renders the formula from
`packaging/homebrew/zmanager.rb.template` using CI-generated checksums. To
generate it locally from release artifacts:

```sh
scripts/generate-package-metadata.sh \
  v1.0.3 \
  https://github.com/tzap-org/zmanager/releases/download/v1.0.3 \
  dist/SHA256SUMS \
  dist/package-metadata
```

Copy `dist/package-metadata/homebrew/Formula/zmanager.rb` to
`tzap-org/homebrew-zmanager`.

## WinGet

After release metadata is generated, validate the manifests before submitting
them to `microsoft/winget-pkgs`:

```powershell
winget validate .\dist\package-metadata\winget\TzapOrg.ZManagerCLI\1.0.3
```

After the manifest is accepted, users install with:

```powershell
winget install TzapOrg.ZManagerCLI
```

WinGet metadata is generated from the same `SHA256SUMS` file as the Homebrew
formula, so installer hashes should not be edited by hand.

## Linux Channels

As of 1.0.3, the supported Linux path is direct tarball installation with checksum
verification. `.deb`, `.rpm`, and repository maintenance can be added later if
there is enough demand to justify owning distro-specific update flows.

The Linux binaries are built as static musl artifacts on GitHub-hosted
`ubuntu-22.04` and `ubuntu-22.04-arm` runners. The release-validation step
records an ELF dependency report and fails if a static Linux artifact contains
dynamic `NEEDED` entries.
