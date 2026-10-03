# Installing ZManager CLI

This document covers the CLI-first distribution paths for `zm`. Release
artifacts are built by GitHub Actions and published with a
top-level `SHA256SUMS` file.

## Linux Install Script

Linux users can install the latest matching static release into
`$HOME/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sh
```

The installer selects the correct `x86_64-unknown-linux-musl` or
`aarch64-unknown-linux-musl` asset, verifies it against `SHA256SUMS`, and prints
the next command to run. Set `ZMANAGER_VERSION` or `ZMANAGER_INSTALL_DIR` to pin
a release or install elsewhere:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh \
  | ZMANAGER_VERSION=v2.1.7 ZMANAGER_INSTALL_DIR="$HOME/bin" sh
```

Use `sudo env` for system-wide locations:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh \
  | sudo env ZMANAGER_VERSION=v2.1.7 ZMANAGER_INSTALL_DIR=/usr/local/bin sh
```

The default installs the **normal** build (reported as `offline`) — every archive command plus
`zm tzap sign`, `verify`, `contact`, `share`, and `certs` (which work entirely
against the local identity catalogue, no network required). To install the
**full** build, which adds online identity and certificate enrollment, pass
`--full`:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh \
  | sh -s -- --full
```

`zm --version` reports which flavor is installed: `zm 2.1.7 (full)` or
`zm 2.1.7 (offline)`.

If no matching binary exists, the installer falls back to building from source.
Source fallback requires `git`, Rust/Cargo, and the target platform's native
compression and cryptography development libraries.

Updates stage the replacement beside the installed executable and publish it
only after copying and setting executable permissions. A failed copy or a
SIGINT/SIGTERM interruption before publication preserves the existing executable. An unwritable
installation directory reports the required sudo command; the default user
installation does not require sudo.

## Direct Downloads

Manual downloads are useful for offline packaging, pinned checksums, and custom
install layouts. Download the archive for your platform from the GitHub release:

| Platform | Asset |
| --- | --- |
| macOS Apple Silicon | `zm-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `zm-x86_64-apple-darwin.tar.gz` |
| Linux ARM64 | `zm-aarch64-unknown-linux-musl.tar.gz` |
| Linux x86_64 | `zm-x86_64-unknown-linux-musl.tar.gz` |
| Windows ARM64 | `zm-aarch64-pc-windows-msvc.zip` |
| Windows x64 | `zm-x86_64-pc-windows-msvc.zip` |

These are the normal (default) build assets. For the **Full** build with online
identity and certificate enrollment, use the corresponding `zm-full-<target>`
archive instead. It contains `zm-full` or `zm-full.exe`; install that binary on
`PATH` as `zm` or `zm.exe` to use the same command name.

Verify checksums before installing.

Unix:

```sh
curl -LO https://github.com/tzap-org/zmanager/releases/download/v2.1.7/SHA256SUMS
curl -LO https://github.com/tzap-org/zmanager/releases/download/v2.1.7/zm-aarch64-apple-darwin.tar.gz
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

Linux release archives are statically linked musl builds that run
without installing extra runtime packages. The install script is the recommended
path; use the manual flow when you want to inspect or stage the tarball yourself.

```sh
curl -LO https://github.com/tzap-org/zmanager/releases/download/v2.1.7/SHA256SUMS
curl -LO https://github.com/tzap-org/zmanager/releases/download/v2.1.7/zm-x86_64-unknown-linux-musl.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf zm-x86_64-unknown-linux-musl.tar.gz
./zm --version
```

Use `zm-aarch64-unknown-linux-musl.tar.gz` on ARM64 systems.

## macOS Install Script

### Gatekeeper and the current portable packages

The macOS tarballs are not Developer ID signed or notarized. Apple Silicon
executables may carry the linker's ad hoc signature; that is not a Developer ID
signature. Checksum verification establishes that the download matches the
published artifact, but does not establish Apple notarization.

A browser-downloaded executable can encounter Gatekeeper on first launch.
If macOS blocks a package you have verified and intend to trust, follow
[Apple's instructions for opening software from an unidentified developer](https://support.apple.com/102445)
using System Settings > Privacy & Security. Keep Gatekeeper enabled; managed
devices may restrict exceptions.

Our package smoke tests execute an unpacked binary through a fresh `PATH`.
They do not reproduce browser quarantine or approve an OS security prompt.
The tested Apple Silicon preview had a valid ad hoc signature and was rejected
by `spctl --assess --type execute`; its unquarantined shell launch passed.
Browser quarantine and the resulting consent interaction remain a separate
manual distribution check.

### Offline identity and Keychain access

The macOS CLI allows native Keychain prompts when stdin and stderr are attached
to a terminal. When either is redirected, a locked Keychain fails promptly with
a locked-store diagnostic. Unlock the Keychain or retry from Terminal when
native authorization is required. Cancelled authorization reports denied
access. Public certificate discovery remains available while the Keychain is
locked.

macOS users can also install the latest matching release into `$HOME/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sh
```

Set `ZMANAGER_VERSION` and `ZMANAGER_INSTALL_DIR` to pin a version or install
elsewhere:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh \
  | ZMANAGER_VERSION=v2.1.7 ZMANAGER_INSTALL_DIR="$HOME/bin" sh
```

Use `sudo env` for system-wide locations:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh \
  | sudo env ZMANAGER_VERSION=v2.1.7 ZMANAGER_INSTALL_DIR=/usr/local/bin sh
```

## Preview Builds (developers)

The [Package Preview workflow](.github/workflows/package-preview.yml) packages
the latest `main` on every push and on manual dispatch, uploading the tarballs
as GitHub Actions artifacts without publishing a release. To test a preview
package with the install script instead of a release, pass `--preview`:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh \
  | sh -s -- --preview
```

`--preview` works on macOS and Linux, requires the
[gh CLI](https://cli.github.com/) to be installed and authenticated, and does
not fall back to a source build. The latest **successful** Package Preview run
is used; pin a specific run with `ZMANAGER_RUN_ID`:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh \
  | ZMANAGER_RUN_ID=26042001498 sh -s -- --preview
```

Combine with `--full` to test the full preview package:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh \
  | sh -s -- --preview --full
```

`ZMANAGER_INSTALL_DIR`, `ZMANAGER_REPO_URL`, and the checksum verification
steps behave the same as release installs. Preview artifacts are kept for
14 days.

## Homebrew

The Homebrew tap repository should be named `homebrew-zmanager`. After the
generated formula is copied to the tap, users install with:

```sh
brew install tzap-org/zmanager/zmanager
# Hosted login and certificate enrollment:
brew install tzap-org/zmanager/zmanager-full
```

The release workflow renders the formula from
`packaging/homebrew/zmanager.rb.template` using CI-generated checksums. To
generate it locally from release artifacts:

```sh
scripts/generate-package-metadata.sh \
  v2.1.7 \
  https://github.com/tzap-org/zmanager/releases/download/v2.1.7 \
  dist/SHA256SUMS \
  dist/package-metadata
```

Copy `dist/package-metadata/homebrew/Formula/zmanager.rb` to
`tzap-org/homebrew-zmanager`.

## WinGet

The currently published package installs the normal offline (default) build:

```powershell
winget install FrankZhu.ZManagerCLI
```

Release downloads are hosted under `tzap-org` on GitHub, but the published
WinGet package ID has not changed. A separate Full package has not been
submitted to WinGet.

The generated `TzapOrg` manifests below are not the currently published package
IDs. After release metadata is generated, validate the manifests before submitting
them to `microsoft/winget-pkgs`:

```powershell
winget validate .\dist\package-metadata\winget\TzapOrg.ZManagerCLI\2.1.7
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
