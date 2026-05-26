# Z-Manager CLI

[![CI](https://github.com/frankmanzhu/zmanager/actions/workflows/ci.yml/badge.svg)](https://github.com/frankmanzhu/zmanager/actions/workflows/ci.yml)
[![Release](https://github.com/frankmanzhu/zmanager/actions/workflows/release.yml/badge.svg)](https://github.com/frankmanzhu/zmanager/actions/workflows/release.yml)
[![Release version](https://img.shields.io/github/v/release/frankmanzhu/zmanager?include_prereleases&label=release)](https://github.com/frankmanzhu/zmanager/releases)
[![Downloads](https://img.shields.io/github/downloads/frankmanzhu/zmanager/total)](https://github.com/frankmanzhu/zmanager/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`zm` is a fast, safe archive utility for macOS, Linux, and Windows. Its goal is
simple: extract almost anything safely, and create new archives only with
modern, practical formats.

The CLI is the open-source part of Z-Manager. It shares the Rust archive engine
with the macOS app, but it is useful on its own: create clean project archives,
extract a broad set of formats safely, inspect archive contents, and script
archive workflows without opening a GUI.

Latest release: `v1.0.1`

## Install

Release builds are published on the
[latest release page](https://github.com/frankmanzhu/zmanager/releases/latest).
For full installation details and checksum examples, see
[docs/INSTALL.md](docs/INSTALL.md).

### macOS

Install from the Homebrew tap:

```sh
brew install frankmanzhu/zmanager/zmanager
zm healthcheck
```

Equivalent explicit form after tapping:

```sh
brew tap frankmanzhu/zmanager
brew install zmanager
```

### Linux

Linux users can download a static single-binary tarball from the GitHub release:

```sh
curl -LO https://github.com/frankmanzhu/zmanager/releases/download/v1.0.1/SHA256SUMS
curl -LO https://github.com/frankmanzhu/zmanager/releases/download/v1.0.1/zm-x86_64-unknown-linux-musl.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf zm-x86_64-unknown-linux-musl.tar.gz
./zm healthcheck
install -m 0755 zm "$HOME/.local/bin/zm"
zm healthcheck
```

Use `zm-aarch64-unknown-linux-musl.tar.gz` on ARM64 systems. The archive also
includes the man page and bash, zsh, fish, and PowerShell completions.

### Windows

Download the Windows `.zip` for your CPU from the
[latest release](https://github.com/frankmanzhu/zmanager/releases/latest),
verify it with `SHA256SUMS`, and place `zm.exe` on `PATH`.

When the WinGet package is published, install with:

```powershell
winget install FrankZhu.ZManagerCLI
```

### Install Script

Install the latest release binary into `$HOME/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/frankmanzhu/zmanager/main/install.sh | sh
```

Install a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/frankmanzhu/zmanager/main/install.sh \
  | ZMANAGER_VERSION=v1.0.1 sh
```

Install somewhere else:

```sh
curl -fsSL https://raw.githubusercontent.com/frankmanzhu/zmanager/main/install.sh \
  | ZMANAGER_INSTALL_DIR=/usr/local/bin sh
```

If a release binary is not available for the platform, the installer falls back
to building from source. Source fallback requires `git`, Rust/Cargo, CMake, and
the native compression development libraries used by libarchive.

## Quick Start

```sh
zm -cf project.zip project/
zm -xf project.zip -C out/

zm create project.tzst project/
zm extract project.tzst -C out/

printf '%s\n' "$ZM_PASSWORD" | zm create backup.tzap project/ --password-stdin
printf '%s\n' "$ZM_PASSWORD" | zm extract backup.tzap -C out/ --password-stdin

zm list project.zip
zm test project.zip
```

The classic flags are there for users who already know archive tools. The
subcommands are there for readable scripts.

## What It Does

- Extracts a broad range of archive, package, disk-image, and raw compression
  formats with safety checks enabled by default.
- Creates modern `.zip`, `.tzst` (`.tar.zst`), `.tzap`, and `.7z` archives
  with focused defaults.
- Opens common desktop, developer, package, and mobile archive formats by name:
  ZIP, ZIPX, JAR, WAR, IPA, APK, APPX, XPI, 7z, TAR, compressed TAR, RAR,
  CPIO, CPGZ, ISO, XAR, CAB, AR, DEB, RPM, SPK-style tar packages, and raw
  compressed files.
- Supports passworded ZIP, 7z, TZAP, and RAR workflows through stdin or
  prompts; new encrypted ZIP, TZAP, and 7z archives use AES-256 encryption
  paths.
- Protects extraction by default against path traversal, unsafe links,
  duplicate normalized paths, case collisions, and accidental overwrite traps.
- Provides both classic archive flags and readable subcommands.

## Why Z-Manager

Z-Manager treats extraction and creation differently:

- **Extract broadly.** Open old, obscure, downloaded, package, mobile, and
  developer archives without knowing which backend normally handles them.
- **Create deliberately.** New archives should use practical modern formats:
  ZIP for universal sharing, TZST (`.tar.zst`) for fast compression, TZAP for
  encrypted recoverable archives, and 7z for high-compression encrypted
  archives.
- **Avoid legacy creation paths.** Old compression methods matter for reading
  existing files, but new archives should use safer and faster defaults.
- **Use strong password protection.** Encrypted ZIP, TZAP, and 7z creation use
  AES-256 paths, and passwords are read through prompts or stdin rather than
  command arguments.

## Safety Model

Archive extraction is hostile-input handling. `zm` rejects or guards against:

- absolute paths and `..` traversal;
- symlink and hardlink escapes;
- duplicate normalized output paths;
- Unicode/case-insensitive path collisions;
- unsafe special files by default;
- excessive expanded-size and compression-ratio cases;
- accidental overwrites unless the requested overwrite mode allows them.

Passwords are not accepted as command arguments. Use the prompt or
`--password-stdin` so secrets do not appear in shell history or process listings.

## Format Support

| Workflow | Formats |
| --- | --- |
| Create modern archives | `.zip` with Deflate/store and AES-256 encryption, `.tzst` (`.tar.zst`) with Zstandard, `.tzap` with Zstandard plus encryption/recovery metadata, `.7z` with LZMA2 and AES-256 encryption |
| ZIP family | `.zip`, `.zipx`, `.jar`, `.war`, `.ipa`, `.apk`, `.appx`, `.xpi`, ZIP-content `.exe` files |
| 7z | `.7z`, including encrypted 7z archives |
| RAR | `.rar`, `.cbr`, split `.partN.rar` volumes, RAR4/RAR5, passworded RAR data, encrypted RAR5 headers, Unicode paths, symlinks, hardlinks, and file-reference entries |
| TAR and variants | `.tar`, `.ustar`, `.pax`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.lzma`, `.tzst`, `.tar.zst`, `.tar.lz`, `.tar.lzo`, `.tar.Z`, `.tar.lz4`, `.tar.lrz` |
| TZAP | `.tzap`, passphrase-protected create/list/test/extract |
| Raw compressed files | `.zst`, `.gz`, `.bz2`, `.xz`, `.lzma`, `.lz`, `.br`, `.lz4`, `.lzo`, `.Z`, `.lrz` |
| Packages and containers | `.deb`, `.rpm`, `.ar`, `.cpio`, `.cpgz`, `.spk`, `.iso`, `.xar`, `.cab` |
| Passwords | ZIP, 7z, TZAP, and RAR list/test/extract through prompt or `--password-stdin` |

Creation is intentionally focused on formats people should use today. Extraction
is intentionally broad, so `zm` can be the one command you try first when
someone sends you an archive.

## Shell Completions

Packages install bash, zsh, and fish completions where the package manager
supports it. The CLI can also print a PowerShell argument completer for manual
Windows setup. For manual setup or troubleshooting, print the script for your
shell:

```sh
source <(zm completions bash)
zm completions zsh > ~/.zfunc/_zm
zm completions fish > ~/.config/fish/completions/zm.fish
```

```powershell
zm completions powershell > zm.ps1
. .\zm.ps1
```

## Output Behavior

Human-readable output uses `--color auto` by default: color is shown only on
terminal streams, and `NO_COLOR` disables automatic color. Use
`--color always` to force color or `--color never` to disable it. JSON output
and raw archive payloads from `--to-stdout` are never colorized.

## Build From Source

```sh
git clone https://github.com/frankmanzhu/zmanager.git
cd zmanager
cargo build -p zmanager-cli --release
./target/release/zm --help
```

## Test

```sh
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

Some compatibility tests use optional external archive tools when installed, but
the core suite is deterministic and should pass without network access.

## Project Links

- [Releases](https://github.com/frankmanzhu/zmanager/releases)
- [Issues](https://github.com/frankmanzhu/zmanager/issues)
- [CI](https://github.com/frankmanzhu/zmanager/actions/workflows/ci.yml)
- [Release workflow](https://github.com/frankmanzhu/zmanager/actions/workflows/release.yml)
- [CLI guide](docs/CLI.md)
- [Install guide](docs/INSTALL.md)
- [Release maintainer notes](RELEASE.md)

## Repository Layout

- `crates/zmanager-cli`: user-facing `zm` command.
- `crates/zmanager-core`: archive planning, creation, extraction, listing,
  testing, safety checks, and backend routing.
- `crates/zmanager-ffi`: C ABI consumed by the macOS app.
- `crates/zmanager-unrar`: bundled extraction-only UnRAR bridge for passworded
  RAR extraction.
- `fixtures/`: committed compatibility fixtures used by integration tests.
- `fuzz/`: `cargo-fuzz` targets for hostile archive and parser surfaces.
- `packaging/`: Homebrew and WinGet metadata templates.
- `scripts/`: release packaging helpers.
- `.github/workflows/`: CI and release automation.

## License

This workspace is released under the Apache License 2.0. The bundled UnRAR
source has its own extraction-only license; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
`vendor/unrar/license.txt`.
