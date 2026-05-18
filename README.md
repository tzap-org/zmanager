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

Current source version: `v1.0.1`

## Product Direction

Z-Manager treats extraction and creation differently:

- **Extract broadly.** Users should be able to open old, obscure, downloaded,
  package, mobile, and developer archives without knowing which backend or
  tool normally handles them.
- **Create deliberately.** New archives should use formats that make sense
  today: ZIP for universal sharing, TZST (`.tar.zst`) for fast modern
  compression, and 7z for high-compression encrypted archives.
- **Avoid legacy creation paths.** Old compression methods still matter for
  reading existing files, but new archives should not depend on outdated
  choices when better performance and safer password encryption are available.
- **Use strong password protection.** Encrypted ZIP and 7z creation use AES-256
  paths, and passwords are read through prompts or stdin rather than command
  arguments.

## Downloads

### Current Version

Release builds are published from GitHub tags. Until the first public tag is
cut, install from source.

- [Latest release](https://github.com/frankmanzhu/zmanager/releases/latest)
- [All releases](https://github.com/frankmanzhu/zmanager/releases)

The release workflow publishes these assets when a `v*` tag is created:

| Platform | Asset |
| --- | --- |
| macOS Apple Silicon | `zm-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `zm-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 | `zm-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 | `zm-aarch64-unknown-linux-gnu.tar.gz` |
| Ubuntu/Debian x86_64 | `zmanager-cli_1.0.1-1_amd64.deb` |
| Ubuntu/Debian ARM64 | `zmanager-cli_1.0.1-1_arm64.deb` |
| Windows x64 | `zm-x86_64-pc-windows-msvc.zip` |
| Windows ARM64 | `zm-aarch64-pc-windows-msvc.zip` |

Each archive contains the `zm` executable, `README.md`, `LICENSE`, `NOTICE`,
`THIRD_PARTY_NOTICES.md`, and `third-party-licenses/`. Windows archives are
built with vcpkg static-library triplets so third-party compression and crypto
libraries are linked into `zm.exe`. Every release also includes a `SHA256SUMS`
file for download verification.

Full installation details, checksum verification examples, and package-channel
maintenance notes are in [docs/INSTALL.md](docs/INSTALL.md).

### Homebrew

Once the tap repository is published, install with:

```sh
brew install frankmanzhu/zmanager/zmanager
```

Equivalent explicit form after tapping:

```sh
brew tap frankmanzhu/zmanager
brew install zmanager
```

The release workflow renders the Homebrew formula from
[packaging/homebrew/zmanager.rb.template](packaging/homebrew/zmanager.rb.template)
using release checksums. Copy the generated
`package-metadata/homebrew/Formula/zmanager.rb` into the separate
`frankmanzhu/homebrew-zmanager` tap.

### WinGet

The release workflow also renders WinGet manifests from
[packaging/winget](packaging/winget). After validation and submission, install
with:

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

zm list project.zip
zm test project.zip
```

The classic flags are there for users who already know archive tools. The
subcommands are there for readable scripts.

## Output Behavior

Human-readable output uses `--color auto` by default: color is shown only on
terminal streams, and `NO_COLOR` disables automatic color. Use
`--color always` to force color or `--color never` to disable it. JSON output
and raw archive payloads from `--to-stdout` are never colorized.

## What It Does

- Extracts a broad range of archive, package, disk-image, and raw compression
  formats with safety checks enabled by default.
- Creates modern `.zip`, `.tzst` (`.tar.zst`), and `.7z` archives with focused defaults.
- Opens common desktop, developer, package, and mobile archive formats by name:
  ZIP, ZIPX, JAR, WAR, IPA, APK, APPX, XPI, 7z, TAR, compressed TAR, RAR,
  CPIO, CPGZ, ISO, XAR, CAB, AR, DEB, RPM, SPK-style tar packages, and raw
  compressed files.
- Supports passworded ZIP, 7z, and RAR workflows through stdin or prompts; new
  encrypted ZIP and 7z archives use AES-256 encryption paths.
- Protects extraction by default against path traversal, unsafe links,
  duplicate normalized paths, case collisions, and accidental overwrite traps.
- Provides both classic archive flags and readable subcommands.

## Format Support

| Workflow | Formats |
| --- | --- |
| Create modern archives | `.zip` with Deflate/store and AES-256 encryption, `.tzst` (`.tar.zst`) with Zstandard, `.7z` with LZMA2 and AES-256 encryption |
| ZIP family | `.zip`, `.zipx`, `.jar`, `.war`, `.ipa`, `.apk`, `.appx`, `.xpi`, ZIP-content `.exe` files |
| 7z | `.7z`, including encrypted 7z archives |
| RAR | `.rar`, `.cbr`, split `.partN.rar` volumes, RAR4/RAR5, passworded RAR data, encrypted RAR5 headers, Unicode paths, symlinks, hardlinks, and file-reference entries |
| TAR and variants | `.tar`, `.ustar`, `.pax`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.lzma`, `.tzst`, `.tar.zst`, `.tar.lz`, `.tar.lzo`, `.tar.Z`, `.tar.lz4`, `.tar.lrz` |
| Raw compressed files | `.zst`, `.gz`, `.bz2`, `.xz`, `.lzma`, `.lz`, `.br`, `.lz4`, `.lzo`, `.Z`, `.lrz` |
| Packages and containers | `.deb`, `.rpm`, `.ar`, `.cpio`, `.cpgz`, `.spk`, `.iso`, `.xar`, `.cab` |
| Passwords | ZIP, 7z, and RAR list/test/extract through prompt or `--password-stdin` |

Creation is intentionally focused on formats people should use today. Extraction
is intentionally broad, so `zm` can be the one command you try first when
someone sends you an archive.

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

## Goals

Z-Manager is designed around three priorities:

- Extract as many real-world archive formats as possible, safely and
  predictably.
- Keep new archive creation focused on modern compression and AES-256 password
  protection instead of preserving every legacy creation method.
- Stay familiar to users who already know `zip`, `tar`, `unzip`, and `7z`.

## Build From Source

```sh
git clone https://github.com/frankmanzhu/zmanager.git
cd zmanager
cargo build -p zmanager-cli --release
./target/release/zm --help
```

Windows build support is being validated. The current local ARM64 and future CI
settings are tracked in [docs/WINDOWS_BUILD.md](docs/WINDOWS_BUILD.md).

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

## Release

Release notes and maintainer steps are in [RELEASE.md](RELEASE.md).

## License

This workspace is released under the Apache License 2.0. The bundled UnRAR
source has its own extraction-only license; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
`vendor/unrar/license.txt`.
