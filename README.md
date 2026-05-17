# Z-Manager CLI

[![CI](https://github.com/frankmanzhu/zmanager/actions/workflows/ci.yml/badge.svg)](https://github.com/frankmanzhu/zmanager/actions/workflows/ci.yml)
[![Release](https://github.com/frankmanzhu/zmanager/actions/workflows/release.yml/badge.svg)](https://github.com/frankmanzhu/zmanager/actions/workflows/release.yml)
[![Release version](https://img.shields.io/github/v/release/frankmanzhu/zmanager?include_prereleases&label=release)](https://github.com/frankmanzhu/zmanager/releases)
[![Downloads](https://img.shields.io/github/downloads/frankmanzhu/zmanager/total)](https://github.com/frankmanzhu/zmanager/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`zm` is a fast, safe archive utility for macOS and Linux. It gives terminal
users familiar `zip`/`tar`-style commands, modern compression defaults, and
guarded extraction for archives from the internet.

The CLI is the open-source part of Z-Manager. It shares the Rust archive engine
with the macOS app, but it is useful on its own: create clean project archives,
extract a broad set of formats safely, inspect archive contents, and script
archive workflows without opening a GUI.

Current source version: `v0.1.0`

## Downloads

### Current Version

Release builds are published from GitHub tags. Until the first public tag is
cut, install from source or use the Homebrew formula with `--HEAD`.

- [Latest release](https://github.com/frankmanzhu/zmanager/releases/latest)
- [All releases](https://github.com/frankmanzhu/zmanager/releases)

The release workflow publishes these archives when a `v*` tag is created:

| Platform | Asset |
| --- | --- |
| macOS Apple Silicon | `zm-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `zm-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 | `zm-x86_64-unknown-linux-gnu.tar.gz` |

Each archive contains the `zm` executable, `README.md`, `LICENSE`, and
`THIRD_PARTY_NOTICES.md`. Every release also includes a `SHA256SUMS` file for
download verification.

### Homebrew

Once the tap repository is published, install with:

```sh
brew install frankmanzhu/zmanager/zm
```

Equivalent explicit form:

```sh
brew tap frankmanzhu/zmanager
brew install zm
```

The Homebrew formula lives at [Formula/zm.rb](Formula/zm.rb). The tap repository
should be named `homebrew-zmanager` on GitHub so Homebrew can resolve
`frankmanzhu/zmanager` to `frankmanzhu/homebrew-zmanager`.

### Install Script

Install the latest release binary into `$HOME/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/frankmanzhu/zmanager/main/install.sh | sh
```

Install a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/frankmanzhu/zmanager/main/install.sh \
  | ZMANAGER_VERSION=v0.1.0 sh
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

zm create project.tar.zst project/
zm extract project.tar.zst -C out/

zm list project.zip
zm test project.zip
```

The classic flags are there for users who already know archive tools. The
subcommands are there for readable scripts.

## What It Does

- Creates `.zip`, `.tar.zst`, and `.7z` archives.
- Extracts ZIP-family archives, 7z, TAR.ZST, compressed TAR, raw streams, RAR,
  Debian packages, ISO, XAR, CAB, AR, CPIO, and other libarchive-backed formats.
- Supports passworded ZIP, 7z, and RAR extraction through stdin or prompts.
- Protects extraction by default against path traversal, unsafe links,
  duplicate normalized paths, case collisions, and accidental overwrite traps.
- Provides both classic archive flags and readable subcommands.

## Format Support

| Task | Supported formats |
| --- | --- |
| Create | ZIP, TAR.ZST, 7z |
| List/test | ZIP family, 7z, TAR.ZST, RAR, raw streams, libarchive-backed archives |
| Extract | ZIP family, 7z, TAR.ZST, compressed TAR, raw streams, RAR, DEB, RPM, ISO, XAR, CAB, AR, CPIO, and related libarchive-backed formats |
| Passwords | ZIP, 7z, RAR extraction/list/test through prompt or `--password-stdin` |

Z-Manager does not create RAR archives. RAR support is extraction/listing only.

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

- Be familiar to users who already know `zip`, `tar`, `unzip`, and `7z`.
- Make safe extraction the default, not an optional expert mode.
- Keep creation focused on formats that matter: ZIP for sharing, TAR.ZST for
  fast modern archives, and 7z for high-compression or encrypted archives.

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
- `Formula/`: Homebrew formula for the CLI.
- `scripts/`: release packaging helpers.
- `.github/workflows/`: CI and release automation.

## Release

Release notes and maintainer steps are in [RELEASE.md](RELEASE.md).

## License

This workspace is released under the MIT license. The bundled UnRAR source has
its own extraction-only license; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
and `vendor/unrar/license.txt`.
