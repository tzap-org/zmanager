# Z-Manager CLI

`zm` is a fast, safe archive utility for people who want familiar macOS/Linux
command-line behavior with modern compression defaults.

The CLI is the open-source part of Z-Manager. It shares the Rust archive engine
with the macOS app, but it is useful on its own: create clean project archives,
extract a broad set of formats safely, inspect archive contents, and script
archive workflows without opening a GUI.

## What It Does

- Creates `.zip`, `.tar.zst`, and `.7z` archives.
- Extracts ZIP-family archives, 7z, TAR.ZST, compressed TAR, raw streams, RAR,
  Debian packages, ISO, XAR, CAB, AR, CPIO, and other libarchive-backed formats.
- Supports passworded ZIP, 7z, and RAR extraction through stdin or prompts.
- Protects extraction by default against path traversal, unsafe links,
  duplicate normalized paths, case collisions, and accidental overwrite traps.
- Provides both classic archive flags and readable subcommands:

  ```sh
  zm -cf project.zip project/
  zm -xf project.zip -C out/
  zm create project.tar.zst project/
  zm extract project.tar.zst -C out/
  zm list project.zip
  zm test project.zip
  ```

## Goals

Z-Manager is designed around three priorities:

- Be familiar to users who already know `zip`, `tar`, `unzip`, and `7z`.
- Make safe extraction the default, not an optional expert mode.
- Keep creation focused on formats that matter: ZIP for sharing, TAR.ZST for
  fast modern archives, and 7z for high-compression or encrypted archives.

The project does not create RAR archives. RAR support is extraction/listing only.

## Install With Homebrew

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

## Install With Script

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

## Build From Source

```sh
git clone https://github.com/frankmanzhu/zmanager.git
cd zmanager
cargo build -p zmanager-cli --release
./target/release/zm --help
```

## Test

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --check
```

Some compatibility tests use optional external archive tools when installed, but
the core suite is deterministic and should pass without network access.

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
