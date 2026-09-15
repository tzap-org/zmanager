# ZManager CLI

[![CI](https://github.com/tzap-org/zmanager/actions/workflows/ci.yml/badge.svg)](https://github.com/tzap-org/zmanager/actions/workflows/ci.yml)
[![Release](https://github.com/tzap-org/zmanager/actions/workflows/release.yml/badge.svg)](https://github.com/tzap-org/zmanager/actions/workflows/release.yml)
[![Release version](https://img.shields.io/github/v/release/tzap-org/zmanager?include_prereleases&label=release)](https://github.com/tzap-org/zmanager/releases)
[![Downloads](https://img.shields.io/github/downloads/tzap-org/zmanager/total)](https://github.com/tzap-org/zmanager/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20lines-brightgreen.svg)](https://github.com/tzap-org/zmanager/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Security audit](https://img.shields.io/badge/security-cargo--deny%20%2B%20vet-brightgreen.svg)](deny.toml)

`zm` is a universal file archiver for macOS, Linux, and Windows, built for
high-performance compression, safe extraction, and seamless handling of
virtually any archive format.

The CLI is the open-source part of ZManager. It shares the Rust archive engine
with the desktop GUI app, but it is useful on its own: create clean project
archives, extract a broad set of formats safely, inspect archive contents, and
script archive workflows without opening a GUI.

## Install

Release builds are published on the
[latest release page](https://github.com/tzap-org/zmanager/releases/latest).
Each release ships two flavors:

- **full** — all commands, including the online identity features behind
  `zm auth` (default install)
- **offline** — the same archive commands with no network features

`zm --version` reports which flavor is installed (`zm 2.1.3 (full)` or
`zm 2.1.3 (offline)`). For full installation details and checksum examples,
see [docs/INSTALL.md](docs/INSTALL.md).

### macOS

Install the full build from the Homebrew tap:

```sh
brew install tzap-org/zmanager/zmanager
```

For the offline build, install the offline formula:

```sh
brew install tzap-org/zmanager/zmanager-offline
```

### Linux

Install the latest matching release into `$HOME/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sh
```

Pass `--offline` for the offline build:

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sh -s -- --offline
```

### Windows

Install with WinGet:

```powershell
winget install FrankZhu.ZManagerCLI
```

For the offline build:

```powershell
winget install TzapOrg.ZManagerCLI.Offline
```

Future version manifests will use `TzapOrg.ZManagerCLI`; new releases use the
organization-scoped package identity.

### Preview builds (developers)

The
[Package Preview workflow](https://github.com/tzap-org/zmanager/actions/workflows/package-preview.yml)
builds packages from the latest `main` without publishing a release. Install a
preview build with the install script (requires the
[gh CLI](https://cli.github.com/)):

```sh
curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sh -s -- --preview
```

Combine with `--offline` for the offline preview build. The latest successful
preview run is used; set `ZMANAGER_RUN_ID` to install a specific run.

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
- Creates `.zip`, `.tzst` (`.tar.zst`), `.tgz` (`.tar.gz`), `.tzap`, `.7z`, and `.aar`/`.aea` (Apple Archive) archives
  with focused defaults.
- Opens common desktop, developer, package, and mobile archive formats by name:
  ZIP, ZIPX, JAR, WAR, IPA, APK, APPX, XPI, 7z, TAR, compressed TAR, RAR,
  CPIO, CPGZ, ISO, XAR, CAB, AR, DEB, RPM, SPK-style tar packages, Apple
  Archives (.aar/.aea), and raw compressed files.
- Supports passworded ZIP, 7z, TZAP, and RAR workflows through stdin or
  prompts; new encrypted ZIP, TZAP, and 7z archives use AES-256 encryption
  paths.
- Protects extraction by default against path traversal, unsafe links,
  duplicate normalized paths, case collisions, and accidental overwrite traps.
- Provides both classic archive flags and readable subcommands.

## Why ZManager

ZManager treats extraction and creation differently:

- **Extract broadly.** Open old, obscure, downloaded, package, mobile, and
  developer archives without knowing which backend normally handles them.
- **Create deliberately.** New archives should use practical, well-supported formats:
  ZIP for universal sharing, TZST (`.tar.zst`) for fast compression, TGZ (`.tar.gz`) for compatibility,
  TZAP for encrypted recoverable archives, 7z for high-compression encrypted archives, and Apple Archive (`.aar`/`.aea`) for Apple platforms.
- **TZAP: a modern, open-source RAR alternative.** The `.tzap` format is engineered to be fast, secure, and resilient: state-of-the-art cryptographic signatures, multi-recipient encryption, secure passphrase protection, and self-healing error recovery.
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
| Create archives | `.zip` with Deflate/store and AES-256 encryption, `.tzst` (`.tar.zst`) with Zstandard, `.tgz` (`.tar.gz`) with gzip, `.tzap` with Zstandard plus encryption/recovery metadata, `.7z` with LZMA2 and AES-256 encryption, `.aar`/`.aea` (Apple Archive) |
| ZIP family | `.zip`, `.zipx`, `.jar`, `.war`, `.ipa`, `.apk`, `.appx`, `.xpi`, `.cbz`, `.epub`, split `.z01`… volumes, ZIP-content `.exe` files |
| 7z | `.7z`, `.cb7`, `.sevenz`, encrypted 7z archives, numbered `.7z.001` volumes |
| RAR | `.rar`, `.cbr`, split `.partN.rar` volumes, RAR4/RAR5, passworded RAR data, encrypted RAR5 headers, Unicode paths, symlinks, hardlinks, and file-reference entries |
| TAR and variants | `.tar`, `.cbt`, `.ustar`, `.pax`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tbz`, `.tar.xz`, `.txz`, `.tar.lzma`, `.tlzma`, `.tzst`, `.tar.zst`, `.tar.lz`, `.tar.lzo`, `.tar.Z`, `.taz`, `.tar.lz4`, `.tar.uu`, `.tar.b64` |
| TZAP | `.tzap` — a modern, open-source RAR alternative. Secure passphrase or multi-recipient encryption, cryptographic signatures, and self-healing error recovery; passphrase-protected create/list/test/extract |
| Raw compressed files | `.zst`, `.gz`, `.bz2`, `.xz`, `.lzma`, `.lz`, `.br`, `.lz4`, `.lzo`, `.Z`, `.uu`, `.b64` |
| Packages and containers | `.deb`, `.rpm`, `.a`, `.ar`, `.lib`, `.cpio`, `.cpio.gz`, `.cpio.bz2`, `.cpio.xz`, `.cpio.lzma`, `.cpio.zst`, `.cpgz`, `.spk`, `.iso`, `.xar`, `.cab`, `.msi`, `.pkg`, `.lha`, `.lzh`, `.warc`, `.mtree` |
| Disk images | `.dmg` (Apple Disk Image), `.vhd` (Virtual PC/Hyper-V), `.vhdx` (Hyper-V v2), `.vmdk` (VMware), `.vdi` (Oracle VirtualBox), `.qcow2`/`.qcow` (QEMU), `.udf` (optical) — extraction resolves MBR/GPT partitions and the inner filesystem (NTFS, FAT/exFAT, ext4, UDF) |
| Raw sector dumps | `.raw`, `.dd`, `.dsk`, `.img` — a bare disk or partition image with no container header, resolved through the same volume and filesystem stack |
| Forensic evidence | `.e01`/`.ex01` (Expert Witness Format v1/v2, EnCase — multi-segment sets resolve their own `.e02…` siblings), `.aff4` (Advanced Forensic Format 4, both physical `ImageStream` and logical `FileImage` containers), `.ad1` (FTK Imager logical image), `.dar` (Disk ARchiver) |
| Optical sector dumps | `.iso`, `.udf`, `.nrg` (Nero), `.mds`/`.mdf` (Alcohol 120%), `.cdi` (DiscJuggler), `.isz` (UltraISO Compressed ISO), `.ccd` with its `.img` companion (CloneCD), `.cue` with its `.bin` companion (CUE/BIN) — raw 2352/2448 and Mode 2 sectors are mapped to logical 2048-byte sectors |
| Linux filesystem images | `.squashfs`, `.sqfs`, and `.appimage` (type 2) — gzip, XZ, LZO, LZ4, and zstd blocks; Unix modes and mtimes are restored |
| Windows imaging | `.wim` and `.swm` split sets — stored, XPRESS-Huffman, and WIM-LZX resources: every image in a multi-image WIM, sibling-part resolution, and reparse-point symlinks. LZMS/`.esd` resources are recognized and rejected with the reason and a `wimlib-imagex export` conversion command |
| Apple Archive | `.aar`, `.aea` encrypted Apple Archives (macOS/iOS) |
| Passwords | ZIP, 7z, TZAP, Apple Archive, and RAR list/test/extract through prompt or `--password-stdin` |

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

GUI and other job-event consumers should follow the phase-aware
[job progress contract](docs/JOB_PROGRESS.md), especially for multi-pass TZAP
creation.

```sh
git clone https://github.com/tzap-org/zmanager.git
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

The core suite is deterministic and should pass without network access. Unix CI
also runs the committed-fixture compatibility test with `unzip`, 7-Zip, and a
tar reader; it lists and extracts the small checked-in ZIP, 7z, TAR, every
supported compressed-TAR variant, and CPIO fixtures, then compares the
resulting tree with `zm`.

## Project Links

- [Releases](https://github.com/tzap-org/zmanager/releases)
- [Issues](https://github.com/tzap-org/zmanager/issues)
- [CI](https://github.com/tzap-org/zmanager/actions/workflows/ci.yml)
- [Release workflow](https://github.com/tzap-org/zmanager/actions/workflows/release.yml)
- [CLI guide](docs/CLI.md)
- [Install guide](docs/INSTALL.md)
- [Release maintainer notes](RELEASE.md)

## Repository Layout

- `crates/zmanager-cli`: user-facing `zm` command.
- `crates/zmanager-core`: archive planning, creation, extraction, listing,
  testing, safety checks, and the engine-owned adapter/session registry.
- `crates/zmanager-ffi`: UniFFI-generated archive/session/job bridge consumed by
  the desktop and mobile GUI apps.
- `crates/zmanager-unrar`: bundled extraction-only UnRAR bridge for passworded
  RAR extraction.
- `crates/zmanager-wim`: publishable WIM parser and resource decoder for stored,
  XPRESS-Huffman, and WIM-LZX resources; LZMS/ESD is intentionally unsupported.
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
