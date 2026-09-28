# Linux Build Notes

Linux release binaries target `*-unknown-linux-musl` and are fully static:
one binary per architecture that runs without a glibc version floor.

## Build mechanism

Both musl targets are packaged inside an Alpine container using
`rust:1-alpine3.22`:

- `scripts/package-release-alpine.sh <target>` runs the container wrapper.
- `scripts/package-release.sh` performs the common packaging steps.

The build mounts the sibling `tzap` and `forensic-vfs-engine` repositories
because the workspace uses those local path dependencies during release
builds. NTFS and UDF are resolved from their published crates.

## Dependencies

The Alpine image supplies the static codec and crypto libraries used by the
Rust archive and authentication crates:

| Library family | Alpine packages | Used for |
| --- | --- | --- |
| zlib | `zlib-dev zlib-static` | ZIP, gzip, and XAR payloads |
| bzip2 | `bzip2-dev bzip2-static` | bzip2 streams and TAR.BZ2 |
| lzma/xz | `xz-dev xz-static` | XZ, LZMA, and 7z payloads |
| zstd | `zstd-dev zstd-static` | Zstandard streams and TAR.ZST |
| lz4 | `lz4-dev lz4-static` | LZ4 streams |
| nettle | `nettle-dev nettle-static` | Native cryptographic operations |

The exact package list is maintained in `scripts/package-release-alpine.sh`.
The production archive registry is native-only; external tools such as
`bsdtar` are used only by compatibility tests and are not linked into the
released binary.

## Verification

Run the artifact profile check before packaging:

```sh
bash scripts/verify-artifact-profiles.sh
cargo test --workspace
```

The profile check verifies both default and reduced-feature dependency graphs
and rejects the removed compatibility runtime. Release CI additionally runs
the external compatibility matrix where the host tools are available.
