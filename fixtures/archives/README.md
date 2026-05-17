# Fixture Archive Corpus

These fixtures are intentionally small and redistributable. They are generated from a temporary `payload/` tree containing:

- `README.txt`
- `nested/file.txt`
- `nested/empty-dir/`
- `nested/readme-link.txt` as a symlink when the local filesystem supports symlinks
- `dir with spaces/file with spaces.txt`
- `unicode/こんにちは.txt`

Regenerate them with:

```sh
bash scripts/generate_fixtures.sh
```

`manifest.tsv` records the expected SHA-256 for each fixture. The CLI fixture
tests verify those hashes before listing or extraction so accidental fixture
drift is caught early.

## Included Fixtures

| File | Format | Created by | Notes |
| --- | --- | --- | --- |
| `basic.zip` | ZIP Deflate | `zmanager-cli zip-create` | Symlink is skipped by the ZIP v1 writer. |
| `basic.7z` | 7Z LZMA2 solid | `zmanager-cli source-small` | Symlink is skipped by the 7z v1 writer. |
| `basic.tar.gz` | TAR.GZ | `bsdtar -czf` | Preserves directory structure and symlink. |
| `basic.tar.xz` | TAR.XZ | `bsdtar -cJf` | Preserves directory structure and symlink. |
| `basic.tar.zst` | TAR.ZST | `zmanager-cli source-fast` | Preserves directory structure and symlink. |
| `basic.cpio` | CPIO | `bsdtar --format=cpio` | Broad libarchive fixture. |
| `basic.xar` | XAR | macOS `xar` | Apple package-adjacent archive fixture. |
| `basic.iso` | ISO 9660/Joliet | macOS `hdiutil makehybrid` | Disk/container listing and extraction fixture; generated without symlink because ISO/Joliet is not the symlink-preserving path. |
| `basic.deb` | Debian package | `bsdtar --format=ar` plus tar members | Package/container fixture; extraction exposes package members. |

## Not Included By Default

- ZIPX: requires a compatible creator such as 7-Zip with ZIPX/Zstd/Deflate64 options.
- RAR: creation requires proprietary tooling and redistribution can be awkward.
- CAB: no stock macOS creator is available.
- WIM: requires `wimlib-imagex` or equivalent.
- RPM: requires an RPM build toolchain and package metadata setup.

Compatibility tests skip optional external validation tools when they are not installed.
