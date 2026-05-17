# Third-Party Notices

Release packages generate a complete `THIRD_PARTY_NOTICES.md` and a
`third-party-licenses/` directory through:

```sh
scripts/generate-third-party-notices.py
```

Do not maintain release notice text by hand. The generator uses:

- `cargo metadata --format-version 1 --locked` for the Rust dependency
  inventory;
- vendored license files under `vendor/libarchive` and `vendor/unrar`;
- vcpkg `copyright` files when Windows static-library triplets are active.

The generated files are staged by `scripts/package-release.sh` on Unix and
`scripts/ci-windows.ps1` on Windows before release archives are created.

## Bundled Source Requiring Explicit Notices

- libarchive 3.8.7: `vendor/libarchive/libarchive-3.8.7/COPYING`
- UnRAR: `vendor/unrar/license.txt`

The bundled UnRAR code is extraction-only. Z-Manager must not use it to create
RAR archives or recreate the RAR compression algorithm.
