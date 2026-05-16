# Hostile Archive Fixtures

The hostile corpus is generated inside `zmanager-core` integration tests instead of committed as binary archives. This keeps the repository small and makes each fixture's intent visible in code.

Covered fixture classes:

- traversal paths
- absolute paths
- symlink escapes
- hardlink escapes
- normalized duplicate paths
- case collisions
- zip-bomb-like high compression ratio entries
- truncated archives
- corrupt headers
- nested archives

Run the deterministic hostile suite with:

```sh
cd cli
cargo test -p zmanager-core --test hostile_archives
```

Run fuzz targets separately from normal tests with:

```sh
FUZZ_SECONDS=60 bash scripts/fuzz.sh
```

The fuzz script requires `cargo-fuzz` and currently exposes `path_normalization`, `zip_metadata`, and `libarchive_input`.
