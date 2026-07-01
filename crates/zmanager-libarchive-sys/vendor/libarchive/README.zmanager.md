# ZManager libarchive Vendor Note

This directory vendors the upstream libarchive 3.8.8 release source.

- Upstream: https://github.com/libarchive/libarchive
- Release: v3.8.8
- Source archive: `libarchive-3.8.8.tar.xz`
- SHA-256: `528f9c91e11238cbb5ce6d79b20fa3bb48a5cd124008036af1913d84fc5ba420`

ZManager builds this source through `crates/zmanager-libarchive-sys`.
Do not edit files under `libarchive-3.8.8/` directly. If a local change becomes
unavoidable, keep it as a documented patch outside the upstream source tree and
explain the affected platform and replacement path here.
