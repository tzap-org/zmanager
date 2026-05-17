# Z-Manager libarchive Vendor Note

This directory vendors the upstream libarchive 3.8.7 release source.

- Upstream: https://github.com/libarchive/libarchive
- Release: v3.8.7
- Source archive: `libarchive-3.8.7.tar.xz`
- SHA-256: `d3a8ba457ae25c27c84fd2830a2efdcc5b1d40bf585d4eb0d35f47e99e5d4774`

Z-Manager builds this source through `crates/zmanager-libarchive-sys`.
Do not edit files under `libarchive-3.8.7/` directly. If a local change becomes
unavoidable, keep it as a documented patch outside the upstream source tree and
explain the affected platform and replacement path here.
