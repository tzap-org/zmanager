# Forensic dependency validation — 2026-10-23

## Result

AFF4 0.2.6 works with `zip-forensic-core 0.2.2` without reader source changes.
AFF4 and archive-core now share the patched ZIP 0.2 reader. ZIP 0.1 is absent
from the core, fuzz and desktop lockfiles; its overrides, checkout pins and
clean sibling checkout have been removed.

The five fork revisions are recorded in `../forensic-forks.lock`. Desktop's
manifest, lockfile, fork pins and existing security inventory assertion have
been aligned. No upstream PR has been opened.

## Upstream checks on macOS ARM64

| Workspace | Tests reported passed, all features | Declared Rust floor verified | Coverage gate |
| --- | ---: | --- | --- |
| AFF4 | 81 | 1.88: workspace tests | Pass, 3 existing exemptions |
| forensic ZIP | 173 | 1.87: workspace build, all features | Pass, 26 existing exemptions/artifacts |
| DAR | 207 | 1.87: workspace tests | Pass, all 1,815 measured lines hit |
| Btrfs | 118 | 1.87: library build | Pass, 18 existing exemptions |
| ZFS | 255 | 1.87: workspace build, all features | Pass, 38 existing exemptions/artifacts |

All five workspaces passed formatting, `cargo clippy --workspace --all-targets
--all-features -- -D warnings`, and workspace/all-target/all-feature checks.
AFF4 also passed its default-feature suite. DAR passed its separate upstream
public-API end-to-end coverage gate. The measured coverage uses each upstream
workflow's existing scope and exemptions; no tests, assertions, coverage
markers, advisory exceptions or feature coverage were weakened.

These test totals are the Rust harness totals, including optional tests that
return early when external data is absent. AFF4's committed Evimetry images and
encrypted fixture were present; its optional `AFF4L_DREAM` corpus was absent.
Large Btrfs/ZFS oracle images and ZIP real-E01, Deflate64 and ZipCrypto
corpora were unset; the optional `7zz` oracle was unavailable. The committed
codec fixtures and synthetic tests ran. Windows/Linux execution, fuzzing,
supply-chain attestations and the complete hosted upstream CI matrix were not
performed in this validation.

## Security and clean changes

DAR, Btrfs, ZFS and forensic ZIP pass `cargo audit --deny yanked` and their local
`cargo deny --all-features check` policies. ZIP's existing test-only `zip 2`
oracle failed three security advisories, so it was upgraded to `zip 9.0.5`.
Its runtime dependency tree and Rust 1.87 build promise remain intact; test
builds use the newer development toolchain. Cargo generated the accompanying
lockfile changes.

AFF4's standalone manifest uses the registry constraint `zip-forensic-core =
"0.2.2"`, with no local path or Git override in the proposed upstream change.
Its standalone tests pass, but the published ZIP 0.2.2 still requires the old
`ruzstd` and therefore its standalone security gate remains red. Selecting the
fixed ZIP fork through a temporary validation-only Cargo configuration makes
AFF4's all-feature tests, audit and deny policy pass. That configuration was
removed after testing. Upstream must release the ZIP fix first, then AFF4
should require that fixed release and refresh its lockfile before merging.

Production reader source changes across the five proposals are limited to
DAR's required `ruzstd::decoding::StreamingDecoder` import. AFF4's existing
ZIP-writer migration adjusts fallible filenames in tests/oracles. No ZIP 0.1
compatibility shim, vendored code or reader redesign was needed.

## Consumer verification

- forensic-vfs-engine: 104 tests reported passed with all five fixed forks.
- ZManager: full workspace suite passed (2,293 passed, 2 ignored), as did all
  16 hostile-archive tests and CLI healthcheck.
- Core and fuzz lockfile security audits passed with no vulnerabilities or
  yanked dependencies. Core reported four unrelated unmaintained-crate
  warnings (`basic-toml`, `zbus_names`, `zvariant`, `zvariant_derive`).
- Final core formatting, workspace/all-target Clippy and checks passed without
  compiler warnings. The final checks temporarily disabled the normal local
  TZAP development override to preserve the existing registry TZAP lock entry;
  `.cargo/config.toml` was restored afterward. No TZAP dependency change ships.
- Desktop staging: security/bootstrap contract tests (10), frontend production
  compilation, backend workspace/all-target check and Clippy, backend tests
  (293 passed, 1 ignored), and macOS native Swift build passed.

The desktop release/bootstrap core revision still identifies the previous
published core security commit. Advance that revision to the committed core
cleanup when preparing the next desktop package: the old core workspace still
has its own ZIP 0.1 path override. Package/signing/notarization validation is
outside this local dependency experiment.

Raw local logs and LCOV outputs are in
`../dist/forensic-validation/2026-10-23/` (generated, gitignored).
