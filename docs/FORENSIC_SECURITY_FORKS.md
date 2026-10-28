# Forensic codec security forks

ZManager temporarily uses sibling forks because the published forensic readers
require vulnerable codec versions. The full upstream workspaces live outside
this repository, so their fixes can be reviewed and submitted upstream without
copying dependency source into ZManager.

| Sibling checkout | Fork | Package version | Change |
| --- | --- | --- | --- |
| `../backhand` | [frankmanzhu/backhand](https://github.com/frankmanzhu/backhand) | `backhand 0.25.5` | `zstd 0.14.3`, `zstd-safe 8.2.0` |
| `../dar-core` | [frankmanzhu/dar-core](https://github.com/frankmanzhu/dar-core/tree/macos/integration-codec-security) | `dar-core 0.7.1` | `ruzstd 0.9.1`, current decoder import, Rust floor 1.87 |
| `../btrfs-core` | [frankmanzhu/btrfs-core](https://github.com/frankmanzhu/btrfs-core/tree/macos/integration-codec-security) | `btrfs-core 0.1.4` | `ruzstd 0.9.1` |
| `../zfs-forensic-core` | [frankmanzhu/zfs-forensic-core](https://github.com/frankmanzhu/zfs-forensic-core/tree/macos/integration-codec-security) | `zfs-forensic-core 0.1.2` | `ruzstd 0.9.1` |
| `../zip-forensic-core` | [frankmanzhu/zip-forensic-core](https://github.com/frankmanzhu/zip-forensic-core/tree/macos/integration-codec-security) | `zip-forensic-core 0.2.2` | `ruzstd 0.9.1`, `zip 9.0.5` test oracle |
| `../aff4` | [frankmanzhu/aff4](https://github.com/frankmanzhu/aff4/tree/macos/integration-codec-security) | `aff4 0.2.6` | `zip-forensic-core 0.2.2`, `zip 9.0.5` for test helpers/oracles, Rust floor 1.88 |

`ruzstd 0.9.1` fixes
[RUSTSEC-2026-0344](https://rustsec.org/advisories/RUSTSEC-2026-0344.html).
ZIP 9 fixes RUSTSEC-2026-0367 through RUSTSEC-2026-0369. Both Rust floors remain
below ZManager's existing 1.93 floor.

Backhand 0.25.5 is built from the fork's upstream-compatible release line. Its
zstd update removes the `zstd 0.13` / `zstd-safe 7` advisories while preserving
the existing SquashFS API used by ZManager.

## Reproduce the tested checkouts

From the ZManager repository:

These augment the existing `tzap`, `localsend-rs`, and `forensic-vfs-engine`
sibling checkouts.

```sh
bash scripts/checkout-forensic-forks.sh
cargo check --workspace --all-targets --locked
cargo test --workspace
cargo update --package tzap-core
cargo update --package crypto-bigint
cargo update --manifest-path fuzz/Cargo.toml --package tzap-core
cargo update --manifest-path fuzz/Cargo.toml --package crypto-bigint
cargo audit --deny yanked --file Cargo.lock
cargo audit --deny yanked --file fuzz/Cargo.lock
```

The exact commit pins are in `forensic-forks.lock`. Build/test and release
workflows use the same fork checkouts. Security Audit CI also clones `../tzap`
and resolves a job-local lockfile against its sibling patch before auditing.
The committed lockfiles continue to track published Tzap for release builds.
The clone helper preserves existing development work and fails if an existing
checkout is on a different commit. Alpine packaging mounts these siblings
beside `/workspace` so Cargo resolves the same paths.

The `cargo update` commands switch only the local lockfiles to the patched
`../tzap` sibling and refresh its yanked crypto transitive dependency for
auditing. Do not commit those generated lockfile changes; release builds use
the published Tzap release recorded in the lock.

The fixes start from the releases already resolved in ZManager's lockfile.
AFF4 now requests the same ZIP 0.2 reader as archive-core, so both share
one patched `zip-forensic-core` checkout. The ZIP 0.1 backport is no longer
needed. Each fork retains the upstream repository structure; the actual
library is under `core/`.

## Workspace boundaries and eventual removal

The main workspace and `fuzz/Cargo.toml` each declare the overrides because Cargo
only reads `[patch]` from the active workspace root. Applications consuming
ZManager must add equivalent overrides at their own workspace root and clone
these siblings until the fixed dependencies are published.

The crates.io publishing workflow audits after removing workspace patches. It
remains blocked while published dependency constraints restore vulnerable
codecs. CLI release packages build with the sibling forks.

When fixed upstream releases are available, remove the corresponding overrides,
fork pins, and checkouts from the clone list. Update both lockfiles and rerun
the audits, workspace checks, and archive safety tests.

## Validation

See [the five-fork validation](FORENSIC_SECURITY_VALIDATION.md) for upstream
tests, minimum-Rust checks, coverage, consumer checks and the ZIP-before-AFF4
release ordering.

## Integration and upstream branches

All five forks keep the tested release fixes on
`macos/integration-codec-security`. The sibling checkouts remain at the exact
revisions in `forensic-forks.lock`; they do not follow newer upstream APIs.

The separate `macos/upstream-codec-security` branches apply one focused commit
to each current upstream `main`. See [the five PRs](FORENSIC_UPSTREAM_PRS.md)
for review links, validation and existing upstream CI blockers. After fixed
releases are published, check their API compatibility before adopting them
and removing the corresponding overrides.
