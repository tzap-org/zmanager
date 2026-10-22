# Forensic codec security forks

ZManager temporarily uses sibling forks because the published forensic readers
require vulnerable codec versions. The full upstream workspaces live outside
this repository, so their fixes can be reviewed and submitted upstream without
copying dependency source into ZManager.

| Sibling checkout | Fork | Package version | Change |
| --- | --- | --- | --- |
| `../dar-core` | [frankmanzhu/dar-core](https://github.com/frankmanzhu/dar-core/tree/macos/fix-codec-advisories) | `dar-core 0.7.1` | `ruzstd 0.9.1`, current decoder import, Rust floor 1.87 |
| `../btrfs-core` | [frankmanzhu/btrfs-core](https://github.com/frankmanzhu/btrfs-core/tree/macos/fix-codec-advisories) | `btrfs-core 0.1.4` | `ruzstd 0.9.1` |
| `../zfs-forensic-core` | [frankmanzhu/zfs-forensic-core](https://github.com/frankmanzhu/zfs-forensic-core/tree/macos/fix-codec-advisories) | `zfs-forensic-core 0.1.2` | `ruzstd 0.9.1` |
| `../zip-forensic-core-0.1` | [frankmanzhu/zip-forensic-core](https://github.com/frankmanzhu/zip-forensic-core/tree/macos/fix-ruzstd-01) | `zip-forensic-core 0.1.0` | Backport `ruzstd 0.9.1` |
| `../zip-forensic-core` | [frankmanzhu/zip-forensic-core](https://github.com/frankmanzhu/zip-forensic-core/tree/macos/fix-codec-advisories) | `zip-forensic-core 0.2.2` | `ruzstd 0.9.1` |
| `../aff4` | [frankmanzhu/aff4](https://github.com/frankmanzhu/aff4/tree/macos/fix-codec-advisories) | `aff4 0.2.6` | `zip 9.0.5` for test helpers/oracles, Rust floor 1.88 |

`ruzstd 0.9.1` fixes
[RUSTSEC-2026-0344](https://rustsec.org/advisories/RUSTSEC-2026-0344.html).
ZIP 9 fixes RUSTSEC-2026-0367 through RUSTSEC-2026-0369. Both Rust floors remain
below ZManager's existing 1.93 floor.

## Reproduce the tested checkouts

From the ZManager repository:

These augment the existing `tzap`, `localsend-rs`, and `forensic-vfs-engine`
sibling checkouts.

```sh
bash scripts/checkout-forensic-forks.sh
cargo check --workspace --all-targets --locked
cargo test --workspace
cargo audit --deny yanked --file Cargo.lock
cargo audit --deny yanked --file fuzz/Cargo.lock
```

The exact commit pins are in `forensic-forks.lock`. CI and release packaging use
the same checkouts. The clone helper preserves existing development work and
fails if an existing checkout is on a different commit. Alpine packaging mounts
these siblings beside `/workspace` so Cargo resolves the same paths.

The fixes start from the releases already resolved in ZManager's lockfile. The
ZIP reader needs two checkouts because AFF4 requires its 0.1 API while
archive-core requires 0.2. Each fork retains the upstream repository structure;
the actual library is under `core/`.

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
