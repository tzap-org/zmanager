# Forensic codec security forks

ZManager now resolves the compatible fixed reader releases from crates.io:

| Crate | Published version | Codec dependency |
| --- | --- | --- |
| `aff4` | `0.3.0` | Uses forensic ZIP `0.2.3` and ZIP 9 |
| `dar-core` | `0.7.2` | `ruzstd 0.9.1` |
| `zip-forensic-core` | `0.2.3` | `ruzstd 0.9.1`; ZIP 9 test oracle |

Three local sibling overrides remain:

| Sibling checkout | Fork package | Why it remains |
| --- | --- | --- |
| `../backhand` | `backhand 0.25.5` | Its fork uses `zstd 0.14.3` / `zstd-safe 8.2.0`; upstream 0.25.5 still requires affected `zstd 0.13.2` / `zstd-safe 7.2.1`. |
| `../btrfs-core` | `btrfs-core 0.1.4` | Preserves a `forensic-vfs 0.7` adapter for the retained engine branch. The fixed upstream 0.2.0 adapter targets VFS 0.10. |
| `../zfs-forensic-core` | `zfs-forensic-core 0.1.2` | Preserves a `forensic-vfs 0.7` adapter. The fixed upstream 0.2.1 adapter targets VFS 0.10. |

`ruzstd 0.9.1` fixes RUSTSEC-2026-0344. ZIP 9 fixes RUSTSEC-2026-0367 through
RUSTSEC-2026-0369. The engine branch in `release-build-inputs.lock` still uses
`forensic-vfs 0.7`; the published Btrfs and ZFS adapters use the incompatible
0.10 contract. Their reader APIs can be called directly, but ZManager would
then own format dispatch and adapt their file traversal and streaming into its
extraction pipeline. That is a separate adapter change from a dependency bump.

The Backhand override remains necessary to avoid its upstream codec versions.
Removing it would reintroduce known advisory ranges and make the RustSec audit
fail; the dependency is not an advisory-clean upstream exception.

## Reproduce the dependency checks

The release lock pins `forensic-vfs-engine` and the three remaining forks.
Cargo.lock and fuzz/Cargo.lock pin the published compatible reader releases.

```sh
bash scripts/checkout-forensic-forks.sh
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo audit --deny unsound --deny yanked --file Cargo.lock
cargo audit --deny unsound --deny yanked --file fuzz/Cargo.lock
```

The audit commands can still fail on the upstream Backhand advisory ranges.
Do not add broad advisory ignores to make the audit appear clean.
