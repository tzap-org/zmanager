# Sibling build inputs

ZManager builds from sibling repositories during local development so changes
to TZAP, LocalSend, the forensic engine, and the reviewed forensic forks can
be integrated before publication. Release packaging must instead use an
immutable, committed snapshot of every sibling checkout.

## Modes

- **Local:** use the current `HEAD` of each existing sibling checkout. Bootstrap
  clones a missing sibling at the configured integration branch. It
  must preserve existing work and report each checkout's branch, commit, and
  dirty state.
- **CI:** resolve the configured sibling integration branches to full commit
  SHAs once per workflow run. Every platform job consumes that same SHA set.
  Preserve the resolved input report with the artifacts.
- **Release:** check out every sibling at the SHA recorded in
  `release-build-inputs.lock`, detached. Release packaging must fail if the
  lock is missing, malformed, or disagrees with the checked-out commit.

The release lock is the authoritative release pin and sibling checkout
inventory. It includes the `tzap` release commit, LocalSend, the forensic engine,
and the remaining Backhand, Btrfs, and ZFS forks. AFF4, DAR, and forensic ZIP
resolve from crates.io and no longer need sibling checkouts. Do not keep a
second pin for the same checkout in a workflow, script, or revision file.

## Release order and gate

The controlled release order is:

1. Release TZAP and confirm its tag and published crate version.
2. Refresh all ZManager sibling repositories from their configured remotes.
   Run the check-in gate, generate and commit `release-build-inputs.lock`,
   then release ZManager against the released TZAP version.
3. The desktop repository pins the released ZManager commit and then releases
   the desktop product.

Before regenerating the lock, the gate fetches every remote and rejects dirty
working trees, staged or untracked files, stashes, local commits not pushed,
branches behind upstream, missing upstreams, and fetch errors. It prints the
repository and branch details needed to resolve each issue. It never commits
or pushes automatically. The lock-generation step records the full current
commit SHA for each configured sibling. Review and commit the generated lock
before tagging the product.

The release workflow does not move sibling branches or regenerate the lock.
It checks out the committed SHAs detached and emits a provenance report with
the product commit, sibling URLs, configured integration branches, checked-out
branches, SHAs, dirty state, build mode, and release tag. Package checksum
files record artifact hashes separately. CI may resolve branch heads for
ordinary validation builds, but freezes and reports one input set for all jobs
in each run.

## Maintainer commands

```sh
# Local sibling setup and input report
bash scripts/ensure-sibling-repos.sh

# Report repository state; --fetch refreshes remote tracking information
bash scripts/check-sibling-repos.sh --fetch

# Prepare: strict check, then regenerate the lock before a release
bash scripts/release-gate.sh prepare
git diff -- release-build-inputs.lock

# After committing and pushing the lock, verify before tagging
bash scripts/release-gate.sh verify

# Release CI validates pinned checkouts without branch updates
bash scripts/release-gate.sh verify-build
```

Windows users can run the equivalent PowerShell entry points. Local work may
be dirty; the strict release gate is intentionally clean-and-pushed.
