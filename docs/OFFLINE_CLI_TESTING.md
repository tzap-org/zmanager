# Offline CLI parity validation

Validated on 3 October 2026 against the workspace based on `7dec715`, with
Rust 1.95.0. Windows' existing offline workflow is now exercised on Unix too.
These results cover macOS ARM64 and Linux ARM64 in Docker; they do not constitute
a new Windows run. The committed main revision `ebb9067` subsequently passed
macOS Intel and Linux x86_64 workspace CI in
[GitHub run 37111976520](https://github.com/tzap-org/zmanager/actions/runs/37111976520).

## Results

| Check | macOS ARM64 | Linux ARM64 / Debian Bookworm Docker |
| --- | --- | --- |
| `cargo test --workspace` | 2,261 passed, 2 existing ignored | 2,144 passed, 2 existing ignored, as an unprivileged user |
| Additional Unix terminal integration tests | 2 passed | Included in the workspace run |
| `cargo clippy --workspace --all-targets` | Passed without warnings | Passed without warnings |
| `cargo check --workspace --all-targets` | Passed without warnings | Passed without warnings |
| `cargo fmt --check` | Passed | Passed |
| `bash scripts/verify-artifact-profiles.sh` | Passed | Passed |
| `cargo run -p zmanager-cli -- healthcheck` | Ready | Ready |
| Sudo consent, cancellation, unattended modes | Passed | Passed |
| Actual sudo password authentication | Passed interactively with the user in macOS Terminal | Passed as a disposable non-root user |
| Encrypted extraction through sudo | Not exercised on macOS | Passed |

The workspace runs include hostile archive, extraction, cancellation, metadata,
format interoperability, CLI help, shell completion, and FFI tests. Linux also
passed a root-run workspace suite before the final normal-user run. After
tightening the key-generation test to fail instead of silently returning on
error, the affected CLI suites passed again: 224 tests on macOS and 223 on
Linux. The final format, clippy and check gates passed without warnings.

An interactive macOS follow-up also passed actual sudo authentication,
extraction of a fixture with spaces and Unicode in its path, preservation of
`--overwrite never` on the elevated retry, and cleanup of root-owned fixture
files. System authentication stayed in Terminal; the test script did not read
or store the user's password.

## Offline workflow coverage

`crates/zmanager-cli/tests/offline_tzap_cli.rs` now runs on every platform and
contains ten tests. It provisions only local TEST certificates, with no hosted
login or network service:

- Document signing and verification, explicit custom trust, tamper rejection.
- Contact key generation, signed export/import, rejection of altered cards,
  listing and removal.
- Sharing to two recipients, extraction and listing using each recipient key,
  exact bytes through `--to-stdout`, spaces and Unicode in paths.
- Overwrite refusal, forced replacement, rejection of removed contacts while
  preserving the existing archive.
- Fresh-install certificate discovery and guidance, invalid account paths,
  certificate discovery without private keys.
- Malformed documents, envelopes and cards, missing signing identities and
  unknown recipients, without creating output on failure.

Fixtures retain the recipient private keys in test memory. The CLI imports the
fixture identity into its native secret store, so macOS need not authorize a
second executable to read keys created by the CLI. Cleanup deletes only the
fixture's random secret references.

Certificate discovery reads the public catalogue directly. It no longer
resolves private keys or requires Keychain authorization merely to list
certificates. Legacy file inventories remain supported.

The completion contract uses the executable built by Cargo and disables shell
startup files. An older Full `zm` installed on PATH no longer changes offline
completion expectations.

## Unix sudo behavior and terminal tests

Before extraction writes files, the CLI checks write/search permission on the
destination or its nearest existing ancestor. A protected destination offers
`Retry extraction with sudo? [y/N]` in an interactive terminal. Sudo handles
system authentication directly; the CLI never reads the system password.
The retry preserves the original argument vector and working directory, and
an already elevated process cannot offer another retry. Files may be owned by
root. Archive password prompts remain separate.

Redirected input/output, JSON, quiet mode, `--password-stdin`, and
`--no-password-prompt` do not offer sudo. Permission problems discovered after
extraction has started are reported by the engine; there is no automatic retry
of partially completed extraction. This preflight concerns destination access,
not privileged metadata restoration or permission failures in other commands.

Run the disposable terminal harness as a normal user:

```sh
python3 scripts/test-unix-elevation.py target/debug/zm
```

The two Rust tests in `unix_elevation_cli.rs` run this harness automatically when
Python is available and reject invocation of the internal retry by an
unprivileged process. A root-run suite cannot exercise a normal user's access
denial, so run it as a non-root user too.

For the Linux password test, create a disposable Docker user with sudo access
and set `ZMANAGER_TEST_SUDO_PASSWORD` in that container's process environment to
its fixture password. Never supply a real user's password. The same harness
then checks actual authentication, Unicode/spaced arguments, preservation of
`--overwrite never`, and a separate archive password prompt without either
password being echoed. It removes its privileged fixture outputs afterward.

Linux native identity tests require an unlocked Secret Service keyring. Use a
UTF-8 locale for external archive-tool tests:

```sh
export LANG=C.UTF-8 LC_ALL=C.UTF-8
dbus-run-session -- bash -c '
  printf "\n" | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  cargo test --workspace
'
```

The validation container used `rust:1.95-bookworm`, separate Cargo/target volumes,
and read-only mounts for the `tzap`, `localsend-rs`, and `forensic-vfs-engine`
siblings. Installing native build tools, archive test oracles, D-Bus and
GNOME Keyring matches the dependencies listed in `.github/workflows/ci.yml`.

## Continuous integration password authentication

The four Unix jobs in `.github/workflows/ci.yml` also invoke
`python3 scripts/ci-unix-elevation.py target/release/zm`: macOS ARM64 and Intel,
and Linux ARM64 and x86_64. This new authentication step still needs its first
GitHub run after publication; the local Linux Docker rehearsal passed.

GitHub-hosted runners normally have passwordless sudo. The helper creates a
separate standard account with a random fixture password and a temporary
password-required sudoers rule. It leaves the runner account's policy intact.
The harness first proves `sudo -n true` fails, then exercises cancellation at the password prompt, real terminal
password authentication, exact extracted bytes, the expected overwrite refusal,
and encrypted extraction with a separate archive password. Passwords stay in
process memory, stdin and the isolated fixture account; they are not command
arguments or log output. The account and sudoers rule are removed in a finally
block. Provisioning is restricted to GitHub-hosted runners.

The overwrite check deliberately expects a nonzero exit and an error containing
`would overwrite`. CI prints `PASS: expected overwrite rejection; existing
contents preserved` for this case. The CLI retains that specific extraction
error and exit status without appending the ambiguous `Sudo extraction failed
or was cancelled` message.

## Critical review of offline build coverage

The workspace suite alone did not establish coverage for isolated reduced
artifacts: it unifies dependency features across packages. CI now separately
runs core and FFI with `--no-default-features`, then the complete CLI suite with
`--release --no-default-features`, on all six macOS/Linux/Windows architecture
jobs. The Unix password harness uses that release binary too. The shared CLI
integration helper now uses Cargo's compile-time binary path, preserving the
selected target and build profile; its old fallback always selected `debug`.
`ZMANAGER_AUDIT_BINARY` can select an unpacked artifact for tests using that
helper. Tests that explicitly use Cargo's binary environment still target the
Cargo-built executable.

Dependency audits now reject HTTP transport (`reqwest`) in the default CLI as
well as reduced CLI, core and reduced FFI. Default FFI deliberately includes
LocalSend and its transport, so it is not subject to that HTTP exclusion.

Remaining coverage limits, in priority order:

1. Native secret-store failure UX: end-to-end signing/key generation against a
   locked, unavailable, or user-denied Keychain/Secret Service. Public certificate
   discovery without private keys is covered; the complete denial/recovery
   interaction is not.
2. Installed package behavior: unpack/install the final signed/notarized macOS,
   Linux and Windows distributions on clean machines, then run the workflows.
   Release-profile Cargo tests do not verify installers, signatures, loader
   dependencies, PATH setup or first-launch OS prompts.
3. Optional compatibility oracles: several tests return early without tools
   such as RAR or platform-specific disk utilities. A passing test count is not
   proof those comparisons ran. Committed fixture/native decoder tests still
   run; missing optional tools need a visible skip inventory in future CI.
4. Failure injection at the CLI boundary: disk-full and process termination
   during identity/contact/archive writes. Core cancellation and hostile archive
   tests cover engine behavior, but do not establish every CLI recovery path.

External-network denial is exercised locally in the Linux Docker validation.
Cargo's `--offline` flag alone only prevents dependency downloads; it does not
prevent a test executable from using the network. The regular macOS and Windows
CI suites do not yet run inside an enforced network-denial environment.
