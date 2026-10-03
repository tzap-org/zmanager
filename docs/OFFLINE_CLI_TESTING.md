# Offline CLI parity validation

## Current coverage audit — 4 October 2026

The sections below preserve the sequence of fixes and verification. Their older
pending statements describe the state at that revision; this table records the
current evidence and outstanding checks.

| Goal requirement | Evidence | Outstanding verification |
| --- | --- | --- |
| Native secret-store failure and recovery | Linux ARM64 packaged executable passed unavailable service, locked collection, native cancellation, authentication/retry, ENOSPC and killed-keygen recovery, including an outbound-denied run | macOS disposable-account Keychain CI; macOS GUI consent/denial remains an explicitly tracked interactive check |
| Installed packages and first launch | Preview 37129928428 at `6ba7bc6` passed all six package architectures; actual macOS/Linux ARM64 packages passed their full identity workflows | New macOS ARM64/Intel producer identity gates in Preview 37132262938; Windows/Intel Linux package smoke does not establish full packaged identity coverage |
| Optional compatibility omissions | CI emits a skip inventory and uploads its JSONL evidence; successful Linux ARM64/x86_64 and Windows x64 jobs in run 37129928507 include reporting | Inspect inventories from the remaining jobs; skipped checks are never counted as verified |
| Disk-full and interrupted writes | Local macOS ARM64, Docker Linux ARM64, Linux x86_64 CI and both Windows architectures establish their required recovery checks; Linux packaged native-key crash recovery also passed | Corrected macOS Intel interruption checkpoint; Windows signed-export process-kill coverage remains unestablished |
| Offline network enforcement | Actual macOS/Linux ARM64 package workflows passed with enforced denial; Linux native GUI recovery also passed in a private network namespace; Windows x64 CI confirmed both firewall paths | Finish the matching corrected six-architecture CI matrix |
| Required Rust gates and fixes | `8ebb644` passed formatting, workspace Clippy/check and workspace tests without warnings; `c7bf9a9` passed workflow lint and affected CLI tests with workspace Clippy/check | Native CI results remain required before claiming parity complete |
| Current macOS distribution policy | Unsigned portable tarballs are documented in INSTALL.md; no signing/notarization scope was added | Browser quarantine and Gatekeeper consent remain a tracked manual distribution check |

Run 37131968021 at `8ebb644` tests the same Rust code and main CI workflow as
`c7bf9a9`; their diff contains only package workflows and this document. The
duplicate main CI run at `c7bf9a9` was cancelled to free runners, while its
changed package workflow remains required and running. The goal is not complete.

## Initial parity baseline

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
and Linux ARM64 and x86_64. The first run containing these checks is
[GitHub run 37118119096](https://github.com/tzap-org/zmanager/actions/runs/37118119096),
triggered by `64fccb0`; its platform results are pending. The local Linux
Docker rehearsal passed.

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

## Final local verification of `64fccb0`

| Suite | macOS ARM64 | Linux ARM64 Docker |
| --- | --- | --- |
| Workspace | 2,263 passed, 2 ignored | 2,144 passed, 2 ignored |
| Isolated reduced core | 1,866 passed, 1 ignored | 1,750 passed, 1 ignored |
| Isolated reduced FFI | 23 passed | 23 passed |
| Release offline CLI | 224 passed | 223 passed |

Format, workspace Clippy/check, dependency profile audits and workflow syntax
validation passed. The Docker container's external network was disconnected
before all these Rust tests; loopback remained available. The workspace and
profile suites ran as root in this final container, so the disposable non-root
account separately verified the release binary's permission and terminal paths,
including actual sudo authentication, cancellation at the password prompt,
overwrite rejection and separate encrypted-archive authentication. Its account,
sudoers rule and root-owned extraction fixtures were removed. On macOS, the
release binary passed the consent/cancellation/unattended terminal harness;
actual user authentication was verified by the earlier interactive smoke test.

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

## Goal progress: failure handling and offline enforcement

The first expanded CI run passed both macOS ARM64 and Intel release and real
password checks. Both Linux jobs passed their isolated release suites, then stopped
before the terminal test because a runner-owned sudoers include was mode 0644.
The harness now validates only its installed fixture rule; a Docker regression
with the same unrelated file permissions passed real authentication and cleanup.
The fixture's `sudo -n` rejection and authenticated retry still prove its
password-required policy is active. Windows results remain pending until inspected.

A real OS file-size limit reproduced truncation of an existing document export.
Document envelopes and contact exports now reuse the durable core atomic writer.
Regression checks exercise partial-write failure, preserve the original bytes,
and then retry successfully for both exports. This covers file-size-limit write
failure, not yet every disk-full or abrupt-termination case.

A Linux native Secret Service test now verifies unavailable-service errors,
unchanged public catalogue after failed key generation, and successful key
generation after recovery. Locked and user-denied interactions remain open.

CLI optional checks append actual skipped checks to a JSON-lines inventory,
including tool absence, unsupported reference formats, and permission/platform
prerequisites. CI publishes a readable summary and the inventory on failure too.
Missing committed fixtures fail instead of returning successfully. Cargo totals
still require this inventory to interpret which optional comparisons ran.

The release CLI suite passed with outbound TCP denied in a macOS process sandbox
(224 tests) and a Linux network namespace without external interfaces (224 tests).
The Linux workspace passed 2,145 tests; macOS passed 2,263. Format, workspace
Clippy/check and workflow validation passed. A negative socket probe proves the
sandbox is active before running tests. Linux Secret Service uses a filesystem
Unix socket to remain accessible across the network namespace. Compiler cache
wrappers are disabled inside the sandbox because they may use local TCP.
Windows network enforcement remains open. Installed-package validation is
expanded below.

## Packaged executables and real write failures

The current goal validates the existing macOS portable tarballs; adding
Developer ID signing or notarization is outside its scope. See
[the installation notes](INSTALL.md#gatekeeper-and-the-current-portable-packages)
for the distinction between an ad hoc signature, Gatekeeper assessment and
browser-quarantined first launch.

`scripts/test-offline-package.py` verifies the package checksum before safe
unpacking, checks notices/completions/manual files, and executes the installed
binary from a fresh `PATH` and home directory. It exercises offline flavor,
engine readiness, unavailable hosted login, read-only certificate discovery,
encrypted ZIP create/test/list/extract, overwrite refusal, streaming output,
Unicode/spaced paths and generated completions. Archive passwords are supplied
through stdin and must not appear in output.

The macOS ARM64 and Linux ARM64 artifacts from
[Package Preview 37120223686](https://github.com/tzap-org/zmanager/actions/runs/37120223686)
passed locally. The Linux static package also passed in a clean
`python:3.13-alpine` container with `--network none`, without Rust, archive tools,
or a secret-service daemon. Preview and release workflows now run this smoke
check on all six architectures before uploading their packages. Those new CI
checks require a subsequent run; the older preview run only proves packaging.
This does not yet test install.sh, Homebrew, WinGet, or packaged signing/contact
workflows that need native private-key storage.

`scripts/test-write-failures.py` fills only a bounded disposable filesystem
(32 MiB macOS disk image or 16 MiB Linux tmpfs). Real ENOSPC failures preserve
the bytes of existing valid ZIP, 7z and tar.zst archives; removing the filler
allows successful replacement, archive testing and exact-byte extraction.
Failed writes leave no temporary output. A separate test observes an active
ZIP temporary writer, kills the process, verifies the original destination,
then retries successfully despite the orphaned temporary file. SIGKILL cannot
run destructor cleanup; the fixture removes its private leftovers afterward.

All four checks passed on macOS ARM64 and Linux ARM64 Docker. CI now runs them
on the four Unix jobs and runs the killed-writer test on both Windows jobs.
Windows disk-full coverage, identity/catalogue disk-full and termination,
and interruption during the final replacement operation remain open.

The local finish gate passed: cargo fmt, workspace Clippy/check without
warnings, and the affected CLI suite. For the preceding implementation,
[CI 37120223644](https://github.com/tzap-org/zmanager/actions/runs/37120223644)
has passed macOS ARM64 and both Linux architectures, including network-denied
release tests and real sudo authentication. Its other jobs were still running
when this note was written; their final results must be inspected separately.

## Native Linux unlock cancellation and recovery

`scripts/test-linux-secret-store.py` exercises GNOME Keyring through its real
Secret Service and GTK unlock dialog. It starts with a private home directory,
D-Bus session and virtual X server; the bus is created after setting the fixture
environment so auto-activated services cannot use the caller's keyring. The
random keyring password exists only in this disposable fixture. The daemon and
prompter are stopped and the fixture directory is removed afterward.

The test first generates a key, then proves an unavailable bus reports the
unavailable-store error without modifying the existing catalogue. It locks the
native collection, checks the locked property, and verifies public certificate
discovery still works. It cancels the actual unlock dialog using Escape and
asserts a nonzero CLI status, a locked-store diagnostic, unchanged catalogue
bytes and unchanged native secret entries. A subsequent retry supplies the
fixture password to the real dialog, verifies the collection becomes unlocked,
and commits exactly one additional key. The current backend reports cancelled
unlock as a locked store; this test does not claim a distinct denied error code.

This passed on Linux ARM64 Docker as an unprivileged user, both with the release
Cargo executable and the actual static musl package from Preview 37120223686.
Both Linux CI architectures now run the harness with required Xvfb/xdotool
dependencies. Native macOS Keychain lock/deny recovery and corresponding Windows
credential-store failures remain open; no personal macOS Keychain was locked.

## Windows outbound-network enforcement

The Windows CI script now repeats the complete reduced release CLI suite under
temporary Windows Firewall outbound block rules for both executable entry
points (`zm.exe` and `zmanager-cli.exe`). The harness first replaces each build
output with a small TCP probe at the exact same path, proves a connection to
staging port 443 succeeds, installs the program rule, and requires socket error
10013 (WSAEACCES). Timeouts and unrelated socket errors fail the check. It then
restores the original executable, verifies its SHA256, and runs the tests while
the rule remains active. This covers tests that use Cargo's binary paths as well
as the shared CLI helper, without redirecting them to another executable.

The probe performs only a TCP handshake, with no HTTP request or credentials.
See Microsoft's documentation for
[program-specific outbound rules](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)
and [socket access-denied errors](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2).
The harness attempts executable restoration, rule removal and profile restoration
even on failure, and retains backups if cleanup cannot be verified. Disabled
firewall profiles may be enabled temporarily only on disposable GitHub-hosted
runners; other hosts must already have enabled profiles.

PowerShell parsing, .NET probe compilation and the TCP positive control passed
in the Windows 11 ARM64 Parallels VM. Its current-user session is not an
administrator, so no firewall rule or profile was modified there. Actual
enforcement and the network-denied CLI run remain pending until both Windows
CI architecture jobs execute this new harness successfully.

## Identity commit failure regression

Failure-injection tests reproduced orphaned private keys when the legacy
inventory facade successfully wrote secrets but the catalogue commit failed,
or when a later secret write failed. The facade now tracks newly written
references and attempts rollback on error, preserving all existing references.
It re-reads the public catalogue before cleanup and retains references that a
backend actually published despite returning an error. A regression covers this
ambiguous-commit case as well as unchanged old key material and successful retry.
The original catalogue/secret-store error remains the diagnostic if cleanup is
unavailable.

The native Linux harness can now fill a bounded tmpfs containing only the
fixture identity catalogue while keeping its private GNOME Keyring elsewhere.
This reproduced the orphan with the preceding binary, independently of the
in-memory tests. `ZMANAGER_TEST_CATALOG_DISK_FULL=1` enables the check; both Linux
CI jobs require it. It verifies unchanged catalogue bytes and native secret
entries on failure, then removes the filler and requires exactly one additional
key after successful retry. Catalogue I/O errors now use plain-language error
descriptions rather than Rust enum names such as `StorageFull`.

The rebuilt release CLI passed this real disk-full check on Linux ARM64 Docker,
along with the native cancellation/unlock sequence. Linux workspace Clippy/check
passed without warnings and 24 focused identity-related core tests passed. The
macOS workspace run passed after the rollback change; final checks after the
plain-language diagnostic update also cover the affected core and CLI crates.

Rollback after a reported error is separate from abrupt process death. The
file-backed facades now add durable recovery for new secret writes, as described
below. If the catalogue cannot be re-read or the secret store refuses deletion,
keys are retained rather than risking deletion of a published identity.

## Unix installer update preservation

The real `install.sh` truncated an existing executable when native `cp` hit a
file-size limit during replacement; the macOS regression reproduced this before
the fix. Installation now copies into a unique sibling temporary file, sets its
executable permissions, then renames it over the destination. Ordinary failures
and SIGINT/SIGTERM clean up the stage, and signals exit with failure. Copy errors
describe the failed replacement and preservation of the old installation;
unwritable directories retain the explicit sudo guidance. Suggested commands
quote paths containing spaces.

`scripts/test-unix-installer.py` uses actual packaged binaries and real curl
file-URL downloads from a private local release layout. It verifies fresh-home
installation and PATH launch, engine readiness, checksum rejection without
replacement, unwritable-destination guidance, partial native-copy failure,
SIGTERM after the copy but before publication, cleanup and successful retry.
These checks passed on macOS ARM64 and Linux ARM64 Docker as an unprivileged
user. Root permission-test skips are printed explicitly. Preview and release
workflows require the harness on all four Unix targets; this does not cover
Homebrew, WinGet or installer SIGKILL cleanup.

The earlier implementation at `89b6a50` has now passed all six platform jobs in
[CI 37120223644](https://github.com/tzap-org/zmanager/actions/runs/37120223644),
including both Unix network-denial and real sudo-authentication architectures.
This is baseline evidence, not verification of subsequent commits: the newer
native-keyring, Windows network-denial and identity rollback changes still need
their current CI results inspected.

## Durable recovery after native key-generation interruption

A real Linux regression observed Secret Service's CreateItem request using
`dbus-monitor --profile` (headers only, no secret arguments), stopped the CLI
while the native service completed its write, then killed the CLI before
catalogue publication. The previous binary preserved the catalogue but left an
orphan after retry. This establishes the crash interval independently of mocked
stores or a product-only test hook.

File-backed inventory writes now durably record new secret purposes/references
before calling the secret store. The journal contains no private material. A
separate OS file lock protects the transaction through publication and journal
cleanup; recovery cannot steal the lock from an active or stopped process.
After process death releases that lock, the next inventory read/write deletes
only pending references absent from the current catalogue. Published keys and
other catalogues' secrets are retained. Unreadable catalogues, malformed
references and unavailable cleanup fail closed and retain the recovery record.
Public certificate discovery still uses the public catalogue directly.

The real kill/retry test now passes on Linux ARM64 Docker, including rejection
of a competing writer without deleting the active key. Three fresh runs as an
unprivileged user also passed. Both Linux CI jobs require the interruption check
through `ZMANAGER_TEST_IDENTITY_INTERRUPT=1`, together with disk-full, native
unlock/cancellation and unavailable-service checks. Core regressions cover
recovery before/after publication, active-lock protection and malformed paths;
they passed on macOS ARM64 and Linux ARM64. macOS workspace tests and both
platforms' workspace Clippy/check passed without warnings.

Windows journal/lock runtime coverage and native macOS Keychain consent/denial
still require their matching CI or interactive checks. This journal covers new
keys written through file-backed inventory facades; it does not establish every
identity deletion, export interruption, installer SIGKILL or power-loss case.

## Inspected CI and Windows package harness correction

Commit `7fcad10` passed all six platform jobs in
[CI 37125348204](https://github.com/tzap-org/zmanager/actions/runs/37125348204).
Both Windows architectures recorded a successful staging TCP positive control
and socket error 10013 under the outbound rules for each release executable,
then passed the network-denied offline CLI suite. This closes the earlier
pending Windows firewall runtime check. Both macOS architectures passed real
sudo password authentication. The interruption journal added in `808b296` still
needs its own complete CI results.

The same commit's package preview passed the four Unix installed-package tests
but failed both Windows tests in the harness before launching the executable:
copying `os.environ` loses its Windows case-insensitive lookup. Fixing that
revealed that Windows CreateProcess searches the parent's PATH rather than the
explicit child environment. The harness now reads SystemRoot through
`os.environ` and launches the command-name check through the system `cmd.exe`
with its fresh PATH. All subsequent operations still invoke the exact installed
executable directly. The corrected harness passed against the published
`89b6a50` ARM64 Windows package in the native Windows 11 VM and against its
macOS ARM64 package. Current six-target package preview results remain required;
the VM result does not establish native x86_64 Windows package coverage.

## Disposable macOS Keychain CI fixture

Both macOS CI jobs now require `ci-unix-elevation.py --keychain`, reusing the
hosted-runner-only disposable account provisioner. This mode installs no sudo
rule for that account. `test-macos-keychain.py` refuses to run as root, outside
GitHub-hosted CI, or for an account other than the provisioner's random `zmci`
user. Default/search-list changes apply only to that disposable user's private
Keychain, which is deleted before the account and home are removed. Fixture
passwords enter `security -i` over stdin rather than process arguments.

The harness requires absent-Keychain failure without catalogue publication,
successful creation after configuring the private Keychain, a lock verified
with `SecKeychainGetStatus`, public discovery while locked, failed private
access with byte-exact catalogue preservation, and successful unlock/retry with
exactly two recipient keys. Commands have bounded timeouts; an unexpected GUI
wait fails the job. This checks failure/recovery through the native store rather
than a mock. It does not click a GUI consent/denial prompt. The new CI runtime
results must be inspected before claiming macOS coverage; local validation so
far covers Python syntax, Apple's interactive command protocol and workflow
lint, without modifying the developer's login Keychain.

## Signed-export disk-full and process-interruption checks

The offline sign/contact workflow now tests both document envelopes and contact
cards against actual ENOSPC on a bounded disposable filesystem. The initial
macOS attempt exposed an HFS+ fixture limitation: failure to extend a large
allocation clump did not prove a small export could not fit. The export harness
also consumes the remaining small allocations, requires the CLI's real
disk-full diagnostic, and asserts the old signed output and identity catalogue
remain byte-exact. Once capacity is released, the document retry must pass
cryptographic verification and the contact retry must pass verified import
into a separate fresh state directory. No production service is involved.

Interruption checks stop the real CLI at its staged-file synchronization: strace
injects SIGKILL at fsync on Linux and LLDB stops at fcntl(F_FULLFSYNC) then kills
its own launched process on macOS. Linux tracing includes only fsync metadata and checks the annotated file
descriptor identifies the intended output. Both require a nonempty staged
export, preservation of the original output and catalogue, and successful
retry followed by the workflow's cryptographic checks. Only the observed
disposable orphan is removed after retry; SIGKILL cannot execute Rust cleanup.

Both export types passed these checks on macOS ARM64 and Linux ARM64 Docker,
including all 11 reduced-profile offline identity tests on Linux. CI installs
and requires the corresponding debugger/tracer and enables actual disk-full
export tests in the isolated release CLI step on all four Unix jobs. Optional
local omissions are recorded in the skip inventory. Native x86_64 results and
Windows-specific export/disk-full checks remain unverified by this addition.

## Windows bounded-filesystem coverage

Both Windows CI jobs now require the archive disk-full harness, rather than
running only its process-kill check. The shared export workflow also enables
real disk-full document/contact exports for the reduced Windows release test.
`test-windows-bounded-volume.ps1` creates a new 32 MiB VHD, associates it with
exactly one non-system disk through `Get-DiskImage`, verifies a bounded size and
RAW partition state, and only then formats the fixture as NTFS. Its empty mount
directory and image path are restricted to the harness's disposable directory;
it accepts no physical disk number. Python independently checks the mounted
filesystem capacity before filling it. Cleanup removes the fixture mount path,
detaches that exact image and verifies detachment.

Provisioning requires an administrator session on a GitHub-hosted runner.
Windows PowerShell parsing and refusal of ordinary local execution passed in
the native Windows 11 ARM64 VM. The VM's standard account did not mount or
format a disk, so these checks do not establish VHD runtime or ENOSPC coverage.
That evidence must come from the matching Windows CI jobs. The existing macOS
workspace gate and Linux reduced-profile export suite passed after sharing the
export test command construction across platforms. Abrupt signed-export
termination on Windows is still not established by this filesystem addition;
its separate archive writer-kill check remains required.

## macOS release interruption checkpoint and installed identity workflow

The release interruption test initially watched libc `fsync`, but Rust's Apple
`sync_all` calls `fcntl(F_FULLFSYNC)`. Reproduction against the downloaded release
failed both inside and outside the network sandbox, identifying a debugger
checkpoint error. The corrected LLDB breakpoint checks opcode 51 in the second
C ABI argument on ARM64 and x86_64. It requires an actual breakpoint stop and a
nonempty staged export before asserting preservation and retry.

The checksum-verified macOS ARM64 package from Preview 37129928428 at `6ba7bc6`
passed all ten reduced-profile identity workflow tests with external networking
denied, including document/contact interruption and recovery. The package test
accepts `--workflow` followed by a test command and exposes its still-unpacked
executable through `ZMANAGER_AUDIT_BINARY`; this prevents the workflow from
silently testing a separate Cargo executable. The basic package smoke tests
passed on all six Preview architectures. The matching Linux ARM64 static musl
package passed all eleven reduced-profile identity tests in Docker with a
private filesystem D-Bus and a network namespace denying outbound TCP. That run
also required actual signed-export disk-full preservation/recovery and killed
document/contact writer recovery. This evidence does not establish packaged
identity workflow coverage for the other four architectures.

Preview and release package jobs now compile the reduced macOS identity test
harness before entering the network sandbox, then run both first-launch smoke
and the full identity workflow against the unpacked archive. The sandbox denies
all network access and the outbound probe must confirm enforcement. Both
architectures use the explicit Cargo target matching their packaged binary.
These new producer gates require successful native CI execution before they
establish Intel package identity coverage.

Windows x64 CI job 111222843531 in run 37129928507 at `6ba7bc6` passed
the complete workspace, reduced-profile and network-denied release suites.
The reduced CLI identity workflow ran with export disk-full checks required.
The archive fixture log confirms real ZIP, 7z and tar.zst disk-full preservation
and recovery, plus killed archive-writer preservation and successful restart.
Both executable paths passed the firewall positive control and enforced TCP
denial. Windows ARM64 job 111222843565 in the same run subsequently passed the
same required suites, both firewall controls, real ZIP/7z/tar.zst disk-full
recovery and killed archive-writer restart. The overall run failed on the older
macOS debugger checkpoint; that does not erase the completed Windows evidence.

The checksum-verified Linux ARM64 static musl package at `6ba7bc6` also passed
`test-linux-secret-store.py` in Docker with both catalogue disk-full and
key-generation interruption checks enabled. Its private D-Bus/X server fixture
confirmed unavailable-service preservation, a genuinely locked collection,
native unlock cancellation, password authentication and retry, real ENOSPC with
no orphaned key, and deletion of an unpublished secret after killing keygen.
The complete native GUI fixture then passed again inside a private network
namespace whose probe confirmed outbound TCP denial. D-Bus, the native keyring
and the X server all started inside that namespace; local IPC remained usable.

## Windows optional-tool discovery

Review of the Windows skip inventory exposed exact-filename lookup in the shared
test helper. A native Windows 11 ARM64 Rust regression found `cmd.exe` on PATH
but failed to find `cmd`. The corrected helper searches Windows PATHEXT in each
PATH directory, retaining directory precedence and explicit-extension behavior.
Unix lookup retains exact filenames. The same helper source and both regression
tests then passed with native MSVC in that VM. This verifies tool discovery;
the newly enabled Windows compatibility tests still require their CI results.

## Native macOS Keychain fixture diagnosis

macOS ARM64 job 111228688777 in run 37131968021 passed the corrected release
interruption suite, network-denied suite, sudo authentication and archive
disk-full/killed-writer recovery. Its native Keychain fixture proved absent-store
failure without catalogue publication, then failed at the first key generation
after creating and verifying an unlocked private Keychain. The assertion
originally hid the CLI diagnostic; the harness now includes its redacted error
and exit status after checking that the fixture password was not echoed.

The manual Offline Keychain Audit workflow downloads only a successful Preview
run with an exact supplied commit SHA, verifies the archive checksum, and tests
the still-unpacked executable on native macOS ARM64 and Intel runners. It reuses
the restricted disposable-account provisioner and cleanup. This provides a short
native diagnosis loop without recompiling the workspace; it does not establish
that a different source revision's packaged build passed or click GUI consent.

The native-domain probe subsequently returned `errSecNoDefaultKeychain` on both
architectures. Creating the disposable account's normal Library/Preferences and
Library/Keychains directories fixed preference persistence: both native default
selection and fresh CLI key generation passed, as did recovery of the earlier
unavailable-store state. The locked-Keychain step then timed out waiting for
native interaction, exposing a separate unattended CLI problem.

The macOS CLI now disables native Keychain interaction for its command lifetime
when stdin or stderr is not a terminal. Terminal invocations retain native
interaction. The store maps Apple's interaction-required errors to Locked,
cancellation/access failures to Denied, and missing/unavailable stores to
Unavailable. A native-error regression failed with the old generic Unavailable
mapping and passed after the fix. The fixture now requires the specific locked
diagnostic, unchanged catalogue and successful unlock/retry. Native runtime
verification of the updated executable remains required.
