# TZAP product profiles

ZManager has one archive and identity contract, composed into product profiles
with positive Cargo features.

| Profile | Archive engine | Offline identity/catalog/sign/verify | Hosted login/enrollment/status | HTTP client |
|---|---|---|---|---|
| default | enabled | enabled | unavailable at product boundaries | absent from the CLI graph |
| `tzap-online` | enabled | enabled | enabled | enabled |

The feature name is `tzap-online` in `zmanager-cli` and `zmanager-ffi`. Hosted
transport is supplied by the explicit `zmanager-tzap-hosted` product crate. The
core's typed identity and transport contracts remain
available in reduced builds so local catalog, certificate parsing, document
signing, document verification, and offline `.tzap` inspection do not require
hosted account behavior. Network transport is supplied by the full CLI
profile; the FFI bridge keeps its UniFFI/JSON function set unchanged and
returns a structured unavailable result only for hosted auth launch, callback,
status, forget, and account-URL operations in reduced builds.
The hosted transport policy and validation boundary are described in
[`TZAP_HOSTED_TRANSPORT.md`](TZAP_HOSTED_TRANSPORT.md).

The reduced FFI profile keeps these operations real:

- bounded public `.tzap` metadata and X.509 inspection;
- local identity/catalog and certificate-inventory operations;
- offline document signing and verification;
- contact and recipient-key operations;
- the common archive engine/session contract.

The profile gate is checked by:

```sh
cargo check --workspace --no-default-features --all-targets
cargo test -p zmanager-core --no-default-features --lib
cargo test -p zmanager-ffi --no-default-features
bash scripts/verify-artifact-profiles.sh
```

Native consumer builds select the same profile through `ZMANAGER_TZAP_PROFILE`.
The root iOS script accepts `full` or `offline` (default `full`); the mobile
Android and pinned iOS wrappers default to `offline`. The desktop macOS
inspection-extension build also defaults to `offline`, while the desktop main
application keeps the explicit `tzap-online` feature because
its account UI uses hosted authentication.

The CLI's default release artifact is the offline profile (`zm-*`). The
enrollment-capable profile is shipped as a separate `zm-full-*` artifact and
is installed explicitly with `install.sh --full`, `zmanager-full`, or
`TzapOrg.ZManagerCLI.Full`.

Adding a hosted operation requires an explicit `tzap-online` product-boundary
decision. It must not be added to archive-engine selection or to the stable
FFI type contract.

## `zmanager-cli` command split

The CLI dependency profile mirrors the same boundary, at the command level
rather than the module level:

| Build | `zmanager-tzap-hosted` | reqwest | Commands |
|---|---|---|---|
| default | present, without `reqwest-transport` | absent | `zm tzap …` |
| `tzap-online` | present, with `reqwest-transport` | present | `zm tzap …` + `zm auth …` |

`zmanager-tzap-hosted` is always a CLI dependency — it separates its own HTTP
transport behind `reqwest-transport` — so the default build keeps `zm tzap
sign`, `verify`, `contact`, `share`, and `certs` (which reads the local
identity catalogue) working entirely offline, while dropping reqwest and the
hosted commands under `zm auth` (`login`, `callback`, `status`, `forget`,
`account`, `me`, `cert enroll|renew|revoke`, `device retire|revoke`)
entirely. See
[`cli-command-structure-and-profiles-plan.md`](../implementation-docs/cli-command-structure-and-profiles-plan.md)
for the full command tree and rationale.

## Revocation is disabled in the CLI (2026-09-12)

`zm tzap device revoke` and `zm tzap device retire` refuse with
`revocation requires an MFA step-up that the CLI cannot perform` unless the crate is built with
the `hosted-revocation` feature.

The sign server requires a recent admin MFA step-up for the personal revoke paths
(`POST /v1/certificates/{id}/revoke`, `POST /v1/devices/{id}/revoke`) so that a stolen session
alone cannot destroy a user's certificates. The satisfaction is keyed on the **calling session**
and lasts 15 minutes, so a step-up performed anywhere else cannot satisfy a CLI session. The CLI
has no code prompt, so the request could only return 403. Revocation lives in the hosted console
until a step-up flow exists here.

`TzapCertificateLifecycleError::AdminMfaRequired` distinguishes that recoverable case from a flat
authorization failure, so a future step-up flow can prompt and retry rather than reporting a
generic error.

### Device identity is per-install by design

`enroll_or_renew_device_certificate` reuses a signing key by looking up a `label` in the local
identity catalog. On desktop the private key is held in the OS keyring, but the reference that
locates it (`TzapSecretRef::generate()`) is deliberately non-discoverable random bytes recorded
only in that catalog, so losing the catalog means a new keypair and — because a device's server
identity is its SPKI SHA-256 fingerprint — a new device.

**That is intended.** `zmanager-mobile/docs/mobile-contact-book-design.md` §9.3 excludes the
device signing key and its certificate from backup: a new install enrolls its own certificate,
and a signing key restorable onto another device would weaken what a signature means. §8.4 makes
the CLI explicitly **not** a consumer of account backups. Do not add key backup or restore for
signing keys here; `/v1/me/key-backup` holds password-sealed *recipient* keys, the opposite case.

The open problem is that superseded devices accumulate on the server with nothing expiring them,
which is a server-side lifecycle question rather than a reason to make signing keys portable.
