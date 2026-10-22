# Review findings and regression coverage

These findings were reviewed against `819c28d5c9a492ca86ada949d044ab7a5fce6a97`.
For each row, the regression was added and observed failing before its
production fix. Tests use temporary directories, local certificate fixtures,
and bounded payloads; no hosted service, credentials, or destructive load is
needed.

| Finding | Concrete failure before the fix | Regression |
| --- | --- | --- |
| Extraction through symlink ancestors | A fresh extraction accepted `a -> .`, `b -> a/..`, then wrote `b/escaped.txt` outside its destination. | `symlink_chains_cannot_escape_fresh_extraction_roots` in `hostile_archives.rs` covers TAR, ZIP, and both link orders. |
| Inventory clearing before account validation | An absolute account key deleted a temporary victim directory, then returned an invalid-account error. | `clearing_inventory_rejects_invalid_accounts_before_deleting_files` also covers parent traversal. |
| Contact identity metadata not bound to its certificate | A card signed with the legitimate fixture key was accepted after its claimed signer ID was changed. | `contact_card_rejects_signed_metadata_that_disagrees_with_certificate` covers signer, organization, device, assurance, policy, and version. |
| Contact certificate validity not enforced | A correctly signed card without a card expiry verified before its certificate's validity began and after it ended. A previously imported contact also remained selectable after certificate expiry. | `contact_card_rejects_certificates_outside_verifier_time` and `accepted_contact_recipients_rejects_a_certificate_that_expired_after_import`. |
| Snapshot identity mismatch bypassing merge decisions | A stale snapshot entry with a different outer contact ID replaced a newer local contact identified by the verified card's key. | `snapshot_rejects_mismatched_contact_ids_without_replacing_newer_contacts`. |
| Unbounded decoded intermediates | Compressed TAR/CPIO listing decoded the whole fixture without an intermediate-byte budget. | `engine_bounds_decoded_intermediates_before_listing_compressed_archives` exercises a small fixture against a 512-byte budget and checks cleanup. |
| Unauthenticated backup parameters controlling KDF work | An envelope's changed iteration count reached password derivation and ciphertext authentication instead of being rejected by an application resource policy. | `restore_rejects_excessive_kdf_work_before_authenticating_ciphertext` uses only 1 MiB and 11 iterations. Policy boundary tests inspect memory and parallelism limits without allocating those amounts. |

## Scope and severity corrections

- Inventory deletion is confirmed in the public file-store API. This review
  did not establish an untrusted remote caller; the impact depends on who
  supplies the account identifier.
- Intermediate decoding was missing its own resource budget. The original
  extraction limit measures output file bytes, so this is not a bypass of
  that limit's stated accounting rules.
- The backup issue concerns resource use before authentication. The tests
  do not show a break in Argon2 or AES-GCM.
- Contact metadata spoofing requires a valid signing certificate and a
  correctly signed card. The defect was trusting claimed identity fields
  without comparing them with the validated certificate identity.
- The earlier Windows login claim is excluded: the launch URL is generated
  locally, and remote command execution was not established.

## Behavior after the fixes

Extraction rejects symlink/reparse ancestors in both existing filesystem
paths and planned archive paths, including link targets. Ordinary safe
symlinks are still restored. These checks address archive-controlled path
graphs; they do not establish race safety against another process changing
the destination concurrently.

Contact import validates the chain at the supplied verifier time and binds
the card's identity metadata to the certificate. Recipient selection checks
the certificate validity again so a contact cannot age past expiry and stay
selectable through the shared API. Snapshot restoration rejects outer IDs
that differ from the verified recipient fingerprint.

`OpenLimits.max_decoded_bytes` bounds engine TAR/CPIO temporary decoder
intermediates independently of extracted output size. Its default is 64 GiB;
callers can lower it or explicitly disable it with `None`. A limit failure
returns `ResourceLimitExceeded` and removes the incomplete intermediate.

Backup creation, restore, and password rewrapping reject costs above 256 MiB
of Argon2 memory, 10 iterations, or 16 lanes. The writer defaults remain
64 MiB, three iterations, and one lane. Older custom backups above the new
limits return an explicit unsupported-parameters error.

## Running the regressions

On macOS, run the affected core tests with network operations denied for
Cargo and its child processes:

```sh
/usr/bin/sandbox-exec -p '(version 1) (allow default) (deny network*)' \
  /bin/bash -c 'cargo test -p zmanager-core --offline --lib contact_card:: &&
    cargo test -p zmanager-core --offline --lib contact_snapshot:: &&
    cargo test -p zmanager-core --offline --lib local_identity_store:: &&
    cargo test -p zmanager-core --offline --lib key_backup:: &&
    cargo test -p zmanager-core --offline --lib safety:: &&
    cargo test -p zmanager-core --offline --lib decoded_reader:: &&
    cargo test -p zmanager-core --offline --test hostile_archives &&
    cargo test -p zmanager-core --offline --test engine_conformance'
```

These commands require dependencies to be cached locally. `--offline` alone
only prevents Cargo from fetching dependencies; it does not deny sockets to
test executables. The full workspace suite also runs LocalSend integration
tests that start receivers and multicast discovery. Those network tests are
outside this focused regression run and can trigger firewall prompts.
The unrestricted core unit suite also includes an unrelated Unix socket
fixture test, which cannot create its fixture under this deny-all-network
policy; the module filters above select the units relevant to these fixes.

Validation was performed on macOS. Windows and Linux execution are not
claimed by this review.

- `cargo fmt`: completed.
- `cargo clippy --workspace --all-targets --offline`: passed without warnings.
- `cargo check --workspace --all-targets --offline`: passed without warnings.
- `cargo test --workspace --offline`: 2,288 passed, two existing tests ignored.
- After the final personal-metadata compatibility adjustment,
  `cargo test -p zmanager-core -p zmanager-tzap-hosted --offline` passed again.
- The focused macOS command above passed all 158 tests with network
  operations denied by the process sandbox.

Thirteen new regression and boundary tests accompany the fixes. No archive
fixtures were regenerated and no bindings changed.

## Follow-up hardening

Review of `cbc73198b5d02b585505028f4b6d6bc78e978639` identified two
remaining gaps, reproduced with small local payloads:

- Nested DEB testing opened payloads with default options, losing the caller's
  decoded-byte budget. DEB extraction passed unbounded decoders directly to
  the TAR backend. Both paths now inherit the configured budget and temporary
  root; direct DEB backend callers receive the default 64 GiB decoded limit.
  The engine regression covers rejection at 512 bytes, explicit opt-out, and
  cleanup. A second regression verifies that a small control payload cannot
  hide an oversized data payload. Cancellation and progress-event tests still
  exercise the direct backend path.
- A final dangling symlink returned `NotFound` from canonicalization and was
  accepted as a missing target even when it pointed outside the root. Failed
  resolution now probes the final target without following it and rejects
  unresolved symlinks/reparse points. The probe removes trailing slashes and
  `.` components without collapsing `..`. TAR and ZIP regressions cover direct
  and chained dangling targets, including directory suffixes; safe forward
  links to ordinary files remain supported. Unresolved links through existing
  dangling redirects are rejected conservatively, including redirects whose
  eventual destination would be inside the root.

The DEB and dangling-target regressions were observed failing before their
fixes. All follow-up tests use local temporary files. No archive fixtures or
public API signatures changed.
