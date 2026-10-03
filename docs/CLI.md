# Offline CLI guide

The normal `zm` build works offline. It creates, lists, tests, and extracts
archives. It also signs JSON documents and manages contacts using an existing
local signing identity. `zm --version` identifies this build as `offline`.

## Find commands and options

```powershell
zm --help
zm create --help
zm extract --help
zm tzap --help
zm tzap sign --help
zm help tzap sign
zm formats
```

Each command's help lists its inputs, options, and examples. `zm formats` also
shows platform restrictions; Apple Archive creation requires macOS or iOS.

Enable Tab completion in your current PowerShell session:

```powershell
zm completions powershell > zm.ps1
. .\zm.ps1
```

Try `zm cr<Tab>`, `zm tzap <Tab>`, `zm create --s<Tab>`, or
`zm extract --overwrite <Tab>`. Windows PowerShell 5.1 needs at least one letter
after `--` to trigger its native argument completer. Source the saved `zm.ps1`
from your PowerShell profile to enable completion in future sessions.

For other shells, see `zm completions --help`. Completions detect the installed
build and hide the online `auth` command in the offline build.

## Create and extract

Run these commands from the directory containing your `project` folder:

```powershell
zm plan project/
zm create project.zip project/
zm list project.zip
zm test project.zip
zm extract project.zip -C out/
```

The output contains `out/project/`. Directories recurse automatically. Change
the archive extension to `.tzst`, `.tgz`, `.7z`, or `.tzap` to select another
supported creation format. `--format` overrides extension inference.

Use `--encrypt` to request a password interactively:

```powershell
zm create secret.tzap project/ --encrypt
zm extract secret.tzap -C private-out/
```

An archive created without a password is not confidential. Passwords are never
command arguments. Scripts can pipe one password line into `--password-stdin`;
`--no-password-prompt` makes unattended commands fail rather than prompt.

Output archives and extracted files are protected against accidental overwrite.
Use `create --force` to replace an archive, or `extract --overwrite always` when
you intend to replace extracted files. Quote filter patterns:

```powershell
zm extract project.zip -C selected/ --include 'project/docs/**'
```

## Sign a TZAP archive with your own certificate

No enrollment or online service is needed for file-based archive signing.
OpenSSL is required only to create the example certificate. Run this as one
command:

```powershell
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout signer.key -out signer.pem -days 30 -subj '/CN=MySigner' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,digitalSignature,keyCertSign'
```

Keep `signer.key` private. Sign, verify, and extract with the offline CLI:

```powershell
zm create signed.tzap project/ --signing-cert signer.pem --signing-private-key signer.key
zm test signed.tzap --public-no-key --trusted-ca-cert signer.pem
zm test signed.tzap --trusted-ca-cert signer.pem
zm extract signed.tzap -C signed-out/
```

The first verification checks the signed commitment without decrypting entries;
the second also tests readable contents. The public check does not establish
complete physical data or recovery-margin integrity. A self-signed certificate
must be trusted explicitly. Obtain it from a source you trust; a certificate
supplied by an untrusted sender does not establish who that sender is.

Add `--encrypt` when creating an archive that also needs confidentiality.

## Sign a JSON document

`zm tzap sign` signs JSON documents, not `.tzap` archive files. It requires an
active certificate and private key already in the local identity catalogue:

```powershell
zm tzap certs
```

A fresh offline installation cannot enroll that identity. Obtain one through
the Full build or desktop/mobile app. Use the certificate id printed by `certs`.
Save this example as `payload.json`:

```json
{"tzap_payload_version":1,"title":"Hello"}
```

```powershell
zm tzap sign payload.json --certificate-id <cert-id> --output envelope.json
zm tzap verify envelope.json
```

Replace `<cert-id>` with the actual id. For a custom certificate chain, verify
with `--custom-trust-root-cert root.pem`. Verification needs no local signing
identity. Offline verification reports `cryptographically_intact_offline`; it
does not establish current online certificate status. Invalid signatures or
changed document contents return a nonzero exit code.

## Contacts and sharing

With an existing signing identity:

```powershell
zm tzap contact keygen --label MyDevice
zm tzap contact export --recipient-key-id <generated-id> --certificate-id <cert-id> --display-name Alice --output alice.json
zm tzap contact import bob.json --accept
zm tzap contact list
zm tzap share shared.tzap project/ --contact <contact-id> --certificate-id <cert-id>
```

Replace the ids with those printed by the commands. For custom roots, add
`--custom-trust-root-cert root.pem` when importing. Repeat `--contact` to share
with multiple recipients. Contact cards contain public keys, not private keys.

A recipient who has a private-key file can extract with:

```powershell
zm extract shared.tzap -C received/ --recipient-key recipient.key
```

**Current limitation:** `contact keygen` stores private keys in the OS keyring.
The CLI has no private-key export command or extraction flag that selects a
keyring recipient key. Receiving with only a key generated by that command
therefore requires a compatible application; this is not yet a complete
standalone CLI receiving workflow.

## Troubleshooting

- **Unknown option or missing input:** follow the command's suggested `--help`.
- **No local certificates:** document signing needs a pre-existing identity;
  archive signing can use your own certificate files instead.
- **Certificate is not trusted:** supply the trusted root explicitly for your
  custom/self-signed chain. Do not bypass trust with an arbitrary certificate.
- **Existing output:** select `--force` or the intended `--overwrite` policy.
- **Windows symlink restoration fails:** Developer Mode or symlink privilege is
  required to restore symlinks. Enable Developer Mode or open your terminal with
  **Run as administrator**, then retry into a fresh output directory because
  some entries may already have been extracted. Interactive TZAP extraction
  checks symlink privilege before writing files and offers **Retry extraction
  as administrator? [y/N]**. Yes opens Windows UAC and an administrator window
  using the same arguments and working directory, including the overwrite
  policy. Declining or cancelling UAC leaves extraction unstarted. The new
  process may ask again for an archive password. Redirected input/output,
  `--json`, `--quiet`, and `--password-stdin` never trigger this offer. Ordinary
  file extraction does not need elevation.
- **Engine diagnostics:** run `zm doctor --json` and include its output with a
  reproducible command when reporting a problem.
