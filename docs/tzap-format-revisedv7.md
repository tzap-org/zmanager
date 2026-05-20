# tzap Archive Format Specification (v0.7)

| Field | Value |
|---|---|
| **Format version** | 1 |
| **Document version** | 0.7 (draft after scalability hardening review) |
| **Status** | Draft for review, no implementation yet |
| **Owner** | Frank Zhu |
| **Maintainers** | Frank Zhu |
| **Supersedes** | v0.1, v0.2, v0.3, v0.4, v0.5, v0.6 |
| **File extension** | `.tzap` (single-volume) / `.tzap.NNN` (multi-volume) |

## Changelog from v0.6

This revision fixes scalability and implementation-hardening issues
identified after v0.6.

1. **Directory locality is required for very large archives.** Archives
   with more than 100,000 files, or archives claiming cloud/object-store
   optimized directory operations, must include a Directory Hint Table.
   Smaller archives may still omit it and fall back to full shard scans.
   (§15.8, §29.)
2. **Hash-prefix runs are bounded.** Writers may split identical 8-byte
   path-hash prefix runs after a fixed safety ceiling so collision-heavy
   inputs cannot balloon one shard without bound. Readers must scan all
   adjacent shards whose boundary hash equals the target. (§15.4,
   §15.7, §24.)
3. **Padding arithmetic is explicitly checked.** v0.6 already rejected
   `pad_len > N`; v0.7 makes checked subtraction and non-zero padding
   canonical, and rejects the proposed `pad_len = 0` optimization.
   (§6.1.)
4. **Metadata degradation reporting is normative.** Readers must surface
   unsupported tar extension records and metadata-application failures
   instead of silently pretending full fidelity. (§16, §29.)

---

## Abstract

tzap is a multi-volume archive format combining POSIX tar bundling, zstd
compression, authenticated encryption (AEAD), and Reed-Solomon forward
error correction (FEC). It targets long-term archival storage where
confidentiality, integrity, bit-rot resilience, volume-loss resilience,
and random access matter together.

The pipeline is `tar member groups → zstd frames → pack → pad → AEAD →
object-local FEC → stripe → split`.

---

## 1. Design Goals

1. **Confidentiality.** File contents, names, per-file metadata, and the
   random-access index are unreadable without the key. The outer
   container still reveals unavoidable traffic-analysis metadata: number
   of volumes, total bytes per volume, block size, padded encrypted
   object sizes, and IndexRoot location/size.
2. **Integrity.** Modification, truncation, reorder, or substitution are
   detected before plaintext is exposed.
3. **Bit-rot resilience.** Random bit flips within a configurable
   tolerance are repaired transparently.
4. **Volume-loss resilience.** Loss of any N volumes is recoverable when
   parity satisfies `G_parity ≥ N × ceil(G_total / V)`. The CLI
   auto-scales parity from the user's tolerance.
5. **Random access.** Any single file is extractable by reading the
   minimum ordered zstd frame extent(s) that contain that file's
   self-contained tar member group. Typical small files require one
   envelope decrypt and one frame decompress; large files may span
   multiple frames and envelopes.
6. **True single-pass append-only streaming.** No seek-back is required
   at any point in the write path. Writers stream from start to close,
   compatible with POSIX and S3 multipart. Fully non-reopenable
   single-sink streams (pipes/tape) are supported for single-volume
   archives; striped multi-volume archives require concurrent,
   append-reopenable, or locally spooled sinks.
7. **Splittable.** Volume size is configurable; volumes are independent
   files sharing an archive UUID.
8. **Implementable with standard libraries.** Metadata application is
   delegated to off-the-shelf tar libraries.
9. **Localized failure.** Sharded index ensures index corruption affects
   only the shard's files.

## 2. Non-Goals

- Highest possible compression ratio.
- Append or in-place edit.
- Multi-recipient key wrapping; public-key mode.
- Network protocol or chunked transfer.
- Cross-archive deduplication.

## 3. Threat Model

**In scope:** passive observation; active modification, truncation,
reorder, substitution; bit-rot; volume loss (any subset); wrong-passphrase
detection; replay attacks; loss of CryptoHeader or ManifestFooter copies;
mid-stream writer crashes.

**Out of scope:** host side channels; quantum adversaries beyond AES-256
Grover resistance; chosen-plaintext attacks against the compression layer
(CRIME/BREACH); DoS via crafted parameters (mitigated by reader caps).

---

## 4. Conventions

- Little-endian integers.
- `u8`, `u16`, `u32`, `u64`, `i64`.
- Tightly packed structs; explicit padding shown.
- UTF-8, NFC-normalized strings; no BOM, no NUL terminator.
- SHA-256; CRC-32C; HMAC-SHA-256.
- Time: nanoseconds since Unix epoch (signed 64-bit).

---

## 5. Algorithm Registry

```rust
#[repr(u16)]
enum CompressionAlgo { None = 0, ZstdFramed = 1 }

#[repr(u16)]
enum AeadAlgo { AesGcmSiv256 = 1, XChaCha20Poly1305 = 2, AesGcm256 = 3 }

#[repr(u16)]
enum FecAlgo { None = 0, ReedSolomonGF16 = 1, Wirehair = 2 }

#[repr(u16)]
enum KdfAlgo { Raw = 0, Argon2id = 1 }
```

Unknown algorithm IDs are hard errors. Range `0xFF00..0xFFFF` is reserved
for experimental use.

---

## 6. Logical Pipeline

### Write path

```
files
  │ build tar member groups (PAX/ustar records for one logical path)
  ▼
tar member group stream
  │ split into independently-decodable zstd frames
  │ frame boundaries prefer tar member group boundaries
  │ uses pre-trained dictionary if one is declared in IndexRoot
  ▼
zstd frames f₁, f₂, …, fₙ
  │ pack complete frames into envelopes; a frame MUST NOT be split
  │ across envelopes
  ▼
envelopes E_j
  │ in-envelope pad (SUFFIX-MARKER SCHEME, §6.1)
  │ envelope_total_size = next multiple of BLOCK_SIZE such that
  │   |E_j| + pad_len + AEAD_TAG_LEN = envelope_total_size
  ▼
padded plaintexts
  │ AEAD-encrypt
  ▼
encrypted envelopes EE_j
  │ split into BLOCK_SIZE-sized blocks
  ▼
data blocks
  │ object-local FEC for this envelope
  ▼
all blocks (data + parity)
  │ stripe across V volumes: volume = block_index mod V
  ▼
archive.tzap.001 … archive.tzap.V
```

### 6.1 In-envelope padding (suffix-marker scheme)

The padding is appended to the end of the envelope plaintext such that
**the very last byte of the plaintext** carries the marker:

```
For pad_len ∈ [1, 254]   (byte form):
    padding = [0×(pad_len − 1) ‖ pad_len: u8]
    Total padding length = pad_len bytes.

For pad_len ∈ [5, …]     (wide form):
    padding = [0×(pad_len − 5) ‖ pad_len: u32 LE ‖ 0xFF]
    Total padding length = pad_len bytes.
```

The writer chooses byte form for `pad_len ≤ 254` and wide form for
`pad_len ≥ 255`. (Wide form is also legal for `pad_len ∈ [5, 254]`, but
byte form is preferred for efficiency.)

**Reader algorithm:**

```
1. Decrypt envelope; let plaintext have length N (multiple of BLOCK_SIZE,
   minus AEAD tag).
2. If N = 0, reject as malformed.
3. Inspect plaintext[N − 1]:
     - if < 0xFF:  byte form. pad_len = plaintext[N − 1].
     - if = 0xFF:  first verify N ≥ 5, then wide form.
                    pad_len = u32 LE at plaintext[N − 5 .. N − 1].
4. Verify pad_len ≥ 1 and pad_len ≤ N. Reject if not. Compute
   payload_len = checked_sub(N, pad_len); any underflow is malformed.
5. Verify all bytes in plaintext[payload_len .. N − marker_size] are zero.
   This is canonical-format validation. Tampering would already have
   failed AEAD, but a valid archive must still use zero padding.
6. zstd payload = plaintext[0 .. payload_len].
```

Edge cases:

- The minimum `pad_len` is 1, so the very last byte is always a padding
  marker, never zstd data. Writers must always include at least 1 byte
  of padding, even if the data fits exactly — in that case, an extra
  `BLOCK_SIZE` is added to the envelope.
- `pad_len = 0` is not valid in v0.7. The extra block in the exact-fit
  case is an accepted canonical-format cost; it keeps padding parsing
  suffix-only and avoids algorithm-specific length exceptions.
- A legitimate zstd frame's last byte cannot equal a padding marker
  because real zstd data never reaches the last byte of the envelope.

### 6.2 Four nested units

- **Tar member group** = one logical path's complete tar records: any
  path-specific PAX/GNU metadata records followed by the main tar header,
  data bytes, and tar padding.
- **Frame** = one independent zstd frame; unit of random decompression.
  A frame contains bytes from the tar member group stream.
- **Envelope** = packed group of frames; unit of AEAD encryption + padding.
- **Block** = fixed-size storage chunk; unit of striping, CRC, and
  object-local FEC.

`tar member group bytes ⊆ frame plaintexts ⊆ envelope plaintexts ⊆
blocks ⊆ volumes`.

Writers SHOULD start a new zstd frame at the beginning of every tar
member group. They MAY split a very large tar member group across
multiple frames, but FileEntry MUST record the exact ordered frame range
and decompressed offset needed to reconstruct that member group (§15.6).

---

## 7. Archive Layout

### 7.1 Per-volume structure

```
Volume_i =
    VolumeHeader            (fixed 128 B, at offset 0)
    CryptoHeader            (replicated; identical across volumes)
    BlockRecord_…           (this volume's striped blocks)
    ManifestFooter          (replicated; authoritative on every volume in default mode)
    VolumeTrailer           (fixed 128 B, at end-of-file; holds ManifestFooter pointer)
```

### 7.2 Block-to-volume striping

```
volume_index_zero_based = block_index mod V
position_in_volume      = block_index div V
```

### 7.3 Volume-loss recoverability rule

```
G_parity ≥ N × ceil(G_total / V)         for N-volume tolerance.
```

The CLI auto-scales `G_parity` from `--volume-loss-tolerance N` (§27).

### 7.4 Default write mode: parallel volumes

The writer opens V volume sinks concurrently, or uses sinks that can be
reopened for append without rewriting earlier bytes. Each sink receives
blocks based on the modulo mapping. The write path is strictly forward
within each sink: no seek-back or overwrite is required.

### 7.5 Single-stream streaming mode

For a fully non-reopenable single sink (for example a pipe or a tape
stream), conforming v0.7 writers MUST use `stripe_width = 1`.

A writer asked to produce `V > 1` striped volumes with only one
non-reopenable sink MUST either:

- reject the request as incompatible with striped multi-volume streaming;
- spool locally until it can write each target volume forward-only; or
- use append-reopenable sinks and follow §7.4.

It MUST NOT claim true streaming while silently buffering an unbounded
amount of future volume data in memory.

---

## 8. Volume Header

Fixed 128 bytes, at offset 0 of every volume.

```rust
#[repr(C, packed)]
struct VolumeHeader {
    magic:                    [u8; 4],   // b"TZAP"
    format_version:           u16,       // 1
    volume_format_rev:        u16,       // 0
    volume_index:             u32,       // 0-based
    stripe_width:             u32,       // V
    archive_uuid:             [u8; 16],
    session_id:               [u8; 16],
    crypto_header_offset:     u32,       // typically = sizeof(VolumeHeader) = 128
    crypto_header_length:     u32,
    _reserved:                [u8; 68],
    header_crc32c:            u32,       // CRC32C over bytes [0..124]
}
```

**Changed from v0.3:** `manifest_footer_offset` and `manifest_footer_length`
are removed. Those pointers now live in the VolumeTrailer (§12). The
removal frees 12 bytes that are reclaimed into `_reserved`. The
VolumeHeader is now fully write-once: no field requires backfill at
archive close.

---

## 9. CryptoHeader

Replicated identically in every volume. Contains static parameters needed
to derive keys and parse the archive.

```rust
#[repr(C, packed)]
struct CryptoHeaderFixed {
    magic:                    [u8; 4],   // b"TZCH"
    length:                   u32,

    compression_algo:         u16,
    aead_algo:                u16,
    fec_algo:                 u16,
    kdf_algo:                 u16,

    chunk_size:               u32,
    envelope_target_size:     u32,
    block_size:               u32,
    fec_data_shards:          u16,
    fec_parity_shards:        u16,
    index_fec_data_shards:    u16,
    index_fec_parity_shards:  u16,
    index_root_fec_data_shards:    u16,    // may be raised if IndexRoot is large
    index_root_fec_parity_shards:  u16,
    stripe_width:             u32,

    volume_loss_tolerance:    u8,
    bit_rot_buffer_pct:       u8,
    has_dictionary:           u8,         // 1 if IndexRoot contains a zstd dict
    _padding_a:               u8,

    max_path_length:          u32,
    expected_volume_size:     u64,

    _reserved:                [u8; 16],
}
// Followed by:
//   KdfParams       (variable)
//   Extension[]     (TLV list; each value ≤ 256 bytes)
//   header_hmac     [u8; 32]
```

`length` is the total CryptoHeader byte length, including
`CryptoHeaderFixed`, `KdfParams`, all Extension TLVs, the terminator TLV,
and `header_hmac`. `header_hmac = HMAC-SHA-256(mac_key,
CryptoHeader[0 .. length - 32])`. Readers MUST reject a CryptoHeader
whose length is smaller than the fixed header plus HMAC, whose TLV list
does not terminate before `length - 32`, or whose reserved bytes are
non-zero.

### 9.1 Extension TLVs

```rust
#[repr(C, packed)]
struct Extension {
    tag:    u16,        // high bit = critical-must-understand
    length: u32,        // MUST be ≤ 256 in CryptoHeader
    value:  [u8; length],
}
// Terminator: tag = 0x0000, length = 0
```

**Changed from v0.3:** Extension payloads in CryptoHeader are now capped
at 256 bytes. This prevents replication bloat (every volume holds an
identical copy of CryptoHeader; a 100 KiB extension × 1000 volumes = 100
MB of dead weight). Bulky data (e.g. zstd dictionary) must live in
IndexRoot instead.

Reserved tags (all under the 256-byte cap):

| Tag | Type | Purpose |
|---|---|---|
| `0x0001` | UTF-8 | User comment |
| `0x0002` | UTF-8 | Creator tool identifier |
| `0x0003` | `i64` | Creation timestamp (ns) |
| `0x0004` | `[u8; 32]` | SHA-256 of tar stream pre-encryption |
| `0x0005` | UTF-8 | Locale tag for filenames |
| ~~`0x0006`~~ | ~~bytes~~ | **Removed; moved to IndexRoot.** A writer setting `has_dictionary = 1` declares that IndexRoot contains a dictionary at the location given by IndexRoot.dictionary_offset. |

### 9.2 Replication

Every volume contains an identical CryptoHeader. Readers can open any
volume to bootstrap; if one copy fails HMAC, try another.

---

## 10. Block Record

Every on-disk block carries exactly `BLOCK_SIZE` bytes of ciphertext or
parity, wrapped in 20 bytes of framing.

```rust
#[repr(C, packed)]
struct BlockRecord {
    magic:         [u8; 4],          // b"TZBK"
    block_index:   u64,
    kind:          u8,               // 0 = payload-data
                                     // 1 = payload-parity
                                     // 2 = index-root-data
                                     // 3 = index-root-parity
                                     // 4 = index-shard-data
                                     // 5 = index-shard-parity
    flags:         u8,               // bit 0: last data block of encrypted object
                                     // bit 1: synthetic zero block (FEC pad)
    _reserved:     [u8; 2],
    payload:       [u8; BLOCK_SIZE],
    record_crc32c: u32,
}
```

On-disk size: `BLOCK_SIZE + 20` bytes per block.

---

## 11. ManifestFooter

Replicated in every volume in default parallel-volume mode. Located via
the VolumeTrailer (§12). The ManifestFooter is intentionally small and
contains only bootstrap metadata; archive content hashes, tar size,
envelope count, and frame count are encrypted inside IndexRoot.

```rust
#[repr(C, packed)]
struct ManifestFooter {
    magic:                       [u8; 4],   // b"TZMF"
    archive_uuid:                [u8; 16],
    session_id:                  [u8; 16],
    volume_index:                u32,
    is_authoritative:            u8,
    _reserved_byte:              [u8; 3],

    total_volumes:               u32,

    index_root_first_block:      u64,
    index_root_data_block_count: u32,
    index_root_parity_block_count: u32,
    index_root_encrypted_size:   u32,
    index_root_decompressed_size: u32,

    _reserved:                   [u8; 32],

    manifest_hmac:               [u8; 32],
}
```

`manifest_hmac = HMAC-SHA-256(mac_key, ManifestFooter bytes
[0 .. sizeof(ManifestFooter) - 32])`. Reserved bytes MUST be zero.
Completed v0.7 writers MUST set `is_authoritative = 1` in every closed
volume footer they emit. Readers MUST treat `is_authoritative = 0` as a
partial, recovery-only, or future extension footer and must not use it
for random-access bootstrap.

---

## 12. Volume Trailer

Fixed 128 bytes. The absolute last bytes of every volume file. **Holds
the ManifestFooter pointer** so the reader can locate it without
relying on any field in the VolumeHeader.

```rust
#[repr(C, packed)]
struct VolumeTrailer {
    magic:                    [u8; 4],   // b"TZVT"
    archive_uuid:             [u8; 16],
    session_id:               [u8; 16],
    volume_index:             u32,
    block_count:              u64,
    bytes_written:            u64,       // file size up to (not including) trailer

    // Pointer to ManifestFooter within this volume
    manifest_footer_offset:   u64,
    manifest_footer_length:   u32,

    closed_at_ns:             i64,

    _reserved:                [u8; 20],
    trailer_hmac:             [u8; 32],  // HMAC-SHA-256(mac_key, trailer bytes [0..96])
}
```

**Changed from v0.3:** Trailer size grows from 96 to 128 bytes to
accommodate the manifest pointer and reach a round size. Seekable readers
use `file_size − 128` to locate the trailer. Non-seekable readers use a
sidecar manifest or sequential extraction (§12.2, §17.3).

### 12.1 Reader diagnostic logic

| Trailer state | Diagnosis |
|---|---|
| Present, valid HMAC, matching session_id | Clean close |
| Present, invalid HMAC | Tampered or wrong key |
| Present, valid HMAC, mismatched session_id | Mixed volumes from different archives |
| Absent (file shorter than 128 bytes from end matching magic) | Writer crashed or truncated |
| Volume file entirely missing | Sibling lost |

### 12.2 Compatibility with non-seekable read

For environments where the reader cannot seek to the end of the file
the writer may *additionally* emit a sidecar manifest file
(`<base>.tzap.manifest`) containing a copy of the ManifestFooter. A
sidecar enables random access and listing without seeking.

If no sidecar is available, a conforming reader MUST either use
sequential extraction (§17.3) or reject operations that require the
ManifestFooter or IndexRoot. The reader MUST NOT pretend random access is
available on a non-seekable stream without a trusted manifest source.

---

## 13. Key Derivation

### 13.1 Argon2id parameters

```rust
#[repr(C, packed)]
struct Argon2idParams {
    algo_tag:    u16,         // 1
    t_cost:      u32,         // default 3
    m_cost_kib:  u32,         // default 262_144 (256 MiB)
    parallelism: u32,         // default 4
    salt_length: u16,         // 16
    salt:        [u8; salt_length],
}
```

`KdfAlgo::Raw`: user supplies 32-byte `master_key` via keyfile.

### 13.2 Master key and subkeys

```
master_key       = Argon2id(passphrase_utf8_nfc, salt, params, len=32)

enc_key          = HKDF(master_key, b"tzap-v1-enc")
mac_key          = HKDF(master_key, b"tzap-v1-mac")
nonce_seed       = HKDF(master_key, b"tzap-v1-nonce")
index_root_key   = HKDF(master_key, b"tzap-v1-idxroot")
index_shard_key  = HKDF(master_key, b"tzap-v1-idxshard")
index_nonce_seed = HKDF(master_key, b"tzap-v1-idxnonce")
```

### 13.3 Reader-side caps

| Cap | Default |
|---|---|
| `m_cost_kib` | 4 GiB |
| `t_cost` | 100 |
| `chunk_size` | 64 MiB |
| `envelope_target_size` | 64 MiB |
| `block_size` | 1 MiB |
| `stripe_width V` | 4096 |
| `fec_data_shards + fec_parity_shards` | 4096 |
| `max_path_length` | 4096 |
| Total extraction size | 100 GiB or 10× archive |

---

## 14. AEAD Construction

### 14.1 Nonces and AAD

```rust
fn derive_nonce(
    seed: &[u8; 32],
    domain: &[u8],
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    counter: u64,
    len: usize,
) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"tzap-v1-");
    info.extend_from_slice(domain);
    info.extend_from_slice(archive_uuid);
    info.extend_from_slice(session_id);
    info.extend_from_slice(&counter.to_le_bytes());
    hkdf_expand_sha256(seed, &info, len)
}

fn aad(domain: &[u8], archive_uuid: &[u8; 16], session_id: &[u8; 16], counter: u64) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(b"tzap-v1-aad");
    a.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    a.extend_from_slice(domain);
    a.extend_from_slice(archive_uuid);
    a.extend_from_slice(session_id);
    a.extend_from_slice(&counter.to_le_bytes());
    a
}
```

`session_id` is part of both nonce derivation and AAD. This binds every
AEAD object to the write session that produced it and prevents
same-key/same-archive counter replay across sessions, including raw
keyfile mode.

### 14.2 Envelope encryption

```rust
fn encrypt_envelope(j: u64, packed_frames: &[u8]) -> Vec<u8> {
    let tag_len = AEAD_TAG_LEN;
    let total_blocks = max(1,
        (packed_frames.len() + tag_len + BLOCK_SIZE - 1) / BLOCK_SIZE);
    let envelope_total = total_blocks * BLOCK_SIZE;
    let pad_len = envelope_total - packed_frames.len() - tag_len;
    // pad_len ≥ 1 is enforced; if frames fit exactly, add an extra BLOCK_SIZE.

    let mut plaintext = Vec::with_capacity(envelope_total - tag_len);
    plaintext.extend_from_slice(packed_frames);
    append_suffix_padding(&mut plaintext, pad_len);   // §6.1

    let nonce = derive_nonce(
        &nonce_seed, b"envelope", &archive_uuid, &session_id, j, AEAD_NONCE_LEN);
    aead_encrypt(
        &enc_key, &nonce, &aad(b"envelope", &archive_uuid, &session_id, j), &plaintext)
}
```

### 14.3 Index encryption

```rust
fn encrypt_index_root(plaintext: &[u8]) -> Vec<u8> {
    let nonce = derive_nonce(
        &index_nonce_seed, b"idxroot", &archive_uuid, &session_id, 0, AEAD_NONCE_LEN);
    aead_encrypt(
        &index_root_key, &nonce,
        &aad(b"idxroot", &archive_uuid, &session_id, u64::MAX), &padded)
}

fn encrypt_index_shard(s: u64, plaintext: &[u8]) -> Vec<u8> {
    let nonce = derive_nonce(
        &index_nonce_seed, b"idxshard", &archive_uuid, &session_id, s, AEAD_NONCE_LEN);
    aead_encrypt(
        &index_shard_key, &nonce,
        &aad(b"idxshard", &archive_uuid, &session_id, s), &padded)
}
```

The same suffix-marker padding scheme is used for index encryption.

---

## 15. Index Format

### 15.1 Layout

```
Index Root          (small, high-parity FEC, may contain zstd dictionary)
Index Shard 0       (each independently encrypted + FEC)
Index Shard 1
…
Index Shard S−1
```

**Files in the index are globally sorted by `SHA-256(path)`,** not by
path string. This change from v0.3 makes shard hash bounds monotonic, so
binary search by hash is valid.

### 15.2 Index Root

```rust
#[repr(C, packed)]
struct IndexRoot {
    magic:                   [u8; 4],   // b"TZIR"
    version:                 u32,       // 1
    shard_count:             u32,
    frame_count:             u64,
    envelope_count:          u64,
    file_count:              u64,
    payload_block_count:     u64,
    tar_total_size:          u64,       // encrypted; original tar stream bytes
    content_sha256:          [u8; 32],  // SHA-256 of tar stream pre-encryption

    shard_table_offset:      u64,
    envelope_table_offset:   u64,
    frame_table_offset:      u64,

    // Pre-trained zstd dictionary (moved from CryptoHeader in v0.4)
    dictionary_offset:       u64,       // 0 if has_dictionary = 0 in CryptoHeader
    dictionary_length:       u32,       // 0 if no dictionary

    // Optional directory-prefix locality hint table (§15.8)
    directory_hint_offset:   u64,       // 0 if omitted
    directory_hint_length:   u32,       // 0 if omitted

    _padding:                u32,
    _reserved:               [u8; 16],
}
// Plaintext layout (concatenated after IndexRoot header):
//   ShardEntry[shard_count]
//   EnvelopeEntry[envelope_count]
//   FrameEntry[frame_count]
//   if dictionary_length > 0:
//       raw_zstd_dictionary_bytes[dictionary_length]
//   if directory_hint_length > 0:
//       DirectoryHintTable bytes (§15.8)
```

**Important:** the IndexRoot itself is compressed with zstd **without
using the user's dictionary**. The dictionary is found *inside* the
IndexRoot plaintext, so it cannot be a prerequisite for decompressing
IndexRoot. After the reader decompresses IndexRoot and extracts the
dictionary bytes, it loads them into a zstd decompression context for
use on payload envelopes only.

### 15.3 Envelope and Frame tables

```rust
#[repr(C, packed)]
struct EnvelopeEntry {
    envelope_index:        u64,
    first_block_index:     u64,
    data_block_count:      u32,       // encrypted envelope data blocks
    parity_block_count:    u32,       // object-local FEC parity blocks
    encrypted_size:        u32,       // AEAD ciphertext+tag bytes before block padding
    plaintext_size:        u32,       // packed frame bytes before suffix padding
    first_frame_index:     u64,
    frame_count:           u32,
    _reserved:             u32,
}

#[repr(C, packed)]
struct FrameEntry {
    frame_index:           u64,
    envelope_index:        u64,
    offset_in_envelope:    u32,       // compressed frame offset in envelope plaintext
    compressed_size:       u32,
    decompressed_size:     u32,
    flags:                 u32,
    tar_stream_offset:     u64,       // decompressed tar-stream offset of frame start
    _reserved:             u32,
}
```

`offset_in_envelope` is an offset in the decrypted, depadded envelope
plaintext. It points to the start of a complete zstd frame, not to a tar
header. A zstd frame MUST be wholly contained in one envelope.
`FrameEntry.flags` bit 0 means the frame starts at a tar member group
boundary; bit 1 means the frame ends at a tar member group boundary.
These flags are hints for validation and diagnostics; FileEntry remains
the authority for extraction extents.

### 15.4 ShardEntry

```rust
#[repr(C, packed)]
struct ShardEntry {
    shard_index:           u64,
    first_block_index:     u64,       // first block of this shard's encrypted bytes
    data_block_count:      u32,
    parity_block_count:    u32,
    encrypted_size:        u32,
    decompressed_size:     u32,
    file_count:            u32,
    first_path_hash:       [u8; 8],   // first 8 bytes of SHA-256(first file path)
    last_path_hash:        [u8; 8],   // first 8 bytes of SHA-256(last  file path)
}
```

Because the global file table is sorted by `SHA-256(path)`, shards are
contiguous ranges in file-table order. `first_path_hash ≤ last_path_hash`
for every shard, and shard ranges are monotonic.

Writers SHOULD avoid splitting identical `SHA-256(path)[0..8]` prefixes
across shard boundaries while a prefix run remains below
`max_hash_prefix_run_files` (§24). If continuing the run would exceed
that ceiling, the writer MUST split the run across adjacent shards rather
than creating an unbounded shard. This gives normal archives a compact
candidate set while bounding malicious or pathological collision-heavy
inputs.

Readers MUST treat boundary equality defensively. When `target_hash`
equals a candidate shard's `first_path_hash` or `last_path_hash`, the
reader MUST scan adjacent shards in both directions while their boundary
hash also equals `target_hash`, until the equal-boundary run ends or
reader resource caps are reached.

### 15.5 Index Shard plaintext

```rust
#[repr(C, packed)]
struct IndexShardHeader {
    magic:                 [u8; 4],   // b"TZIS"
    shard_index:           u64,
    file_count:            u32,
    file_table_offset:     u32,
    string_pool_offset:    u32,
    string_pool_size:      u32,
}
// Then:
//   FileEntry[file_count]   sorted by SHA-256(path)
//   string_pool: [u8; string_pool_size]
```

### 15.6 FileEntry

```rust
#[repr(C, packed)]
struct FileEntry {
    path_hash:             [u8; 8],   // SHA-256(path)[0..8] — sort key
    path_offset:           u32,       // into this shard's string_pool
    path_length:           u32,
    first_frame_index:     u64,
    frame_count:           u32,
    offset_in_first_frame_plaintext: u32,
    tar_member_group_size: u64,       // metadata records + main tar entry + padding
    file_data_size:        u64,       // logical file payload size, 0 for non-regular entries
    flags:                 u32,
    _reserved:             u32,
}
```

`FileEntry` addresses decompressed frame plaintext, not envelope
plaintext. The target file's tar member group begins at
`offset_in_first_frame_plaintext` within `first_frame_index` and spans
`tar_member_group_size` bytes across `frame_count` ordered zstd frames.
The group includes any path-specific PAX/GNU metadata records needed to
restore the main tar entry.

### 15.7 Lookup path

```
1. Compute target_hash = SHA-256(target_path)[0..8].
2. Open IndexRoot: locate its data/parity block extent via
   ManifestFooter, FEC-repair if needed, decrypt with index_root_key,
   and decompress (without dictionary).
3. Binary search ShardEntry[]: find the shard with
   first_path_hash ≤ target_hash ≤ last_path_hash. If target_hash equals
   any boundary hash, scan adjacent shards in both directions while their
   boundary hash also equals target_hash, subject to reader caps.
4. Read candidate shard data/parity block extent(s) from ShardEntry;
   FEC-repair if needed, decrypt with index_shard_key, and decompress
   (without dictionary).
5. Binary search FileEntry[] by path_hash within each candidate shard.
   On hash match, verify by
   reading the actual path from string_pool and comparing strings.
   Repeat for collisions if any (linear scan around landing position).
6. Extract (first_frame_index, frame_count,
   offset_in_first_frame_plaintext, tar_member_group_size).
7. Look up each FrameEntry in the ordered frame range. For each unique
   envelope_index, read the corresponding EnvelopeEntry blocks,
   FEC-repair using its object-local data/parity counts, AEAD-decrypt,
   and strip suffix padding (§6.1).
8. For each FrameEntry, slice
   envelope_plaintext[offset_in_envelope ..
   offset_in_envelope + compressed_size] and zstd-decode that complete
   frame using the dictionary if has_dictionary = 1.
9. Concatenate decoded frame plaintexts in frame order, discard
   offset_in_first_frame_plaintext bytes from the first frame, and stream
   exactly tar_member_group_size bytes into a tar library.
```

### 15.8 Directory and path-order operations

Because the primary index is sorted by hash, listing files alphabetically
requires either (a) reading all shards, building a full file table in
memory, and sorting by path, or (b) using a path-locality structure.

For typical archives (≤1M files × 40-byte entries + path strings),
option (a) uses ~50 MiB of RAM — acceptable for an offline operation.

Writers MUST include a Directory Hint Table inside IndexRoot when
`file_count > directory_hint_required_file_count` (§24) or when the
archive claims cloud/object-store optimized directory-prefix operations.
Writers MAY include it for smaller archives. The table maps normalized
directory paths to the shard IDs that contain direct children or
descendants of that directory. It is an acceleration structure only:
readers MUST verify actual paths from each shard's string pool before
extracting or listing.

```rust
#[repr(C, packed)]
struct DirectoryHintTable {
    magic:                  [u8; 4],    // b"TZDH"
    version:                u32,        // 1
    entry_count:            u32,
    entry_table_offset:     u32,
    shard_list_offset:      u32,
    string_pool_offset:     u32,
    string_pool_size:       u32,
    _reserved:              u32,
}

#[repr(C, packed)]
struct DirectoryHintEntry {
    dir_hash:               [u8; 8],    // SHA-256(directory_path)[0..8]
    path_offset:            u32,        // into hint string pool
    path_length:            u32,
    shard_list_offset:      u32,        // u32 shard IDs, sorted ascending
    shard_count:            u32,
}
```

Directory-prefix extraction may use the hint table to select candidate
shards, then apply normal path checks. If the table is absent, corrupt,
or incomplete in an archive that requires it, readers SHOULD warn and
fall back to scanning all shards when resource caps permit. If caps do
not permit a full scan, readers MUST fail clearly with
"directory index unavailable."

### 15.9 Structural validation

After decrypting and decompressing IndexRoot or an IndexShard, readers
MUST validate all counts, offsets, lengths, and table sizes against the
actual plaintext buffer before allocating heap storage or indexing into
the buffer. A reader MUST reject a structure if:

- a table offset points before the fixed header or beyond the plaintext;
- `count × sizeof(entry)` overflows or exceeds the plaintext length;
- dictionary, directory-hint, string-pool, or shard-list ranges overflow
  or overlap invalidly;
- `path_offset + path_length` exceeds the owning string pool;
- `shard_count`, `envelope_count`, `frame_count`, or `file_count` exceed
  reader resource caps;
- any object `data_block_count`, `parity_block_count`, or
  `encrypted_size` exceeds the class limits declared in CryptoHeader or
  reader caps.

---

## 16. File Metadata Handling

Metadata preservation is profile-based, not magic. The baseline archive
profile is POSIX ustar: path, type, mode, uid/gid, size, mtime, symlink
targets, and hardlink targets that fit ustar limits. A writer that
claims xattrs, ACLs, sparse files, long paths, non-ASCII names, or
nanosecond timestamps MUST emit the corresponding PAX or GNU tar
extension records inside the same tar member group as the main entry.

The tzap format does not duplicate per-file metadata outside the
encrypted zstd/tar stream. Readers delegate metadata application to a tar
library, but conformance claims MUST name the tar extension profile they
support. A reader that does not support an extension profile may still
extract file contents but MUST report that metadata fidelity is degraded.
CLI readers MUST write this warning to stderr. Library readers MUST
surface it through their diagnostics/error channel. Unsupported PAX/GNU
extension records, failed xattr/ACL application, timestamp precision
loss, sparse-file fallback, and ownership/mode application failures MUST
be reported unless the user explicitly requested best-effort quiet mode.

Path validation (no `..`, no leading `/`, no escape via symlinks) is
performed by the extractor at write and read time.

---

## 17. Read Algorithm

### 17.1 Open

```
1. Read VolumeHeader at offset 0; verify CRC.
2. Read CryptoHeader (at crypto_header_offset, length crypto_header_length).
3. Parse KdfParams; prompt for passphrase or load keyfile.
4. Run KDF → master_key. Derive mac_key. Verify CryptoHeader HMAC.
   On failure: try another volume's CryptoHeader copy. If all fail under
   the same key: abort "wrong key or all CryptoHeader copies corrupt."
5. Derive enc_key, nonce_seed, index_root_key, index_shard_key,
   index_nonce_seed.
6. If the input is seekable:
     a. Determine file size of an available volume (OS stat / Content-Length).
     b. Seek to file_size − 128; read VolumeTrailer.
     c. Verify trailer magic and trailer HMAC. On failure: this volume is
        tampered or truncated; try another volume.
     d. Read ManifestFooter at trailer's manifest_footer_offset / length.
        Verify HMAC.
     e. If ManifestFooter.is_authoritative = 0, this volume is not a
        random-access bootstrap source. Try another volume, use a
        trusted sidecar manifest, or enter sequential recovery mode.
7. If the input is non-seekable:
     a. If a trusted sidecar manifest is supplied, use it for index
        bootstrap.
     b. Otherwise enter sequential extraction mode (§17.3). Random access,
        listing, and directory-prefix extraction are unavailable.
8. If has_dictionary = 1 in CryptoHeader: defer loading until step 11.
```

### 17.2 Random extract

```
9. Read IndexRoot data and parity blocks using
   ManifestFooter.index_root_first_block,
   index_root_data_block_count, and index_root_parity_block_count.
   FEC-repair, trim to index_root_encrypted_size, AEAD-decrypt with
   index_root_key, and zstd-decompress (no dictionary).
10. Validate IndexRoot structure (§15.9); extract shard table,
    envelope table, frame table, and optional directory hint table.
11. If has_dictionary = 1: read the dictionary bytes from IndexRoot
    plaintext at dictionary_offset / dictionary_length. Initialize the
    zstd decompression context with this dictionary. Subsequent payload
    decompression uses it.
12. Compute target_hash = SHA-256(target_path)[0..8].
13. Binary search ShardEntry → candidate shard set, including adjacent
    equal-boundary shards if needed.
14. Read candidate shard data/parity blocks using each ShardEntry's
    object-local FEC counts; repair, trim to encrypted_size,
    AEAD-decrypt with index_shard_key, and zstd-decompress
    (no dictionary).
15. Validate each IndexShard structure (§15.9).
16. Binary search FileEntry by path_hash; resolve collisions via string
    compare; get (first_frame_index, frame_count,
    offset_in_first_frame_plaintext, tar_member_group_size).
17. Read the FrameEntry range and collect the unique EnvelopeEntry
    records needed by those frames.
18. For each needed envelope, read its data and parity blocks using the
    EnvelopeEntry object-local FEC counts, repair if needed, trim to
    encrypted_size, AEAD-decrypt with enc_key, and strip suffix padding.
19. Slice and zstd-decode each complete compressed frame from its
    containing envelope. Concatenate decoded frame plaintexts in order,
    skip offset_in_first_frame_plaintext bytes from the first frame, and
    stream exactly tar_member_group_size bytes to a tar library.
```

### 17.3 Sequential extract

Sequential extraction does not require IndexRoot or ManifestFooter.
Starting from a VolumeHeader and CryptoHeader, the reader streams
payload-data BlockRecords in block order, skipping payload-parity blocks
unless repair is requested. It uses the envelope-end flag to assemble
each encrypted envelope, verifies AEAD, strips suffix padding,
zstd-decompresses each packed frame, and feeds the resulting tar bytes to
a tar library.

For non-seekable single-volume input, this is the required fallback when
no sidecar manifest is available. For multi-volume striped archives, a
non-seekable sequential reader must receive all required volume streams
in a way that allows global block order to be reconstructed; otherwise
it must reject with "random-access manifest required."

### 17.4 Recovery mode

Sequentially read surviving blocks, FEC-repair object by object when the
needed parity blocks are available, decrypt envelopes in order, and hand
the concatenated tar bytes to a tar library. Files in unrecoverable
envelopes manifest as gaps that the tar library reports. For V=1
non-reopenable streaming, loss of the only volume is unrecoverable unless
a separate copy exists.

---

## 18. Forward Error Correction

Default Reed-Solomon over GF(2¹⁶) (Leopard). FEC is object-local: every
encrypted object is encoded independently before its blocks are assigned
global block indices and striped with `block_index mod V`.

Object classes:

- payload envelope: uses `fec_data_shards` / `fec_parity_shards`;
- index shard: uses `index_fec_data_shards` / `index_fec_parity_shards`;
- IndexRoot: uses `index_root_fec_data_shards` /
  `index_root_fec_parity_shards`.

For each object, the writer splits encrypted bytes into
`data_block_count` data blocks, pads with synthetic zero blocks if needed
to satisfy the chosen Reed-Solomon encoder, computes
`parity_block_count` parity blocks, and writes data followed by parity.
The object's table entry records `first_block_index`,
`data_block_count`, `parity_block_count`, and `encrypted_size`; readers
use those fields to fetch exactly the blocks required to repair and
decrypt that object.

Writers MUST size objects so `data_block_count` does not exceed the data
shard limit for that object class. If an envelope, index shard, or
IndexRoot would exceed its limit, the writer must split earlier or choose
larger FEC parameters before writing.

Recoverability for each object: `G_parity ≥ N × ceil(G_total / V)` for
N-volume tolerance, where `G_total = data_block_count +
parity_block_count` for that object. The CLI auto-scaling rule in §27
chooses parity parameters that satisfy this for the configured maximum
data shard count, then applies them to each object.

---

## 19. Write Algorithm

### 19.1 Default: parallel-volume forward-only write

```
1. Generate archive_uuid and session_id.
2. Derive keys.
3. Determine V and N. Auto-scale G_parity via §27.
4. Optionally load a pre-trained zstd dictionary. Set has_dictionary
   accordingly.
5. Build CryptoHeader; compute HMAC.
6. Open V sinks (file handles, S3 multipart streams, etc.).
7. For each sink: write VolumeHeader, then CryptoHeader bytes.
   (Both are now fully write-once. No fields to backfill.)
8. Stream files into tar member groups. For each group:
     - emit any path-specific PAX/GNU metadata records first;
     - emit the main tar header, data, and tar padding;
     - record FileEntry as a decompressed frame extent.
9. Compress tar bytes into independent zstd frames. Prefer one frame per
   tar member group; split very large groups into ordered frame ranges.
   Record FrameEntry.tar_stream_offset and decompressed_size for each
   frame.
10. Pack complete frames into envelopes. A frame MUST NOT be split across
    envelopes. When closing an envelope:
     - suffix-pad and AEAD-encrypt it;
     - split encrypted bytes into data blocks;
     - compute object-local parity blocks;
     - write data+parity blocks through the stripe mapper;
     - record EnvelopeEntry with data/parity counts and frame range;
     - backfill FrameEntry.envelope_index and offset_in_envelope.
11. Build index (compute SHA-256(path) for every FileEntry, sort by hash):
     a. Partition into shards of ~10,000 files each (default)
        while applying the bounded hash-prefix run rule (§15.4).
     b. For each shard: serialize, zstd-compress (no dict), AEAD-encrypt,
        object-local FEC-encode, write blocks (continuing block_index,
        kind 4/5), and record ShardEntry data/parity counts.
     c. Build Index Root: encrypted archive totals + shard table +
        envelope table + frame table + raw dictionary bytes
        (if has_dictionary = 1) + Directory Hint Table when required or
        explicitly requested.
     d. zstd-compress IndexRoot (no dictionary even if has_dictionary = 1),
        AEAD-encrypt with index_root_key, object-local FEC-encode with
        high parity, write blocks (kind 2/3), and record IndexRoot
        data/parity counts for the ManifestFooter.
12. Build ManifestFooter (authoritative).
13. For each sink, in any order (no inter-sink dependencies):
     - Write ManifestFooter at current sink position
     - Write VolumeTrailer with:
         block_count = blocks written to this sink
         bytes_written = sink's current cursor
         manifest_footer_offset = position where footer was written above
         manifest_footer_length = sizeof(ManifestFooter)
         trailer_hmac = HMAC over trailer bytes [0..96]
     - Close the sink. No seek-back ever required.
```

### 19.2 Cloud / S3 compatibility

The above write algorithm is fully compatible with S3 multipart uploads
(or any append-only object storage):

- Each volume is an S3 multipart upload.
- Each "block" or batch of blocks is written as a multipart part (5 MiB+
  per part is the S3 minimum).
- VolumeHeader, CryptoHeader, payload blocks, ManifestFooter, and
  VolumeTrailer are all appended sequentially.
- The CompleteMultipartUpload API finalizes the object.

No part of the v0.7 write path needs to revisit a closed S3 part or to
write at an arbitrary byte offset.

### 19.3 Single-stream streaming mode

Single-sink, fully non-reopenable streaming is supported only with
`stripe_width = 1`. The writer emits one volume forward-only:
VolumeHeader, CryptoHeader, payload/index blocks, ManifestFooter, and
VolumeTrailer.

For `stripe_width > 1`, the writer must use §7.4 behavior. If only one
non-reopenable sink is available, it must reject or spool locally before
writing final volumes. There is no conforming v0.7 mode that round-robins
striped blocks into multiple non-reopenable volume streams without
either concurrent sinks or spooling.

---

## 20. Performance

### 20.1 Padding overhead (v0.7 unchanged from v0.6)

| Envelope size | Block size | Avg overhead |
|---|---|---|
| 1 MiB | 64 KiB | ~3% |
| 4 MiB | 64 KiB | ~0.8% |
| 16 MiB | 64 KiB | ~0.2% |

### 20.2 Dictionary

When `has_dictionary = 1`, the dictionary is loaded once per archive
(after IndexRoot decode) and reused across all payload envelope
decompressions. For small-file corpora, compression ratio improvements
of 30–50% are typical.

### 20.3 Parallelism

Same as v0.6. Envelope-level AEAD, object-local FEC encoding, zstd frame
compression, and per-sink writes are all independent.

---

## 21. Failure Modes

| Failure | Detection | Recovery |
|---|---|---|
| Bit-rot in block payload | record_crc32c | FEC repair |
| Any single volume lost (default mode) | block_index gap | FEC (if parity sized correctly) |
| CryptoHeader corrupt in 1 volume | HMAC fails | Use another volume's copy |
| ManifestFooter corrupt in 1 volume | HMAC fails | Use another volume's copy |
| VolumeTrailer corrupt | HMAC fails | Try another volume; if all corrupt, scan from end for magic |
| V=1 streaming volume lost | Volume file missing | Unrecoverable unless another copy exists |
| Mid-stream writer crash | VolumeTrailer absent or HMAC fails | Reader reports clearly |
| Adversarial volume splice | session_id mismatch | Detected; rejected |
| Index Root unrecoverable | High parity usually saves it | If exhausted, recovery mode |
| Index Shard S unrecoverable | Shard FEC exhausted | Files in shard S lose random-access; sequential extract still works |

---

## 22. Security Analysis

- File data, paths, per-file metadata, archive content hash, file count,
  frame count, envelope count, tar size, and directory hints are inside
  AEAD-protected encrypted objects.
- The outer container necessarily leaks volume count, total volume sizes,
  block size, CryptoHeader parameters, IndexRoot location/size, and
  padded encrypted object sizes.
- Per-envelope padding masks exact packed-frame length within the chosen
  block-size granularity; it does not hide total archive size or object
  count from an observer who can see all volume bytes.
- All plaintext-deriving bytes are authenticated by AEAD and/or HMAC.
- `session_id` is bound into AEAD nonce derivation and AAD, preventing
  same-key/same-archive envelope or index replay across write sessions.
- Padding is authenticated by AEAD; zero padding is additionally checked
  as canonical-format validation.
- Reader caps and structural validation are mandatory before allocation.

---

## 23. Versioning

`format_version` bumps on breaking changes; `volume_format_rev` on
additive changes. Unknown algorithm IDs and critical extensions are hard
errors.

---

## 24. Sizing Defaults

| Parameter | Default | Notes |
|---|---|---|
| `chunk_size` | 256 KiB | |
| `envelope_target_size` | 1 MiB | |
| `block_size` | 64 KiB | |
| `fec_data_shards` | 224 | |
| `fec_parity_shards` | derived from V and N | §27 |
| `index_fec_data_shards` | 16 | |
| `index_fec_parity_shards` | 16 | |
| `index_root_fec_data_shards` | 4 | Increase if dictionary/hints make IndexRoot larger |
| `index_root_fec_parity_shards` | 12 | 75% parity |
| Files per shard | 10_000 | |
| `max_hash_prefix_run_files` | 50_000 | shard split ceiling for identical 8-byte hash prefixes |
| `directory_hint_required_file_count` | 100_000 | Directory Hint Table required above this count |
| `stripe_width V` | 8 | |
| AEAD | AES-256-GCM-SIV | |
| KDF | Argon2id t=3 m=256 MiB p=4 | |
| `volume_loss_tolerance N` | 1 | |
| `bit_rot_buffer_pct` | 5 | |

---

## 25. Magic Numbers

| ASCII | Hex | Purpose |
|---|---|---|
| `TZAP` | `54 5A 41 50` | Volume header |
| `TZCH` | `54 5A 43 48` | CryptoHeader |
| `TZBK` | `54 5A 42 4B` | Block record |
| `TZIR` | `54 5A 49 52` | Index Root |
| `TZIS` | `54 5A 49 53` | Index Shard |
| `TZDH` | `54 5A 44 48` | Directory Hint Table |
| `TZMF` | `54 5A 4D 46` | ManifestFooter |
| `TZVT` | `54 5A 56 54` | VolumeTrailer |

---

## 26. CLI Sketch (non-normative)

```
tzap create  [--volumes V | --volume-size 100M]
             [--volume-loss-tolerance N]
             [--unsafe-parity DATA:PARITY]
             [--password-stdin] [--keyfile FILE]
             [--compression-level 3]
             [--chunk-size 256K] [--envelope-size 1M] [--block-size 64K]
             [--files-per-shard 10000]
             [--dictionary FILE]
             [--exclude PATTERN] -o BASENAME INPUT...

tzap extract [--password-stdin] [--keyfile FILE]
             [--strip-components N] [-C DIR] ARCHIVE [PATH...]

tzap list    [--password-stdin] [--keyfile FILE] [--long]
             [--sort path|hash] ARCHIVE        # sort=hash is faster

tzap verify  [--password-stdin] [--keyfile FILE] [--repair-to DIR] ARCHIVE

tzap info    ARCHIVE

tzap recover [--password-stdin] [--keyfile FILE]
             [--manifest FILE] ARCHIVE...
```

---

## 27. Parity Auto-Scaling (Required CLI Behavior)

```
inputs:
    G_data           = fec_data_shards (default 224)
    V                = stripe_width
    N                = --volume-loss-tolerance (default 1)
    bit_rot_pct      = bit_rot_buffer_pct (default 5)

iterate until G_parity stabilizes:
    G_total          = G_data + G_parity
    G_parity_volume  = N × ceil(G_total / V)
    G_parity_bitrot  = ceil(G_total × bit_rot_pct / 100)
    G_parity         = max(G_parity_volume + G_parity_bitrot, min_parity)
```

The same calculation is applied independently to payload, index-shard,
and IndexRoot FEC classes using their respective `*_data_shards`
defaults unless the user overrides them explicitly.

For defaults (G_data=224, V=8, N=1, bit_rot=5%): the recurrence
stabilizes at `G_parity = 48`. That is 272 encoded shards total, a
17.6% parity fraction of encoded blocks and ~21.4% storage overhead over
data, surviving any 1 volume loss plus ~5% scattered bit-rot.

The CLI emits the chosen parity and the resilience guarantee in plain
English at archive creation. Power users may override with
`--unsafe-parity D:P` combined with an explicit acknowledgment flag.

---

## 28. Reference Implementation Notes

Crate selection unchanged from v0.6. Module layout unchanged.

### 28.1 Test corpus additions for v0.7

- **Padding boundaries**: envelopes whose plaintext + tag is exactly a
  multiple of BLOCK_SIZE (force the writer to add an extra BLOCK_SIZE of
  padding); verify reader correctly truncates.
- **Padding marker collisions**: ensure a zstd frame whose last byte
  *would* be 0xFF cannot occur (because real data never reaches the
  envelope's last byte). Verify by random fuzzing.
- **Wide-form padding**: envelopes where pad_len ≥ 255 (common when
  envelope is large and last frame is small); include malformed
  plaintexts with final byte 0xFF and N < 5. Verify `pad_len > N`
  rejects before subtraction or slicing, and verify `pad_len = 0` is
  rejected.
- **Session-bound AEAD**: two archives with the same raw key,
  archive_uuid, and envelope counter but different session_id; verify
  envelope and index splicing fails authentication.
- **Frame-addressed random access**: files whose tar member group starts
  at frame offset 0, starts mid-frame after another file, and spans
  multiple frames/envelopes. Verify extraction decodes frame ranges and
  slices decompressed frame plaintext, never envelope plaintext.
- **Object-local FEC repair**: corrupt one data block in a payload
  envelope, an index shard, and IndexRoot. Verify each object repairs
  using only its recorded data/parity block extent.
- **Large tar member group**: one regular file larger than
  `envelope_target_size`; verify FileEntry.frame_count > 1 and random
  extraction streams the reconstructed tar member group correctly.
- **Metadata profiles**: ustar-only entry, PAX long path, xattr/ACL
  profile entry, and sparse-file profile entry. Verify unsupported
  profiles report degraded metadata fidelity.
- **Hash-sorted index**: 1M files with various path distributions; verify
  binary search by hash succeeds for every file and rejects non-existent
  paths.
- **Hash collisions**: synthetically construct two paths whose 8-byte
  SHA-256 prefixes match; verify lookup correctly disambiguates by
  string compare. Also force a would-be shard-boundary collision and
  verify the writer extends the shard below `max_hash_prefix_run_files`
  and splits the run above that ceiling. Verify readers scan all adjacent
  equal-boundary shards.
- **Directory hints**: archive with many directories whose files hash
  into distant shards; verify prefix extraction uses hinted shard IDs and
  still validates string-pool paths. Verify archives with more than
  `directory_hint_required_file_count` files include the table, and
  readers warn/fall back or fail clearly when a required table is absent
  or corrupt.
- **Structural validation**: malformed IndexRoot and IndexShard buffers
  with overflowing counts, invalid offsets, and out-of-range string-pool
  paths; verify rejection before allocation.
- **Single-sink streaming rejection**: attempt `stripe_width > 1` with a
  fully non-reopenable sink; verify the writer rejects or requires local
  spooling instead of silently buffering unbounded data.
- **Non-seekable sequential extract**: pipe a single-volume archive into
  the reader without a sidecar; verify sequential envelope extraction
  succeeds while listing/random extract fail clearly.
- **S3 round-trip**: write to actual S3 (or minio) via multipart upload;
  read back via Range requests; no seek-back used.
- **Dictionary**: archives created with and without dictionary; verify
  dictionary correctly bootstraps from IndexRoot.
- **Trailer-from-end**: verify seekable readers locate the trailer from
  `file_size - 128`, then reject cleanly if the required VolumeHeader or
  CryptoHeader bytes are unavailable.
- **Metadata warnings**: unsupported PAX/GNU extension record, failed
  xattr/ACL application, timestamp precision loss, and sparse-file
  fallback all produce diagnostics unless best-effort quiet mode is
  explicitly enabled.

---

## 29. Conformance

A conformant writer:

1. Produces archives whose write sequence is strictly forward
   (no seek-back, no overwrite-in-place).
2. Sorts the file table by `SHA-256(path)[0..8]` globally.
3. Avoids splitting identical 8-byte path-hash prefixes below
   `max_hash_prefix_run_files`, and splits rather than creating
   unbounded shards above that ceiling.
4. Records FileEntry as a decompressed zstd frame extent, never as a tar
   offset inside envelope plaintext.
5. Keeps every zstd frame wholly inside one envelope.
6. Records object-local FEC data/parity counts for every encrypted
   object.
7. Stores the ManifestFooter pointer in the VolumeTrailer.
8. Caps CryptoHeader extension payloads at 256 bytes each.
9. Stores any pre-trained zstd dictionary in IndexRoot, not CryptoHeader.
10. Applies suffix-marker padding (§6.1).
11. Binds AEAD nonce derivation and AAD to both `archive_uuid` and
   `session_id`.
12. Uses `stripe_width = 1` for fully non-reopenable single-sink
   streaming.
13. Emits PAX/GNU tar extension records when claiming metadata beyond
   ustar baseline.
14. Includes a Directory Hint Table when required by §15.8.
15. Auto-scales `G_parity` per §27 unless `--unsafe-parity` is set.

A conformant reader:

1. On seekable input, locates the VolumeTrailer by seeking to
   `file_size - 128`.
2. Locates the ManifestFooter from the trailer or from a trusted sidecar
   manifest, not from VolumeHeader.
3. Rejects non-authoritative ManifestFooter copies for random-access
   bootstrap.
4. On non-seekable input without a sidecar, either performs sequential
   extraction (§17.3) or rejects random-access operations clearly.
5. Strips padding by reading the final byte (and possibly 4 more for
   wide form), not by scanning from the start.
6. Rejects wide-form padding with N < 5 before indexing into the buffer.
7. Searches the file table by `SHA-256(path)` hash, not by string compare
   on partial path bounds.
8. Handles adjacent shard-boundary hash equality defensively by scanning
   all adjacent equal-boundary shards subject to resource caps.
9. Validates IndexRoot and IndexShard structural counts and offsets
   before allocation or indexing.
10. Reconstructs random-access file bytes by decoding the FileEntry
   frame range and slicing decompressed frame plaintext.
11. Uses object-local FEC counts from ManifestFooter, EnvelopeEntry, or
   ShardEntry to repair encrypted objects.
12. Loads the zstd dictionary (if `has_dictionary = 1`) from IndexRoot
   before decompressing any payload envelope.
13. Reports degraded metadata fidelity when the relevant tar extension
   profile is unsupported or metadata application fails.
14. Enforces all resource caps from §13.3.

---

## 30. Open Questions / Future Work

1. Optional full secondary path-sorted index for fast alphabetical
   listing on huge archives. Directory hints accelerate prefix
   extraction but are not a complete sorted listing index.
2. Append support.
3. Multi-recipient key wrap; public-key (age-style) mode.
4. Detached signatures.
5. Mid-stream readable checkpoints for very large streaming archives.
6. Per-file content_sha256 in FileEntry (optional, for random-access
   verification).

---

## 31. Glossary

- **Block** — fixed-`BLOCK_SIZE` ciphertext/parity; FEC unit.
- **Envelope** — packed group of zstd frames; AEAD unit.
- **Frame** — one zstd frame; compression unit.
- **FEC object** — one independently repaired encrypted object: payload
  envelope, index shard, or IndexRoot.
- **Group** — `G_total = data_block_count + parity_block_count` blocks;
  FEC math unit for one object.
- **Shard** — independent encrypted/FEC-protected segment of the file table.
- **Index Root** — small encrypted block with shard/envelope/frame tables
  and (optionally) the zstd dictionary.
- **Tar member group** — all tar records needed to restore one logical
  archive path, including path-specific metadata records and main entry.
- **Stripe width V** — number of volumes; `volume = block_index mod V`.
- **session_id** — random per-write-invocation; distinguishes archives
  even when archive_uuid coincides.
- **Suffix-marker padding** — padding scheme where the last byte of the
  envelope plaintext encodes the padding length (extending to a 5-byte
  wide form for pad_len ≥ 255).

---

## Appendix A: All changes from v0.6 → v0.7

| Section | Change |
|---|---|
| §6.1 | Padding algorithm now requires checked subtraction before slicing and explicitly rejects `pad_len = 0` |
| §15.4 | Hash-prefix runs may split after `max_hash_prefix_run_files` instead of creating unbounded shards |
| §15.7 | Lookup must scan all adjacent equal-boundary shards subject to caps |
| §15.8 | Directory Hint Table required for archives above `directory_hint_required_file_count` or cloud-optimized directory claims |
| §16 | Metadata extension and application failures must be reported unless quiet best-effort mode is explicit |
| §24 | Added `max_hash_prefix_run_files` and `directory_hint_required_file_count` defaults |
| §28.1 | v0.7 test corpus added for padding arithmetic, bounded hash runs, directory hints, and metadata warnings |
| §29 | Conformance requirements updated |

---

*End of v0.7 specification.*
