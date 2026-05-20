# tzap Archive Format Specification (v0.4)

| Field | Value |
|---|---|
| **Format version** | 1 |
| **Document version** | 0.4 (draft after third review round) |
| **Status** | Draft for review, no implementation yet |
| **Owner** | Frank Zhu |
| **Maintainers** | Frank Zhu |
| **Supersedes** | v0.1, v0.2, v0.3 |
| **File extension** | `.tzap` (single-volume) / `.tzap.NNN` (multi-volume) |

## Changelog from v0.3

This revision fixes four specific issues uncovered in the third review
round. Two were genuine wire-format bugs; two were architectural
trade-offs that limited deployment to seekable POSIX filesystems.

1. **Padding marker moved to the last byte (suffix scheme).** v0.3's
   length-prefix layout (`[pad_len, 0×N]`) is unparseable — the reader
   doesn't know where the zstd payload ends and the prefix begins. v0.4
   uses a suffix-marker (`[0×N, …, pad_len]`) so the reader inspects the
   final byte of the decrypted plaintext and truncates from the right.
   (§6, §14.3.)
2. **Index now sorted by `SHA-256(path)`, not by path string.** v0.3's
   ShardEntry stored `first_path_hash` and `last_path_hash` as bounds
   for binary search, but with lexical sorting these are not monotonic
   and the binary search is invalid. v0.4 sorts globally by path hash;
   shard bounds become a strictly increasing numeric sequence. Sequential
   extraction is unaffected (it bypasses the index). (§15.4, §15.5,
   §15.8.)
3. **ManifestFooter pointer moved from VolumeHeader to VolumeTrailer.**
   v0.3 required a small backfill at byte 0 of each volume to record the
   ManifestFooter location, which fails on S3 / object storage / tape.
   v0.4 stores the pointer in the trailer, which is the last thing
   written. The reader seeks from end-of-file (always possible via Range
   requests or LSEEK_END) to find the trailer, then jumps to the
   manifest. (§8, §12, §17.1, §19.1.)
4. **Pre-trained zstd dictionary relocated to IndexRoot.** v0.3 stored
   the dictionary in CryptoHeader Extension `0x0006`, which replicates
   identically to every volume — a 100 KiB dictionary × 1000 volumes =
   100 MB of pure duplication. v0.4 moves the dictionary into IndexRoot,
   stored once. CryptoHeader Extensions are capped at 256 bytes each.
   IndexRoot itself must not use the dictionary (chicken-and-egg).
   (§9.2, §15.2.)

---

## Abstract

tzap is a multi-volume archive format combining POSIX tar bundling, zstd
compression, authenticated encryption (AEAD), and Reed-Solomon forward
error correction (FEC). It targets long-term archival storage where
confidentiality, integrity, bit-rot resilience, volume-loss resilience,
and random access matter together.

The pipeline is `tar → zstd → pack → pad → AEAD → FEC → stripe → split`.

---

## 1. Design Goals

1. **Confidentiality.** Contents (file data, names, sizes, structure,
   timestamps) are unreadable without the key. Per-envelope ciphertext
   sizes are hidden by in-envelope padding.
2. **Integrity.** Modification, truncation, reorder, or substitution are
   detected before plaintext is exposed.
3. **Bit-rot resilience.** Random bit flips within a configurable
   tolerance are repaired transparently.
4. **Volume-loss resilience.** Loss of any N volumes is recoverable when
   parity satisfies `G_parity ≥ N × ceil(G_total / V)`. The CLI
   auto-scales parity from the user's tolerance.
5. **Random access.** Any single file is extractable in one envelope
   decrypt + one frame decompress.
6. **True single-pass append-only streaming.** No seek-back is required
   at any point in the write path. Writers stream from start to close,
   compatible with POSIX, S3 multipart, tape, and pipes.
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
  │ tar (POSIX ustar)
  ▼
tar stream
  │ zstd, multi-frame (end_frame() every chunk_size bytes)
  │ uses pre-trained dictionary if one is declared in IndexRoot
  ▼
zstd frames f₁, f₂, …, fₙ
  │ pack into envelopes: accumulate frames until total ≥ envelope_target_size
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
  │ FEC per group
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
2. Inspect plaintext[N − 1]:
     - if < 0xFF:  byte form. pad_len = plaintext[N − 1].
     - if = 0xFF:  wide form. pad_len = u32 LE at plaintext[N − 5 .. N − 1].
3. Verify pad_len ≥ 1 and pad_len ≤ N. Reject if not.
4. Verify all bytes in plaintext[N − pad_len .. N − marker_size] are zero.
   (Sanity check; tampering would already have failed AEAD, but defensive.)
5. zstd payload = plaintext[0 .. N − pad_len].
```

Edge cases:

- The minimum `pad_len` is 1, so the very last byte is always a padding
  marker, never zstd data. Writers must always include at least 1 byte
  of padding, even if the data fits exactly — in that case, an extra
  `BLOCK_SIZE` is added to the envelope.
- A legitimate zstd frame's last byte cannot equal a padding marker
  because real zstd data never reaches the last byte of the envelope.

### 6.2 Three nested units

- **Frame** = one zstd frame; unit of compression.
- **Envelope** = packed group of frames; unit of AEAD encryption + padding.
- **Block** = fixed-size storage chunk; unit of FEC + per-block CRC.

`frame ⊆ envelope ⊆ blocks ⊆ volumes`.

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

The writer opens V volume sinks concurrently (file handles, S3 multipart
streams, etc.). Each sink receives blocks based on the modulo mapping.
The write path is strictly forward — no seek-back required anywhere.

### 7.5 Single-stream streaming mode

For environments where only one sink can be open at a time, the writer
serializes block emission. Same forward-only semantics; just rotates
through sinks linearly instead of writing to all in parallel.

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
    _reserved:                [u8; 60],
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
    index_root_fec_data_shards:    u16,    // small group; high parity
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
    flags:         u8,               // bit 0: last block of an envelope
                                     // bit 1: synthetic zero block (FEC pad)
    _reserved:     [u8; 2],
    payload:       [u8; BLOCK_SIZE],
    record_crc32c: u32,
}
```

On-disk size: `BLOCK_SIZE + 20` bytes per block.

---

## 11. ManifestFooter

Replicated in every volume in default mode; authoritative only in the
final volume in single-stream streaming mode. Located via the
VolumeTrailer (§12).

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
    envelope_count:              u64,
    frame_count:                 u64,
    payload_block_count:         u64,
    tar_total_size:              u64,

    index_root_first_block:      u64,
    index_root_block_count:      u32,
    index_root_decompressed_size: u32,

    content_sha256:              [u8; 32],

    manifest_hmac:               [u8; 32],
}
```

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

    _reserved:                [u8; 24],
    trailer_hmac:             [u8; 32],  // HMAC-SHA-256(mac_key, all preceding bytes)
}
```

**Changed from v0.3:** Trailer size grows from 96 to 128 bytes to
accommodate the manifest pointer and reach a round size. Reader algorithm
now begins with a seek to `file_size − 128` to read the trailer.

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
(rare; even pipes can be wrapped), the writer may *additionally* emit a
sidecar manifest file (`<base>.tzap.manifest`) containing a copy of the
ManifestFooter. This is informational and not required by the format.

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
fn derive_nonce(seed: &[u8; 32], domain: &[u8], counter: u64, len: usize) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"tzap-v1-");
    info.extend_from_slice(domain);
    info.extend_from_slice(&counter.to_le_bytes());
    hkdf_expand_sha256(seed, &info, len)
}

fn aad(archive_uuid: &[u8; 16], counter: u64) -> [u8; 24] {
    let mut a = [0u8; 24];
    a[..16].copy_from_slice(archive_uuid);
    a[16..].copy_from_slice(&counter.to_le_bytes());
    a
}
```

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

    let nonce = derive_nonce(&nonce_seed, b"envelope", j, AEAD_NONCE_LEN);
    aead_encrypt(&enc_key, &nonce, &aad(&archive_uuid, j), &plaintext)
}
```

### 14.3 Index encryption

```rust
fn encrypt_index_root(plaintext: &[u8]) -> Vec<u8> {
    let nonce = derive_nonce(&index_nonce_seed, b"idxroot", 0, AEAD_NONCE_LEN);
    aead_encrypt(&index_root_key, &nonce, &aad(&archive_uuid, u64::MAX), &padded)
}

fn encrypt_index_shard(s: u64, plaintext: &[u8]) -> Vec<u8> {
    let nonce = derive_nonce(&index_nonce_seed, b"idxshard", s, AEAD_NONCE_LEN);
    aead_encrypt(&index_shard_key, &nonce, &aad(&archive_uuid, s), &padded)
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

    shard_table_offset:      u64,
    envelope_table_offset:   u64,
    frame_table_offset:      u64,

    // Pre-trained zstd dictionary (moved from CryptoHeader in v0.4)
    dictionary_offset:       u64,       // 0 if has_dictionary = 0 in CryptoHeader
    dictionary_length:       u32,       // 0 if no dictionary
    _padding:                u32,
    _reserved:               [u8; 16],
}
// Plaintext layout (concatenated after IndexRoot header):
//   ShardEntry[shard_count]
//   EnvelopeEntry[envelope_count]
//   FrameEntry[frame_count]
//   if dictionary_length > 0:
//       raw_zstd_dictionary_bytes[dictionary_length]
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
    block_count:           u32,
    encrypted_size:        u32,
    decompressed_size:     u32,       // packed_frames length (pre-pad)
    _reserved:             u32,
}

#[repr(C, packed)]
struct FrameEntry {
    frame_index:           u64,
    envelope_index:        u64,
    offset_in_envelope:    u32,       // byte offset of zstd frame within envelope plaintext
    decompressed_size:     u32,
    compressed_size:       u32,
    _reserved:             u32,
}
```

### 15.4 ShardEntry

```rust
#[repr(C, packed)]
struct ShardEntry {
    shard_index:           u64,
    first_block_index:     u64,       // first block of this shard's encrypted bytes
    block_count:           u32,
    encrypted_size:        u32,
    decompressed_size:     u32,
    file_count:            u32,
    first_path_hash:       [u8; 8],   // first 8 bytes of SHA-256(first file path)
    last_path_hash:        [u8; 8],   // first 8 bytes of SHA-256(last  file path)
}
```

Because the global file table is sorted by `SHA-256(path)`, shards are
contiguous ranges in hash space. `first_path_hash ≤ last_path_hash` for
every shard, and shard ranges do not overlap or skip — they tile the
hash space. Binary search by hash is now valid.

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
    envelope_index:        u64,
    offset_in_envelope:    u32,       // points at start of tar header (POSIX 512-byte)
    tar_entry_size:        u64,       // tar header + data + tar's own padding
    flags:                 u32,
    _reserved:             u32,
}
```

`offset_in_envelope` points at the **POSIX tar header** for this file
(not the file data). Metadata application — mode, mtime, uid/gid,
xattrs, ACLs, symlinks, hardlinks, sparse files — is handled by passing
the byte slice to a standard tar library.

### 15.7 Lookup path

```
1. Compute target_hash = SHA-256(target_path)[0..8].
2. Open Index Root: locate via ManifestFooter, decrypt with index_root_key,
   decompress (without dictionary).
3. Binary search ShardEntry[]: find the unique shard with
   first_path_hash ≤ target_hash ≤ last_path_hash.
4. Read that shard's blocks; FEC-repair; decrypt with index_shard_key;
   decompress (without dictionary).
5. Binary search FileEntry[] by path_hash. On hash match, verify by
   reading the actual path from string_pool and comparing strings.
   Repeat for collisions if any (linear scan around landing position).
6. Extract (envelope_index, offset_in_envelope, tar_entry_size).
7. Look up EnvelopeEntry; read envelope blocks; FEC-repair; decrypt with
   enc_key; strip suffix padding (§6.1).
8. zstd-decode forward from offset_in_envelope, USING the dictionary if
   has_dictionary = 1. Decode exactly tar_entry_size bytes.
9. Hand the byte slice to a tar library.
```

### 15.8 Listing in path order (operator convenience)

Because the index is sorted by hash, listing files alphabetically requires:
either (a) read all shards, build full file table in memory, sort by
path, or (b) maintain an optional secondary path-sorted index (deferred,
not in v0.4).

For typical archives (≤1M files × 40-byte entries + path strings),
option (a) uses ~50 MiB of RAM — acceptable for an offline operation.

---

## 16. File Metadata Handling

All file metadata is preserved in the POSIX tar headers stored in the
zstd-compressed stream. The tzap format does not duplicate metadata; it
delegates application to a tar library (e.g. `tar` crate in Rust, GNU
tar, BSD tar).

Path validation (no `..`, no leading `/`, no escape via symlinks) is
performed by the extractor at write and read time.

---

## 17. Read Algorithm

### 17.1 Open

```
1. Determine file size of an available volume (OS stat / Content-Length).
2. Seek to file_size − 128; read VolumeTrailer.
3. Verify trailer magic; defer HMAC verification until keys are derived.
4. Seek to offset 0; read VolumeHeader; verify CRC.
5. Read CryptoHeader (at crypto_header_offset, length crypto_header_length).
6. Parse KdfParams; prompt for passphrase or load keyfile.
7. Run KDF → master_key. Derive mac_key. Verify CryptoHeader HMAC.
   On failure: try another volume's CryptoHeader copy. If all fail under
   the same key: abort "wrong key or all CryptoHeader copies corrupt."
8. Derive enc_key, nonce_seed, index_root_key, index_shard_key,
   index_nonce_seed.
9. Verify trailer HMAC (now that mac_key is known). On failure: this
   volume is tampered or truncated; try another volume.
10. Read ManifestFooter at trailer's manifest_footer_offset / length.
    Verify HMAC.
11. If has_dictionary = 1 in CryptoHeader: defer loading until step 14.
```

### 17.2 Random extract

```
12. Read Index Root blocks (kind 2/3) using ManifestFooter pointer.
    FEC-repair. AEAD-decrypt with index_root_key. zstd-decompress
    (no dictionary).
13. Parse IndexRoot; extract shard table, envelope table, frame table.
14. If has_dictionary = 1: read the dictionary bytes from IndexRoot
    plaintext at dictionary_offset / dictionary_length. Initialize the
    zstd decompression context with this dictionary. Subsequent payload
    decompression uses it.
15. Compute target_hash = SHA-256(target_path)[0..8].
16. Binary search ShardEntry → candidate shard.
17. Read shard blocks (kind 4/5); FEC-repair; AEAD-decrypt with
    index_shard_key; zstd-decompress (no dictionary).
18. Binary search FileEntry by path_hash; resolve collisions via string
    compare; get (envelope_index, offset_in_envelope, tar_entry_size).
19. Look up EnvelopeEntry; read envelope blocks; FEC-repair; AEAD-decrypt
    with enc_key; strip suffix padding.
20. zstd-decode envelope plaintext from offset_in_envelope, using
    dictionary if applicable. Read tar_entry_size bytes (may span
    multiple envelopes for very large files).
21. Hand the byte slice to a tar library; apply metadata.
```

### 17.3 Sequential extract

Decompress all envelopes in order; concatenate plaintexts; stream into
a tar library. The index is not strictly required.

### 17.4 Recovery mode (final volume lost in streaming mode)

Sequentially read surviving blocks, FEC-repair, decrypt all envelopes in
order, hand the concatenated plaintext to a tar library. Files in
unrecoverable envelopes manifest as gaps that the tar library reports.

---

## 18. Forward Error Correction

Default Reed-Solomon over GF(2¹⁶) (Leopard). Groups of `G_total =
G_data + G_parity` blocks. Striped via `block_index mod V`.

Recoverability: `G_parity ≥ N × ceil(G_total / V)` for N-volume
tolerance.

Index FEC: shards use `index_fec_*` parameters (default 16 + 16, 50%
parity). Index Root uses its own higher-parity parameters
`index_root_fec_*` (default 4 + 12, 75% parity).

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
8. Stream files through tar → zstd. For each completed zstd frame:
     - record a FrameEntry (envelope assignment is deferred)
     - append to envelope packer buffer
     - if buffer + tag ≥ envelope_target_size:
         close envelope, encrypt with suffix-padding, split into blocks,
         stripe to sinks, FEC-encode each completed group
         record EnvelopeEntry, backfill FrameEntries with envelope info
9. After last file: close final envelope, pad final FEC group.
10. Build index (compute SHA-256(path) for every FileEntry, sort by hash):
     a. Partition into shards of ~10,000 files each (default)
     b. For each shard: serialize, zstd-compress (no dict), AEAD-encrypt,
        FEC-encode, write blocks (continuing block_index, kind 4/5)
     c. Build Index Root: shard table + envelope table + frame table
        + raw dictionary bytes (if has_dictionary = 1)
     d. zstd-compress IndexRoot (no dictionary even if has_dictionary = 1),
        AEAD-encrypt with index_root_key, FEC-encode with high parity,
        write blocks (kind 2/3)
11. Build ManifestFooter (authoritative).
12. For each sink, in any order (no inter-sink dependencies):
     - Write ManifestFooter at current sink position
     - Write VolumeTrailer with:
         block_count = blocks written to this sink
         bytes_written = sink's current cursor
         manifest_footer_offset = position where footer was written above
         manifest_footer_length = sizeof(ManifestFooter)
         trailer_hmac = HMAC over preceding bytes
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

No part of the V0.4 write path needs to revisit a closed S3 part or to
write at an arbitrary byte offset.

### 19.3 Single-stream streaming mode

One sink at a time. Same forward-only semantics; ManifestFooter is
authoritative only in the final sink's volume. A sidecar file is
optional.

---

## 20. Performance

### 20.1 Padding overhead (v0.4 unchanged from v0.3)

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

Same as v0.3. Envelope-level AEAD, FEC group encoding, and per-sink
writes are all independent.

---

## 21. Failure Modes

| Failure | Detection | Recovery |
|---|---|---|
| Bit-rot in block payload | record_crc32c | FEC repair |
| Any single volume lost (default mode) | block_index gap | FEC (if parity sized correctly) |
| CryptoHeader corrupt in 1 volume | HMAC fails | Use another volume's copy |
| ManifestFooter corrupt in 1 volume | HMAC fails | Use another volume's copy |
| VolumeTrailer corrupt | HMAC fails | Try another volume; if all corrupt, scan from end for magic |
| Final volume lost (streaming mode) | No authoritative footer | Sidecar file or recovery mode |
| Mid-stream writer crash | VolumeTrailer absent or HMAC fails | Reader reports clearly |
| Adversarial volume splice | session_id mismatch | Detected; rejected |
| Index Root unrecoverable | High parity usually saves it | If exhausted, recovery mode |
| Index Shard S unrecoverable | Shard FEC exhausted | Files in shard S lose random-access; sequential extract still works |

---

## 22. Security Analysis

Same as v0.3:

- Confidentiality preserved (file data, names, sizes, structure).
- Per-envelope sizes masked by padding.
- All plaintext-deriving bytes authenticated.
- session_id distinguishes intra-archive volumes from splices.
- Padding now correctly authenticatable (suffix scheme; tampering fails AEAD).
- Reader caps mandatory.

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
| `index_root_fec_data_shards` | 4 | |
| `index_root_fec_parity_shards` | 12 | 75% parity |
| Files per shard | 10_000 | |
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

For defaults (G_data=224, V=8, N=1, bit_rot=5%): G_parity ≈ 45. ~17%
overhead, survives any 1 volume loss plus ~5% scattered bit-rot.

The CLI emits the chosen parity and the resilience guarantee in plain
English at archive creation. Power users may override with
`--unsafe-parity D:P` combined with an explicit acknowledgment flag.

---

## 28. Reference Implementation Notes

Crate selection unchanged from v0.3. Module layout unchanged.

### 28.1 Test corpus additions for v0.4

- **Padding boundaries**: envelopes whose plaintext + tag is exactly a
  multiple of BLOCK_SIZE (force the writer to add an extra BLOCK_SIZE of
  padding); verify reader correctly truncates.
- **Padding marker collisions**: ensure a zstd frame whose last byte
  *would* be 0xFF cannot occur (because real data never reaches the
  envelope's last byte). Verify by random fuzzing.
- **Wide-form padding**: envelopes where pad_len ≥ 255 (common when
  envelope is large and last frame is small).
- **Hash-sorted index**: 1M files with various path distributions; verify
  binary search by hash succeeds for every file and rejects non-existent
  paths.
- **Hash collisions**: synthetically construct two paths whose 8-byte
  SHA-256 prefixes match; verify lookup correctly disambiguates by
  string compare.
- **S3 round-trip**: write to actual S3 (or minio) via multipart upload;
  read back via Range requests; no seek-back used.
- **Dictionary**: archives created with and without dictionary; verify
  dictionary correctly bootstraps from IndexRoot.
- **Trailer-from-end**: verify reader works even when the volume file's
  initial bytes are unreadable (only the last 128 bytes matter for
  initial bootstrap, given a valid trailer).

---

## 29. Conformance

A conformant writer:

1. Produces archives whose write sequence is strictly forward
   (no seek-back, no overwrite-in-place).
2. Sorts the file table by `SHA-256(path)[0..8]` globally.
3. Stores the ManifestFooter pointer in the VolumeTrailer.
4. Caps CryptoHeader extension payloads at 256 bytes each.
5. Stores any pre-trained zstd dictionary in IndexRoot, not CryptoHeader.
6. Applies suffix-marker padding (§6.1).
7. Auto-scales `G_parity` per §27 unless `--unsafe-parity` is set.

A conformant reader:

1. Locates the VolumeTrailer by seeking to `file_size - 128`.
2. Locates the ManifestFooter from the trailer (not from VolumeHeader).
3. Strips padding by reading the final byte (and possibly 4 more for
   wide form), not by scanning from the start.
4. Searches the file table by `SHA-256(path)` hash, not by string compare
   on partial path bounds.
5. Loads the zstd dictionary (if `has_dictionary = 1`) from IndexRoot
   before decompressing any payload envelope.
6. Enforces all resource caps from §13.3.

---

## 30. Open Questions / Future Work

1. Optional secondary path-sorted index for fast alphabetical listing on
   huge archives.
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
- **Group** — `G_total = G_data + G_parity` blocks; FEC math unit.
- **Shard** — independent encrypted/FEC-protected segment of the file table.
- **Index Root** — small encrypted block with shard/envelope/frame tables
  and (optionally) the zstd dictionary.
- **Stripe width V** — number of volumes; `volume = block_index mod V`.
- **session_id** — random per-write-invocation; distinguishes archives
  even when archive_uuid coincides.
- **Suffix-marker padding** — padding scheme where the last byte of the
  envelope plaintext encodes the padding length (extending to a 5-byte
  wide form for pad_len ≥ 255).

---

## Appendix A: All changes from v0.3 → v0.4

| Section | Change |
|---|---|
| §6.1 | Padding is now suffix-marker (last byte = pad_len or 0xFF) instead of length-prefix |
| §8 | VolumeHeader: removed `manifest_footer_offset` / `manifest_footer_length`; reclaimed bytes into `_reserved` |
| §9 | CryptoHeader: added `has_dictionary: u8`; added `index_root_fec_*` shard counts |
| §9.1 | Extension TLV payloads capped at 256 bytes |
| §9.1 | Tag `0x0006` (dictionary) removed from CryptoHeader; relocated to IndexRoot |
| §12 | VolumeTrailer: grew to 128 bytes; added `manifest_footer_offset` and `manifest_footer_length` |
| §15.2 | IndexRoot: added `dictionary_offset` and `dictionary_length`; dictionary bytes follow tables in plaintext |
| §15.3 | FrameEntry, EnvelopeEntry — unchanged from v0.3 |
| §15.4 | ShardEntry hash bounds: now monotonic because the index is sorted by hash |
| §15.5 | IndexShardHeader — unchanged |
| §15.6 | FileEntry: added `path_hash` as the sort key (8 bytes) |
| §15.7 | Lookup path now computes target hash and binary-searches by hash |
| §17.1 | Reader opens by seeking to `file_size - 128` for the VolumeTrailer first |
| §19.1 | Write algorithm: no seek-back at any stage; S3-compatible |
| §27 | Parity auto-scaling unchanged from v0.3 |
| §29 | Conformance requirements updated |

---

*End of v0.4 specification.*
