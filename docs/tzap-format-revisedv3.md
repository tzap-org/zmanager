# tzap Archive Format Specification (v0.3)

| Field | Value |
|---|---|
| **Format version** | 1 |
| **Document version** | 0.3 (draft after second review round) |
| **Status** | Draft for review, no implementation yet |
| **Owner** | Frank Zhu |
| **Maintainers** | Frank Zhu |
| **Supersedes** | v0.1, v0.2 |
| **File extension** | `.tzap` (single-volume) / `.tzap.NNN` (multi-volume) |

## Changelog from v0.2

This revision addresses a second round of external review feedback. Six
substantive changes:

1. **Envelope packing.** Introduces an "envelope" layer between zstd frames
   and storage blocks. Multiple zstd frames are concatenated into a single
   AEAD envelope before padding. This reduces padding overhead from ~5% (per
   small frame) to <0.5% (amortized across an envelope) — critical for
   small-chunk-size or low-compressibility workloads. (§6, §10, §14.)
2. **Tar-pointer FileEntry.** `FileEntry.offset_in_envelope` now points at
   the start of the file's POSIX tar header (not the file data). Metadata
   application — mode, mtime, owner, xattrs, ACLs, symlinks, hardlinks — is
   delegated to off-the-shelf tar libraries. `FileEntry` shrinks from ~200
   to ~64 bytes; sequential and random extraction paths become identical.
   (§15, §16.)
3. **Always-authoritative ManifestFooter.** In the default parallel-volume
   write mode, the ManifestFooter is written authoritatively to every
   volume at archive close. Losing any single volume — including the final
   one — preserves the index pointer. Recovery mode is now an edge-case
   safety net, not a likely-to-trigger fallback. (§9, §11, §19.)
4. **Sharded index.** The file table is split into independently-encrypted,
   independently-FEC-protected shards (default: 10,000 files per shard).
   Localized index corruption now affects only its shard, not the whole
   archive. (§15.)
5. **HMAC-authenticated VolumeTrailer.** The trailer carries a cryptographic
   proof of clean close, derived from `mac_key`. A reader can definitively
   distinguish "writer crashed mid-stream" from "this volume was tampered
   with" from "siblings missing." (§12.)
6. **Auto-scaling parity at the CLI.** The user-facing knob is
   `--volume-loss-tolerance N`. The tool computes `fec_parity_shards`
   from `N`, the stripe width `V`, and the desired bit-rot buffer. Raw
   parity numbers remain available for power users via
   `--unsafe-parity`. The format records the tolerance target in the
   CryptoHeader for downstream validation. (§13.4, §27.)

---

## Abstract

tzap is a multi-volume archive format combining POSIX tar bundling, zstd
compression, authenticated encryption (AEAD), and Reed-Solomon forward
error correction (FEC). It targets long-term archival storage where
confidentiality, integrity, bit-rot resilience, volume-loss resilience,
and random access all matter. Archives can be split into size-bounded
volumes for media or transfer constraints.

The pipeline is `tar → zstd → pack → pad → AEAD → FEC → stripe → split`.

---

## 1. Design Goals

1. **Confidentiality.** Archive contents (file data, names, sizes,
   structure, timestamps) are unreadable without the key. Per-envelope
   ciphertext sizes are hidden by in-envelope padding.
2. **Integrity.** Any modification, truncation, or reordering is detected
   before plaintext is exposed.
3. **Bit-rot resilience.** Random bit flips within a configurable tolerance
   are repaired transparently.
4. **Volume-loss resilience.** Loss of N entire volume files is recoverable
   when parity satisfies `G_parity ≥ N × ceil(G_total / V)`. The CLI
   enforces this by auto-scaling parity from the user's stated tolerance.
5. **Random access.** A single file can be extracted by decrypting one
   envelope, decompressing one zstd frame within it, and slicing the
   resulting tar entry — no full-archive scan.
6. **True single-pass streaming.** Authoritative ManifestFooter on every
   volume means no seek-back is required. Writers stream from start to
   close without revisiting earlier data.
7. **Splittable.** Volume size is configurable; volumes are independent
   files sharing an archive UUID.
8. **Implementable with standard libraries.** Delegating metadata
   application to a stock tar library — and isolating crypto, compression,
   FEC, and storage to independent stages — keeps the reference
   implementation small and auditable.
9. **Localized failure.** Sharded index ensures index corruption affects
   only the shard's files, not the whole archive.

## 2. Non-Goals

- Highest possible compression ratio.
- Append or in-place edit (write-once).
- Multi-recipient key wrapping; public-key mode (deferred).
- Network protocol or chunked transfer.
- Cross-archive deduplication.

## 3. Threat Model

**In scope:**

- Passive adversary reading archive bytes.
- Active adversary modifying, truncating, reordering, or substituting bytes.
- Storage media bit-rot.
- Loss of one or more volume files (including the final).
- Volume reorder, rename, shuffle.
- Wrong-passphrase entry (early detection).
- Frame/envelope replay attacks (defended by AAD binding).
- Loss of CryptoHeader or ManifestFooter in any one volume (defended by
  replication).
- Writer-process crash mid-stream (detected by HMAC'd trailer absence).

**Out of scope:**

- Host machine side channels (timing, cache, memory).
- Quantum adversaries beyond AES-256's Grover resistance.
- Chosen-plaintext attacks against the compression layer (CRIME/BREACH).
- DoS via crafted parameters (mitigated by reader-side caps).

---

## 4. Conventions

- **Endianness:** little-endian.
- **Integers:** `u8`, `u16`, `u32`, `u64`, `i64`.
- **Packed structs:** tightly packed; explicit padding shown.
- **Strings:** UTF-8, NFC-normalized, no BOM, no NUL terminator.
- **Hash:** SHA-256.
- **CRC:** CRC-32C.
- **HMAC:** HMAC-SHA-256.
- **Time:** nanoseconds since Unix epoch (signed 64-bit).

---

## 5. Algorithm Registry

```rust
#[repr(u16)]
enum CompressionAlgo {
    None       = 0,
    ZstdFramed = 1,
}

#[repr(u16)]
enum AeadAlgo {
    AesGcmSiv256       = 1,
    XChaCha20Poly1305  = 2,
    AesGcm256          = 3,
}

#[repr(u16)]
enum FecAlgo {
    None             = 0,
    ReedSolomonGF16  = 1,
    Wirehair         = 2,
}

#[repr(u16)]
enum KdfAlgo {
    Raw      = 0,
    Argon2id = 1,
}
```

Unknown algorithm IDs are a hard error. Range `0xFF00..0xFFFF` is reserved
for experimental use.

---

## 6. Logical Pipeline

### Write path

```
files
  │ tar (POSIX ustar)
  ▼
tar stream
  │ zstd, multi-frame: end_frame() every chunk_size input bytes
  ▼
zstd frames f₁, f₂, …, fₙ   (variable compressed sizes)
  │ pack frames into envelopes:
  │   accumulate frames until total compressed size ≥ envelope_target_size,
  │   then close the envelope
  ▼
envelopes E_j = f_{a_j} ‖ f_{a_j+1} ‖ … ‖ f_{b_j}   (variable size)
  │ in-envelope pad each envelope:
  │   pt_j = E_j ‖ pad(envelope_total_size − |E_j| − AEAD_TAG_LEN)
  │ where envelope_total_size = next multiple of BLOCK_SIZE
  ▼
padded plaintexts pt_j   (|pt_j| + AEAD_TAG_LEN ≡ 0 mod BLOCK_SIZE)
  │ AEAD-encrypt each envelope independently
  ▼
encrypted envelopes EE_j = ct_j ‖ tag_j   (|EE_j| exact multiple of BLOCK_SIZE)
  │ split each EE_j into (|EE_j| / BLOCK_SIZE) blocks
  ▼
data blocks D_k of exactly BLOCK_SIZE bytes
  │ FEC per group: G_data data → G_parity parity blocks
  ▼
all blocks (data + parity)
  │ assign global block_index, map to volume by block_index mod V
  ▼
archive.tzap.001 … archive.tzap.V
```

### Read path

Reverse. For random access:
- Look up file → which envelope contains its tar header
- Read envelope's blocks, FEC-repair as needed
- AEAD-decrypt envelope, strip padding
- zstd-decode from the frame boundary within the envelope's plaintext
- Pass the resulting bytes to a tar library to extract the file

### Three nested units

- **Frame** = one zstd frame. The unit of compression.
- **Envelope** = a packed batch of frames. The unit of AEAD encryption and
  in-envelope padding.
- **Block** = a fixed-size storage chunk. The unit of FEC and per-block CRC.

`frame ⊆ envelope ⊆ blocks ⊆ volumes`.

### In-envelope padding

After packing frames into an envelope of compressed size `S`, the writer
chooses `envelope_total_size = ceil((S + AEAD_TAG_LEN) / BLOCK_SIZE) ×
BLOCK_SIZE`, then pads with:

```
padding_byte = [pad_len: u8, 0, 0, ..., 0]      // pad_len ∈ [1, 254]
padding_wide = [0xFF, pad_len: u32 LE, 0, ...]  // when pad_len ≥ 255
```

The padding bytes are inside the AEAD plaintext and are authenticated by
the tag. Tampering with padding fails AEAD verification.

---

## 7. Archive Layout

### 7.1 Per-volume structure

```
Volume_i =
    VolumeHeader
    CryptoHeader            ; replicated, identical across volumes
    BlockRecord_{...}       ; this volume's striped blocks
    ...
    ManifestFooter          ; replicated; authoritative on every volume
                            ; in default parallel-write mode
    VolumeTrailer           ; HMAC-authenticated; confirms clean close
```

### 7.2 Block-to-volume striping

```
volume_index_zero_based = block_index mod V
position_in_volume      = block_index div V
```

V = stripe width, fixed at archive creation and recorded in `CryptoHeader`
and `VolumeHeader`. All volumes must agree on V.

### 7.3 Volume-loss recoverability rule

```
G_parity ≥ N × ceil(G_total / V)
```

For tolerance to N volume losses. The CLI auto-derives `G_parity` from the
user's `--volume-loss-tolerance N` (§13.4, §27).

### 7.4 Default write mode: parallel volumes open

In the default mode, the writer opens all V volumes simultaneously and
writes blocks to each based on the modulo mapping. At archive close, the
writer emits the (now-known-authoritative) ManifestFooter and trailer to
every volume in turn, then closes them all.

This is the natural mode for striping and the recommended default.

### 7.5 Append-only-streaming mode (degraded)

For environments where only one volume can be written at a time and earlier
volumes cannot be revisited (e.g. piping to cloud upload that commits each
volume immediately), the writer must serialize block emission across volumes.
ManifestFooter is then authoritative only in the final volume; intermediate
volumes carry placeholder footers. A sidecar file
(`<base>.tzap.manifest`) holding a copy of the final ManifestFooter is
strongly recommended for this mode.

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
    stripe_width:             u32,       // V; identical across volumes
    archive_uuid:             [u8; 16],
    session_id:               [u8; 16],  // random per writer invocation
    crypto_header_offset:     u32,       // byte offset within this volume
    crypto_header_length:     u32,
    manifest_footer_offset:   u64,       // u64::MAX if not yet known
    manifest_footer_length:   u32,
    _reserved:                [u8; 48],
    header_crc32c:            u32,       // CRC32C over bytes [0..124]
}
```

`session_id` is a fresh random value generated at writer start. It appears
in every header and trailer of the same archive-write session. Two volumes
with different `session_id` cannot belong to the same archive write —
detected immediately, regardless of whether `archive_uuid` matches.

---

## 9. CryptoHeader

Replicated identically in every volume. Contains all static parameters.

```rust
#[repr(C, packed)]
struct CryptoHeaderFixed {
    magic:                    [u8; 4],   // b"TZCH"
    length:                   u32,

    compression_algo:         u16,
    aead_algo:                u16,
    fec_algo:                 u16,
    kdf_algo:                 u16,

    chunk_size:               u32,       // zstd input per frame
    envelope_target_size:     u32,       // packing target before padding
    block_size:               u32,
    fec_data_shards:          u16,
    fec_parity_shards:        u16,
    index_fec_data_shards:    u16,
    index_fec_parity_shards:  u16,
    stripe_width:             u32,       // matches VolumeHeader

    // Resilience intent (informational; readers may verify)
    volume_loss_tolerance:    u8,        // N from CLI; 0 = bit-rot only
    bit_rot_buffer_pct:       u8,        // extra parity margin in percent
    _padding_a:               [u8; 2],

    max_path_length:          u32,
    expected_volume_size:     u64,

    _reserved:                [u8; 16],
}
// Followed by: KdfParams, Extension TLVs, header_hmac [u8; 32]
```

`header_hmac` = HMAC-SHA-256 over all preceding CryptoHeader bytes using
`mac_key`. Wrong passphrase → wrong `mac_key` → HMAC fails → early abort.

### 9.1 Replication

Every volume contains an identical CryptoHeader. Readers open any volume,
find CryptoHeader at `VolumeHeader.crypto_header_offset`, and verify the
HMAC. If verification fails on one volume's copy (bit-rot), try another.

### 9.2 Extension TLVs

```rust
#[repr(C, packed)]
struct Extension {
    tag:    u16,        // high bit = critical-must-understand
    length: u32,
    value:  [u8; length],
}
// Terminator: tag = 0x0000, length = 0
```

Reserved tags (non-critical):

| Tag | Type | Purpose |
|---|---|---|
| `0x0001` | UTF-8 | User comment |
| `0x0002` | UTF-8 | Creator tool identifier |
| `0x0003` | `i64` | Creation timestamp (ns) |
| `0x0004` | `[u8; 32]` | SHA-256 of tar stream pre-encryption |
| `0x0005` | UTF-8 | Locale tag for filenames |
| `0x0006` | bytes | Pre-trained zstd dictionary |

---

## 10. Block Record

Every block on disk: exactly `BLOCK_SIZE` bytes of ciphertext or parity,
wrapped in 20 bytes of framing.

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
    flags:         u8,               // bit 0: last block of an envelope (informational)
                                     // bit 1: synthetic zero block (padding final FEC group)
    _reserved:     [u8; 2],
    payload:       [u8; BLOCK_SIZE],
    record_crc32c: u32,
}
```

On-disk size: `BLOCK_SIZE + 20` bytes per block.

---

## 11. ManifestFooter

Replicated in every volume. **Default mode (parallel-volume write):
authoritative on every volume.** Append-only-streaming mode: placeholders
in intermediates, authoritative only in the final volume.

```rust
#[repr(C, packed)]
struct ManifestFooter {
    magic:                       [u8; 4],   // b"TZMF"
    archive_uuid:                [u8; 16],
    session_id:                  [u8; 16],
    volume_index:                u32,
    is_authoritative:            u8,        // 1 = final values
    _reserved_byte:              [u8; 3],

    total_volumes:               u32,
    envelope_count:              u64,
    frame_count:                 u64,
    payload_block_count:         u64,
    tar_total_size:              u64,

    // Index root pointer
    index_root_first_block:      u64,
    index_root_block_count:      u32,
    index_root_decompressed_size: u32,

    // Optional content hash
    content_sha256:              [u8; 32],

    manifest_hmac:               [u8; 32],
}
```

`manifest_hmac` covers all preceding ManifestFooter bytes with `mac_key`.

---

## 12. VolumeTrailer

Fixed 96 bytes. HMAC-authenticated. Final structure in each volume.

```rust
#[repr(C, packed)]
struct VolumeTrailer {
    magic:              [u8; 4],   // b"TZVT"
    archive_uuid:       [u8; 16],
    session_id:         [u8; 16],
    volume_index:       u32,
    block_count:        u64,       // blocks written to this volume
    bytes_written:      u64,       // file size up to (not including) this trailer
    closed_at_ns:       i64,       // wall-clock timestamp, informational
    trailer_hmac:       [u8; 32],  // HMAC-SHA-256(mac_key, all preceding bytes)
}
```

### 12.1 Reader diagnostic logic

When opening a multi-volume archive, the reader inspects each volume:

| Trailer state | Diagnosis |
|---|---|
| Present, valid HMAC, matching session_id | Clean close |
| Present, invalid HMAC | Tampered or wrong key |
| Present, valid HMAC, mismatched session_id | Mixed volumes from different archives |
| Absent (file truncated past trailer position) | Writer crashed or transfer truncated |
| Volume file entirely missing | Sibling lost |

This is the distinguishing power the v0.2 spec lacked: "writer crashed
mid-stream" vs. "wrong volumes glued together" vs. "siblings missing"
become unambiguous.

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

For `KdfAlgo::Raw`: user supplies 32-byte `master_key` via keyfile.

### 13.2 Master key

```
master_key = Argon2id(passphrase_utf8_nfc, salt, t_cost, m_cost_kib, parallelism, len=32)
```

### 13.3 Subkeys (HKDF-SHA256, L=32 unless noted)

```
enc_key            = HKDF(master_key, b"tzap-v1-enc")
mac_key            = HKDF(master_key, b"tzap-v1-mac")
nonce_seed         = HKDF(master_key, b"tzap-v1-nonce")
index_root_key     = HKDF(master_key, b"tzap-v1-idxroot")
index_shard_key    = HKDF(master_key, b"tzap-v1-idxshard")
index_nonce_seed   = HKDF(master_key, b"tzap-v1-idxnonce")
```

Domain separation across all uses prevents nonce or key collisions.

### 13.4 Reader-side resource caps

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
| Total decompressed extraction size | 100 GiB or 10× archive size |

A reader must enforce these against its own policy regardless of declared
values.

---

## 14. AEAD Construction

### 14.1 Nonces

```rust
fn derive_nonce(seed: &[u8; 32], domain: &[u8], counter: u64, len: usize) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"tzap-v1-");
    info.extend_from_slice(domain);
    info.extend_from_slice(&counter.to_le_bytes());
    hkdf_expand_sha256(seed, &info, len)
}
```

### 14.2 Associated data

```rust
fn aad(archive_uuid: &[u8; 16], envelope_index: u64) -> [u8; 24] {
    let mut a = [0u8; 24];
    a[..16].copy_from_slice(archive_uuid);
    a[16..].copy_from_slice(&envelope_index.to_le_bytes());
    a
}
```

### 14.3 Envelope encryption with in-envelope padding

```rust
fn encrypt_envelope(j: u64, packed_frames: &[u8]) -> Vec<u8> {
    let tag_len = AEAD_TAG_LEN;       // 16 for current AEADs
    let total_blocks = ((packed_frames.len() + tag_len + BLOCK_SIZE - 1) / BLOCK_SIZE).max(1);
    let envelope_total = total_blocks * BLOCK_SIZE;
    let pad_len = envelope_total - packed_frames.len() - tag_len;

    let mut plaintext = Vec::with_capacity(envelope_total - tag_len);
    plaintext.extend_from_slice(packed_frames);
    append_padding(&mut plaintext, pad_len);     // §6

    let nonce = derive_nonce(&nonce_seed, b"envelope", j, AEAD_NONCE_LEN);
    let aad = aad(&archive_uuid, j);
    aead_encrypt(&enc_key, &nonce, &aad, &plaintext)
}
```

### 14.4 Index shard encryption

```rust
fn encrypt_index_shard(s: u64, plaintext: &[u8]) -> Vec<u8> {
    let nonce = derive_nonce(&index_nonce_seed, b"idxshard", s, AEAD_NONCE_LEN);
    let aad = aad(&archive_uuid, s);
    aead_encrypt(&index_shard_key, &nonce, &aad, &padded_plaintext)
}

fn encrypt_index_root(plaintext: &[u8]) -> Vec<u8> {
    let nonce = derive_nonce(&index_nonce_seed, b"idxroot", 0, AEAD_NONCE_LEN);
    let aad = aad(&archive_uuid, u64::MAX);  // distinct AAD for root
    aead_encrypt(&index_root_key, &nonce, &aad, &padded_plaintext)
}
```

---

## 15. Index Format

### 15.1 Structure

```
Index
├── Index Root           (small; locates shards)
└── Index Shard 0
    Index Shard 1
    ...
    Index Shard S−1      (each independently encrypted + FEC)
```

The Index Root is small (typically <100 KiB) and gets high FEC parity
(default 75%). Each shard is encrypted and FEC-protected independently
with the standard `index_fec_*` parameters.

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
    _reserved:               [u8; 16],
}
// Then in order, all within the (encrypted) IndexRoot plaintext:
//   ShardEntry[shard_count]
//   EnvelopeEntry[envelope_count]
//   FrameEntry[frame_count]
```

The envelope table and frame table live in the Root because they're small
and integer-indexed (no need to shard). The file table is sharded (next).

### 15.3 Envelope and Frame tables

```rust
#[repr(C, packed)]
struct EnvelopeEntry {
    envelope_index:        u64,
    first_block_index:     u64,
    block_count:           u32,
    encrypted_size:        u32,       // includes AEAD tag
    decompressed_size:     u32,       // = packed_frames length pre-pad
    _reserved:             u32,
}

#[repr(C, packed)]
struct FrameEntry {
    frame_index:           u64,
    envelope_index:        u64,
    offset_in_envelope:    u32,       // byte offset within envelope plaintext
                                      //   where this frame's zstd bytes start
    decompressed_size:     u32,       // size after zstd-decode
    compressed_size:       u32,       // size of zstd frame bytes
    _reserved:             u32,
}
```

### 15.4 ShardEntry (FileEntry shards)

```rust
#[repr(C, packed)]
struct ShardEntry {
    shard_index:           u64,
    first_block_index:     u64,       // block index of shard's first block
    block_count:           u32,       // blocks the encrypted shard occupies
    encrypted_size:        u32,
    decompressed_size:     u32,
    file_count:            u32,       // FileEntry count in this shard
    first_path_hash:       [u8; 8],   // first 8 bytes of SHA-256(first path)
    last_path_hash:        [u8; 8],   // first 8 bytes of SHA-256(last path)
}
```

Files within a shard are sorted by path. The hash bounds enable fast shard
lookup via binary search. The full SHA-256 of paths is not stored; 64-bit
truncation is enough for ordering, and the reader confirms by full string
comparison after decrypting the candidate shard.

### 15.5 IndexShard (decrypted, decompressed)

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
//   FileEntry[file_count]   (sorted by path)
//   string_pool: [u8; string_pool_size]   (UTF-8, no NUL terminator)
```

### 15.6 FileEntry (slimmed)

```rust
#[repr(C, packed)]
struct FileEntry {
    path_offset:           u32,       // into this shard's string_pool
    path_length:           u32,
    envelope_index:        u64,       // envelope containing the file's tar header
    offset_in_envelope:    u32,       // byte offset in envelope plaintext
                                      //   pointing at the START OF THE TAR HEADER
    tar_entry_size:        u64,       // tar header (512) + data + tar padding
    flags:                 u32,       // see §15.7
    _reserved:             u32,
}
```

**Crucial change vs. v0.2:** `offset_in_envelope` points at the **start of
the tar header**, not at file data. The reader's random-access path then
hands the byte slice `envelope_plaintext[offset_in_envelope..]` to a
standard tar library (e.g. Rust `tar` crate), which natively handles:

- POSIX mode bits, including special files
- mtime, atime, ctime
- uid/gid/uname/gname
- symlink targets
- hardlink targets
- xattrs (via PAX extended headers)
- POSIX ACLs (via xattrs)
- sparse files (via PAX or GNU extensions)

No tzap-specific cross-platform metadata applicator is required. Sequential
extract (pipe-decompressed-stream-to-tar) and random extract (slice + pass
to tar) become the same code path.

### 15.7 File flags

```
bit 0: directory
bit 1: symlink
bit 2: hardlink
bit 3: regular file (sanity bit; mutually exclusive with 0–2)
bit 4+: reserved (must be zero)
```

Detailed metadata lives in the tar header.

### 15.8 Lookup path

```
1. Open Index Root; decrypt; iterate ShardEntry[].
2. Binary search by (first_path_hash, last_path_hash) to candidate shard.
3. Decrypt and decompress that shard.
4. Binary search FileEntry[] by path string.
5. Get (envelope_index, offset_in_envelope, tar_entry_size).
6. Open envelope (decrypt via index path); slice plaintext at offset.
7. Pass slice to tar library; extract first entry.
```

### 15.9 Failure mode

If shard S is unrecoverable (FEC exhausted on its blocks), only the files
in shard S are inaccessible by random lookup. Other shards' files remain
fully extractable. The unaffected envelopes/frames are still readable;
sequential extraction (which doesn't use the index) still recovers
everything.

---

## 16. File Metadata Handling

All file metadata application is delegated to the tar library used at
extraction. tzap stores:

- The raw tar headers in the compressed stream (always — they're how tar
  works).
- A pointer into the encrypted-then-compressed stream identifying where
  each file's tar header begins.

The tar library reads from that pointer, parses headers, and applies
metadata correctly per the host OS's capabilities.

### 16.1 Path validation

Both at write time and read time, the extractor must:

- Reject paths containing `..` segments.
- Reject absolute paths (leading `/`).
- Reject symlinks whose target escapes the extraction root.
- Reject hardlinks pointing to files outside the archive.

These are policy checks performed by the extractor, not format constraints.

---

## 17. Read Algorithm

### 17.1 Open

```
1. Open any available volume (usually Volume_1).
2. Read VolumeHeader; verify CRC; check session_id consistency
   across other discovered volumes.
3. Read CryptoHeader; parse KdfParams.
4. Prompt for passphrase or load keyfile. Run KDF → master_key.
5. Derive mac_key. Verify CryptoHeader HMAC.
   On failure: try other volumes' CryptoHeader copies.
   On all-failures: abort "wrong key or all CryptoHeaders unrecoverable".
6. Derive enc_key, nonce_seed, index_root_key, index_shard_key, index_nonce_seed.
7. Read VolumeTrailer of every available volume; verify each HMAC.
   This confirms which volumes are intact and not tampered with.
8. Find an authoritative ManifestFooter (is_authoritative=1) with valid HMAC.
   Default mode: every clean-closed volume has one; use any.
   Streaming mode: only final volume has authoritative; if final lost,
   look for sidecar manifest file; if absent, enter recovery mode.
```

### 17.2 Random extract

```
9.  Map global block_index → (volume_i, position) via b mod V.
10. Read Index Root blocks (kind 2/3); FEC-repair; AEAD-decrypt with index_root_key.
11. Parse Index Root; locate target file's ShardEntry by path hash.
12. Read that shard's blocks (kind 4/5); FEC-repair; AEAD-decrypt with index_shard_key.
13. Parse shard; binary search FileEntry by path.
14. Get (envelope_index, offset_in_envelope, tar_entry_size).
15. Look up EnvelopeEntry by envelope_index.
16. Read envelope's blocks; FEC-repair; AEAD-decrypt with enc_key.
17. Strip padding to get packed_frames plaintext.
18. zstd-decode forward from offset_in_envelope, decoding exactly tar_entry_size
    bytes (or following multi-envelope continuation, §17.4).
19. Pass extracted bytes to tar library; apply file metadata.
```

### 17.3 Sequential extract (all files)

Decompress envelopes in order, hand the entire decompressed tar stream to
a tar library. Index is not strictly required — useful only for selective
extraction.

### 17.4 Files spanning multiple envelopes

A file larger than `envelope_target_size` may span envelopes. The tar
library naturally handles this when given a continuous stream: simply
concatenate the decompressed plaintext of envelopes
`envelope_index..envelope_index + ceil(tar_entry_size / envelope_target_size)`.

### 17.5 Recovery mode (final-volume lost AND no sidecar manifest)

```
1. Sequentially read all surviving blocks.
2. Group by FEC group, repair what's recoverable.
3. Decrypt envelopes in block_index order, skipping unrecoverable ones.
4. Concatenate decompressed plaintexts; pass to a tar library streaming
   extractor.
5. Lost envelopes manifest as corrupted tar stream segments; the tar lib
   reports which files were affected.
```

Slow (O(archive size)) but bounded — and now only triggered in the rare
streaming-mode + final-volume-lost + no-sidecar scenario. In the default
parallel-write mode this path is essentially unreachable, because every
volume has an authoritative ManifestFooter.

---

## 18. Forward Error Correction

### 18.1 Reed-Solomon GF(2¹⁶) (Leopard)

Default G_total = G_data + G_parity. Group g's blocks have indices
`[g·G_total, (g+1)·G_total)`. Data blocks first, parity second.

### 18.2 Encoding

```
for each group g:
    pad to G_data data blocks if needed (synthetic zero blocks, flags bit 1)
    parity = Leopard.encode(data, G_parity)
    for each block, wrap in BlockRecord and place at (b mod V, b div V)
```

### 18.3 Recoverability rule (recap from §7.3)

`G_parity ≥ N × ceil(G_total / V)` for N-volume tolerance. The CLI
derives G_parity from `--volume-loss-tolerance N`.

### 18.4 Index-shard FEC

Each shard is FEC-encoded independently using `index_fec_*` params
(default 16 + 16, 50% parity). Shard groups don't cross other shards or
the root.

### 18.5 Index-root FEC

Single small set with higher parity (default 4 + 12, 75% parity, since
total root size is small).

---

## 19. Write Algorithm

### 19.1 Default: parallel-volume single-pass write

```
1. Generate archive_uuid and session_id (CSPRNG).
2. Derive keys from passphrase or keyfile.
3. Determine V (from --volumes or estimated from size budget).
4. Compute G_parity from --volume-loss-tolerance N (see §27).
5. Build CryptoHeader; compute HMAC.
6. Open V volume files in parallel.
7. For each volume: write VolumeHeader (with crypto_header_offset set
   to immediately after; manifest_footer_offset = u64::MAX placeholder),
   then CryptoHeader bytes (identical across all volumes).
8. Initialize:
     - tar writer → zstd encoder (end_frame() every chunk_size)
     - envelope packer: buffer of complete frames
     - FEC group buffer
     - frame_index = 0, envelope_index = 0, block_index = 0
     - in-memory tables: frames, envelopes, files
9. Stream files. For each completed zstd frame f_k:
     - record FrameEntry (envelope_index TBD, offset_in_envelope TBD)
     - append f_k to envelope packer buffer
     - if buffer size + AEAD overhead ≥ envelope_target_size:
         close envelope j = envelope_index
         compute padded plaintext
         encrypted = encrypt_envelope(j, plaintext)
         split into blocks; assign block indices b, b+1, ...
         for each block:
             volume_i = b mod V; position = b div V
             write BlockRecord at (volume_i, position)
         feed into FEC group buffer; when G_data blocks accumulated,
             encode parity, write all G_total blocks (same striping)
         record EnvelopeEntry
         backfill FrameEntry.envelope_index and .offset_in_envelope for
             all frames in this envelope
         envelope_index += 1
10. As tar headers stream past, record FileEntry for each file. Track
    which envelope contains each file's tar header (= the envelope
    being packed when the tar header is emitted).
11. After last file:
     - finalize tar, flush zstd, close final envelope
     - pad final FEC group with synthetic zero blocks
12. Build the index:
     a. Sort FileEntries by path
     b. Split into shards of ~10K entries each
     c. For each shard: serialize, zstd-compress, AEAD-encrypt with
        index_shard_key, split into blocks, FEC-encode, write blocks
        (block indices continue monotonically, kind=4/5)
     d. Build Index Root with envelope table, frame table, shard table
     e. zstd-compress root, AEAD-encrypt with index_root_key, split, FEC, write (kind=2/3)
13. Build authoritative ManifestFooter:
     - total_volumes = V, envelope_count, frame_count, etc.
     - index_root_first_block, index_root_block_count
     - is_authoritative = 1
     - compute manifest_hmac
14. For each of V volumes (still open):
     - write the (identical) authoritative ManifestFooter
     - update VolumeHeader.manifest_footer_offset and length in place
       (small backfill at fixed position; allowed in this mode)
     - write VolumeTrailer with trailer_hmac
     - close the file
```

### 19.2 Append-only-streaming mode

Writer streams one volume at a time. Intermediate volumes get a placeholder
ManifestFooter (`is_authoritative = 0`) and a trailer with HMAC.
The final volume gets the authoritative ManifestFooter. The writer also
emits a sidecar file `<base>.tzap.manifest` containing a copy of the
final ManifestFooter (and its HMAC) for resilience.

---

## 20. Performance Considerations

### 20.1 Parallelism

- Envelope-level AEAD: independent across envelopes.
- Frame-level zstd: independent across frames within an envelope, but
  sequential within the same envelope's plaintext stream (per zstd's
  framing).
- FEC groups: independent.
- Volume writes: V independent file handles in default mode.

### 20.2 Memory

- Envelope packer holds ~`envelope_target_size` of compressed bytes (e.g.
  1 MiB) before flushing.
- One FEC group buffer: `G_total × BLOCK_SIZE` ≈ 16 MiB.
- Index building: full file table in RAM during write (~64 B × file_count
  + path bytes).

### 20.3 Padding overhead (v3)

With envelope packing:

| Envelope size | Block size | Avg padding overhead |
|---|---|---|
| 1 MiB | 64 KiB | ~3% |
| 4 MiB | 64 KiB | ~0.8% |
| 16 MiB | 64 KiB | ~0.2% |

Compare to v0.2 (per-frame padding):

| Chunk size | Block size | Avg padding overhead |
|---|---|---|
| 128 KiB | 64 KiB | ~25% (problematic) |
| 1 MiB | 64 KiB | ~3% |

Envelope packing removes the chunk_size sensitivity entirely.

### 20.4 Small-file corpora

Two complementary mitigations:

1. **Envelope packing** (this revision) — many tiny zstd frames combine
   into one AEAD envelope, eliminating per-frame padding overhead.
2. **Pre-trained zstd dictionary** stored in Extension `0x0006` — restores
   ratio that single-frame zstd's lack of cross-frame backref would
   otherwise lose. Each frame uses the shared dictionary as initial state.

### 20.5 Throughput estimates

Same as v0.2; the new pipeline stages are negligible compared to
compression and AEAD.

---

## 21. Failure Mode Matrix

| Failure | Detection | Recovery |
|---|---|---|
| Bit-rot in block payload | record_crc32c | FEC repair |
| Whole volume lost | block_index gap | FEC if parity covers (§7.3) |
| Multiple volumes lost | Same | FEC if `G_parity ≥ N × ceil(G_total / V)` |
| CryptoHeader corrupt in 1 volume | HMAC fails | Use another volume's copy |
| ManifestFooter corrupt in 1 volume | HMAC fails | Use another volume's copy |
| Final volume entirely lost (default mode) | ManifestFooter still present in surviving volumes | No issue |
| Final volume entirely lost (streaming mode) | No authoritative footer found | Use sidecar manifest if available; else recovery mode |
| Writer crashed mid-stream | VolumeTrailer absent or HMAC invalid | Clear diagnostic; recover up to last full group |
| Volumes from different archives glued together | session_id mismatch | Detected; reject |
| Tampered any byte | AEAD or HMAC failure | Detected; reject |
| Index Root lost | High parity (75%) usually recovers | If exhausted, recovery mode |
| Index Shard S lost | Shard parity exhausted | Files in shard S lose random-access; sequential extract still works |
| Adversarial envelope swap | AAD includes envelope_index | Tag failure |

---

## 22. Security Analysis

### 22.1 Confidentiality

Passive observer learns: format identity, algorithm IDs, geometry, archive
UUID, session ID, total block/volume counts, KDF parameters.

They do NOT learn: file names, sizes, count, paths, content hashes,
per-envelope sizes (in-envelope padding masks them), individual frame
boundaries (frames are inside encrypted envelopes).

### 22.2 Integrity

All plaintext-deriving bytes are authenticated by AEAD. CryptoHeader,
ManifestFooter, and VolumeTrailer each have an HMAC. Per-block CRC32C is
accidental-corruption triage only.

### 22.3 Replay resistance

AEAD AAD binds `(archive_uuid, envelope_index)`. Cross-archive replay or
envelope reorder fails verification.

### 22.4 Session identification

`session_id` in headers, footers, and trailers distinguishes intra-archive
volumes from cross-archive splices. An attacker cannot mix volumes from
two archives even when both share an `archive_uuid` (e.g. one is an
authorized copy and the other is a tampered version), because session_ids
differ.

### 22.5 Padding authentication

In-envelope padding is part of AEAD plaintext; tampering fails the tag.
The length-prefix marker scheme (§6) is unambiguous.

### 22.6 Reader-side resource limits

See §13.4. Required by every conformant reader.

### 22.7 Known unmitigated risks

- Format identity leak (CryptoHeader is unencrypted).
- Weak passphrases.
- Compression-before-encryption (CRIME/BREACH for non-archival use).

---

## 23. Versioning & Compatibility

`format_version` bumps on breaking changes. `volume_format_rev` bumps on
additive changes. Unknown algorithm IDs are hard errors. Critical
extensions (high bit set) are hard errors if unknown.

---

## 24. Sizing Defaults

| Parameter | Default | Notes |
|---|---|---|
| `chunk_size` | 256 KiB | zstd input per frame; smaller is fine now |
| `envelope_target_size` | 1 MiB | typically 4 frames per envelope |
| `block_size` | 64 KiB | |
| `fec_data_shards` | 224 | |
| `fec_parity_shards` | derived from V and N | see §27 |
| `index_fec_data_shards` | 16 | |
| `index_fec_parity_shards` | 16 | 50% parity for shards |
| Index Root FEC | 4 + 12 (75%) | small root, high parity |
| Files per index shard | 10_000 | tunable; smaller = finer-grained loss isolation |
| `stripe_width V` | 8 | matches default G_total/G_parity at N=1 |
| AEAD | AES-256-GCM-SIV | |
| KDF | Argon2id t=3, m=256 MiB, p=4 | |
| zstd level | 3 | |
| `volume_loss_tolerance N` | 1 | survive losing any single volume |

---

## 25. Magic Numbers

| ASCII | Hex bytes | Purpose |
|---|---|---|
| `TZAP` | `54 5A 41 50` | Volume header |
| `TZCH` | `54 5A 43 48` | CryptoHeader |
| `TZBK` | `54 5A 42 4B` | Block record |
| `TZIR` | `54 5A 49 52` | Index Root (after decrypt) |
| `TZIS` | `54 5A 49 53` | Index Shard (after decrypt) |
| `TZMF` | `54 5A 4D 46` | ManifestFooter |
| `TZVT` | `54 5A 56 54` | VolumeTrailer |

---

## 26. CLI Sketch (non-normative)

```
tzap create  [--volumes V | --volume-size 100M]
             [--volume-loss-tolerance N]        # default 1
             [--unsafe-parity DATA:PARITY]      # power-user override
             [--password-stdin] [--keyfile FILE]
             [--compression-level 3]
             [--chunk-size 256K] [--envelope-size 1M] [--block-size 64K]
             [--files-per-shard 10000]
             [--dictionary FILE]
             [--exclude PATTERN] -o BASENAME INPUT...

tzap extract [--password-stdin] [--keyfile FILE]
             [--strip-components N] [-C DIR] ARCHIVE [PATH...]

tzap list    [--password-stdin] [--keyfile FILE] [--long] ARCHIVE
tzap verify  [--password-stdin] [--keyfile FILE] [--repair-to DIR] ARCHIVE
tzap info    ARCHIVE                # no key required
tzap recover [--password-stdin] [--keyfile FILE]
             [--manifest FILE] ARCHIVE...
```

---

## 27. Parity Auto-Scaling (Required CLI Behavior)

The CLI computes `fec_parity_shards` from user inputs:

```
inputs:
    G_data           = fec_data_shards (default 224)
    V                = stripe_width
    N                = --volume-loss-tolerance (default 1)
    bit_rot_pct      = bit-rot buffer in percent (default 5)

derived:
    per_vol_loss     = ceil((G_data + G_parity_estimate) / V)
    G_parity_volume  = N × per_vol_loss
    G_parity_bitrot  = ceil((G_data + G_parity_estimate) × bit_rot_pct / 100)
    G_parity_total   = max(G_parity_volume + G_parity_bitrot, minimum_parity)

solve iteratively:
    start with G_parity = G_parity_estimate (e.g. 32)
    recompute until stable
```

For typical defaults (`G_data = 224, V = 8, N = 1, bit_rot_pct = 5`):

```
per_vol_loss     = ceil(256/8) = 32
G_parity_volume  = 1 × 32      = 32
G_parity_bitrot  = ceil(256 × 0.05) = 13
G_parity_total   = 32 + 13     = 45  (fixed-point converges)
```

Result: `G_parity = 45` (~17% overhead). Survives any single volume loss
plus ~5% scattered bit-rot.

For `N = 0` (bit-rot-only mode): `G_parity = ceil(G_total × bit_rot_pct /
100)`, typically 12 (~5% overhead).

The CLI emits the chosen parity and the resilience guarantee in plain
English at archive creation time, e.g.:

```
Creating archive with 8 volumes, 224+45 FEC (~17% overhead).
Survives: loss of any 1 volume + up to 5% bit-rot across remaining data.
```

Power users can override with `--unsafe-parity 224:32`, which the tool
accepts only if combined with an explicit acknowledgment flag.

---

## 28. Reference Implementation Notes

Target language: Rust.

### 28.1 Crate selection

| Need | Crate | Notes |
|---|---|---|
| zstd | `zstd` (gyscos) | Frame APIs |
| AES-256-GCM-SIV | `aes-gcm-siv` (RustCrypto) | |
| XChaCha20-Poly1305 | `chacha20poly1305` (RustCrypto) | |
| Argon2id | `argon2` (RustCrypto) | |
| HKDF | `hkdf` (RustCrypto) | |
| HMAC | `hmac` (RustCrypto) | |
| CRC32C | `crc32c` | |
| Leopard-RS | `reed-solomon-erasure` or equivalent | Verify maintenance |
| **tar (DELEGATED)** | `tar` crate | Reads/writes streams and applies metadata; no custom applicator |
| Parallel | `rayon` | |
| UUID | `uuid` | |
| CLI | `clap` v4 | |

### 28.2 Module layout

```
crates/
  tzap-format/    # wire-format types (no crypto deps)
  tzap-crypto/    # KDF, AEAD, HMAC, HKDF
  tzap-fec/       # Leopard wrapper
  tzap-stripe/    # block↔(volume, position) math
  tzap-pack/      # envelope packer + padder
  tzap-io/        # block reader/writer, volume manager
  tzap-archive/   # high-level create/extract/list/verify/recover
  tzap-cli/       # binary
```

`tzap-format` remains crypto-free.

### 28.3 Test corpus

Same as v0.2, plus:

- **Envelope-boundary cases**: file's tar header lands at exact envelope
  boundary; envelope contains exactly 1 frame; envelope contains 100+
  tiny frames.
- **Index shard isolation**: deliberately corrupt one shard's blocks
  beyond FEC tolerance; verify only that shard's files are inaccessible
  by random lookup while sequential extract still recovers them.
- **Streaming-mode + final-volume-lost + sidecar**: verify sidecar
  manifest restores random access without recovery mode.
- **Mid-stream crash simulation**: kill the writer at various points;
  verify reader diagnostic accurately reports "interrupted" vs "missing"
  vs "tampered."
- **Parity auto-scaling**: V = 2, 4, 8, 16, 32; N = 0, 1, 2; verify
  computed parity meets the recoverability rule.
- **Tar library delegation**: extract archive containing every supported
  POSIX entry type (regular, dir, symlink, hardlink, FIFO, device,
  xattrs, ACLs, sparse). Verify metadata is preserved end-to-end via the
  tar library, not via tzap-specific code.

---

## 29. Conformance

A conformant writer produces archives that any conformant reader can:

1. Verify (all HMACs, all CRCs, all AEAD tags).
2. List (Index Root + ShardEntry iteration).
3. Sequentially extract via tar library.
4. Randomly extract any single file via index → envelope → tar slice.
5. Distinguish missing/tampered/interrupted volumes from intact ones.
6. Recover surviving shards' files even when other shards are unrecoverable.

A conformant reader rejects:

1. Unknown `format_version`.
2. Unknown critical extensions.
3. Unknown algorithm IDs.
4. Resource requests exceeding caps.
5. Any AEAD tag, HMAC, or session_id mismatch.

A conformant CLI:

1. Computes `fec_parity_shards` from `--volume-loss-tolerance N` per §27.
2. Refuses to write parity below the computed minimum unless
   `--unsafe-parity` is explicitly set.
3. Prints the resilience guarantee in plain English at archive creation.

---

## 30. Open Questions / Future Work

1. Pre-trained zstd dictionary tooling (extension `0x0006` is defined;
   training UX is not).
2. Append support.
3. Multi-recipient key wrap; public-key (age-style) mode.
4. Detached signatures for archive authorship.
5. Per-file encryption keys for selective disclosure.
6. Network-resilient streaming variant with checkpointed manifests at
   periodic intervals (mid-stream readable checkpoints).
7. Per-file content_sha256 — currently delegated to tar library or
   computed by sequential pass at verify time; consider promoting to
   FileEntry as an optional field if random-access checksum becomes a
   common use case.

---

## 31. Glossary

- **Block** — fixed `BLOCK_SIZE` bytes of ciphertext/parity; unit of FEC.
- **Envelope** — packed group of zstd frames; unit of AEAD encryption.
- **Frame** — one zstd frame; unit of compression.
- **Group** — `G_total = G_data + G_parity` blocks; unit of FEC math.
- **Shard** — independent encrypted/FEC-protected segment of the file table.
- **Index Root** — small encrypted table with envelope/frame/shard pointers.
- **Stripe width V** — number of volumes; block→volume = b mod V.
- **session_id** — random per-write-invocation identifier; distinguishes
  archives even when archive_uuid coincides.

---

## Appendix A: Comparison to v0.2 (changes only)

| Feature | v0.2 | v0.3 |
|---|---|---|
| AEAD unit | one zstd frame | one envelope (multiple frames) |
| Padding overhead | ~5% (bad at small chunks) | <1% (amortized) |
| FileEntry size | ~200 bytes | ~40 bytes |
| Metadata application | custom per-OS code in tzap | delegated to tar library |
| Sequential vs random extract | two code paths | one code path |
| Index structure | one monolithic compressed table | sharded; localized loss |
| ManifestFooter | only authoritative in final volume | authoritative in every volume (default mode) |
| Final volume loss | recovery mode (slow) | no impact (default mode) |
| VolumeTrailer | CRC only | HMAC + session_id |
| Mid-stream crash diagnosis | ambiguous | clear |
| CLI parity input | raw shard counts | `--volume-loss-tolerance N`, auto-scaled |
| Wrong-parity-for-V archives | "warning emitted" | "refused unless --unsafe-parity" |

---

## Appendix B: Worked Example (1 GiB archive, revised)

**Input:** 1 GiB of mixed content. ~10,000 files of mixed sizes.

**Parameters (defaults):**
- `chunk_size = 256 KiB` (zstd frames)
- `envelope_target_size = 1 MiB`
- `block_size = 64 KiB`
- `V = 8`
- `--volume-loss-tolerance N = 1`
- `--bit-rot-buffer 5%`

**Auto-scaling computes:**
- `G_data = 224`
- `G_parity = 45` (≈ 17% overhead)
- `G_total = 269`

**Pipeline:**

- Tar: ~1.001 GiB.
- Zstd: ~400 MiB compressed; ~4000 zstd frames at 256 KiB chunk_size,
  ~100 KiB compressed each.
- Envelope packing: ~10 frames per 1 MiB envelope → ~400 envelopes.
- Per envelope: 1 MiB payload + AEAD tag (16 B) → padded to 17 blocks ×
  64 KiB = 1.0625 MiB. Padding overhead ≈ 6% in this borderline case;
  drops to <1% at larger envelope_size.
- Total payload data blocks: 400 × 17 = 6800 blocks.
- FEC groups: ceil(6800 / 224) = 31 groups.
- Parity blocks: 31 × 45 = 1395.
- Total payload blocks: ~8195.

**Striping across 8 volumes:**
- Blocks per volume: ~1025.
- Per-volume payload: 1025 × (64 KiB + 20 B) ≈ 66 MiB.

**Index:**
- 10,000 FileEntries → 1 shard (under 10K threshold) or 2 shards if just
  over.
- Shard size: ~10K × 40 B + path strings (~500 KiB) → ~900 KiB pre-compress.
- After zstd: ~150 KiB. Encrypted + FEC (16+16): ~360 KiB.
- Index Root: ~10 KiB; encrypted + FEC (4+12): ~80 KiB.
- Index total: ~440 KiB, ~7 blocks. Striped: <1 block per volume.

**Total archive:** ~530 MiB across 8 volumes (~66 MiB each).

**Resilience:**
- Any 1 of 8 volumes lost: fully recoverable.
- Bit-rot: ~5% scattered corruption recoverable.
- CryptoHeader lost in up to 7 volumes: still recoverable from any one.
- ManifestFooter lost in up to 7 volumes: still recoverable (default mode).
- Index shard 0 unrecoverable + shard 1 intact: files in shard 0 lose
  random-access but recover via sequential extraction.

---

*End of v0.3 specification.*
