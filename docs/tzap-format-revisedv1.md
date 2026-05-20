# tzap Archive Format Specification

| Field | Value |
|---|---|
| **Format version** | 1 |
| **Document version** | 0.1 (draft for review) |
| **Status** | Draft, no implementation yet |
| **Owner** | Frank Zhu |
| **Maintainers** | Frank Zhu |
| **File extension** | `.tzap` (single-volume) / `.tzap.NNN` (multi-volume) |
| **Suggested MIME type** | `application/vnd.tzap` |
| **Suggested UTI** | `dev.tzap.archive` |

---

## Abstract

tzap is a multi-volume archive format combining POSIX tar bundling, zstd
compression (multi-frame, random-access capable), authenticated encryption
(AEAD), and Reed-Solomon forward error correction (FEC). It targets long-term
archival storage where confidentiality, integrity, bit-rot resilience, and
volume-loss resilience matter together — and where the archive may need to be
split into size-bounded pieces for media or transfer constraints.

The pipeline is `tar → zstd → AEAD → FEC → split`. The format name `tzap`
mnemonically tracks that ordering: **t**ar, **z**std, **a**ead, **p**arity.

---

## 1. Design Goals

1. **Confidentiality.** Archive contents (file data, file names, sizes,
   directory structure, timestamps) are unreadable without the key.
2. **Integrity.** Any modification, truncation, or reordering of archive bytes
   is detected before plaintext is exposed.
3. **Bit-rot resilience.** Random bit flips within a configurable tolerance
   are repaired transparently.
4. **Volume-loss resilience.** Loss of an entire volume is recoverable if FEC
   parity was budgeted for it.
5. **Random access.** A single file can be extracted without reading or
   decrypting the rest of the archive.
6. **Streaming.** Both write and read paths can operate in a single pass when
   seekable output is available; non-seekable output is supported via a
   documented two-pass write.
7. **Splittable.** Output can be capped at any target volume size; volumes are
   independent files that share an archive UUID.
8. **Format stability.** A version byte and algorithm IDs make future changes
   non-breaking for old archives.
9. **Auditable.** Wire format is fully specified by struct layouts and
   construction recipes. No undefined fields, no hidden state.

## 2. Non-Goals

- Highest possible compression ratio. Per-frame zstd gives up some ratio for
  random access; this is intentional.
- Append or in-place edit. tzap is write-once; modifications require re-pack.
- Multi-recipient encryption / key wrapping. Single symmetric key per archive
  (passphrase or keyfile). Public-key and multi-recipient modes are deferred.
- Network or chunked-transfer protocol. tzap is a file format, not a wire
  protocol.
- Cross-archive deduplication.

## 3. Threat Model

**In scope:**

- Passive adversary reading archive bytes (e.g. compromised cloud storage).
- Active adversary modifying, truncating, reordering, or substituting
  archive bytes.
- Storage media bit-rot (single-bit and burst errors within FEC tolerance).
- Loss or absence of one or more volume files.
- Volume reordering, renaming, or shuffling.
- User entering the wrong passphrase (must be detected early, before
  expensive operations).
- Replay attacks where an attacker substitutes a valid block from one frame
  into another frame's position (defended by binding `frame_index` and
  `archive_uuid` into the AEAD AAD).

**Out of scope:**

- Side-channel attacks on the host machine (timing, cache, memory disclosure).
- Adversaries with access to the user's KDF parameters *and* a strong
  side channel on key derivation.
- Quantum adversaries; this format uses AES-256 (≈128-bit post-quantum
  security against Grover) and is acceptable for archival but does not claim
  post-quantum security beyond that.
- Adaptive chosen-plaintext attacks against the compression layer
  (CRIME/BREACH-class). tzap compresses before encrypting; this is acceptable
  for static archives but unsuitable for interactive/streaming contexts where
  an attacker can mix chosen plaintext with sensitive data.
- Denial-of-service via crafted archives that trigger huge memory allocations
  (mitigated by reader-side sanity limits, see §22.6).

---

## 4. Conventions

- **Endianness:** all multi-byte integers are little-endian.
- **Integer types:** `u8`, `u16`, `u32`, `u64` (unsigned). Signed: `i64`.
- **Packed structs:** all on-disk structs are tightly packed; no implicit
  padding. Explicit padding is shown.
- **String encoding:** UTF-8, no BOM, no NUL terminator. Lengths are
  byte counts, not codepoint counts. NFC normalization is recommended.
- **Hash function:** SHA-256.
- **CRC:** CRC-32C (Castagnoli polynomial, 0x1EDC6F41).
- **Authentication:** "authenticated" = covered by an AEAD tag or the global
  header HMAC. CRC32C protects against accidental corruption only, not
  adversarial modification.
- **Time:** nanoseconds since Unix epoch (signed 64-bit). Timestamps before
  1970 are represented as negative values.

Struct definitions are shown in Rust syntax for clarity; the wire format is
language-agnostic.

---

## 5. Algorithm Registry

```rust
#[repr(u16)]
enum CompressionAlgo {
    None       = 0,
    ZstdFramed = 1,   // default; each chunk produces an independent zstd frame
}

#[repr(u16)]
enum AeadAlgo {
    AesGcmSiv256       = 1,   // default; nonce-misuse-resistant
    XChaCha20Poly1305  = 2,   // alternative; large nonce, random-nonce-safe
    AesGcm256          = 3,   // discouraged for archives (nonce-fragile)
}

#[repr(u16)]
enum FecAlgo {
    None             = 0,
    ReedSolomonGF16  = 1,   // default; Leopard-RS implementation
    Wirehair         = 2,   // optional; rateless fountain code
}

#[repr(u16)]
enum KdfAlgo {
    Raw      = 0,   // user supplies a 32-byte master key (keyfile)
    Argon2id = 1,   // default; passphrase-derived
}
```

**Negotiation rules:**

- Any unknown algorithm ID is a hard error. Readers must not "best-effort
  guess."
- Reserved range for experimental algorithms: `0xFF00..0xFFFF` per enum.
  Implementations may emit values in this range; readers may accept them but
  must not treat them as standardized.

---

## 6. Logical Pipeline

### Write path

```
files
  │ tar (POSIX ustar, no compression, no auto-metadata stripping)
  ▼
tar stream
  │ zstd, multi-frame: emit a new frame every CHUNK_SIZE input bytes
  ▼
frames F₁, F₂, …, Fₙ   (variable compressed size)
  │ AEAD-encrypt each frame independently
  ▼
encrypted frames EFₖ = ctₖ ‖ tagₖ
  │ split each EFₖ into BLOCK_SIZE-sized blocks (last block zero-padded)
  ▼
data blocks D₁, D₂, …, Dₘ   (all of size BLOCK_SIZE)
  │ FEC per group: G_data data blocks → G_parity parity blocks
  ▼
all blocks (data + parity)
  │ pack into volumes by target volume size
  ▼
archive.tzap.001, archive.tzap.002, …
```

### Read path

Reverse: per-volume block reads → FEC group repair → block reassembly → AEAD
decryption → zstd decode → tar extraction.

### Two distinct units

- **Frame** = a content unit. One zstd frame = one AEAD encryption unit. The
  unit at which random access is possible.
- **Block** = a storage unit. Fixed size. The unit of FEC and per-block
  integrity checks.

A frame's encrypted bytes span one or more contiguous blocks. Blocks never
span frames. The last block of each frame is zero-padded to `BLOCK_SIZE`.

---

## 7. Archive Layout

```
Archive  =  Volume_1 ‖ Volume_2 ‖ … ‖ Volume_K

Volume   =  VolumeHeader
            [GlobalHeader]              ; present in Volume_1 only
            BlockRecord_1
            BlockRecord_2
            …
            BlockRecord_n
            VolumeFooter
```

**Global block index** is a monotonically increasing `u64` counter starting at
`0`, continuous across volumes. Every block on disk carries its global
`block_index`. This is the primary key into the FEC scheme and the index
tables.

**Single-volume archives** are valid: `volume_total = 1`, file extension may
be `.tzap` instead of `.tzap.001`. Otherwise identical.

**Volume naming convention** for multi-volume archives:
`<base>.tzap.NNN` where `NNN` is a zero-padded decimal volume number,
3 digits minimum, growing as needed (`001`, `002`, …, `999`, `1000`, …).

---

## 8. Volume Header

Fixed 128 bytes. At offset 0 of every volume file.

```rust
#[repr(C, packed)]
struct VolumeHeader {
    magic:              [u8; 4],   // b"TZAP" = 0x54 0x5A 0x41 0x50
    format_version:     u16,       // 1
    volume_format_rev:  u16,       // 0
    volume_index:       u32,       // 1-based
    volume_total:       u32,       // 0 = unknown at write time, else total count
    archive_uuid:       [u8; 16],  // random, identical across volumes of one archive
    first_block_index:  u64,       // global index of first block in this volume
    block_count:        u32,       // number of blocks contained in this volume
    has_global_header:  u8,        // 1 in Volume_1, 0 elsewhere
    _reserved:          [u8; 67],  // must be zero
    header_crc32c:      u32,       // CRC32C of bytes [0..124]
}
```

`archive_uuid` is the volume-reorder anchor: if filenames are mangled, the
reader sorts volumes by `(archive_uuid, volume_index)` from headers.

`volume_total = 0` permits streaming write where the final volume count is
unknown until close. Readers must tolerate this and infer the count by
scanning the directory or by failing gracefully when a referenced volume is
absent.

---

## 9. Global Header

Present in Volume_1 only, immediately after the VolumeHeader. Variable size
due to KDF parameters and TLV extensions.

### 9.1 Fixed portion

```rust
#[repr(C, packed)]
struct GlobalHeaderFixed {
    magic:              [u8; 4],   // b"TZGH"
    length:             u32,       // total bytes of GlobalHeader (incl. HMAC)

    // Algorithm selection
    compression_algo:   u16,
    aead_algo:          u16,
    fec_algo:           u16,
    kdf_algo:           u16,

    // Geometry
    chunk_size:         u32,       // zstd input bytes per frame (e.g. 1 MiB)
    block_size:         u32,       // bytes per storage block (e.g. 64 KiB)
    fec_data_shards:    u16,       // G_data per group
    fec_parity_shards:  u16,       // G_parity per group
    frame_count:        u64,
    payload_block_count: u64,      // data + parity blocks, excluding index blocks
    tar_total_size:     u64,       // sum of uncompressed bytes streamed through zstd

    // Index pointer
    index_first_block:        u64,
    index_block_count:        u32,
    index_decompressed_size:  u64,

    // FEC sizing for the index (independent of payload FEC)
    index_fec_data_shards:    u16,
    index_fec_parity_shards:  u16,

    // Sanity caps (reader enforces against its own policy)
    max_path_length:    u32,       // longest path stored in index, for read-side sizing

    _reserved:          [u8; 16],
}
// Followed in order by:
//   KdfParams   (variable length, §12.1)
//   Extension[] (TLV list, §9.2, may be empty; terminated by tag = 0x0000)
//   header_hmac [u8; 32]   // HMAC-SHA-256(mac_key, all preceding GlobalHeader bytes)
```

`length` covers the entire GlobalHeader including the trailing HMAC, so a
reader can skip an unrecognized extension list and still locate the HMAC.

### 9.2 Extension TLVs

```rust
#[repr(C, packed)]
struct Extension {
    tag:    u16,        // high bit = critical-must-understand
    length: u32,        // length of `value`
    value:  [u8; length],
}
// Terminator entry: tag = 0x0000, length = 0
```

Reserved tags (high bit clear = non-critical):

| Tag | Type | Purpose |
|---|---|---|
| `0x0001` | UTF-8 | User comment |
| `0x0002` | UTF-8 | Creator tool identifier (e.g. `"tzap-cli/0.1.0"`) |
| `0x0003` | `i64` | Creation timestamp, nanoseconds since Unix epoch |
| `0x0004` | `[u8; 32]` | SHA-256 of archive contents pre-encryption (optional) |
| `0x0005` | UTF-8 | Locale tag for filenames (e.g. `"und"`, `"en-US"`) |

Unallocated non-critical tags must be ignored by readers.
Critical tags (high bit set) cause a hard error if unknown.

### 9.3 Header authentication

The HMAC at the end of GlobalHeader is computed over all preceding bytes of
GlobalHeader (from `magic` up to but not including `header_hmac`), keyed by
`mac_key` (see §12). Wrong passphrase → wrong `mac_key` → HMAC fails →
early "wrong key" detection without touching any payload block.

The HMAC also binds the algorithm/geometry parameters: an attacker cannot
swap a header for one with different `chunk_size` or `aead_algo` without
detection.

---

## 10. Block Record

Every block on disk is wrapped in a small framing structure.

```rust
#[repr(C, packed)]
struct BlockRecord {
    magic:         [u8; 4],          // b"TZBK"
    block_index:   u64,              // global index, matches FEC layout
    kind:          u8,               // 0 = payload-data
                                     // 1 = payload-parity
                                     // 2 = index-data
                                     // 3 = index-parity
    flags:         u8,               // bit 0: last block of a frame (data only)
                                     // bit 1: tail is zero-padded
                                     // bit 2: this is a synthetic zero block
                                     //        (used to pad the final FEC group)
    payload_len:   u16,              // bytes of real data in payload; rest is padding
    _reserved:     [u8; 2],
    payload:       [u8; BLOCK_SIZE],
    record_crc32c: u32,              // CRC32C over magic..payload (inclusive)
}
```

On-disk size of each block: `BLOCK_SIZE + 24` bytes of framing.

`payload_len` allows a reader to find the real data tail of a frame's final
block without consulting the index, enabling damaged-archive scanning.

`flags` bit 2 (synthetic) marks zero-blocks added solely to fill the last
FEC group; they decode to nothing.

`record_crc32c` is for accidental-corruption triage: a block whose CRC fails
is treated as missing by the FEC layer. AEAD remains the only authentication
authority.

---

## 11. Volume Footer

Fixed 24 bytes. At end of every volume.

```rust
#[repr(C, packed)]
struct VolumeFooter {
    magic:         [u8; 4],   // b"TZVF"
    block_count:   u32,       // must equal VolumeHeader.block_count
    bytes_written: u64,       // total volume size up to (not including) this footer
    footer_crc32c: u32,
    _reserved:     [u8; 4],
}
```

Footer block_count duplicates the header value as a corruption check. Mismatch
or missing footer is a strong signal that the volume was truncated.

---

## 12. Key Derivation

### 12.1 KDF parameters

For `KdfAlgo::Argon2id`:

```rust
#[repr(C, packed)]
struct Argon2idParams {
    algo_tag:    u16,         // 1
    t_cost:      u32,         // iterations (recommend 3)
    m_cost_kib:  u32,         // memory in KiB (recommend 262_144 = 256 MiB)
    parallelism: u32,         // (recommend 4)
    salt_length: u16,         // (recommend 16)
    salt:        [u8; salt_length],
}
```

For `KdfAlgo::Raw`:

```rust
#[repr(C, packed)]
struct RawKeyParams {
    algo_tag: u16,            // 0
    // No further fields; the user supplies master_key out-of-band via keyfile.
}
```

### 12.2 Master key

```
master_key = Argon2id(passphrase_utf8_nfc, salt, t_cost, m_cost_kib, parallelism, len=32)
```

Passphrases are UTF-8 NFC normalized before hashing. Implementations must
either perform normalization or document the requirement to the user.

### 12.3 Derived subkeys

```
enc_key       = HKDF-SHA256(master_key, info=b"tzap-v1-enc",      L=32)
mac_key       = HKDF-SHA256(master_key, info=b"tzap-v1-mac",      L=32)
nonce_seed    = HKDF-SHA256(master_key, info=b"tzap-v1-nonce",    L=32)
index_key     = HKDF-SHA256(master_key, info=b"tzap-v1-index",    L=32)
index_nonce_seed = HKDF-SHA256(master_key, info=b"tzap-v1-idxnonce", L=32)
```

Domain-separated labels prevent cross-purpose key reuse and let any single
purpose be rotated by changing only its label in a future format revision.

### 12.4 Reader-side DoS protection

A malicious archive can declare `m_cost_kib = 16 GiB`, forcing the reader to
allocate. Readers must enforce a configurable cap (recommended default:
4 GiB) and refuse archives requesting more. The cap is a reader policy, not a
format constraint.

---

## 13. AEAD Construction

Each encryption unit (a zstd frame, or an index chunk) is encrypted
independently. Nonces are deterministic; no inline nonce storage.

### 13.1 Nonce derivation

```rust
fn derive_nonce(seed: &[u8; 32], domain: &[u8], counter: u64, len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(domain.len() + 8 + 8);
    info.extend_from_slice(b"tzap-v1-");
    info.extend_from_slice(domain);
    info.extend_from_slice(&counter.to_le_bytes());
    hkdf_expand_sha256(seed, &info, len)
}
```

Nonce length depends on AEAD:
- `AesGcmSiv256` and `AesGcm256`: 12 bytes
- `XChaCha20Poly1305`: 24 bytes

### 13.2 Associated data

```rust
fn aad(archive_uuid: &[u8; 16], frame_index: u64) -> [u8; 24] {
    let mut a = [0u8; 24];
    a[..16].copy_from_slice(archive_uuid);
    a[16..].copy_from_slice(&frame_index.to_le_bytes());
    a
}
```

AAD binds each ciphertext to its archive and its position. Tag verification
fails on any reorder, swap, or cross-archive replay.

### 13.3 Frame encryption

```rust
fn encrypt_frame(k: u64, plaintext: &[u8]) -> Vec<u8> {
    let nonce = derive_nonce(&nonce_seed, b"frame", k, AEAD_NONCE_LEN);
    let aad   = aad(&archive_uuid, k);
    aead_encrypt(&enc_key, &nonce, &aad, plaintext)  // returns ct || tag
}
```

### 13.4 Index chunk encryption

The index is compressed (one zstd frame) and then encrypted as one or more
chunks of bounded size (recommend `chunk_size`, same as frame size).

```rust
fn encrypt_index_chunk(j: u64, plaintext: &[u8]) -> Vec<u8> {
    let nonce = derive_nonce(&index_nonce_seed, b"index", j, AEAD_NONCE_LEN);
    let aad   = aad(&archive_uuid, j);
    aead_encrypt(&index_key, &nonce, &aad, plaintext)
}
```

Separate `index_key` and `index_nonce_seed` prevent any possibility of nonce
collision between frame and index encryptions.

### 13.5 Why AES-256-GCM-SIV is the default

- Nonce-misuse-resistant: deterministic nonces are safe, no inline nonce
  storage required.
- 128-bit AEAD tag is robust against random tampering.
- Hardware acceleration via AES-NI / ARM crypto extensions.
- Standardized (RFC 8452).

XChaCha20-Poly1305 is offered as an alternative for environments without AES
hardware acceleration or where extra-large nonces simplify random-nonce
schemes.

Plain AES-GCM is allowed but discouraged: it is catastrophically broken under
nonce reuse, which is hard to prevent at archival timescales.

---

## 14. Forward Error Correction

### 14.1 Default: Reed-Solomon over GF(2¹⁶) (Leopard)

Groups of `G_data + G_parity` equal-size blocks. Default: 224 data + 32
parity (12.5% overhead, tolerates 32 lost blocks per 256-block group).

```
Group g  →  global blocks [g·G_total … (g+1)·G_total)
            where G_total = fec_data_shards + fec_parity_shards
  Data:    block_index in [g·G_total                    .. g·G_total + G_data)
  Parity:  block_index in [g·G_total + G_data           .. g·G_total + G_total)
```

### 14.2 Encoding

```
for each group g:
    # Collect G_data data blocks. If we have fewer (end of archive):
    #   - pad with synthetic zero blocks (flags bit 2 set, payload_len = 0)
    parity_blocks = Leopard.encode(data_blocks, G_parity)
    for each block in (data_blocks ++ parity_blocks):
        wrap in BlockRecord with appropriate magic, kind, flags, CRC
        write to current volume; roll to next if size cap reached
```

### 14.3 Decoding

```
for each group g:
    collect all available blocks for this group's index range
    discard any block whose record_crc32c fails -> treat as missing
    if surviving_count < G_data:
        FAIL: group unrecoverable
    if any data block is missing:
        reconstruct via Leopard.decode using surviving (data + parity) blocks
    # All G_data data blocks now present.
    # AEAD verification happens at the frame layer (§17).
```

### 14.4 Volume-loss budget

To survive loss of N entire volumes, parity must satisfy:

```
fec_parity_shards ≥ ceil(max_blocks_per_volume / fec_data_shards) × N × fec_data_shards
                  (approximately; depends on alignment)
```

For practical sizing: if each volume holds ~1000 blocks and groups are 256
blocks each, ~4 groups per volume. To survive losing 1 volume per ~10
volumes, parity ≥ 10% × group_size suffices. The default 12.5% covers most
sensible cases. For higher resilience, increase `fec_parity_shards`.

### 14.5 Index FEC

The index uses a separate FEC pool, sized independently and (by default)
with a much higher parity ratio (recommended: 50%). Losing the index means
losing random access to the entire archive, so the trade-off favors
robustness over space.

Index FEC groups follow `fec_algo` but with parameters
`index_fec_data_shards` / `index_fec_parity_shards`.

### 14.6 Optional: Wirehair (fountain code)

Wirehair is offered for use cases where the data-shard count is unknown at
write time (streaming) or where any-of-many recovery semantics are preferred.
When `fec_algo = Wirehair`, `fec_parity_shards` is interpreted as the
*target* number of recovery blocks; readers reconstruct from any
`G_data + ε` surviving blocks.

For v1 reference implementations, Leopard-RS is the recommended baseline.

---

## 15. Index Format

The index is the random-access map. Stored as a sequence of blocks at the
end of the archive (across one or more volumes), referenced by
`index_first_block` / `index_block_count` in the global header.

### 15.1 On-disk path

```
IndexBytes  =  serialize(IndexHeader + tables + string_pool)
            →  zstd-compress (single frame)
            →  split into chunks of size ≤ chunk_size
            →  AEAD-encrypt each chunk (§13.4)
            →  split into BLOCK_SIZE blocks (zero-padded)
            →  FEC-encode (§14.5)
            →  emit as BlockRecord with kind ∈ {2 (data), 3 (parity)}
```

Read path: reverse.

### 15.2 In-memory structure (after AEAD decrypt + zstd decode)

```rust
#[repr(C, packed)]
struct IndexHeader {
    magic:               [u8; 4],   // b"TZIX"
    version:             u32,       // 1
    frame_count:         u64,
    file_count:          u64,
    frame_table_offset:  u64,       // bytes from start of IndexHeader
    file_table_offset:   u64,
    string_pool_offset:  u64,
    string_pool_size:    u64,
    sha256_self:         [u8; 32],  // SHA-256 of all following bytes (tables + pool)
}
// Then in order:
//   FrameEntry[frame_count]
//   FileEntry[file_count]
//   string_pool: [u8; string_pool_size]   // UTF-8, no NUL terminators
```

### 15.3 Frame table

```rust
#[repr(C, packed)]
struct FrameEntry {
    frame_index:            u64,
    decompressed_offset:    u64,   // cumulative offset of this frame's decoded bytes
                                   // within the underlying tar stream
    decompressed_size:      u32,   // size of decoded bytes (typically chunk_size,
                                   // smaller for the last frame)
    compressed_size:        u32,   // size of the zstd frame (pre-AEAD)
    encrypted_size:         u32,   // = compressed_size + AEAD tag length (16)
    first_block_index:      u64,   // global block index where ciphertext starts
    block_count:            u32,   // number of blocks the ciphertext spans
    last_block_payload_len: u16,   // bytes of real data in the final block of this frame
    _reserved:              u16,
}
```

### 15.4 File table

```rust
#[repr(C, packed)]
struct FileEntry {
    path_offset:             u64,   // into string_pool
    path_length:             u32,
    flags:                   u32,   // see §15.5
    frame_index:             u64,   // frame containing this file's first data byte
    offset_in_frame:         u32,   // decompressed byte offset within that frame
    decompressed_size:       u64,   // total file data length
    mode:                    u32,   // POSIX mode bits (S_IFMT included)
    mtime_ns:                i64,
    atime_ns:                i64,
    ctime_ns:                i64,
    btime_ns:                i64,   // birth time, INT64_MIN if unknown
    uid:                     u32,
    gid:                     u32,
    uname_offset:            u64,   // into string_pool; 0 if unset
    uname_length:            u32,
    gname_offset:            u64,
    gname_length:            u32,
    symlink_target_offset:   u64,   // into string_pool; 0 if not a symlink
    symlink_target_length:   u32,
    hardlink_target_offset:  u64,   // into string_pool; 0 if not a hardlink
    hardlink_target_length:  u32,
    xattr_offset:            u64,   // into string_pool; 0 if no xattrs
    xattr_length:            u32,   // serialized xattr blob (§16.3)
    content_sha256:          [u8; 32],  // optional; zero if not computed
    _reserved:               [u8; 8],
}
```

### 15.5 File flags

| Bit | Meaning |
|---|---|
| 0 | Directory |
| 1 | Symlink |
| 2 | Hardlink (to a previously-listed path) |
| 3 | Sparse file (decompressed_size = logical size; data layout described in xattrs) |
| 4 | Has extended attributes (xattr_length > 0) |
| 5 | Has POSIX ACL (stored in xattrs) |
| 6 | content_sha256 field is populated |
| 7 | Reserved |
| 8–31 | Reserved (must be zero) |

### 15.6 Why the index lives at the end

- Single-pass write: file table is known only after all files are streamed.
- Index can grow without pre-allocating space at the archive head.
- Reader fetches just `index_first_block`/`index_block_count` from the global
  header (known at the top) and seeks to the end.

### 15.7 Listing without decrypting payload

```
1. Open Volume_1; read VolumeHeader, GlobalHeader.
2. Derive keys, verify GlobalHeader HMAC.
3. Locate index blocks; FEC-repair; AEAD-decrypt with index_key.
4. zstd-decompress; iterate FileEntry[] + string_pool.
5. Print names, sizes, modes, mtimes. Done.
```

No frame decompression touched. Useful for `tzap list <archive>` UX.

---

## 16. File Metadata Handling

### 16.1 Paths

- Stored UTF-8, NFC-normalized.
- Forward slashes (`/`) as separators on all platforms.
- No leading `/`; paths are always relative to extraction root.
- No `..` segments in stored paths. Extraction validates paths at write time
  (refuse) and at read time (refuse on read).
- Max path length is reader-configurable (default cap: 4096 bytes); the
  global header records `max_path_length` actually used.

### 16.2 Symlinks and hardlinks

- Symlink target stored as-is in `symlink_target_*`. No normalization or
  resolution.
- Hardlinks reference an earlier `FileEntry` by path. Resolution during
  extraction depends on extracted files; if the target was not yet extracted,
  hardlinks may be deferred.
- Security: extractors must refuse to follow symlinks that would escape the
  target directory at extraction time. This is an extraction-time policy,
  not a format constraint.

### 16.3 Extended attributes

Xattrs are stored as a length-prefixed list in the string pool:

```
xattr_blob = entry_count: u32
             entry[entry_count]

entry      = name_length: u32
             value_length: u32
             name: [u8; name_length]      ; UTF-8
             value: [u8; value_length]    ; opaque bytes
```

POSIX ACLs are serialized as xattrs under the standard `system.posix_acl_*`
names. No special-case handling; if the extractor doesn't understand the
xattr name, it skips it (with a warning).

### 16.4 Sparse files

When file flag bit 3 (sparse) is set, the file's stored data is a logical
representation. The actual sparse extent map is stored in the xattr blob
under a reserved key `tzap.sparse_map` containing a sequence of
`(logical_offset: u64, length: u64)` pairs of populated regions; all other
regions are zero on extraction.

### 16.5 Empty files and directories

Empty files have `decompressed_size = 0` and no frame data. They still get a
`FileEntry` for metadata. Directories likewise.

### 16.6 Time zones

All timestamps stored as UTC nanoseconds. The format does not preserve
"original time zone" information. Implementations that need it can store it
as a custom xattr.

### 16.7 Special files

Block devices, character devices, FIFOs, and sockets are represented by mode
bits in `FileEntry.mode`. Major/minor device numbers are stored in xattrs
under `tzap.devnum.major` and `tzap.devnum.minor` (decimal UTF-8). Extractors
without permission to create such files should warn and skip rather than fail.

---

## 17. Read Algorithm

### 17.1 List archive contents

```
1. Open Volume_1. Read VolumeHeader; verify magic + CRC.
2. Read GlobalHeaderFixed. Parse KdfParams and extensions.
3. Prompt for passphrase (or load keyfile). Run KDF → master_key.
4. Derive mac_key. Verify GlobalHeader HMAC.
   On failure: report "wrong key or corrupt header"; abort.
5. Derive enc_key, nonce_seed, index_key, index_nonce_seed.
6. Resolve index block locations: walk volume headers to map
   global block_index → (volume file, byte offset).
7. Read all index blocks. For each FEC group:
     - verify per-block CRC32C
     - FEC-repair missing/failed blocks
8. Reassemble index ciphertext chunks; AEAD-decrypt each chunk
   using index_key + derive_nonce(index_nonce_seed, "index", j).
9. Concatenate decrypted chunks; zstd-decompress (single frame).
10. Parse IndexHeader; iterate FileEntry[] + string_pool.
11. Format and emit to user.
```

### 17.2 Extract a single file

Steps 1–10 as above, then:

```
11. Look up target path in FileEntry[]. Get frame_index, offset_in_frame,
    decompressed_size.
12. Walk frame_index forward until `decompressed_size` bytes have been
    delivered (a file may span multiple frames if larger than chunk_size).
13. For each spanned frame:
    a. Look up FrameEntry → first_block_index, block_count.
    b. Read those blocks (across volumes if needed); FEC-repair group(s).
    c. Reassemble ciphertext from block payloads (respect payload_len).
    d. AEAD-decrypt with enc_key + derive_nonce(nonce_seed, "frame", k)
       and aad(archive_uuid, k). Verify tag.
    e. zstd-decode the frame.
    f. Output the requested byte range from this frame.
14. Set file metadata (mode, mtime, etc.) from FileEntry.
```

### 17.3 Extract all files

For sequential extraction, skip the per-file frame lookup and just decode
frames in order, splitting their decompressed bytes back into files using the
tar entry boundaries embedded in the decompressed stream (the index is only
strictly needed for random access; sequential decode reads the tar stream
naturally).

### 17.4 Verify mode

Walk every payload block, FEC group, and index block. Verify CRCs, repair as
possible, AEAD-decrypt every frame and verify tag. Report any unrecoverable
groups. Do not write any extracted files.

---

## 18. Write Algorithm

### 18.1 Streaming write (seekable output)

```
1. Generate archive_uuid (16 random bytes from a CSPRNG).
2. Acquire passphrase or keyfile. Run KDF. Derive all subkeys.
3. Open Volume_1; reserve a placeholder GlobalHeader by writing zeros of
   the expected size. (Length can be precomputed from KdfParams and known
   extensions.)
4. Initialize:
     - tar writer
     - zstd encoder configured to call end_frame() after CHUNK_SIZE input bytes
     - per-frame index tracking
     - per-block FEC group buffer
5. For each file:
     a. Write tar header to tar writer.
     b. Stream file data through tar writer.
     c. As zstd frames complete, run:
          - encrypt frame (§13.3) → ciphertext
          - split ciphertext into BLOCK_SIZE-sized blocks
          - append to current FEC group buffer
          - when G_data data blocks accumulated:
              compute G_parity parity via Leopard
              emit all G_data + G_parity wrapped BlockRecords to current
              volume; roll to next volume if size cap reached
          - record FrameEntry
6. After last file:
     - finalize tar (footer blocks)
     - flush zstd encoder
     - encrypt + emit the final frame
     - pad final FEC group with synthetic zero blocks (flags bit 2)
     - emit parity for that group
7. Build the index:
     - FrameEntry table
     - FileEntry table
     - string_pool
     - IndexHeader with sha256_self
     - zstd-compress; encrypt chunks; FEC-encode; emit as kind=2/3 blocks
       (across remaining volumes or a new one)
8. Backfill GlobalHeader fields now known:
     - frame_count, payload_block_count, tar_total_size
     - index_first_block, index_block_count, index_decompressed_size
9. Compute HMAC over GlobalHeader; write to its reserved tail position.
10. Write VolumeFooter at end of each volume.
```

### 18.2 Non-seekable output (pipe to stdout)

The GlobalHeader cannot be backfilled. Two options:

**(a) Two-pass via temporary file.** Write the payload (BlockRecords + index
blocks) to a temp file. After completion, assemble Volume_1 by writing
VolumeHeader, finalized GlobalHeader, then concatenating the temp file's
relevant prefix. Larger archives use multiple temp files (one per volume).

**(b) Index-at-head variant.** Not supported in this format version; would
require pre-computing the entire index, which contradicts streaming. Deferred
to a future revision.

### 18.3 Volume rolling

When the current volume would exceed `target_volume_size` bytes:

```
1. Finish writing the in-progress BlockRecord.
2. Write VolumeFooter to current volume; close.
3. Open next volume: <base>.tzap.NNN+1.
4. Write VolumeHeader (has_global_header = 0).
5. Continue writing blocks.
```

Volume boundaries do not need to align with FEC group boundaries. A single
group can span volumes. The index records each block's global index;
volume-to-block mapping is reconstructed at read time by scanning headers.

---

## 19. Verification Mode

`tzap verify <archive>` performs:

1. Steps 1–5 of §17.1 (verify GlobalHeader).
2. Walk every volume header and footer; verify CRCs and counts.
3. Walk every BlockRecord; verify CRC32C.
4. For each FEC group, confirm enough survivors; do not actually repair
   unless `--repair-to <dir>` is given.
5. AEAD-decrypt and tag-verify every frame.
6. zstd-decode every frame to confirm decompression integrity.
7. Optionally, verify each file's `content_sha256` (if populated) by hashing
   the decompressed tar stream slices.

Report per-stage success counts and any failures. Exit code 0 iff fully
recoverable.

---

## 20. Performance Considerations

### 20.1 Parallelism

- Per-frame AEAD and zstd are independent → trivially parallelizable across
  frames.
- FEC groups are independent → parallel across groups.
- Block I/O can be a producer-consumer queue with backpressure.
- Recommended implementation: a `rayon` work-stealing pool or per-stage
  channel-based pipeline.

### 20.2 Memory

- Streaming write: one FEC group's worth of blocks in memory at a time.
  Default (256 blocks × 64 KiB = 16 MiB) plus per-frame buffers.
- Random extract: one frame's compressed + decompressed sizes plus its FEC
  group's blocks. Default ≤ 32 MiB.
- Index size: bounded by `max_files × FileEntry_size + string_pool`. For
  100k files, ~16 MB uncompressed; compresses to a few MB.

### 20.3 Throughput estimates

On modern hardware (8-core x86_64 with AES-NI, NVMe):

| Stage | Single-thread throughput | Notes |
|---|---|---|
| zstd compress (level 3) | ~300 MB/s | adjustable |
| AES-256-GCM-SIV | ~1 GB/s | AES-NI |
| Leopard FEC encode | ~2 GB/s | per group |
| CRC32C | ~10 GB/s | SSE4.2 |

Bottleneck is usually compression. Multi-threaded zstd (`zstdmt`) can
saturate I/O on most modern disks.

### 20.4 Compression ratio cost of framing

Per-frame zstd loses 1–5% of compression ratio vs. single-frame zstd at 1
MiB chunks, on typical text/code corpora. The cost shrinks as chunk_size
grows (less per-frame dictionary warm-up overhead) and grows on small chunks.
A pre-trained zstd dictionary stored in an extension TLV can recover most of
the lost ratio for known data shapes; deferred for v1 reference impl.

### 20.5 Hardware acceleration

- **AES-NI / ARM crypto extensions** for AES-GCM-SIV: ubiquitous on modern
  CPUs; implementations should use platform AEAD libraries.
- **AVX2 / AVX-512** for Leopard-RS: Leopard ships SIMD code paths.
- **CRC32C hardware instruction** (`crc32` on x86, ARMv8.1 CRC): used by
  most CRC32C libraries automatically.

---

## 21. Failure Mode Matrix

| Failure | Detection | Recovery |
|---|---|---|
| Bit-rot in BlockRecord payload | `record_crc32c` | FEC repair if group survivors ≥ G_data |
| Bit-rot in BlockRecord framing | magic mismatch / CRC | Block treated as missing → FEC |
| Wrong passphrase | GlobalHeader HMAC fails | Abort with clear error |
| Tampered GlobalHeader | HMAC fails | Abort; consider mitigation in §22 |
| Corrupt KdfParams | Parsing fails or HMAC fails downstream | Abort |
| Truncated volume | Missing VolumeFooter; block_count mismatch | Partial recovery via FEC headroom |
| Whole volume lost | block_index gap detected at read time | FEC if parity covers gap; else partial |
| Volume reorder | `archive_uuid` + `volume_index` | Re-sort by header values |
| Volume rename / mangled filename | Same as reorder | Same |
| Adversarial frame swap | AEAD AAD includes frame_index | Tag verification fails → reject |
| Adversarial cross-archive replay | AEAD AAD includes archive_uuid | Tag verification fails → reject |
| Cosmic ray flipping one bit | CRC catches; FEC repairs | Recovered transparently |
| Index lost or unrecoverable | Index FEC headroom; if exceeded, fail | Higher index parity ratio mitigates |
| Index block corruption | Same CRC + FEC + AEAD chain | Same as data blocks |
| Truncated final frame | Last FrameEntry block_count mismatch | Partial frame extract; report |

---

## 22. Security Analysis

### 22.1 Confidentiality

All file data, metadata, and the index are encrypted under keys derived from
the user's passphrase via Argon2id. An attacker observing only archive bytes
learns:

- That the archive is in tzap format (magic bytes).
- The format version, algorithm IDs, geometry parameters (chunk_size,
  block_size, FEC ratio).
- The number of frames, blocks, and approximate archive size.
- The archive UUID (random per archive; no information about contents).
- KDF parameters (salt, m_cost, etc.).

An attacker does *not* learn:

- File names, sizes, count, paths.
- File contents.
- Creation/modification times of contents.
- Whether two archives share files (no cross-archive deduplication; UUIDs
  differ; deterministic nonces are per-archive).

### 22.2 Integrity

Every byte that contributes to plaintext output is covered by an AEAD tag
(via either the frame or index encryption). AEAD tags are 128-bit.

The GlobalHeader is covered by a 256-bit HMAC. Volume headers and footers
are covered by CRC32C only (accidental corruption only); their fields
duplicate authenticated fields in GlobalHeader or are verifiable against the
archive_uuid, so adversarial header tampering causes a downstream HMAC or
AEAD failure.

### 22.3 Replay resistance

AEAD AAD binds `(archive_uuid, frame_index)`. Swapping a frame from another
archive, or reordering frames within an archive, produces an AAD mismatch
and tag failure.

### 22.4 Deterministic nonces

AES-256-GCM-SIV is nonce-misuse-resistant by design (RFC 8452). Deterministic
nonces derived from `(nonce_seed, frame_index)` cannot collide across frames
of the same archive (frame_index is unique). Different archives use
different `nonce_seed` (derived from per-archive `master_key`).

### 22.5 Compression-before-encryption considerations

tzap compresses then encrypts. This is correct ordering (encrypting random
data is wasteful and reveals nothing), but in scenarios where an attacker
can choose part of the plaintext alongside sensitive plaintext (e.g.
TLS-style streaming), CRIME/BREACH-class attacks become possible. For
*archival* use cases — where the archive is built once from a fixed set of
files and not interactively updated — this risk does not apply.

Implementations should not expose APIs that allow per-byte interactive
plaintext injection during archive creation.

### 22.6 Reader-side resource limits

Readers must enforce caps on:

- `m_cost_kib` (default cap: 4 GiB)
- `chunk_size` (default cap: 64 MiB)
- `block_size` (default cap: 1 MiB)
- `fec_data_shards + fec_parity_shards` (default cap: 4096)
- `max_path_length` (default cap: 4096)
- `frame_count` and `payload_block_count` (default cap: 2³² each)
- Total decompressed extraction size (user-configurable; recommend default:
  prompt or refuse if > 10× archive size, indicating possible zip bomb)

### 22.7 Key rotation and re-encryption

tzap has no in-place rekey. To rotate the encryption key, re-encrypt: decrypt
to a new archive with the new key. This is consistent with the write-once
design and avoids the complexity of partial-rekey integrity proofs.

### 22.8 Known unmitigated risks

- **Header bytes leak archive metadata.** Format version, algorithm choices,
  and geometry are intentionally in cleartext for forensic parseability.
  Users who must hide tzap's identity should wrap the archive in another
  envelope.
- **Argon2 parameters define cost.** Users with weak passphrases choosing
  weak `m_cost` will be brute-forceable. Reader can refuse low parameters
  on read; writers should default to ≥ 256 MiB.
- **Quantum adversaries.** AES-256 retains ~128-bit security against
  Grover's algorithm. Symmetric-key archival is generally considered
  quantum-acceptable; signature/asymmetric agility is irrelevant here.

---

## 23. Versioning & Compatibility

- `format_version` is bumped only for breaking changes.
- `volume_format_rev` is bumped for backward-compatible additions within a
  major version. Old readers may warn but should still parse.
- Algorithm ID additions are non-breaking (old readers reject the unknown
  algorithm; new readers accept both).
- Extension TLVs with the critical bit *clear* are always non-breaking.
- Format extensions that need cryptographic binding (e.g. a new key wrap
  mode) require a `format_version` bump.

---

## 24. Sizing Defaults and Limits

### 24.1 Defaults

| Parameter | Default | Rationale |
|---|---|---|
| `chunk_size` | 1 MiB | Balances random-access granularity vs compression ratio |
| `block_size` | 64 KiB | Balances FEC granularity vs framing overhead |
| `fec_data_shards` | 224 | Standard 256-shard Leopard group |
| `fec_parity_shards` | 32 | ~12.5% overhead |
| `index_fec_data_shards` | 16 | Smaller groups for index |
| `index_fec_parity_shards` | 16 | 50% overhead: index loss is fatal |
| Volume size cap | 100 MiB | Reasonable for media transfer / cloud chunking |
| AEAD | AES-256-GCM-SIV | Hardware-accelerated, misuse-resistant |
| KDF | Argon2id t=3, m=256 MiB, p=4 | Strong defaults; tune for constrained hardware |
| zstd level | 3 | Default zstd level; users may override |

### 24.2 Hard limits

| Limit | Value |
|---|---|
| Max format_version | 65535 (u16) |
| Max volume_index | 4_294_967_295 (u32) |
| Max global block_index | 18 EB worth (u64) — effectively unbounded |
| Max single-file size | 2⁶³ − 1 bytes (i64 of `decompressed_size`) |
| Max path length | 2³² − 1 bytes (per-archive policy, ≤ this) |
| Max frame_count | 2⁶⁴ − 1 (u64) |
| Max chunk_size | 2³² − 1 bytes (u32); recommended cap 64 MiB |

---

## 25. Magic Numbers

| ASCII | Hex bytes (file order) | Purpose |
|---|---|---|
| `TZAP` | `54 5A 41 50` | Volume header |
| `TZGH` | `54 5A 47 48` | Global header |
| `TZBK` | `54 5A 42 4B` | Block record |
| `TZIX` | `54 5A 49 58` | Index header (after decrypt) |
| `TZVF` | `54 5A 56 46` | Volume footer |

Note: bytes as written to disk, in order. Treat the four bytes as a literal
sequence, not as a little-endian u32.

---

## 26. CLI Sketch (non-normative)

```
tzap create  [--volume-size 100M] [--password-stdin] [--keyfile FILE]
             [--compression-level 3] [--chunk-size 1M] [--block-size 64K]
             [--fec-ratio 0.125] [--index-fec-ratio 0.5]
             [--exclude PATTERN] -o ARCHIVE INPUT...

tzap extract [--password-stdin] [--keyfile FILE] [--strip-components N]
             [-C DIR] ARCHIVE [PATH...]

tzap list    [--password-stdin] [--keyfile FILE] [--long] ARCHIVE

tzap verify  [--password-stdin] [--keyfile FILE] [--repair-to DIR] ARCHIVE

tzap info    ARCHIVE   # prints algorithms, geometry, volume count — no key needed
```

`--password-stdin` reads passphrase from stdin (recommended for scripts).
Interactive prompt if neither `--password-stdin` nor `--keyfile` given.

---

## 27. Reference Implementation Notes

Target language: Rust.

### 27.1 Dependency choices

| Need | Crate | Notes |
|---|---|---|
| zstd | `zstd` (gyscos) | Use frame APIs; no need for `zstd-safe::seekable` since we manage framing |
| zstd seekable (optional) | `zstd-safe` with `seekable` feature | Only if using its frame-batching helpers |
| AES-256-GCM-SIV | `aes-gcm-siv` (RustCrypto) | Audited, pure Rust + AES-NI assembly |
| XChaCha20-Poly1305 | `chacha20poly1305` (RustCrypto) | Same trust source |
| Argon2id | `argon2` (RustCrypto) | Pure Rust |
| HKDF | `hkdf` (RustCrypto) | Pure Rust |
| CRC32C | `crc32c` | SSE4.2 intrinsics where available |
| Leopard-RS | `reed-solomon-erasure` or `leopard-codec` | Verify maintenance status before adoption |
| tar | `tar` crate | Mature; emit POSIX ustar |
| CLI | `clap` v4 | Standard |
| Async / parallel | `rayon` | Per-frame parallelism |
| UUID | `uuid` with `v4` feature | CSPRNG-backed |

### 27.2 Module layout

```
crates/
  tzap-format/     # pure data types: structs, enums, parsers, serializers
  tzap-crypto/    # KDF, AEAD wrappers, HMAC
  tzap-fec/       # Leopard wrapper, group encode/decode
  tzap-io/        # block reader/writer, volume manager
  tzap-archive/   # high-level: create, extract, list, verify
  tzap-cli/       # the binary
```

`tzap-format` has zero crypto dependencies — easier to audit and reason
about as pure parsing/serialization code.

### 27.3 Audit-friendliness

- Keep the wire-format module dependency-free of crypto. Wire format is
  bytes-in / bytes-out; crypto is a separate layer that composes on top.
- Pin all dependencies in `Cargo.lock`; commit it; consider `cargo vendor`
  for supply-chain isolation.
- Run `cargo audit` in CI. Add `cargo deny` for license / version policies.
- Add property-based tests (`proptest`) for round-trip encode/decode at the
  wire-format layer.
- Include a fuzz harness for the block parser and the index decoder
  (`cargo-fuzz`).

### 27.4 Test corpus

- Empty archive (no files)
- Single tiny file (< chunk_size)
- Single huge file (> chunk_size, spans multiple frames)
- Many tiny files (stress index size)
- Hardlinks, symlinks, special files
- Sparse files
- Unicode paths (NFC/NFD mixed)
- Path edge cases: empty components, max length, names with `\n`, etc.
- Multi-volume rollover at every interesting boundary (mid-block, mid-frame,
  mid-FEC-group)
- Deliberately corrupted archives at every layer (header, block payload,
  parity, index, footer)

---

## 28. Conformance and Test Vectors

A conformant writer produces archives that any conformant reader can:

1. Verify (HMAC + every CRC + every AEAD tag).
2. List (file table iteration).
3. Sequentially extract.
4. Randomly extract any single file.

A conformant reader rejects:

1. Unknown `format_version`.
2. Unknown critical extensions.
3. Unknown algorithm IDs.
4. Resource requests exceeding configured caps.
5. Any AEAD tag mismatch.
6. Any HMAC mismatch.

The reference implementation will publish a fixed test vector set covering
each of the above, with golden bytes and expected outputs.

---

## 29. Open Questions and Future Work

These are deferred from v1:

1. **Pre-trained zstd dictionary**, stored in an extension TLV, for restoring
   compression ratio on known data shapes.
2. **Append support.** Currently write-once. Append would require chaining
   indices or rewriting the existing one. Probably introduces a v2.
3. **Multi-recipient key wrap.** Each recipient gets a wrapped copy of
   `master_key` under their own KEK (passphrase or public key). Format would
   add a list of `KeyWrap` entries before `KdfParams`.
4. **Public-key mode.** age-style X25519 + symmetric AEAD. Composes naturally
   with the existing AEAD pipeline; key derivation chain changes.
5. **Streaming-from-stdin** with index-at-head. Requires either knowing all
   files upfront or a different index strategy (e.g. periodic index
   checkpoints).
6. **Secondary index location.** A duplicate index near the start of Volume_1
   improves resilience against tail truncation.
7. **Per-file encryption keys.** Useful if selective key disclosure is
   desired. Significant complexity; deferred.
8. **Detached signatures.** Sign the GlobalHeader HMAC with an asymmetric
   key for archive authorship verification.
9. **Hardware security module integration.** KDF via HSM or platform
   keychain. Implementation concern, not format concern.

---

## 30. Glossary

- **AAD** — Additional Authenticated Data; bytes covered by an AEAD tag but
  not encrypted.
- **AEAD** — Authenticated Encryption with Associated Data.
- **Block** — Fixed-size storage unit; the unit of FEC and CRC.
- **Chunk** — `chunk_size` bytes of input to the zstd encoder; produces one
  frame.
- **FEC** — Forward Error Correction.
- **Frame** — One independent zstd frame = one AEAD encryption unit.
- **Group** — A set of `G_data + G_parity` blocks treated as one FEC unit.
- **HKDF** — HMAC-based Key Derivation Function (RFC 5869).
- **Index** — File and frame tables stored at the end of the archive,
  enabling random access.
- **Leopard-RS** — A specific FFT-accelerated Reed-Solomon implementation
  over GF(2¹⁶).
- **Master key** — 32-byte symmetric key derived from passphrase via Argon2id,
  or supplied as a keyfile.
- **Shard** — Synonym for "block" in FEC literature.
- **Volume** — One file of a multi-volume archive (e.g. `archive.tzap.001`).

---

## Appendix A: Comparison to Related Formats

| Format | Encrypted | Compressed | FEC | Random access | Splittable | Streaming |
|---|---|---|---|---|---|---|
| `tar` | no | no | no | partial | no | yes |
| `tar.gz` | no | yes | no | no | no | yes |
| `tar.zst` | no | yes | no | with seekable | no | yes |
| `tar.gpg` | yes | no/optional | no | no | no | yes |
| `tar.zst.age` | yes | yes | no | no | no | yes |
| `7z` | yes | yes | no | yes | yes | partial |
| `rar` | yes | yes | optional | yes | yes | no |
| `dar` | yes | yes | optional | yes | yes | partial |
| `par2` (+ any) | no | no | yes | n/a | per-volume | n/a |
| **`tzap`** | yes | yes | yes | yes | yes | yes |

tzap's distinguishing combination: every box checked, plus a modern crypto
stack (Argon2id + AEAD), explicit nonce derivation, an authenticated header,
and resilience to whole-volume loss out of the box.

---

## Appendix B: Worked Example (1 GiB Archive)

**Input:** 1 GiB of mixed-content files.

**Parameters (defaults):**
- chunk_size = 1 MiB
- block_size = 64 KiB
- FEC = 224 + 32 = 256
- Volume size = 100 MiB

**After tar:** ~1.001 GiB (tar headers add ~0.1%).
**After zstd (level 3):** ~400 MiB (assume 60% reduction).
**Frame count:** ceil(1.001 GiB / 1 MiB) ≈ 1026 frames.

Per frame:
- Average compressed size ≈ 400 KiB
- AEAD tag adds 16 bytes
- Encrypted frame ≈ 400 KiB + 16 B
- Blocks per frame ≈ ceil(400 KiB / 64 KiB) = 7 blocks
- Last block payload_len ≈ 400 KiB mod 64 KiB ≈ 16 KiB (rest zero-padded)

Total payload data blocks ≈ 1026 × 7 ≈ 7182 blocks.
FEC groups (224 data each): ceil(7182 / 224) ≈ 33 groups.
Parity blocks: 33 × 32 = 1056.
Total blocks (data + parity): 7182 + 1056 ≈ 8238 blocks.

Disk bytes per block: 64 KiB + 24 B framing ≈ 65560 B.
Total payload bytes: 8238 × 65560 ≈ 540 MiB.

Index:
- 1026 FrameEntry × ~64 B = ~64 KiB
- Per file: ~150 B (FileEntry) + ~50 B (path in pool) → for 1000 files,
  ~200 KiB
- Compressed → ~80 KiB
- Encrypted + framing + FEC (50% parity, 16+16 group): ~5 blocks ≈ ~325 KiB

Total archive: ~541 MiB.
Volumes: ceil(541 / 100) = 6 volumes (5 × 100 MiB + 1 × 41 MiB).

**Resilience:** Can lose any 32 blocks per group = ~32 × 64 KiB = 2 MiB per
group, distributed. With 33 groups, total tolerable corruption ≈ 66 MiB
spread evenly. Losing one whole volume (100 MiB) is *not* guaranteed
recoverable with default parity ratio — for that resilience, increase
`fec_parity_shards` (e.g. 64 or 96 for higher overhead).

---

*End of specification.*
