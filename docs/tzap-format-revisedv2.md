# tzap Archive Format Specification (Revised)

| Field | Value |
|---|---|
| **Format version** | 1 |
| **Document version** | 0.2 (revised after external review) |
| **Status** | Draft for review, no implementation yet |
| **Owner** | Frank Zhu |
| **Maintainers** | Frank Zhu |
| **File extension** | `.tzap` (single-volume) / `.tzap.NNN` (multi-volume) |
| **Suggested MIME type** | `application/vnd.tzap` |
| **Suggested UTI** | `dev.tzap.archive` |

## Changelog from v0.1 (this revision)

This revision incorporates external review feedback. Summary of substantive
changes:

1. **Round-robin block striping across volumes** is now the default layout.
   The previous linear layout made the stated "volume-loss resilience" goal
   mathematically unattainable at any practical FEC ratio. The block→volume
   mapping is now `block_index mod V`, and parity sizing rules guarantee
   recoverability against single-volume loss when configured correctly. (§7,
   §14, Appendix B.)
2. **Split GlobalHeader into a static `CryptoHeader` and a dynamic
   `ArchiveManifestFooter`.** All variable counters (frame_count, block_count,
   index pointer) move to a footer at the end of the final volume; the
   header at the top of Volume_1 contains only static, write-time-known
   crypto parameters. This makes single-pass non-seekable streaming write
   trivial. (§9.)
3. **In-envelope padding.** Frames are now padded to a multiple of
   `BLOCK_SIZE` *before* AEAD encryption, eliminating the per-frame-size
   leak that the previous on-disk `payload_len` field exposed. Every block
   on disk is a full `BLOCK_SIZE` of ciphertext; `payload_len` is removed
   from `BlockRecord`. (§6, §10, §13.)
4. **CryptoHeader and ManifestFooter are replicated** across volumes.
   CryptoHeader appears in every volume's prefix; ManifestFooter appears in
   every volume's suffix. Either single point of failure is mitigated. (§8,
   §9, §11.)
5. **Random-access semantics clarified.** `FileEntry.offset_in_frame` is
   defined to point at the start of file *data* (not the tar header). Tar
   header bytes for that file remain in the stream for sequential extract
   compatibility, but random-access extract uses parsed `FileEntry` fields
   directly. (§15, §17.)
6. **Small-file compression guidance.** Tuning advice and a pre-trained
   zstd dictionary extension are recommended for archives dominated by
   tiny files. (§20.)

---

## Abstract

tzap is a multi-volume archive format combining POSIX tar bundling, zstd
compression (multi-frame, random-access capable), authenticated encryption
(AEAD), and Reed-Solomon forward error correction (FEC). It targets long-term
archival storage where confidentiality, integrity, bit-rot resilience, and
volume-loss resilience matter together — and where the archive may need to be
split into size-bounded pieces for media or transfer constraints.

The pipeline is `tar → zstd → pad → AEAD → FEC → stripe → split`. The format
name `tzap` mnemonically tracks the core processing order: **t**ar, **z**std,
**a**ead, **p**arity.

---

## 1. Design Goals

1. **Confidentiality.** Archive contents (file data, file names, sizes,
   directory structure, timestamps) are unreadable without the key. Per-frame
   ciphertext sizes are hidden from passive observers by in-envelope padding.
2. **Integrity.** Any modification, truncation, or reordering of archive
   bytes is detected before plaintext is exposed.
3. **Bit-rot resilience.** Random bit flips within a configurable tolerance
   are repaired transparently.
4. **Volume-loss resilience.** Loss of one or more entire volume files is
   recoverable when parity is budgeted accordingly. This goal is now backed
   by mathematically sufficient layout rules (§14.4).
5. **Random access.** A single file can be extracted without reading or
   decrypting the rest of the archive.
6. **True single-pass streaming.** Both write and read paths can operate
   in a single pass on non-seekable streams (stdout, pipe, sequential
   media). The ManifestFooter pattern (§9) removes the previous
   GlobalHeader-backfill requirement.
7. **Splittable.** Output can be capped at any target volume size; volumes
   are independent files sharing an archive UUID.
8. **Format stability.** A version byte and algorithm IDs allow future
   changes without breaking existing archives.
9. **Auditable.** Wire format is fully specified by struct layouts and
   construction recipes. No undefined fields, no hidden state, no required
   pre-knowledge between layers.

## 2. Non-Goals

- Highest possible compression ratio. Per-frame zstd gives up some ratio
  for random access; this is intentional. Pre-trained dictionaries can
  recover most of the lost ratio for known data shapes.
- Append or in-place edit. tzap is write-once; modifications require re-pack.
- Multi-recipient encryption / key wrapping. Single symmetric key per
  archive (passphrase or keyfile). Public-key and multi-recipient modes
  are deferred to a future revision.
- Network protocol / chunked transfer. tzap is a file format.
- Cross-archive deduplication.

## 3. Threat Model

**In scope:**

- Passive adversary reading archive bytes (e.g. compromised cloud storage).
  Such an adversary should learn only: format identity, algorithm IDs,
  geometry parameters, archive UUID, total block count, total volume count,
  KDF parameters. They should *not* learn per-frame sizes or any per-file
  metadata.
- Active adversary modifying, truncating, reordering, or substituting bytes.
- Storage media bit-rot (single-bit and burst errors within FEC tolerance).
- Loss or absence of one or more volume files.
- Volume reordering, renaming, shuffling.
- User entering the wrong passphrase (must be detected early).
- Replay attacks substituting valid frames from one position to another
  (defended by binding `frame_index` and `archive_uuid` into AAD).
- Loss of the start of Volume_1, or the end of the final volume (defended
  by replicating CryptoHeader and ManifestFooter).

**Out of scope:**

- Side-channel attacks on the host machine (timing, cache, memory).
- Adversaries with KDF parameter access *and* a strong side channel.
- Quantum adversaries (AES-256 retains ~128-bit security against Grover).
- Adaptive chosen-plaintext attacks against the compression layer
  (CRIME/BREACH-class). Acceptable for static archival; unsuitable for
  interactive contexts where an attacker can inject chosen plaintext.
- Denial-of-service via crafted parameters (mitigated by reader-side caps,
  §22).

---

## 4. Conventions

- **Endianness:** all multi-byte integers are little-endian.
- **Integer types:** `u8`, `u16`, `u32`, `u64`. Signed: `i64`.
- **Packed structs:** tightly packed; explicit padding shown.
- **String encoding:** UTF-8, NFC-normalized, no BOM, no NUL terminator.
- **Hash:** SHA-256.
- **CRC:** CRC-32C (Castagnoli polynomial, 0x1EDC6F41).
- **Authentication:** "authenticated" = covered by an AEAD tag or an HMAC.
  CRC32C is for accidental corruption only.
- **Time:** nanoseconds since Unix epoch (signed 64-bit).

Struct definitions are shown in Rust syntax. The wire format is
language-agnostic.

---

## 5. Algorithm Registry

```rust
#[repr(u16)]
enum CompressionAlgo {
    None       = 0,
    ZstdFramed = 1,   // default; one zstd frame per chunk_size of input
}

#[repr(u16)]
enum AeadAlgo {
    AesGcmSiv256       = 1,   // default; nonce-misuse-resistant (RFC 8452)
    XChaCha20Poly1305  = 2,   // alternative; large nonce
    AesGcm256          = 3,   // discouraged for archives
}

#[repr(u16)]
enum FecAlgo {
    None             = 0,
    ReedSolomonGF16  = 1,   // default; Leopard-RS
    Wirehair         = 2,   // optional; rateless fountain code
}

#[repr(u16)]
enum KdfAlgo {
    Raw      = 0,   // user supplies 32-byte master_key via keyfile
    Argon2id = 1,   // default; passphrase-derived
}
```

Unknown algorithm IDs are a hard error. Range `0xFF00..0xFFFF` per enum is
reserved for experimental use.

---

## 6. Logical Pipeline

### Write path

```
files
  │ tar (POSIX ustar, no compression, no auto-metadata stripping)
  ▼
tar stream
  │ zstd, multi-frame: emit one frame every CHUNK_SIZE input bytes
  ▼
frames F₁, F₂, …, Fₙ   (variable compressed size Sₖ)
  │ pad each frame to next multiple of BLOCK_SIZE: append (pad_len, 0×(pad_len-1))
  │ where pad_len = (BLOCK_SIZE − ((Sₖ + AEAD_TAG_LEN) mod BLOCK_SIZE)) mod BLOCK_SIZE
  ▼
padded frames P₁, P₂, …, Pₙ   (each |Pₖ| + AEAD_TAG_LEN ≡ 0 mod BLOCK_SIZE)
  │ AEAD-encrypt each padded frame independently
  ▼
encrypted frames EFₖ = ctₖ ‖ tagₖ   (|EFₖ| is an exact multiple of BLOCK_SIZE)
  │ split EFₖ into (|EFₖ| / BLOCK_SIZE) data blocks of size BLOCK_SIZE
  ▼
data blocks D₁, D₂, …, Dₘ   (all exactly BLOCK_SIZE bytes)
  │ FEC per group: G_data data blocks → G_parity parity blocks
  ▼
all blocks (data + parity)
  │ assign each block a global block_index, then map to volume by
  │   volume_index = (block_index mod V)
  │ where V = configured volume count (the stripe width)
  ▼
archive.tzap.001, archive.tzap.002, …, archive.tzap.V
```

### Read path

Reverse: per-volume block reads → FEC group repair → block reassembly per
frame → AEAD decryption → strip padding (using length prefix at end of
padded plaintext) → zstd decode → tar extraction.

### Two distinct units

- **Frame** = a content unit. One zstd frame = one AEAD encryption unit.
  The unit at which random access is possible.
- **Block** = a storage unit. Exactly `BLOCK_SIZE` bytes of ciphertext.
  The unit of FEC and per-block integrity checks.

A frame's encrypted bytes span an integer number of contiguous blocks
(possible because of in-envelope padding). Frames never share a block, and
blocks never span frames.

### In-envelope padding format

Plaintext input to AEAD is `zstd_frame_bytes ‖ padding`, where padding is:

```
padding = [pad_len_byte, 0, 0, ..., 0]  // length = pad_len
```

`pad_len_byte` is a single byte at the *first* padding position, encoding
the number of padding bytes (1 to 255). The remaining `pad_len - 1` bytes
are zero. This is a simplified PKCS#7 scheme constrained to `pad_len ∈
[1, BLOCK_SIZE]`. When `pad_len ≥ 256`, the first 4 bytes encode `pad_len`
as a little-endian `u32` and a marker byte indicates the wide variant:

```
padding_wide = [0xFF, pad_len: u32 LE, 0, 0, ..., 0]   // total length = pad_len; pad_len ≥ 5
padding_byte = [pad_len: u8, 0, 0, ..., 0]              // total length = pad_len; pad_len ∈ [1, 254]
                                                          // (pad_len = 0xFF is reserved for wide)
```

The reader inspects the last byte of decrypted plaintext: if it is `0xFF`,
read the wide form by walking back from end; otherwise read the byte form.

(The padding is authenticated as part of the AEAD plaintext; tampering is
detected by AEAD tag verification.)

---

## 7. Archive Layout

### 7.1 Per-volume structure

```
Volume_i  =  VolumeHeader
             CryptoHeader              ; static crypto/KDF parameters, replicated in every volume
             BlockRecord_{stripe_0}
             BlockRecord_{stripe_1}
             …
             BlockRecord_{stripe_n−1}
             ManifestFooter            ; replicated in every volume (final values only known to last writer)
             VolumeTrailer             ; CRC over the volume; closes out the file
```

Both `CryptoHeader` and `ManifestFooter` are replicated in every volume.
`CryptoHeader` is identical across all volumes — it is finalized before
writing begins, so each volume writer can emit a copy. `ManifestFooter` is
identical only for streams where the final values are known to all writers;
otherwise it may be a placeholder in intermediate volumes and authoritative
only in the final volume. Readers prefer the latest fully-validated copy.

### 7.2 Block-to-volume mapping

```
volume_index_zero_based = block_index mod V
position_in_volume      = block_index div V
```

Where `V` is the total volume count, fixed at write start (`stripe_width`
in CryptoHeader). For the i-th volume, its blocks have global indices
`{i, V+i, 2V+i, 3V+i, …}` up to `block_count − 1`.

This is **round-robin striping**. Every FEC group of `G_total = G_data +
G_parity` consecutive blocks gets distributed across volumes with at most
`ceil(G_total / V)` blocks landing on any single volume. Losing one volume
loses at most `ceil(G_total / V)` blocks per FEC group, which is repairable
when `G_parity ≥ ceil(G_total / V)`.

### 7.3 Block index sequence

Block indices are assigned in pipeline order: data blocks of frame 1,
parity blocks of FEC group(s) containing frame 1's blocks, data blocks of
frame 2, and so on. Within a single FEC group, data blocks come first
(indices `g·G_total` to `g·G_total + G_data − 1`), then parity blocks
(`g·G_total + G_data` to `g·G_total + G_total − 1`).

**Important consequence:** consecutive block indices do *not* mean
consecutive bytes on a single volume. To read block `b`, compute
`(b mod V, b div V)` to find which volume and where in that volume.

### 7.4 Volume size targeting

The writer aims for a configured `target_volume_size`, but striping makes
volumes essentially equal-size by construction. With V volumes and total
block count `M = data_block_count + parity_block_count`, each volume holds
`ceil(M / V)` or `floor(M / V)` blocks (within one block of each other).
The user configures V directly, or sets a target volume size from which V
is derived once total block count is estimated.

### 7.5 Streaming writes with unknown V

For streams where V cannot be fixed in advance (true stdout streaming), V
defaults to a configurable value (e.g. 16). The writer rotates through V
volumes as block indices increase, but if total block count is less than V,
some volumes simply hold fewer blocks (or zero). Readers tolerate missing
volume files iff overall FEC has enough headroom.

---

## 8. Volume Header

Fixed 128 bytes, at offset 0 of every volume.

```rust
#[repr(C, packed)]
struct VolumeHeader {
    magic:              [u8; 4],   // b"TZAP"
    format_version:     u16,       // 1
    volume_format_rev:  u16,       // 0
    volume_index:       u32,       // 0-based (note: filename uses 1-based)
    volume_total:       u32,       // stripe width V; 0 if unknown at write time
    archive_uuid:       [u8; 16],  // random, identical across volumes
    crypto_header_offset: u32,     // byte offset within this volume to CryptoHeader
    crypto_header_length: u32,     // length of CryptoHeader
    manifest_footer_offset: u64,   // byte offset within this volume to ManifestFooter
                                   //  (or u64::MAX if not yet written, placeholder only)
    manifest_footer_length: u32,   // length of ManifestFooter
    _reserved:          [u8; 56],
    header_crc32c:      u32,       // CRC32C over bytes [0..124]
}
```

`volume_total` carries the stripe width V. All volumes in an archive must
agree on V; readers verify this.

Filename convention: `<base>.tzap.NNN` where NNN is `volume_index + 1`,
zero-padded to 3 digits minimum.

---

## 9. CryptoHeader

Replicated identically in every volume. Contains all static parameters
needed to derive keys and parse the rest of the archive. Located via
`VolumeHeader.crypto_header_offset`.

### 9.1 Fixed portion

```rust
#[repr(C, packed)]
struct CryptoHeaderFixed {
    magic:              [u8; 4],   // b"TZCH"
    length:             u32,       // total bytes of CryptoHeader (incl. HMAC)

    // Algorithm selection
    compression_algo:   u16,
    aead_algo:          u16,
    fec_algo:           u16,
    kdf_algo:           u16,

    // Geometry (write-time-known, static)
    chunk_size:         u32,       // zstd input bytes per frame
    block_size:         u32,       // bytes per storage block
    fec_data_shards:    u16,       // G_data per group
    fec_parity_shards:  u16,       // G_parity per group
    index_fec_data_shards:    u16, // separate FEC sizing for index
    index_fec_parity_shards:  u16,
    stripe_width:       u32,       // V; matches VolumeHeader.volume_total

    // Sanity caps (advisory; readers enforce per-policy)
    max_path_length:    u32,
    expected_volume_size: u64,     // target size; advisory

    _reserved:          [u8; 24],
}
// Followed in order by:
//   KdfParams       (variable length, §12.1)
//   Extension[]     (TLV list, §9.2; terminator = tag 0x0000)
//   header_hmac     [u8; 32]   // HMAC-SHA-256(mac_key, all preceding CryptoHeader bytes)
```

CryptoHeader has **no dynamic fields**. Every value is known at archive
creation start. This is what makes single-pass streaming work: no
backfilling required.

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

Reserved tags (high bit clear = non-critical, ignorable):

| Tag | Type | Purpose |
|---|---|---|
| `0x0001` | UTF-8 | User comment |
| `0x0002` | UTF-8 | Creator tool identifier |
| `0x0003` | `i64` | Creation timestamp, nanoseconds since Unix epoch |
| `0x0004` | `[u8; 32]` | SHA-256 of archive contents pre-encryption (optional) |
| `0x0005` | UTF-8 | Locale tag for filenames |
| `0x0006` | bytes | Pre-trained zstd dictionary (see §20.4) |

Critical tags (high bit set) cause hard error if unknown.

### 9.3 Replication

Every volume writes an identical copy of CryptoHeader. A reader opens any
volume, locates CryptoHeader via `VolumeHeader.crypto_header_offset`, and
validates `header_hmac`. If the first attempt fails (bit-rot in this
volume's copy), the reader tries another volume's copy. As long as at
least one of V volumes has an intact CryptoHeader, the archive's
parameters are recoverable.

For extra resilience, large archives may FEC-encode the CryptoHeader
itself (treated as a small set of pseudo-blocks, kind = 4/5). This is a
future extension and not required by the base format.

---

## 10. Block Record

Every block on disk is wrapped in a small framing structure. Because of
in-envelope padding (§6), every block carries exactly `BLOCK_SIZE` bytes
of ciphertext or parity.

```rust
#[repr(C, packed)]
struct BlockRecord {
    magic:         [u8; 4],          // b"TZBK"
    block_index:   u64,              // global index
    kind:          u8,               // 0 = payload-data
                                     // 1 = payload-parity
                                     // 2 = index-data
                                     // 3 = index-parity
                                     // 4 = crypto-mirror-data (reserved)
                                     // 5 = crypto-mirror-parity (reserved)
    flags:         u8,               // bit 0: last block of a frame (informational)
                                     // bit 1: synthetic zero block padding final FEC group
    _reserved:     [u8; 2],
    payload:       [u8; BLOCK_SIZE], // exactly BLOCK_SIZE bytes of ciphertext/parity
    record_crc32c: u32,              // CRC32C over magic..payload (inclusive)
}
```

On-disk size per block: `BLOCK_SIZE + 20` bytes (20 B framing, down from 24
because `payload_len` is gone).

Notes vs. previous draft:

- `payload_len` is **removed**. Every block payload is fully populated with
  AEAD ciphertext, because in-envelope padding has made every frame's
  encrypted output a multiple of `BLOCK_SIZE`.
- `flags` bit 0 is now informational only (it does not affect parsing).
- `flags` bit 1 still marks synthetic zero blocks used to fill the final
  FEC group; these blocks contain zeros and decode to nothing.

---

## 11. ManifestFooter

Replicated in every volume, written at the end (before the VolumeTrailer).
Contains all dynamic counters and the index pointer — values that may only
be known at archive close.

```rust
#[repr(C, packed)]
struct ManifestFooter {
    magic:                    [u8; 4],   // b"TZMF"
    archive_uuid:             [u8; 16],  // matches CryptoHeader / VolumeHeader
    volume_index:             u32,       // 0-based; this volume's position
    is_authoritative:         u8,        // 1 = values are final; 0 = placeholder
    _reserved_byte:           [u8; 3],

    // Final totals (authoritative only when is_authoritative = 1)
    total_volumes:            u32,
    frame_count:              u64,
    payload_block_count:      u64,       // data + parity blocks, excl. index
    tar_total_size:           u64,

    // Index pointer (authoritative only when is_authoritative = 1)
    index_first_block:        u64,
    index_block_count:        u32,
    index_decompressed_size:  u64,

    // Optional content hash
    content_sha256:           [u8; 32],  // SHA-256 of tar stream (zero if not computed)

    manifest_hmac:            [u8; 32],  // HMAC-SHA-256(mac_key, all preceding bytes)
}
```

### 11.1 Authoritative vs. placeholder copies

Multi-volume writers face a sequencing problem: as Volume_1 is being
written and then closed, the final `frame_count` and index pointers are
not yet known. Three strategies:

- **Lazy footer writers:** each intermediate volume writes a placeholder
  ManifestFooter with `is_authoritative = 0`. The final volume writes the
  authoritative copy. Readers prefer the authoritative copy.
- **Tail-pass footer writers:** if the output medium permits seek-back, the
  writer may go back at archive close and overwrite each volume's
  ManifestFooter with the authoritative values. This is optional and
  required only when readers may open intermediate volumes first.
- **True append-only streams:** intermediate volumes carry placeholders.
  As long as the final volume is intact, the archive is recoverable.

A reader scans all available volumes and uses the highest-`volume_index`
authoritative footer with a valid HMAC. If none is authoritative (final
volume lost), the reader may attempt recovery by reconstructing counts
from VolumeHeader/BlockRecord scanning, but this is best-effort.

### 11.2 HMAC binding

`manifest_hmac` is computed over the entire ManifestFooter excluding the
HMAC field itself, keyed with `mac_key` (derived from `master_key`). Any
tampering with the counters or pointers is detected. Wrong passphrase
yields a wrong `mac_key` and the HMAC fails — this is the second
opportunity (after `CryptoHeader.header_hmac`) to detect wrong-key early.

### 11.3 Resilience implications

With ManifestFooter replicated in every volume (placeholder in
intermediates, authoritative in the final volume), losing the final
volume means: (a) authoritative counters are lost; (b) the index pointer
is lost; (c) but all CryptoHeader copies and all data are still
recoverable via FEC.

In that pathological case, the reader can still verify all surviving
blocks, decrypt them (deriving the index pointer is impossible without
the authoritative manifest), but cannot directly use the index. A
"recovery mode" reader can scan all decrypted frames in order and
reconstruct the index by re-parsing the tar stream. This is slow but
viable.

---

## 12. VolumeTrailer

Fixed 24 bytes, at the very end of every volume file.

```rust
#[repr(C, packed)]
struct VolumeTrailer {
    magic:           [u8; 4],   // b"TZVT"
    volume_index:    u32,
    bytes_written:   u64,       // total bytes in this volume up to (not incl) trailer
    trailer_crc32c:  u32,
    _reserved:       [u8; 4],
}
```

The trailer's presence (with matching `volume_index`) confirms the volume
was finalized cleanly. Missing trailer = truncated volume (recoverable via
FEC headroom if margin exists).

---

## 13. Key Derivation

### 13.1 KDF parameters

```rust
#[repr(C, packed)]
struct Argon2idParams {
    algo_tag:    u16,         // 1
    t_cost:      u32,         // iterations (default 3)
    m_cost_kib:  u32,         // memory in KiB (default 262_144 = 256 MiB)
    parallelism: u32,         // default 4
    salt_length: u16,         // typically 16
    salt:        [u8; salt_length],
}

#[repr(C, packed)]
struct RawKeyParams {
    algo_tag: u16,            // 0
}
```

For `KdfAlgo::Raw`, the user provides `master_key` directly via keyfile.

### 13.2 Master key derivation

```
master_key = Argon2id(passphrase_utf8_nfc, salt, t_cost, m_cost_kib, parallelism, len=32)
```

### 13.3 Subkey derivation

```
enc_key          = HKDF-SHA256(master_key, info=b"tzap-v1-enc",       L=32)
mac_key          = HKDF-SHA256(master_key, info=b"tzap-v1-mac",       L=32)
nonce_seed       = HKDF-SHA256(master_key, info=b"tzap-v1-nonce",     L=32)
index_key        = HKDF-SHA256(master_key, info=b"tzap-v1-index",     L=32)
index_nonce_seed = HKDF-SHA256(master_key, info=b"tzap-v1-idxnonce",  L=32)
```

### 13.4 Reader-side resource limits

A reader must enforce caps to prevent crafted-archive DoS:

| Cap | Default | Notes |
|---|---|---|
| `m_cost_kib` | 4 GiB | Argon2 memory ceiling |
| `t_cost` | 100 | Argon2 iteration ceiling |
| `chunk_size` | 64 MiB | per-frame buffer ceiling |
| `block_size` | 1 MiB | per-block buffer ceiling |
| `stripe_width V` | 4096 | open-files ceiling |
| `fec_data_shards + fec_parity_shards` | 4096 | FEC group size ceiling |
| `max_path_length` | 4096 | per-path string allocation ceiling |
| Total decompressed extraction size | 100 GiB or 10× archive size | zip-bomb defense; user can override |

---

## 14. AEAD Construction

### 14.1 Nonce derivation

```rust
fn derive_nonce(seed: &[u8; 32], domain: &[u8], counter: u64, len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(8 + domain.len() + 8);
    info.extend_from_slice(b"tzap-v1-");
    info.extend_from_slice(domain);
    info.extend_from_slice(&counter.to_le_bytes());
    hkdf_expand_sha256(seed, &info, len)
}
```

Nonce length depends on AEAD:
- `AesGcmSiv256`, `AesGcm256`: 12 bytes
- `XChaCha20Poly1305`: 24 bytes

### 14.2 Associated data

```rust
fn aad(archive_uuid: &[u8; 16], frame_index: u64) -> [u8; 24] {
    let mut a = [0u8; 24];
    a[..16].copy_from_slice(archive_uuid);
    a[16..].copy_from_slice(&frame_index.to_le_bytes());
    a
}
```

### 14.3 Frame encryption with in-envelope padding

```rust
fn encrypt_frame(k: u64, zstd_frame: &[u8]) -> Vec<u8> {
    let tag_len = AEAD_TAG_LEN;                 // 16 for current AEADs
    let total_blocks = ((zstd_frame.len() + tag_len + BLOCK_SIZE - 1) / BLOCK_SIZE).max(1);
    let envelope_size = total_blocks * BLOCK_SIZE;
    let pad_len = envelope_size - zstd_frame.len() - tag_len;

    let mut plaintext = Vec::with_capacity(envelope_size - tag_len);
    plaintext.extend_from_slice(zstd_frame);
    append_padding(&mut plaintext, pad_len);    // see §6, in-envelope padding format

    let nonce = derive_nonce(&nonce_seed, b"frame", k, AEAD_NONCE_LEN);
    let aad   = aad(&archive_uuid, k);
    aead_encrypt(&enc_key, &nonce, &aad, &plaintext)  // returns ct || tag, |output| = envelope_size
}
```

### 14.4 Frame decryption

```rust
fn decrypt_frame(k: u64, ciphertext_and_tag: &[u8]) -> Result<Vec<u8>> {
    let nonce = derive_nonce(&nonce_seed, b"frame", k, AEAD_NONCE_LEN);
    let aad   = aad(&archive_uuid, k);
    let mut plaintext = aead_decrypt(&enc_key, &nonce, &aad, ciphertext_and_tag)?;
    strip_padding(&mut plaintext)?;   // remove zstd_frame's trailing padding
    Ok(plaintext)  // bare zstd frame, ready for zstd-decode
}
```

### 14.5 Index chunk encryption

The index is compressed (one zstd frame), padded, then split into chunks
of size `≤ chunk_size`. Each chunk is encrypted independently with
`index_key`:

```rust
fn encrypt_index_chunk(j: u64, plaintext: &[u8]) -> Vec<u8> {
    // Same in-envelope padding as frames; tag included in size budget.
    let nonce = derive_nonce(&index_nonce_seed, b"index", j, AEAD_NONCE_LEN);
    let aad   = aad(&archive_uuid, j);
    aead_encrypt(&index_key, &nonce, &aad, &padded_plaintext)
}
```

---

## 15. Forward Error Correction

### 15.1 Default scheme

Reed-Solomon over GF(2¹⁶), Leopard implementation. FEC groups of size
`G_total = G_data + G_parity` blocks. Default: 224 data + 32 parity.

### 15.2 Group layout and striping

```
group g     →  global blocks [g·G_total … (g+1)·G_total)
  data:        block_index in [g·G_total              … g·G_total + G_data)
  parity:      block_index in [g·G_total + G_data     … g·G_total + G_total)

after striping:
  block_index b → volume (b mod V), position (b div V)
```

Critically, after striping, each FEC group occupies at most
`ceil(G_total / V)` slots on any single volume.

### 15.3 Volume-loss recoverability rule

To survive losing N entire volumes, parity must satisfy:

```
G_parity ≥ N × ceil(G_total / V)
```

Equivalent rules:
- For N = 1 (lose one volume): G_parity ≥ ceil(G_total / V).
- For V ≥ G_total: G_parity ≥ N suffices (each group has at most one
  block per volume; lose N volumes ⇒ lose N blocks per group).
- For V < G_total: G_parity grows; consider raising parity ratio.

**Worked examples:**

| V (volumes) | G_total | G_data | G_parity (default 32) | Survives N volumes lost? |
|---|---|---|---|---|
| 4   | 256 | 224 | 32  | N=0 only (lose any 1 vol ⇒ 64 blocks lost per group; > 32 parity) |
| 8   | 256 | 224 | 32  | N=1 (32 blocks lost per group; exactly fits) |
| 16  | 256 | 224 | 32  | N=2 |
| 32  | 256 | 224 | 32  | N=4 |
| 256+ | 256 | 224 | 32  | N=32 |

**For V < 8 the default parity ratio does not deliver single-volume-loss
recovery.** The writer must either raise `fec_parity_shards`, lower
`fec_data_shards`, or accept the limitation. A conformant CLI warns at
archive-creation time when the configured V and parity ratio fail to meet
the user's stated recovery goal.

### 15.4 Encoding

```
group g, conceptually:
    data_blocks  = the next G_data block-sized ciphertext slices
    if fewer than G_data are available at archive end:
        pad with synthetic zero blocks (flags bit 1 set)
    parity_blocks = Leopard.encode(data_blocks, G_parity)
    for each block in (data ‖ parity):
        wrap in BlockRecord with appropriate kind, magic, CRC
        place at (volume_index = block_index mod V, position = block_index div V)
        write to corresponding volume's pending buffer
```

### 15.5 Decoding

```
for each FEC group g:
    collect all available blocks for this group's index range
    discard blocks failing record_crc32c (treat as missing)
    if surviving_count < G_data:  FAIL — group unrecoverable
    if any data block missing:    reconstruct via Leopard.decode
    # all G_data data blocks now present and CRC-clean
    # AEAD verification happens at the frame layer
```

### 15.6 Index FEC

The index has its own FEC parameters (`index_fec_data_shards`,
`index_fec_parity_shards`), defaulting to 16 + 16 (50% overhead). Same
striping rules apply; with V ≥ 2 and 50% parity, single-volume loss of
the index is recoverable.

---

## 16. Index Format

### 16.1 On-disk path

```
Index bytes
  → serialize (IndexHeader + tables + string_pool)
  → zstd-compress (single frame)
  → split into chunks ≤ chunk_size
  → in-envelope-pad each chunk (§6)
  → AEAD-encrypt each chunk with index_key (§14.5)
  → split into BLOCK_SIZE blocks
  → FEC-encode (§15.6)
  → emit as BlockRecord with kind ∈ {2 (index-data), 3 (index-parity)}
  → block_index continues monotonically from payload blocks
  → stripe across volumes by `b mod V`
```

The pointer (`index_first_block`, `index_block_count`) lives in
`ManifestFooter`. Readers locate the index after validating the
ManifestFooter HMAC.

### 16.2 In-memory structure (after decrypt + decompress)

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
    sha256_self:         [u8; 32],  // SHA-256 of all following bytes
}
// Then in order:
//   FrameEntry[frame_count]
//   FileEntry[file_count]
//   string_pool: [u8; string_pool_size]
```

### 16.3 Frame table

```rust
#[repr(C, packed)]
struct FrameEntry {
    frame_index:            u64,
    decompressed_offset:    u64,   // cumulative offset into tar stream
    decompressed_size:      u32,   // size of decoded bytes (≤ chunk_size)
    compressed_size:        u32,   // size of zstd frame (pre-pad, pre-AEAD)
    envelope_size:          u32,   // size after pad + AEAD tag (= block_count × BLOCK_SIZE)
    first_block_index:      u64,   // global block index of frame's first block
    block_count:            u32,   // number of blocks the encrypted frame spans
    _reserved:              u32,
}
```

(No `last_block_payload_len` anymore — every block is full BLOCK_SIZE
ciphertext under in-envelope padding.)

### 16.4 File table

```rust
#[repr(C, packed)]
struct FileEntry {
    path_offset:             u64,   // into string_pool
    path_length:             u32,
    flags:                   u32,   // §16.5
    frame_index:             u64,   // frame containing first byte of file data
    offset_in_frame:         u32,   // decompressed byte offset of file DATA within frame
                                    //   (skips the tar header — see §16.6)
    decompressed_size:       u64,   // total file data length
    mode:                    u32,   // POSIX mode bits (S_IFMT included)
    mtime_ns:                i64,
    atime_ns:                i64,
    ctime_ns:                i64,
    btime_ns:                i64,   // INT64_MIN if unknown
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
    xattr_offset:            u64,   // serialized xattr blob; 0 if no xattrs
    xattr_length:            u32,
    content_sha256:          [u8; 32],  // optional; zero if not computed
    tar_header_offset:       u64,   // decompressed offset of file's tar header
                                    //   in the tar stream (for sequential extract)
    _reserved:               [u8; 8],
}
```

### 16.5 File flags

| Bit | Meaning |
|---|---|
| 0 | Directory |
| 1 | Symlink |
| 2 | Hardlink |
| 3 | Sparse file |
| 4 | Has extended attributes |
| 5 | Has POSIX ACL (in xattrs) |
| 6 | `content_sha256` is populated |
| 7+ | Reserved (must be zero) |

### 16.6 Tar-boundary clarification

`offset_in_frame` points at the **start of file data**, not the tar
header. The tar header for each file remains in the tar stream (at
`tar_header_offset` in the decompressed stream) for sequential
compatibility — a reader can pipe the decompressed stream through `tar -x`
and get correct extraction.

For **random access**, the extractor uses the parsed fields in `FileEntry`
(mode, mtime, uname, etc.) directly. It does *not* parse the tar header at
extract time. The tar header is duplicated information in this case; its
purpose is only the sequential-compatibility path.

**Hardlinks** reference `hardlink_target_offset` (a path string), which
the extractor resolves to a previously-extracted file. The tar header for
hardlinks is informational only.

---

## 17. File Metadata Handling

Same semantics as v0.1; reiterated briefly here for completeness.

### 17.1 Paths

- UTF-8, NFC-normalized.
- Forward slashes (`/`) as separators on all platforms.
- No leading `/`; paths are relative to extraction root.
- No `..` segments. Validated at both write and extract time.
- Max path length is reader-policy; format permits up to `u32` bytes.

### 17.2 Symlinks and hardlinks

- Symlink target stored verbatim.
- Hardlinks reference a previously-listed path.
- Extractor must refuse symlinks that escape the extraction root.

### 17.3 Extended attributes

```
xattr_blob = entry_count: u32
             entry[entry_count]

entry      = name_length: u32
             value_length: u32
             name: [u8; name_length]
             value: [u8; value_length]
```

POSIX ACLs are stored as `system.posix_acl_*` xattrs. Unknown xattr names
are preserved but optionally skipped during extraction (with warning).

### 17.4 Sparse files

Flag bit 3 set; extent map stored in xattr `tzap.sparse_map` as a sequence
of `(logical_offset: u64, length: u64)` pairs of populated regions.

### 17.5 Special files

Mode bits identify devices, FIFOs, sockets. Major/minor numbers stored in
xattrs `tzap.devnum.major` / `tzap.devnum.minor`.

---

## 18. Read Algorithm

### 18.1 Open

```
1. Open any available volume (typically Volume_1).
2. Read VolumeHeader; validate magic and CRC.
3. Locate and read CryptoHeader at VolumeHeader.crypto_header_offset.
4. Parse KdfParams; prompt for passphrase or load keyfile.
5. Run KDF → master_key. Derive mac_key.
6. Verify CryptoHeader.header_hmac. If fails:
     - try another volume's CryptoHeader copy
     - if all copies fail under same passphrase: report "wrong key or all CryptoHeader copies corrupt"
7. Derive enc_key, nonce_seed, index_key, index_nonce_seed.
8. Find ManifestFooter:
     a. Scan all available volumes for ManifestFooter with is_authoritative=1
        and valid manifest_hmac
     b. Prefer the copy with the highest volume_index
     c. If no authoritative copy: enter recovery mode (see §18.3)
9. Now we have: counters, index location, stripe_width V.
```

### 18.2 Extract a file (random access)

```
10. Walk volume directory; map global block_index → (volume, position).
11. Read index blocks:
      - block_index range: [index_first_block, index_first_block + index_block_count)
      - for each FEC group spanned: collect blocks, repair via FEC if needed
12. Reassemble encrypted-index chunks; AEAD-decrypt with index_key.
13. Concatenate decrypted chunks; zstd-decompress.
14. Parse IndexHeader, FrameEntry[], FileEntry[], string_pool.
15. Look up target path in FileEntry[]; get frame_index, offset_in_frame, decompressed_size.
16. For each frame spanning the requested data:
      a. Look up FrameEntry → first_block_index, block_count.
      b. Walk those block indices; map each to (volume, position); read.
         Repair FEC groups as needed.
      c. Concatenate block payloads → encrypted_frame.
      d. AEAD-decrypt (key=enc_key, nonce(b"frame", k), aad(uuid, k)).
      e. Strip in-envelope padding.
      f. zstd-decode → frame plaintext (chunk_size or smaller).
      g. Read requested byte range.
17. Reconstruct file with metadata from FileEntry.
```

### 18.3 Recovery mode (no authoritative ManifestFooter)

```
1. With CryptoHeader available, derive subkeys.
2. Walk every BlockRecord across all available volumes; tally block indices.
3. Group blocks into FEC groups (by block_index / G_total).
4. Repair groups where possible; decrypt frames in order.
5. For each frame, decompress and parse the contained tar stream chunk.
6. Reconstruct an in-memory tar inventory ≈ what the index would have provided.
7. Proceed with sequential extraction or list.
```

Slow but viable. Random access by path is impossible until the index is
reconstructed; this is the cost of losing the authoritative manifest.

---

## 19. Write Algorithm

### 19.1 Single-pass streaming

```
1. Generate archive_uuid (16 random bytes from CSPRNG).
2. Acquire passphrase or keyfile. Run KDF. Derive all subkeys.
3. Choose stripe_width V (from user, or from estimated total size and
   target volume size).
4. Build CryptoHeaderFixed + KdfParams + Extension list.
5. Compute header_hmac. CryptoHeader is now final.
6. Open Volume_1 (and conceptually all V volumes, though writers may use
   a single rotating output for sequential media).
7. For each volume_i in 0..V:
     - write VolumeHeader (with crypto_header_offset / length set;
       manifest_footer_offset = u64::MAX as placeholder)
     - write CryptoHeader (identical bytes across all volumes)
8. Initialize:
     - tar writer feeding zstd encoder
     - zstd encoder set to end_frame() every chunk_size input bytes
     - per-block FEC group buffer
     - per-volume output position tracker
     - frame_index = 0, block_index = 0
     - in-memory frame table and file table (built as we go)
9. Stream files through tar → zstd. For each completed zstd frame F_k:
     a. encrypted = encrypt_frame(k, F_k)  // includes in-envelope pad
     b. Split encrypted into N = |encrypted|/BLOCK_SIZE data blocks.
     c. Append to current FEC group buffer.
     d. When G_data blocks accumulated:
          parity = Leopard.encode(data_blocks, G_parity)
          for each block in (data ‖ parity):
              compute volume_i = block_index mod V
              compute position = block_index div V
              wrap in BlockRecord; write at (volume_i, position)
              block_index += 1
          rotate to new FEC group
     e. Record FrameEntry { frame_index: k, first_block_index: …, block_count: N, … }
     f. As tar headers stream past, record FileEntry for each file.
     g. frame_index += 1
10. After last file:
     - finalize tar; flush zstd; encrypt final frame
     - pad final FEC group with synthetic zero blocks (flags bit 1)
     - emit parity for that group
11. Build index:
     - assemble IndexHeader + FrameEntry[] + FileEntry[] + string_pool
     - zstd-compress (single frame)
     - split into chunks; pad-then-AEAD each chunk with index_key
     - split into BLOCK_SIZE blocks
     - FEC-encode with index_fec_* parameters
     - emit as kind=2/3 blocks; continue block_index sequence
12. Finalize:
     - frame_count, payload_block_count, tar_total_size known
     - index_first_block, index_block_count, index_decompressed_size known
     - Build ManifestFooter with is_authoritative=1; compute manifest_hmac.
13. For each volume_i in 0..V:
     - write ManifestFooter at the volume's current end
     - write VolumeTrailer
     - update VolumeHeader.manifest_footer_offset / length
       (this is a small backfill at the start of each volume — required
        for direct opening of arbitrary volumes; if not done, readers can
        still scan from the end and locate the footer by magic search)
     - close volume
```

### 19.2 Strictly non-seekable writers

When even the small step-13 backfill of `manifest_footer_offset` is
impossible (true append-only pipes), set `manifest_footer_offset =
u64::MAX` in VolumeHeader and require readers to scan backwards from
end-of-volume for `b"TZMF"` magic. This costs ~one extra read but
preserves true one-pass write.

### 19.3 Volume size targeting

Striping makes volumes very nearly equal. The writer estimates total
block count from `tar_total_size` if known in advance, or rolls volumes
dynamically by checking byte counts. Output rotation between volumes
happens on every block emission (or batched per FEC group) — implementation
detail, not format detail.

---

## 20. Performance Considerations

### 20.1 Parallelism

- Per-frame AEAD and zstd are independent → parallelize across frames.
- FEC group encoding/decoding is independent → parallelize across groups.
- Block I/O can be producer-consumer with backpressure.
- Multi-volume writers can interleave writes across V open file handles.

### 20.2 Memory

- Streaming write: one FEC group's blocks in memory (≈ `G_total × BLOCK_SIZE`,
  default 16 MiB) plus per-frame buffers.
- Random extract: blocks for the spanning FEC groups (typically 16–32 MiB).
- Index size: bounded by file count × FileEntry size + string pool. For
  100k files, ~16 MiB uncompressed; compresses well.

### 20.3 Throughput (modern hardware estimates)

| Stage | Throughput (single-thread) |
|---|---|
| zstd compress (level 3) | ~300 MB/s |
| AES-256-GCM-SIV | ~1 GB/s (with AES-NI) |
| Leopard FEC encode | ~2 GB/s per group |
| CRC32C | ~10 GB/s (with SSE4.2) |

Compression is the typical bottleneck. Multi-threaded zstd (`zstdmt`)
saturates most modern disks.

### 20.4 Small-file corpus considerations

Per-frame zstd with `chunk_size = 1 MiB` works well on average corpora
(1–5% ratio cost vs. monolithic compression). On corpora dominated by
millions of tiny files, the cost can grow substantially because zstd
cannot back-reference across frame boundaries. Mitigations:

1. **Increase `chunk_size`** at archive-creation time. Larger frames mean
   fewer frame boundaries and longer back-references. 8 MiB or 16 MiB
   chunks remain practical for random access on typical files.
2. **Pre-train a zstd dictionary** on a representative sample of the
   corpus, then ship it as Extension tag `0x0006`. Each frame is then
   compressed with that shared dictionary as initial state; ratio
   recovers most of the loss vs. monolithic.
3. **Sort files by similarity** before tarring (if backup workflow
   permits) — groups similar files into the same frames, improving
   per-frame ratio.

A future format revision may add an explicit "dense small-file mode"
that packs multiple files per zstd frame with a finer-grained internal
structure, but this is out of scope for v1.

### 20.5 Padding overhead

In-envelope padding wastes up to `BLOCK_SIZE - 1` bytes per frame. With
default `BLOCK_SIZE = 64 KiB` and `chunk_size = 1 MiB` (frames typically
30–60% compressed → 300–600 KiB), padding overhead averages 32 KiB per
frame, ≈ 5% on top of compressed size, ≈ 2% of decompressed size. This
is the cost of removing the per-frame size leak.

### 20.6 Hardware acceleration

- AES-NI / ARM crypto extensions for AES-GCM-SIV.
- AVX2 / AVX-512 SIMD for Leopard-RS.
- Hardware CRC32C (SSE4.2 / ARMv8.1 CRC).

---

## 21. Failure Mode Matrix

| Failure | Detection | Recovery |
|---|---|---|
| Bit-rot in block payload | `record_crc32c` | FEC repair if group survivors ≥ G_data |
| Bit-rot in BlockRecord framing | magic / CRC fail | Block treated as missing → FEC |
| Wrong passphrase | CryptoHeader HMAC fails | Abort with clear error |
| Tampered CryptoHeader | HMAC fails | Try replicated copy in another volume |
| Whole volume lost | Block-index gap | FEC if G_parity ≥ ceil(G_total / V) (§15.3) |
| Multiple volumes lost | Same | FEC if G_parity ≥ N × ceil(G_total / V) |
| Truncated final volume | Missing trailer or footer | ManifestFooter copy in earlier volume serves |
| Final volume entirely lost | ManifestFooter absent | Recovery mode (§18.3) — slow but viable |
| Tampered ManifestFooter | HMAC fails | Try another volume's copy |
| Volume reorder / rename | `archive_uuid` + `volume_index` | Re-sort by header values |
| Adversarial frame swap | AEAD AAD includes frame_index | Tag verification fails → reject |
| Cross-archive replay | AEAD AAD includes archive_uuid | Tag verification fails → reject |
| Index lost | Index FEC headroom; if exhausted, recovery mode | Recovery mode reconstructs from tar stream |

---

## 22. Security Analysis

### 22.1 Confidentiality

All file data, metadata, and the index are encrypted under keys derived
from the user's passphrase via Argon2id. A passive observer learns only:

- Format identity (magic bytes).
- Format version, algorithm IDs, geometry parameters.
- Archive UUID (random per archive).
- Total block count, total volume count, stripe width.
- KDF parameters (salt, m_cost, etc.).

They do **not** learn:

- File names, sizes, count, paths.
- Per-frame ciphertext sizes (hidden by in-envelope padding).
- Content hashes (unless `content_sha256` extension is explicitly enabled).
- Whether two archives share files.

### 22.2 Integrity

Every byte that contributes to plaintext output is covered by an AEAD tag.
The CryptoHeader and ManifestFooter are each covered by HMAC-SHA-256.
VolumeHeader and VolumeTrailer are covered by CRC32C only (accidental
corruption); their fields duplicate authenticated fields in CryptoHeader
or are verifiable against archive_uuid, so adversarial tampering
ultimately produces a downstream HMAC or AEAD failure.

### 22.3 Replay resistance

AEAD AAD binds `(archive_uuid, frame_index)`. Cross-archive replay, frame
reorder, and frame substitution all produce tag failures.

### 22.4 Deterministic nonce safety

AES-256-GCM-SIV is nonce-misuse-resistant. Deterministic nonces derived
from `(nonce_seed, frame_index)` cannot collide because:
- Within an archive, frame_index is unique.
- Across archives, nonce_seed differs (derived from per-archive master_key).

### 22.5 Padding is authenticated

In-envelope padding is part of the AEAD plaintext. Tampering with padding
bytes corrupts the AEAD tag. Padding length is encoded with a marker
scheme (§6); decoding errors are caught.

### 22.6 Reader-side resource limits

See §13.4 for required caps. A reader must enforce these against its
own policy regardless of declared values.

### 22.7 Known unmitigated risks

- **Format identity leak.** CryptoHeader bytes reveal that the file is
  tzap. Users needing format hiding should wrap in another envelope.
- **Weak passphrase ⇒ weak archive.** Argon2 parameters define cost;
  brute-force is bounded by `m_cost × t_cost`. Defaults (256 MiB × 3) are
  appropriate for desktop-scale offline use but not for nation-state
  adversaries.
- **Compression-before-encryption.** Acceptable for static archival;
  unsafe for adversary-influenced plaintext (CRIME/BREACH-class).

---

## 23. Versioning & Compatibility

- `format_version` bumps only on breaking changes.
- `volume_format_rev` bumps for backward-compatible additions.
- Unknown algorithm IDs = hard error.
- Non-critical extensions are ignored if unknown.
- Critical extensions (high bit set) = hard error if unknown.

---

## 24. Sizing Defaults

| Parameter | Default | Notes |
|---|---|---|
| `chunk_size` | 1 MiB | Tune up for small-file corpora |
| `block_size` | 64 KiB | |
| `fec_data_shards` | 224 | |
| `fec_parity_shards` | 32 | See §15.3 for V-dependent guidance |
| `index_fec_data_shards` | 16 | |
| `index_fec_parity_shards` | 16 | 50% overhead — index is critical |
| `stripe_width V` | 8 | Single-volume-loss-safe with default parity |
| AEAD | AES-256-GCM-SIV | |
| KDF | Argon2id t=3, m=256 MiB, p=4 | |
| zstd level | 3 | |

**V default rationale:** V = 8 with default 224 + 32 parity exactly
satisfies the single-volume-loss rule (`G_parity ≥ ceil(G_total / V)` ⇒
`32 ≥ ceil(256/8) = 32`). For more or fewer volumes, the writer adjusts
parity accordingly or warns.

---

## 25. Magic Numbers

| ASCII | Hex bytes (file order) | Purpose |
|---|---|---|
| `TZAP` | `54 5A 41 50` | Volume header |
| `TZCH` | `54 5A 43 48` | Crypto header (replicated) |
| `TZBK` | `54 5A 42 4B` | Block record |
| `TZIX` | `54 5A 49 58` | Index header (after decrypt) |
| `TZMF` | `54 5A 4D 46` | Manifest footer (replicated) |
| `TZVT` | `54 5A 56 54` | Volume trailer |

---

## 26. CLI Sketch (non-normative)

```
tzap create  [--volumes V | --volume-size 100M] [--password-stdin] [--keyfile FILE]
             [--compression-level 3] [--chunk-size 1M] [--block-size 64K]
             [--fec-data 224] [--fec-parity 32]
             [--index-fec-data 16] [--index-fec-parity 16]
             [--dictionary FILE] [--exclude PATTERN]
             -o BASENAME INPUT...

tzap extract [--password-stdin] [--keyfile FILE] [--strip-components N]
             [-C DIR] ARCHIVE [PATH...]

tzap list    [--password-stdin] [--keyfile FILE] [--long] ARCHIVE

tzap verify  [--password-stdin] [--keyfile FILE] [--repair-to DIR] ARCHIVE

tzap info    ARCHIVE   # prints algorithms, geometry — no key needed

tzap recover [--password-stdin] [--keyfile FILE] [--scan-only] ARCHIVE...
             # recovery mode when ManifestFooter is unrecoverable
```

CLI must warn at create-time when configured parameters don't meet the
user's stated resilience goal (see §15.3 rule).

---

## 27. Reference Implementation Notes

Target language: Rust.

### 27.1 Dependency choices

| Need | Crate | Notes |
|---|---|---|
| zstd | `zstd` (gyscos) | Frame APIs only |
| AES-256-GCM-SIV | `aes-gcm-siv` (RustCrypto) | |
| XChaCha20-Poly1305 | `chacha20poly1305` (RustCrypto) | |
| Argon2id | `argon2` (RustCrypto) | |
| HKDF | `hkdf` (RustCrypto) | |
| CRC32C | `crc32c` | |
| Leopard-RS | `reed-solomon-erasure` or equivalent | Verify maintenance |
| tar | `tar` crate | |
| Parallel | `rayon` | |
| UUID | `uuid` v4 | |
| CLI | `clap` v4 | |

### 27.2 Module layout

```
crates/
  tzap-format/    # wire-format types: structs, parsers, serializers — no crypto
  tzap-crypto/    # KDF, AEAD, HMAC wrappers
  tzap-fec/       # Leopard wrapper, group encode/decode
  tzap-stripe/    # block↔(volume, position) mapping
  tzap-io/        # block reader/writer, volume manager
  tzap-archive/   # high-level: create, extract, list, verify, recover
  tzap-cli/       # binary
```

`tzap-format` has zero crypto deps — easier to audit.

### 27.3 Test corpus (additions vs. v0.1)

- Single-volume archive (V=1) — ensure striping degenerates correctly.
- V=2 archive with 50% parity — must survive losing 1 volume.
- V=8 archive with default parity — must survive losing 1 volume.
- V=16 archive — must survive losing 2 volumes.
- Final-volume-only loss — recovery mode must work.
- CryptoHeader corruption in Volume_1 only — fall back to other copies.
- ManifestFooter corruption in final volume only — fall back to other
  copies (if present) or recovery mode.
- Padding-boundary frames (compressed size exactly = multiple of BLOCK_SIZE,
  or BLOCK_SIZE - 1, or 1).
- Small-file corpus with and without pre-trained dictionary.

---

## 28. Conformance and Test Vectors

A conformant writer produces archives that any conformant reader can:

1. Verify (all HMACs, all CRCs, all AEAD tags).
2. List (file table iteration).
3. Sequentially extract.
4. Randomly extract any single file.
5. Recover when the final volume is lost (recovery mode).

A conformant reader rejects:

1. Unknown `format_version`.
2. Unknown critical extensions.
3. Unknown algorithm IDs.
4. Resource requests exceeding configured caps.
5. Any AEAD tag mismatch.
6. Any HMAC mismatch.

A conformant CLI warns at create time when configured `(stripe_width,
G_parity)` does not satisfy the user's stated resilience goal per §15.3.

---

## 29. Open Questions and Future Work

Deferred from v1:

1. **Pre-trained zstd dictionary** (partially defined here via Extension
   `0x0006`; tooling and recommended training procedure deferred).
2. **Append support.** Currently write-once.
3. **Multi-recipient key wrap.**
4. **Public-key (age-style) mode.**
5. **Dense small-file mode** — alternative compression layout that
   addresses small-file corpora more aggressively.
6. **FEC over CryptoHeader/ManifestFooter copies** as first-class blocks
   (kind = 4/5 are reserved).
7. **Detached signatures** for archive authorship.
8. **Per-file encryption keys** for selective disclosure.

---

## 30. Glossary

- **AAD** — Additional Authenticated Data.
- **AEAD** — Authenticated Encryption with Associated Data.
- **Block** — Fixed-`BLOCK_SIZE`-bytes storage unit; the unit of FEC and CRC.
- **CryptoHeader** — Static, write-time-known crypto parameters; replicated
  in every volume.
- **FEC** — Forward Error Correction.
- **Frame** — One zstd frame = one AEAD encryption unit.
- **Group** — `G_data + G_parity` blocks treated as one FEC unit.
- **ManifestFooter** — Dynamic counters and index pointer; replicated, but
  only authoritative in the final volume (or after archive close).
- **Master key** — 32-byte symmetric key from Argon2id passphrase or keyfile.
- **Stripe width V** — Number of volumes; block→volume mapping is mod V.

---

## Appendix A: Comparison to Related Formats

| Format | Encrypted | Compressed | FEC | Random access | Splittable | Streaming write | Volume-loss safe |
|---|---|---|---|---|---|---|---|
| `tar` | no | no | no | partial | no | yes | n/a |
| `tar.gz` | no | yes | no | no | no | yes | n/a |
| `tar.zst` | no | yes | no | with seekable | no | yes | n/a |
| `tar.zst.age` | yes | yes | no | no | no | yes | n/a |
| `7z` | yes | yes | no | yes | yes | partial | no |
| `rar` | yes | yes | optional | yes | yes | no | optional |
| `dar` | yes | yes | optional | yes | yes | partial | optional |
| `par2` (+ any) | no | no | yes | n/a | per-volume | n/a | yes |
| **`tzap`** | yes | yes | yes | yes | yes | yes | **yes (with proper parity sizing)** |

---

## Appendix B: Worked Example (1 GiB Archive, Revised)

**Input:** 1 GiB of mixed content.

**Parameters:**
- `chunk_size = 1 MiB`
- `block_size = 64 KiB`
- `fec_data_shards = 224`, `fec_parity_shards = 32` (G_total = 256)
- `stripe_width V = 8` (per §24 default)

**Pipeline:**

- After tar: ~1.001 GiB.
- After zstd (level 3, assume 60% reduction): ~400 MiB compressed.
- Frame count: `ceil(1.001 GiB / 1 MiB) ≈ 1026 frames`.
- Average compressed frame size: ~400 KiB.
- In-envelope padding adds avg ~32 KiB per frame → padded plaintext ~432 KiB.
- After AEAD tag (16 B): ~432 KiB + 16 B → padded to next BLOCK_SIZE
  boundary → `ceil(432 KiB / 64 KiB) = 7` blocks per frame typically (with
  enough margin for the tag).
- Total payload data blocks: `1026 × 7 ≈ 7182 blocks`.
- FEC groups: `ceil(7182 / 224) ≈ 33 groups`.
- Parity blocks: `33 × 32 = 1056`.
- Total payload blocks: `7182 + 1056 ≈ 8238 blocks`.

**Striping across V=8 volumes:**

- Blocks per volume: `ceil(8238 / 8) ≈ 1030 blocks`.
- Per-volume payload bytes: `1030 × (64 KiB + 20 B framing) ≈ 66.3 MiB`.
- Add CryptoHeader (~1 KiB), ManifestFooter (~256 B), VolumeHeader (128 B),
  VolumeTrailer (24 B): negligible overhead.
- Each volume ≈ 67 MiB.

**Volume-loss budget check:**

- Per §15.3: `G_parity ≥ ceil(G_total / V) = ceil(256/8) = 32`.
- Default `G_parity = 32`. **Satisfied exactly.**
- Losing any 1 of 8 volumes: each FEC group loses
  `ceil(256/8) = 32` blocks (matches `G_parity`). **Recoverable.**
- Losing 2 volumes: each group loses up to 64 blocks. **Not recoverable**
  at default parity. Mitigation: raise `fec_parity_shards = 64` (overhead
  → 25%), or set V=16 with default parity.

**Index:**

- 1026 FrameEntry × 48 B + ~1000 FileEntry × 200 B + ~50 KiB string pool
  ≈ 300 KiB uncompressed.
- After zstd (highly repetitive): ~80 KiB compressed.
- After in-envelope pad + AEAD: ~96 KiB → 2 chunks of `chunk_size` each
  (or 1 chunk if small).
- Index FEC: 16 + 16 = 32 blocks total per group → ~2 MiB index storage.
- Striped across 8 volumes: ~256 KiB per volume of index data.

**Per-volume size:** ~67 MiB payload + ~256 KiB index ≈ 67.3 MiB.
**Total archive size:** ~538 MiB across 8 volumes.

**Resilience summary:**

- Survives losing **any 1** of 8 volumes — recovery is automatic via FEC.
- Survives bit-rot up to 32 blocks per group (≈ 2 MiB per group, spread
  across volumes).
- Survives loss of CryptoHeader in up to 7 of 8 volumes (any one
  authoritative copy suffices).
- Survives loss of ManifestFooter in up to 7 of 8 volumes (same).
- If the final volume is lost, falls back to recovery mode and reconstructs
  the index from the tar stream.

---

*End of revised specification.*
