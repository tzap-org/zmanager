# tzap Archive Format Specification (v0.15)

| Field | Value |
|---|---|
| **Format version** | 1 |
| **Document version** | 0.15 / 2026-05-21.1 (draft after counted-table, striping, and KDF-layout review) |
| **Status** | Draft for review, no implementation yet |
| **Owner** | Frank Zhu |
| **Maintainers** | Frank Zhu |
| **Last updated** | 2026-05-21 |
| **Supersedes** | v0.1, v0.2, v0.3, v0.4, v0.5, v0.6, v0.7, v0.8, v0.9, v0.10, v0.11, v0.12, v0.13, v0.14 |
| **Superseded by** | None |
| **Conflict rule** | This document supersedes earlier tzap format drafts. If it conflicts with v0.1-v0.14 text, this v0.15 draft wins unless a later dated spec explicitly supersedes it. |
| **File extension** | `.tzap` (single-volume) / `.tzap.NNN` (multi-volume) |

## Changelog from v0.14

This revision fixes counted-table zero-offset handling, KDF wire-layout
ambiguity, striping validation, and several boundary checks identified
after v0.14.

1. **Draft visibility is bumped.** `volume_format_rev = 15` for this
   draft, while per-structure versions remain independently versioned.
   (§8, §17.1, §23)
2. **Counted zero tables are unambiguous.** Table offsets are zero and
   not range-validated when their associated count/size is zero.
   (§15.2, §15.9)
3. **KDF parameter layout is explicit.** Argon2id and raw KDF params are
   defined as field tables, with salt length and Argon2 memory/parallelism
   constraints enforced before invoking Argon2id. (§13.1, §17.1)
4. **Striped BlockRecords have per-volume congruence checks.** A volume
   with index `v` and stripe width `V` contains only block indices
   congruent to `v mod V`, spaced exactly by `V`. (§10, §29)
5. **Sidecar packing handles sparse presence flags.** Offsets are derived
   by a cursor over the present sections in canonical order, so skipped
   sections cannot create ambiguity. (§12.3)
6. **Index invariants are tightened.** `payload_block_count`,
   `FileEntry.path_length`, DirectoryHintShardEntry range monotonicity,
   and directory-hint offset rules are validated. (§15.8, §15.9)
7. **Bootstrap bounds checks are explicit.** CryptoHeader internal length
   must match the VolumeHeader length, footer pointers are range-checked
   before reading, and zero stripe widths are rejected. (§9, §17.1)
8. **Nonce and packed-layout hygiene are clearer.** Nonce domain strings
   are length-prefixed, and implementations are warned that packed wire
   fields are not naturally aligned. (§4, §14.1)

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
   append-reopenable, or locally spooled sinks. Live stdout-to-stdin
   decompression without a sidecar requires `has_dictionary = 0`;
   dictionary-compressed streams require a bootstrap sidecar or buffering
   until the dictionary object is available.
7. **Splittable.** Volume size is configurable; volumes are independent
   files sharing an archive UUID.
8. **Implementable with standard libraries.** Metadata application is
   delegated to off-the-shelf tar libraries.
9. **Localized failure.** After bootstrap metadata is recovered, sharded
   index corruption affects only the files whose IndexShard or
   directory-hint shard is unrecoverable.

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
- Tightly packed structs; explicit padding shown. Multi-byte integer
  fields are not guaranteed to be naturally aligned, even when shown in
  Rust-like `#[repr(C, packed)]` notation. Implementations MUST decode
  integer fields with unaligned-safe loads or by copying bytes into
  aligned scratch storage before interpretation.
- UTF-8, NFC-normalized strings; no BOM, no NUL terminator.
- SHA-256; CRC-32C; HMAC-SHA-256.
- Time: nanoseconds since Unix epoch (signed 64-bit).
- The `||` operator denotes raw byte concatenation with no length
  prefix, separator, or terminator. Operands are encoded according to
  their declared type: for example `[u8; 16]` UUIDs and session IDs are
  the 16 raw bytes on the wire, not hex strings.
- Every field named `_reserved`, `_reserved1`, `_reserved2`,
  `_reserved_a`, `_reserved_b`,
  `_padding_*`, or otherwise explicitly reserved MUST be zero on the
  wire. Readers MUST reject any parsed structure whose reserved bytes or
  reserved integer fields are non-zero unless a later format version
  explicitly assigns that field.

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

AEAD parameter constants are determined by `aead_algo`:

| `aead_algo` | Algorithm | `AEAD_NONCE_LEN` | `AEAD_TAG_LEN` |
|---|---|---:|---:|
| 1 | AES-256-GCM-SIV | 12 bytes | 16 bytes |
| 2 | XChaCha20-Poly1305 | 24 bytes | 16 bytes |
| 3 | AES-256-GCM | 12 bytes | 16 bytes |

Writers and readers MUST use the nonce and tag lengths from this table
when applying §14. AES-256-GCM-SIV is the default AEAD and refers to the
nonce-misuse-resistant AES-GCM-SIV construction from RFC 8452.
AES-256-GCM remains registered for environments that can enforce unique
nonces; nonce derivation in §14 binds nonce uniqueness to
`(archive_uuid, session_id, domain, counter)`.

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
  │ uses pre-trained dictionary if one is located by IndexRoot
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
writers SHOULD NOT use it below 255; byte form is the canonical efficient
choice for `pad_len ≤ 254`.)

**Reader algorithm:**

```
1. Decrypt envelope; let plaintext have length N (multiple of BLOCK_SIZE,
   minus AEAD tag).
2. If N = 0, reject as malformed.
3. Inspect plaintext[N − 1]:
     - if < 0xFF:  byte form. marker_size = 1;
                    pad_len = plaintext[N − 1].
     - if = 0xFF:  first verify N ≥ 5, then wide form.
                    marker_size = 5;
                    pad_len = u32 LE at plaintext[N − 5 .. N − 1].
4. Verify pad_len ≥ marker_size and pad_len ≤ N. Reject if not. This is
   equivalent to `pad_len ≥ 1` for byte form and `pad_len ≥ 5` for wide
   form. Compute payload_len = checked_sub(N, pad_len); any underflow is
   malformed.
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
- `pad_len = 0` is not valid in v0.15. The extra block in the exact-fit
  case is an accepted canonical-format cost; it keeps padding parsing
  suffix-only and avoids algorithm-specific length exceptions.
- Because padding always occupies at least the final byte, zstd payload
  data never extends into the final byte of the envelope plaintext.
  The marker is therefore parsed from padding bytes, not from zstd data.
- In wide form, `N ≥ 5` is necessary but not sufficient: readers still
  must enforce `pad_len ≥ 5` and `pad_len ≤ N` before subtraction. This
  rejects malformed tiny or hostile wide-form markers whose 4-byte length
  field would otherwise be partly exposed as zstd payload bytes.

### 6.2 Four nested units

- **Tar member group** = one logical path's complete tar records: any
  path-specific PAX/GNU metadata records followed by the main tar header,
  data bytes, and tar padding.
- **Frame** = one independent zstd frame; unit of random decompression.
  A frame contains bytes from the tar member group stream.
- **Envelope** = packed group of frames; unit of AEAD encryption + padding.
- **Block** = fixed-size storage chunk; unit of striping, CRC, and
  object-local FEC.

`tar member group bytes ⊆ decompressed zstd frame plaintexts ⊆ envelope
plaintexts ⊆ blocks ⊆ volumes`.

Writers SHOULD start a new zstd frame at the beginning of every tar
member group. They MAY split a very large tar member group across
multiple frames, but FileEntry MUST record the exact ordered frame range
and decompressed offset needed to reconstruct that member group (§15.6).
`CryptoHeader.chunk_size` is the writer's target maximum uncompressed
zstd-frame payload when splitting large tar member groups. It is a
writer framing target, not a reader parsing boundary: readers MUST use
FrameEntry and EnvelopeEntry metadata to locate bytes.

---

## 7. Archive Layout

### 7.1 Per-volume structure

```
Volume_i =
    VolumeHeader            (fixed 128 B, at offset 0)
    CryptoHeader            (replicated; identical across volumes)
    BlockRecord_…           (this volume's striped blocks)
    ManifestFooter          (per-volume authoritative copy; same index-root fields,
                             volume_index matches this volume)
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

Writers MUST enforce `0 ≤ N < V`. A single-volume archive (`V = 1`) can
protect against bit-rot within that volume, but it cannot tolerate loss
of that only volume; it therefore requires `N = 0`. The CLI auto-scales
parity from `--volume-loss-tolerance N` (§27).

### 7.4 Default write mode: parallel volumes

The writer opens V volume sinks concurrently, or uses sinks that can be
reopened for append without rewriting earlier bytes. Each sink receives
blocks based on the modulo mapping. The write path is strictly forward
within each sink: no seek-back or overwrite is required.

### 7.5 Single-stream streaming mode

For a fully non-reopenable single sink (for example a pipe or a tape
stream), conforming v0.15 writers MUST use `stripe_width = 1`,
`volume_loss_tolerance = 0`, and either `has_dictionary = 0` or a
bootstrap sidecar containing authenticated encrypted IndexRoot and
dictionary-object copies (§12.2, §17.3). A live reader cannot decompress
dictionary-compressed payload frames until that sidecar is available.

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
    volume_format_rev:        u16,       // 15 for this draft
    volume_index:             u32,       // 0-based
    stripe_width:             u32,       // V
    archive_uuid:             [u8; 16],
    session_id:               [u8; 16],
    crypto_header_offset:     u32,       // typically = sizeof(VolumeHeader) = 128
    crypto_header_length:     u32,
    _reserved:                [u8; 68],
    header_crc32c:            u32,       // CRC32C over first 124 bytes
                                             // (offsets 0..123; excludes this field)
}
```

**Changed from v0.3:** `manifest_footer_offset` and `manifest_footer_length`
are removed. Those pointers now live in the VolumeTrailer (§12). The
removal frees 12 bytes that are reclaimed into `_reserved`. The
VolumeHeader is now fully write-once: no field requires backfill at
archive close.

`header_crc32c` is an unkeyed corruption detector only. Readers MUST NOT
treat VolumeHeader identity fields or offsets as authenticated until they
are matched against authenticated CryptoHeader, VolumeTrailer, and
ManifestFooter fields after HMAC verification (§17.1). Readers MUST
range-check `crypto_header_offset` and `crypto_header_length` against
the actual volume or stream bounds and reader caps before allocating or
reading the CryptoHeader. Writers MUST set `stripe_width ≥ 1`; readers
MUST reject a VolumeHeader whose `stripe_width = 0`.

---

## 9. CryptoHeader

Replicated identically in every volume. Contains static parameters needed
to derive keys and parse the archive. "Replicated identically" refers to
the CryptoHeader bytes themselves; each volume's VolumeHeader may carry
its own `crypto_header_offset` pointer to that identical byte sequence.

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
    index_root_fec_data_shards:    u16,    // may be raised if IndexRoot/dictionary is large
    index_root_fec_parity_shards:  u16,
    stripe_width:             u32,

    volume_loss_tolerance:    u8,
    bit_rot_buffer_pct:       u8,
    has_dictionary:           u8,         // 1 if IndexRoot locates a zstd dict object
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
and `header_hmac`. `CryptoHeaderFixed.length` MUST exactly equal
`VolumeHeader.crypto_header_length`; readers MUST reject any mismatch
before parsing extension bytes beyond the shorter length.
`header_hmac = HMAC-SHA-256(mac_key, b"tzap-v1-crypto-header" ||
VolumeHeader.archive_uuid || VolumeHeader.session_id || all CryptoHeader
bytes before the header_hmac field)`. Readers MUST reject a CryptoHeader
whose length is smaller than
the fixed header plus HMAC, whose TLV list does not terminate before
`length - 32`, or whose reserved bytes are non-zero.

Binding the VolumeHeader UUID/session into the CryptoHeader HMAC makes a
mismatched header pair fail immediately after KDF/HMAC verification,
before any object AEAD attempt. The VolumeHeader is still not trusted as
a security boundary; the same identity fields are later checked against
the authenticated VolumeTrailer and ManifestFooter.

`chunk_size` records the writer's target maximum uncompressed zstd-frame
payload for large tar member groups (§6.2). Writers SHOULD set
`1 ≤ chunk_size ≤ envelope_target_size`; readers MUST reject
`chunk_size = 0`, `envelope_target_size = 0`, `stripe_width = 0`, or
`block_size < 4096`.
Readers MUST NOT allocate memory or infer frame boundaries from
`chunk_size` alone. If `chunk_size > envelope_target_size`, readers MUST
treat it as advisory metadata only and MAY warn; actual frame sizes are
described by FrameEntry.

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
encrypted metadata objects located by IndexRoot instead.

Reserved tags (all under the 256-byte cap):

| Tag | Type | Purpose |
|---|---|---|
| `0x0001` | UTF-8 | User comment |
| `0x0002` | UTF-8 | Creator tool identifier |
| `0x0003` | `i64` | Creation timestamp (ns) |
| ~~`0x0004`~~ | ~~`[u8; 32]`~~ | **Forbidden in v0.15.** The tar-stream content hash is encrypted inside IndexRoot. Writers MUST NOT emit this extension; readers MUST reject it if present. |
| `0x0005` | UTF-8 | Locale tag for filenames |
| ~~`0x0006`~~ | ~~bytes~~ | **Removed; moved to encrypted metadata.** A writer setting `has_dictionary = 1` declares that IndexRoot locates a dictionary-object extent (§15.2). |

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
                                     // 6 = dictionary-data
                                     // 7 = dictionary-parity
                                     // 8 = directory-hint-data
                                     // 9 = directory-hint-parity
    flags:         u8,               // bit 0: last data block of encrypted object
                                     // bits 1..7: reserved; MUST be zero in v0.15
    _reserved:     [u8; 2],
    payload:       [u8; BLOCK_SIZE],
    record_crc32c: u32,
}
```

On-disk size: `BLOCK_SIZE + 20` bytes per block.

`record_crc32c` is computed over the preceding `16 + BLOCK_SIZE` bytes:
offsets `0 .. 16 + BLOCK_SIZE - 1`, including `magic`, `block_index`,
`kind`, `flags`, `_reserved`, and `payload`, and excluding the CRC field
itself.

BlockRecord kind values 0 through 9 are defined above. Values 10 through
255 are reserved for future use. Writers MUST NOT emit reserved kind
values; readers MUST reject any BlockRecord with a `kind` outside
0 through 9.

Writers MUST set all reserved `BlockRecord.flags` bits to zero. Readers
MUST reject a BlockRecord with any reserved flag bit set; in v0.15 this
means any flag bit other than bit 0 is invalid. Bit 0 is meaningful only
on encrypted-object data blocks and MUST be zero on parity blocks
(kinds 1, 3, 5, 7, and 9). Readers MUST reject parity blocks with bit 0
set.

For a volume whose authenticated header/trailer identity establishes
`volume_index = v` and `stripe_width = V`, every BlockRecord in that
volume MUST satisfy `block_index mod V = v`. Consecutive BlockRecords in
the same volume MUST differ by exactly `V`; this is stronger than merely
being sorted and lets a reader detect per-volume omissions even when it
does not have every other volume available.

A "complete input set" means all `V` volumes named by `stripe_width` are
available to the reader and have passed header/trailer identity checks.
For a complete input set, no two BlockRecords may share the same
`block_index`, and the observed global block indices MUST cover every
value from 0 through the final emitted block index. Object extents
declared by ManifestFooter, ShardEntry, DirectoryHintShardEntry, or
EnvelopeEntry MUST refer to contiguous global block-index ranges. Readers
MUST reject duplicates, decreasing order, gaps in a complete input set,
or any missing block required by an operation when no recovery mode can
repair it.

---

## 11. ManifestFooter

Written to every volume in default parallel-volume mode and located via
the VolumeTrailer (§12). ManifestFooter copies are semantically
replicated but not byte-identical: `archive_uuid`, `session_id`,
`total_volumes`, and IndexRoot location/size fields are the same across
all volume footers, while `volume_index` MUST match the containing
volume. The ManifestFooter is intentionally small and contains only
bootstrap metadata; archive content hashes, tar size, envelope count,
and frame count are encrypted inside IndexRoot.

```rust
#[repr(C, packed)]
struct ManifestFooter {
    magic:                       [u8; 4],   // b"TZMF"
    archive_uuid:                [u8; 16],
    session_id:                  [u8; 16],
    volume_index:                u32,
    is_authoritative:            u8,
    _reserved_a:                 [u8; 3],

    total_volumes:               u32,

    index_root_first_block:      u64,
    index_root_data_block_count: u32,
    index_root_parity_block_count: u32,
    index_root_encrypted_size:   u32,
    index_root_decompressed_size: u32,

    _reserved_b:                 [u8; 32],

    manifest_hmac:               [u8; 32],
}
```

`manifest_hmac = HMAC-SHA-256(mac_key, b"tzap-v1-manifest-footer" ||
archive_uuid || session_id || all ManifestFooter bytes before the
manifest_hmac field)`. Reserved bytes MUST be zero. Writers MUST set
`is_authoritative` to either 0 or 1; readers MUST reject any other value.
Completed v0.15 writers MUST set `is_authoritative = 1` in every closed
volume footer they emit. Readers MUST treat `is_authoritative = 0` as a
partial, recovery-only, or future extension footer and must not use it
for random-access bootstrap.

In this version, `is_authoritative = 1` means "this footer was emitted
after the final IndexRoot was written and can bootstrap the completed
archive." Because every closed volume is intended to be a valid
bootstrap point, normal completed writers set the flag on every volume.
`is_authoritative = 0` is reserved for partial checkpoints, crash
recovery artifacts, or future append/checkpoint extensions; such footers
are never random-access authorities.

The ManifestFooter is the bootstrap authority for locating and sizing
IndexRoot. IndexRoot is still FEC-protected as an object, but that repair
is possible only after the reader has obtained an authenticated
ManifestFooter or authenticated bootstrap sidecar that identifies the
IndexRoot block extent. Replication of ManifestFooter across volumes and
the optional sidecar are therefore part of the bootstrap resilience
model.

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
    trailer_hmac:             [u8; 32],  // HMAC-SHA-256(mac_key,
                                             // b"tzap-v1-volume-trailer" ||
                                             // archive_uuid || session_id ||
                                             // first 96 bytes)
                                             // (offsets 0..95; excludes this field)
}
```

**Changed from v0.3:** Trailer size grows from 96 to 128 bytes to
accommodate the manifest pointer and reach a round size. Seekable readers
use `file_size − 128` to locate the trailer. Non-seekable readers use a
bootstrap sidecar or sequential extraction (§12.2, §17.3).

`trailer_hmac = HMAC-SHA-256(mac_key, b"tzap-v1-volume-trailer" ||
archive_uuid || session_id || first 96 trailer bytes)`.

### 12.1 Reader diagnostic logic

| Trailer state | Diagnosis |
|---|---|
| Present, valid HMAC, matching session_id | Clean close |
| Present, invalid HMAC | Tampered or wrong key |
| Present, valid HMAC, mismatched session_id | Mixed volumes from different archives |
| Absent (file shorter than 128 bytes from end matching magic) | Writer crashed or truncated |
| Volume file entirely missing | Sibling lost |

### 12.2 Compatibility with non-seekable read

For environments where the reader cannot seek to the end of the file, the
writer may additionally emit a bootstrap sidecar file
(`<base>.tzap.bootstrap`) or a separate sidecar stream/file descriptor.
The sidecar may contain:

- a copy of the ManifestFooter;
- BlockRecord copies for the encrypted IndexRoot data/parity blocks
  (§12.3);
- for dictionary archives, BlockRecord copies for the encrypted
  dictionary object.

Sidecar bytes are not trusted merely because they are adjacent to the
archive. Readers MUST verify the same HMAC/AEAD authentication that would
be verified when reading the bytes from a volume. A dictionary archive
uses the sidecar's authenticated encrypted IndexRoot copy to locate the
dictionary object and the sidecar's authenticated encrypted dictionary
copy to recover dictionary bytes before payload decompression. If a
reader starts from a live non-seekable stream before the sidecar is
complete, it MUST either buffer encrypted payload bytes until the
dictionary is recovered or reject with "dictionary bootstrap required."
The core tzap payload stream does not define an in-band sidecar
multiplexing format; a live pipe workflow that needs dictionary
decompression must deliver the sidecar out of band and make it available
to the reader before payload frame decompression begins.

A sidecar can provide bootstrap metadata without seeking. It does not by
itself make a non-seekable payload stream randomly accessible: random
extraction still requires range-capable volume storage, reopened volume
files, or local buffering of the needed blocks. If no sidecar is
available, a conforming reader MUST either use sequential extraction
(§17.3) or reject operations that require the ManifestFooter or
IndexRoot.

### 12.3 Bootstrap sidecar layout

The bootstrap sidecar is a forward-written helper file. It is not part
of the core volume set, does not change `archive_uuid`, and does not
change `volume_count`.

```rust
#[repr(C, packed)]
struct BootstrapSidecarHeader {
    magic:                       [u8; 4],   // b"TZBS"
    version:                     u32,       // 1
    archive_uuid:                [u8; 16],
    session_id:                  [u8; 16],
    flags:                       u32,       // bit 0: ManifestFooter present
                                             // bit 1: IndexRoot BlockRecords present
                                             // bit 2: Dictionary BlockRecords present

    manifest_footer_offset:      u64,       // 0 if absent
    manifest_footer_length:      u32,       // 0 if absent

    index_root_records_offset:   u64,       // 0 if absent
    index_root_records_length:   u64,       // 0 if absent

    dictionary_records_offset:   u64,       // 0 if absent
    dictionary_records_length:   u64,       // 0 if absent

    _reserved:                   [u8; 4],
    sidecar_hmac:                [u8; 32],  // HMAC-SHA-256(mac_key,
                                               // b"tzap-v1-sidecar" ||
                                               // archive_uuid || session_id ||
                                               // first 92 bytes)
                                               // (offsets 0..91; excludes this field and CRC)
    header_crc32c:               u32,       // CRC32C over first 124 bytes
                                                // (offsets 0..123; excludes this field)
}
```

On-disk size: 128 bytes.

If a presence flag is set, the corresponding offset and length fields
MUST be non-zero; `manifest_footer_length` MUST equal
`sizeof(ManifestFooter)`. If a presence flag is clear, the corresponding
offset and length fields MUST be zero.

When present, the sidecar layout is a packed sequence:

```
BootstrapSidecarHeader
ManifestFooter bytes, if flag bit 0 is set
BlockRecord[] for IndexRoot data/parity blocks, if flag bit 1 is set
BlockRecord[] for dictionary data/parity blocks, if flag bit 2 is set
```

No padding, extension bytes, or unclaimed gaps are permitted in a v0.15
bootstrap sidecar. Offsets are validated by a canonical cursor:

1. Initialize `cursor = 128`.
2. If flag bit 0 is set, `manifest_footer_offset` MUST equal `cursor`,
   then advance by `manifest_footer_length`; otherwise both
   ManifestFooter fields MUST be zero.
3. If flag bit 1 is set, `index_root_records_offset` MUST equal
   `cursor`, then advance by `index_root_records_length`; otherwise both
   IndexRoot record fields MUST be zero.
4. If flag bit 2 is set, `dictionary_records_offset` MUST equal
   `cursor`, then advance by `dictionary_records_length`; otherwise both
   dictionary record fields MUST be zero.
5. The sidecar file size MUST equal the final cursor.

This cursor rule is authoritative for sparse flag combinations: a
present later section follows the last present earlier section in the
canonical order, not an absent section's zero offset.

`index_root_records_length` MUST be an integer multiple of
`sizeof(BlockRecord)`, and every copied BlockRecord MUST have kind 2
(`index-root-data`) or kind 3 (`index-root-parity`). The copied
BlockRecord payload bytes are the same authenticated encrypted/parity
bytes that would be read from the volume set.
`dictionary_records_length`, when present, follows the same rule and may
contain only kind 6 (`dictionary-data`) or kind 7 (`dictionary-parity`)
BlockRecords.
For a bootstrap sidecar intended to support non-seekable dictionary
extraction, flags bits 0, 1, and 2 MUST all be set and all three
declared byte ranges MUST be present.

The sidecar header CRC is only an early corruption check. Readers MAY
check it before HMAC to reject obvious corruption early; `sidecar_hmac`
verification is mandatory before trusting flags, offsets, or lengths.
The CRC covers the `sidecar_hmac` bytes because it covers the first 124
header bytes; this is intentional and does not make the CRC an
authentication mechanism.
Authority for copied archive objects still comes from the ManifestFooter
HMAC plus AEAD verification of IndexRoot and any copied dictionary
object.
Readers MUST verify that the sidecar `archive_uuid` and `session_id`
match the VolumeHeader/CryptoHeader pair before using any sidecar bytes.
Readers implementing this draft MUST reject `version != 1`.
Readers MUST range-check every non-zero offset/length pair against the
sidecar file size before reading and MUST reject overlapping declared
ranges unless a future version explicitly defines such overlap.
Readers MUST ignore unknown flag bits only if they are explicitly marked
non-critical by a future version; for v0.15, unknown flag bits are a hard
error.

---

## 13. Key Derivation

### 13.1 Argon2id parameters

For `KdfAlgo::Argon2id`, the CryptoHeader KdfParams payload is exactly
the following byte sequence:

| Offset | Size | Field | Required value / meaning |
|---:|---:|---|---|
| 0 | 2 | `algo_tag` | `1` |
| 2 | 4 | `t_cost` | Argon2id iterations; default `3` |
| 6 | 4 | `m_cost_kib` | Argon2id memory in KiB; default `262_144` |
| 10 | 4 | `parallelism` | Argon2 lanes/threads; default `4` |
| 14 | 2 | `salt_length` | byte length of following salt |
| 16 | `salt_length` | `salt` | raw salt bytes |

There is no second salt field and no implicit alignment padding. Writers
MUST use `8 ≤ salt_length ≤ 64`, `parallelism ≥ 1`, and
`m_cost_kib ≥ 8 × parallelism`. Readers MUST reject salts or Argon2id
parameter sets outside those bounds, or KDF parameter buffers that do
not fit inside CryptoHeader, before invoking Argon2id.

For `KdfAlgo::Raw`, the CryptoHeader KdfParams payload is exactly
two bytes: `algo_tag: u16 = 0`. The user supplies the 32-byte
`master_key` via keyfile. No KDF salt is stored for raw mode because
HKDF-Extract already uses the archive UUID and session ID as public
per-archive/session salt (§13.2). Readers MUST reject a KdfParams
`algo_tag` that does not match `CryptoHeader.kdf_algo`.

### 13.2 Master key and subkeys

```
master_key       = Argon2id(passphrase_utf8_nfc, salt, params, len=32)

prk              = HKDF-Extract-SHA-256(
                       salt = b"tzap-v1-subkeys" ||
                              archive_uuid ||
                              session_id,
                       IKM  = master_key)

enc_key          = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-enc",      L=32)
mac_key          = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-mac",      L=32)
nonce_seed       = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-nonce",    L=32)
index_root_key   = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-idxroot",  L=32)
index_shard_key  = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-idxshard", L=32)
dictionary_key   = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-dict",     L=32)
dir_hint_key     = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-dirhint",  L=32)
index_nonce_seed = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-idxnonce", L=32)
```

This HKDF construction is normative. Writers and readers MUST use
HKDF-SHA-256 Extract followed by Expand exactly as shown. The HKDF salt
binds the public archive identity to the subkey schedule, giving raw-key
mode the same per-archive/session key separation that Argon2id mode gets
from its random KDF salt. The Argon2id salt remains the per-archive
password-hardening salt in §13.1. Raw-key mode uses the supplied 32-byte
value as `master_key` and still runs the same HKDF subkey schedule.

### 13.3 Reader-side caps

| Cap | Default |
|---|---|
| `m_cost_kib` | 4 GiB |
| `t_cost` | 100 |
| `parallelism` | 64; also requires `m_cost_kib ≥ 8 × parallelism` |
| `argon2id_salt_length` | 8..64 bytes |
| `chunk_size` | 64 MiB |
| `envelope_target_size` | 64 MiB |
| `block_size` | 1 MiB |
| `stripe_width V` | 1..4096 |
| `fec_data_shards + fec_parity_shards` | 4096 |
| `max_path_length` | 4096 |
| `max_files_per_index_shard` | 1,000,000 |
| `max_hash_collision_shard_scan` | 16 adjacent shards per direction |
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
    info.extend_from_slice(b"tzap-v1-nonce");
    info.extend_from_slice(&(domain.len() as u16).to_le_bytes());
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

`hkdf_expand_sha256` in nonce derivation is HKDF-Expand-SHA-256 using
the 32-byte nonce seed as the PRK and the constructed `info` bytes above.
It is used here as an HMAC-SHA-256-based deterministic PRF with variable
output length, not as a password-hardening step. The domain string is
length-prefixed, and archive UUID, session ID, and counter are fixed
length, so the nonce derivation has unambiguous domain separation. The
requested output length is the AEAD nonce length from §5. No nonce
randomness is required after `session_id` is generated.

### 14.2 Envelope encryption

```rust
fn encrypt_envelope(j: u64, packed_frames: &[u8]) -> Vec<u8> {
    let tag_len = AEAD_TAG_LEN;
    let mut total_blocks = max(1,
        (packed_frames.len() + tag_len + BLOCK_SIZE - 1) / BLOCK_SIZE);
    let mut envelope_total = total_blocks * BLOCK_SIZE;
    let mut pad_len = envelope_total - packed_frames.len() - tag_len;
    if pad_len == 0 {
        total_blocks += 1;
        envelope_total = total_blocks * BLOCK_SIZE;
        pad_len = BLOCK_SIZE;
    }
    // pad_len is now always ≥ 1.

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
    let padded = suffix_pad_for_aead(plaintext, AEAD_TAG_LEN, BLOCK_SIZE);
    let counter = 0; // IndexRoot is a singleton within the archive.
    let nonce = derive_nonce(
        &index_nonce_seed, b"idxroot", &archive_uuid, &session_id, counter, AEAD_NONCE_LEN);
    aead_encrypt(
        &index_root_key, &nonce,
        &aad(b"idxroot", &archive_uuid, &session_id, counter), &padded)
}

fn encrypt_index_shard(s: u64, plaintext: &[u8]) -> Vec<u8> {
    let padded = suffix_pad_for_aead(plaintext, AEAD_TAG_LEN, BLOCK_SIZE);
    let nonce = derive_nonce(
        &index_nonce_seed, b"idxshard", &archive_uuid, &session_id, s, AEAD_NONCE_LEN);
    aead_encrypt(
        &index_shard_key, &nonce,
        &aad(b"idxshard", &archive_uuid, &session_id, s), &padded)
}

fn encrypt_dictionary(plaintext: &[u8]) -> Vec<u8> {
    let padded = suffix_pad_for_aead(plaintext, AEAD_TAG_LEN, BLOCK_SIZE);
    let counter = 0; // one dictionary object per archive.
    let nonce = derive_nonce(
        &index_nonce_seed, b"dict", &archive_uuid, &session_id, counter, AEAD_NONCE_LEN);
    aead_encrypt(
        &dictionary_key, &nonce,
        &aad(b"dict", &archive_uuid, &session_id, counter), &padded)
}

fn encrypt_directory_hint_shard(h: u64, plaintext: &[u8]) -> Vec<u8> {
    let padded = suffix_pad_for_aead(plaintext, AEAD_TAG_LEN, BLOCK_SIZE);
    let nonce = derive_nonce(
        &index_nonce_seed, b"dirhint", &archive_uuid, &session_id, h, AEAD_NONCE_LEN);
    aead_encrypt(
        &dir_hint_key, &nonce,
        &aad(b"dirhint", &archive_uuid, &session_id, h), &padded)
}
```

The same suffix-marker padding scheme is used for index encryption.
`suffix_pad_for_aead` is the §6.1 construction with the exact-fit extra
block rule from §14.2; it MUST NOT produce `pad_len = 0`.

For every AEAD object, the counter used in nonce derivation MUST match
the counter encoded in AAD. The IndexRoot is a singleton and uses
counter 0; IndexShard uses its shard index.
The dictionary object uses `dictionary_key`, domain `dict`, and counter
0. Directory hint shards use `dir_hint_key`, domain `dirhint`, and their
directory-hint shard index.

---

## 15. Index Format

### 15.1 Layout

```
Index Root          (small, high-parity FEC root with shard/object tables)
Index Shard 0       (file table + local frame/envelope tables)
Index Shard 1
…
Index Shard S−1
Dictionary object   (optional encrypted metadata object)
Directory Hint Shards (optional encrypted metadata objects)
```

**Files in the index are globally sorted by
`(SHA-256(path)[0..8], normalized path bytes)`,** not alphabetically by
path string alone. The 8-byte hash prefix is the primary sort key; the
normalized UTF-8 path string is the collision tie-breaker. This keeps
shard hash bounds monotonic while making equal-prefix ordering
deterministic without storing the full 32-byte hash.

### 15.2 Index Root

```rust
#[repr(C, packed)]
struct IndexRoot {
    magic:                   [u8; 4],   // b"TZIR"
    version:                 u32,       // 1
    shard_count:             u32,
    directory_hint_shard_count: u32,
    frame_count:             u64,
    envelope_count:          u64,
    file_count:              u64,
    payload_block_count:     u64,       // total payload-data BlockRecords (kind 0)
    tar_total_size:          u64,       // encrypted; original tar stream bytes
    content_sha256:          [u8; 32],  // SHA-256 of tar stream pre-encryption

    shard_table_offset:      u64,
    directory_hint_shard_table_offset: u64, // 0 if omitted

    // Optional pre-trained zstd dictionary metadata object.
    dictionary_first_block:  u64,       // ignored if has_dictionary = 0
    dictionary_data_block_count: u32,   // 0 if no dictionary
    dictionary_parity_block_count: u32, // 0 if no dictionary
    dictionary_encrypted_size: u32,     // 0 if no dictionary
    dictionary_decompressed_size: u32,  // raw dictionary byte length, 0 if none

    _reserved2:              u32,
    _reserved:               [u8; 28],
}
// Plaintext layout (concatenated after IndexRoot header):
//   ShardEntry[shard_count]
//   if directory_hint_shard_count > 0:
//       DirectoryHintShardEntry[directory_hint_shard_count]
```

**Important:** the IndexRoot itself is compressed with zstd **without
using the user's dictionary**. The dictionary is a separate encrypted
metadata object located by the dictionary fields above, so it cannot be a
prerequisite for decompressing IndexRoot. After the reader decrypts and
decompresses the dictionary object, it loads those bytes into a zstd
decompression context for use on payload envelopes only.

When `has_dictionary = 1`, every payload-envelope zstd frame MUST be
compressed using the loaded dictionary. Metadata objects (IndexRoot,
IndexShard, dictionary object, and directory-hint shards) MUST NOT use
the dictionary. Readers MUST initialize metadata zstd contexts without a
dictionary and payload zstd contexts with the dictionary after it is
authenticated and decompressed.

Whenever `CryptoHeader.has_dictionary = 0`,
`dictionary_first_block`, `dictionary_data_block_count`,
`dictionary_parity_block_count`, `dictionary_encrypted_size`, and
`dictionary_decompressed_size` MUST all be zero. Readers MUST reject an
archive with `has_dictionary = 0` and any non-zero dictionary field.
`payload_block_count` is an authenticated archive total and MUST equal
the sum of data blocks for all distinct payload envelopes. Because
EnvelopeEntry rows are shard-local, random extraction may not observe
the whole sum; full-archive `verify` MUST check it (§15.9).

IndexRoot MUST remain a bounded root object. It contains shard metadata
and encrypted archive totals, but not global FrameEntry or EnvelopeEntry
tables and not raw dictionary bytes. Those tables live in IndexShard
objects (§15.5), and dictionary bytes live in the dictionary metadata
object. This keeps random access proportional to the target shard set
and keeps IndexRoot within the selected FEC object's shard limit.

Empty archives are valid. For an archive with zero input files, writers
set `file_count = 0`, `shard_count = 0`, `frame_count = 0`,
`envelope_count = 0`, `payload_block_count = 0`, `tar_total_size = 0`,
and `directory_hint_shard_count = 0`. `payload_block_count` counts only
payload-data BlockRecords (kind 0); IndexRoot blocks (kinds 2/3) are not
payload blocks. `has_dictionary` in CryptoHeader MUST be 0, all
dictionary fields in IndexRoot MUST be zero, `shard_table_offset = 0`,
`directory_hint_shard_table_offset = 0`, and `content_sha256 =
SHA-256(b"")`, whose hex digest is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Writers MUST NOT emit tar end-of-archive zero blocks for empty archives,
and `tar_total_size = 0`. No payload envelopes, IndexShard objects,
directory hint shards, or dictionary object are written, but the archive
still contains a valid IndexRoot, ManifestFooter, and VolumeTrailer.

For IndexRoot counted tables, a zero count means the corresponding table
is absent and its offset MUST be zero. Specifically,
`shard_table_offset = 0` when `shard_count = 0`, and
`directory_hint_shard_table_offset = 0` when
`directory_hint_shard_count = 0`. Readers MUST NOT apply fixed-header
range validation to an absent zero-count table.

### 15.3 Envelope and Frame tables

```rust
#[repr(C, packed)]
struct EnvelopeEntry {
    envelope_index:        u64,
    first_block_index:     u64,
    data_block_count:      u32,       // encrypted envelope data blocks
    parity_block_count:    u32,       // object-local FEC parity blocks
    encrypted_size:        u32,       // total ciphertext bytes including AEAD tag
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

Payload envelopes are assigned `envelope_index` values in write order,
starting at 0 and increasing by 1 for every payload envelope. The
EnvelopeEntry table MUST be sorted by `envelope_index` and contain no
gaps. The envelope AEAD counter `j` is exactly `envelope_index`; a
sequential reader without IndexRoot can therefore maintain a local
`next_envelope_index` counter.

Payload EnvelopeEntry records MUST describe at least one complete zstd
frame: `frame_count ≥ 1` and `plaintext_size > 0`. Empty archives use no
payload EnvelopeEntry records; writers MUST NOT emit empty payload
envelopes, and readers MUST reject them.

`FrameEntry.flags` bit 0 means the frame starts at a tar member group
boundary; bit 1 means the frame ends at a tar member group boundary.
Bits 2..31 are reserved and MUST be zero. These flags are hints for
validation and diagnostics; FileEntry remains the authority for
extraction extents.

For every encrypted object in v0.15, `encrypted_size` is the total
ciphertext length including the AEAD tag after suffix padding. It MUST
equal `data_block_count * block_size`. Writers MUST ensure this product
fits in `u32`; readers MUST reject any encrypted object whose recorded
`encrypted_size` is not exactly that product or whose product would
overflow `u32`.

All u32 plaintext size fields are hard wire-format caps. Writers MUST
reject any payload envelope whose packed-frame `plaintext_size` exceeds
`u32::MAX`; any FrameEntry whose `compressed_size` or `decompressed_size`
exceeds `u32::MAX`; and any IndexRoot, IndexShard, dictionary object, or
DirectoryHintTable whose recorded decompressed size would exceed
`u32::MAX`. Readers MUST reject decompression output that exceeds the
recorded u32 size or any configured resource cap.

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

Because the global file table is sorted by
`(SHA-256(path)[0..8], normalized path bytes)`, shards are contiguous
ranges in file-table order. `first_path_hash ≤ last_path_hash` for every
shard, and shard ranges are monotonic. ShardEntry records in IndexRoot
MUST be sorted by `(first_path_hash, last_path_hash, shard_index)`
ascending. Adjacent entries MAY share boundary hashes, which is why
readers apply the boundary-defensive scan below.

Writers SHOULD avoid splitting identical `SHA-256(path)[0..8]` prefixes
across shard boundaries while a prefix run remains below
`max_hash_prefix_run_files` (§24). If continuing the run would exceed
that ceiling, the writer MUST split the run across adjacent shards rather
than creating an unbounded shard. This gives normal archives a compact
candidate set while bounding malicious or pathological collision-heavy
inputs.
Writers MUST also size shards so `file_count ≤ max_files_per_index_shard`
(default 1,000,000 in §13.3).

Readers MUST treat boundary equality defensively. When `target_hash`
equals a candidate shard's `first_path_hash` or `last_path_hash`, the
reader MUST scan adjacent shards in both directions while their boundary
hash also equals `target_hash`, until the equal-boundary run ends or
reader resource caps are reached. Readers MUST cap this scan at
`max_hash_collision_shard_scan` adjacent shards per direction (§13.3). If
the cap is reached before the run ends, the reader MUST fail with
"hash-prefix collision run exceeds resource caps" rather than returning a
partial lookup result.

This is an intentional availability trade-off: adversarial archives may
be rejected if they require unbounded equal-prefix scanning, but
conforming readers do not perform unlimited random-access lookups.

### 15.5 Index Shard plaintext

```rust
#[repr(C, packed)]
struct IndexShardHeader {
    magic:                 [u8; 4],   // b"TZIS"
    version:               u32,       // 1
    shard_index:           u64,
    file_count:            u32,
    frame_count:           u32,
    envelope_count:        u32,
    file_table_offset:     u32,
    frame_table_offset:    u32,
    envelope_table_offset: u32,
    string_pool_offset:    u32,
    string_pool_size:      u32,
    _reserved:             [u8; 16],
}
// Then:
//   FileEntry[file_count]   sorted by (SHA-256(path)[0..8], path bytes)
//   FrameEntry[frame_count] sorted by frame_index
//   EnvelopeEntry[envelope_count] sorted by envelope_index
//   string_pool: [u8; string_pool_size]
```

Each IndexShard carries the FileEntry records for its path-hash range and
the local FrameEntry/EnvelopeEntry rows needed to extract those files.
For each counted table in `IndexShardHeader`, a zero count means the
corresponding table is absent and its offset MUST be zero; readers MUST
NOT range-validate absent zero-count tables against the fixed header.
If `string_pool_size = 0`, `string_pool_offset` MUST also be zero.
Frame and envelope rows MAY be duplicated across shards when a compressed
frame or envelope is referenced by files whose paths hash into different
shards. Writers SHOULD minimize duplication by starting zstd frames at
tar member group boundaries, but correctness does not depend on that
optimization.
Archives with very large shared frame/envelope ranges across many hash
shards can grow a larger index because of this self-contained-shard
design. Writers SHOULD close frames and envelopes at tar member group
boundaries where practical to keep shard-local duplication low.

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

`FileEntry.flags` is reserved in v0.15. Writers MUST set it to zero, and
readers MUST reject a FileEntry with any non-zero flag bit.
`path_length` MUST be at least 1 and no greater than
`CryptoHeader.max_path_length`; the empty string is reserved only for the
root directory encoding in DirectoryHintTable (§15.8), never for a file
path.

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
5. Binary search FileEntry[] by `(path_hash, normalized path bytes)`
   within each candidate shard. On hash match, verify by reading the
   actual path from string_pool and comparing strings. Repeat for
   collisions if any (linear scan around landing position).
6. Extract (first_frame_index, frame_count,
   offset_in_first_frame_plaintext, tar_member_group_size).
7. Look up each FrameEntry in the shard-local FrameEntry table. For each
   unique envelope_index, look up the corresponding EnvelopeEntry in the
   shard-local EnvelopeEntry table, read its blocks, FEC-repair using its
   object-local data/parity counts, AEAD-decrypt, and strip suffix
   padding (§6.1).
8. For each FrameEntry, slice
   envelope_plaintext[offset_in_envelope ..
   offset_in_envelope + compressed_size] and zstd-decode that complete
   frame using the dictionary if has_dictionary = 1.
9. Concatenate decoded frame plaintexts in frame order, discard
   offset_in_first_frame_plaintext bytes from the first frame, and stream
   exactly tar_member_group_size bytes into a tar library.
```

The adjacent-boundary scan is deliberately resource-bounded. A malicious
archive producer or malicious path set can force up to
`2 × max_hash_collision_shard_scan` extra candidate-shard reads per
lookup before a compliant reader fails. Implementations for hostile
archives MAY lower that cap, require `verify` first, or disable random
single-file extraction after repeated collision-run failures.

### 15.8 Directory and path-order operations

Because the primary index is sorted by hash, listing files alphabetically
requires either (a) reading all shards, building a full file table in
memory, and sorting by path, or (b) using a path-locality structure.

For typical archives (≤1M files × 56-byte FileEntry records + path
strings), option (a) uses roughly 75-120 MiB of RAM depending on average
path length — acceptable for many offline operations.

Writers MUST include Directory Hint Shard metadata when
`file_count > directory_hint_required_file_count` (§24) or when the
archive claims cloud/object-store optimized directory-prefix operations.
Writers MAY include it for smaller archives. Directory hints are stored
as one or more encrypted/FEC-protected directory-hint shard objects
listed by IndexRoot. They map normalized directory paths to the shard IDs
that contain direct children or descendants of that directory. They are
acceleration structures only:
readers MUST verify actual paths from each shard's string pool before
extracting or listing.

Directory paths in this table are NFC-normalized UTF-8 with `/` as the
separator. The empty string is the canonical encoding of the root
directory and is the only directory path with `path_length = 0`. All
other directory paths MUST have at least one non-empty component, no
leading `/`, no `..` component, no empty inter-segment component, and no
trailing slash.

```rust
#[repr(C, packed)]
struct DirectoryHintTable {
    magic:                  [u8; 4],    // b"TZDH"
    version:                u32,        // 1
    hint_shard_index:       u64,
    entry_count:            u64,
    entry_table_offset:     u64,
    shard_list_offset:      u64,
    string_pool_offset:     u64,
    string_pool_size:       u64,
    _reserved:              [u8; 16],
}

#[repr(C, packed)]
struct DirectoryHintEntry {
    dir_hash:               [u8; 8],    // SHA-256(directory_path)[0..8]
    path_offset:            u64,        // into hint string pool
    path_length:            u32,
    _reserved:              u32,
    shard_list_offset_in_array: u64,    // byte offset from DirectoryHintTable.shard_list_offset
    shard_count:            u32,
    _reserved2:             u32,
}

#[repr(C, packed)]
struct DirectoryHintShardEntry {
    hint_shard_index:       u64,
    first_dir_hash:         [u8; 8],
    last_dir_hash:          [u8; 8],
    first_block_index:      u64,
    data_block_count:       u32,
    parity_block_count:     u32,
    encrypted_size:         u32,
    decompressed_size:      u32,
    entry_count:            u64,
}
```

DirectoryHintShardEntry records live in IndexRoot and are sorted by
`(first_dir_hash, hint_shard_index)`. Their hash ranges MUST be
monotonic: for adjacent entries,
`last_dir_hash ≤ next.first_dir_hash`; if the boundary hashes are equal,
readers use the same adjacent-scan cap as §15.7, and
`last_dir_hash > next.first_dir_hash` is malformed. Each
DirectoryHintTable is the
plaintext of one directory-hint shard object encrypted with
`dir_hint_key`, AEAD domain `dirhint`, and counter
`hint_shard_index`. DirectoryHintEntry records inside a shard are sorted
by `(dir_hash, directory_path)` using bytewise comparison of normalized
UTF-8 directory paths as the collision
tie-breaker. If multiple directory paths share the same `dir_hash`,
readers MUST compare the actual string from the hint string pool.
`DirectoryHintTable.shard_list_offset` points to the start of a
contiguous u32 shard-ID array in the DirectoryHintTable plaintext and
MUST be 4-byte aligned. `DirectoryHintEntry.shard_list_offset_in_array`
is a byte offset from that array start, not from the start of the whole
object. It MUST be 4-byte aligned. The `shard_count` u32 IDs for an entry at
`DirectoryHintTable.shard_list_offset + shard_list_offset_in_array` MUST
fit within the shard-list array, be sorted ascending, and be unique.
Every shard ID MUST be `< IndexRoot.shard_count`.

If `DirectoryHintTable.entry_count = 0`, then `entry_table_offset`,
`shard_list_offset`, `string_pool_offset`, and `string_pool_size` MUST
all be zero and the table contains no usable hint entries. Readers MUST
NOT range-validate absent zero-count tables against the fixed header.

Writers MUST split directory hints into multiple DirectoryHintTable
objects before any single directory-hint shard would exceed the FEC
object shard limits in §18 or reader resource caps. The 64-bit offsets
inside DirectoryHintTable are used to avoid silent overflow in large
hint shards; they do not permit a single FEC object to exceed §18.
Each DirectoryHintTable object is bounded by the
`index_fec_data_shards` / `index_fec_parity_shards` class maxima and by
the ReedSolomonGF16 65,535-total-shard limit. Writers MUST size and
split directory-hint shards before encryption/FEC so each object fits
those limits.

Directory-prefix extraction resolves hints with this normative
procedure:

1. Normalize the requested directory path using the rules above, then
   compute `dir_hash = SHA-256(normalized_dir_path)[0..8]`.
2. Binary-search `DirectoryHintShardEntry[]` in IndexRoot by
   `(first_dir_hash, last_dir_hash, hint_shard_index)`, using the same
   boundary-defensive adjacent scan rule as §15.4 when `dir_hash` equals
   a boundary hash.
3. For each matching hint shard, read its object-local block extent,
   FEC-repair if needed, AEAD-decrypt with `dir_hint_key`, and
   zstd-decompress without a dictionary.
4. Validate the DirectoryHintTable (§15.9), then binary-search
   DirectoryHintEntry records by `(dir_hash, directory_path)`. Resolve
   hash collisions by comparing the actual normalized directory string
   from the hint string pool.
5. Use the associated sorted u32 shard-ID list as the candidate
   IndexShard set, then verify actual FileEntry paths from each
   candidate shard before extracting or listing.

If required hint shards are absent, corrupt, or incomplete in an archive
that requires them, readers SHOULD warn and fall back to scanning all
shards when resource caps permit. If caps do not permit a full scan,
readers MUST fail clearly with "directory index unavailable."

Alphabetical listing still requires sorting verified paths after reading
the candidate shard(s). Directory hints are not a full
path-sorted index and do not by themselves define listing order.

### 15.9 Structural validation

After decrypting and decompressing IndexRoot, an IndexShard, or a
DirectoryHintTable object, readers MUST validate all counts, offsets,
lengths, and table sizes against the actual plaintext buffer before
allocating heap storage or indexing into the buffer. For validation, a
"counted table" means a specific `(count, offset)` or `(size, offset)`
pair such as `file_count/file_table_offset` or
`string_pool_size/string_pool_offset`; the zero-offset exception is
applied per pair, not to the whole structure. A reader MUST reject a
structure if:

- a present table offset points before the fixed header or beyond the
  plaintext;
- a counted table has count/size zero but a non-zero offset, or has a
  non-zero count/size but a zero offset;
- `count × sizeof(entry)` overflows or exceeds the plaintext length;
- `IndexRoot.version != 1`, `IndexShardHeader.version != 1`, or
  `DirectoryHintTable.version != 1`;
- any reserved field or reserved byte range is non-zero;
- `CryptoHeader.has_dictionary = 0` while any IndexRoot dictionary field
  is non-zero;
- dictionary-object fields, directory-hint shard entries, string-pool, or
  shard-list ranges overflow or overlap invalidly;
- any DirectoryHintTable `shard_list_offset` is not 4-byte aligned;
- any DirectoryHintEntry shard-list byte offset is not 4-byte aligned or
  is not relative to `DirectoryHintTable.shard_list_offset` as specified
  in §15.8;
- any `FileEntry.path_length` is zero or exceeds
  `CryptoHeader.max_path_length`;
- `path_offset + path_length` exceeds the owning string pool;
- `shard_count`, `envelope_count`, `frame_count`, or `file_count` exceed
  reader resource caps;
- any object `data_block_count`, `parity_block_count`, or
  `encrypted_size` exceeds the class limits declared in CryptoHeader or
  reader caps;
- any IndexShard `file_count` exceeds `max_files_per_index_shard`;
- any encrypted object's `data_block_count * block_size` overflows `u32`
  or does not equal its recorded `encrypted_size`;
- any recorded `decompressed_size`, payload `plaintext_size`, frame
  `compressed_size`, or frame `decompressed_size` is inconsistent with
  the actual decompressed/decrypted size or would require more than
  `u32::MAX` bytes;
- any FrameEntry has flag bits other than 0 or 1 set.

Readers MUST also validate cross-table references before decoding:

- ShardEntry records are sorted as required by §15.4, with
  `last_path_hash ≤ next.first_path_hash` for adjacent entries; if the
  boundary hashes are equal, readers use the §15.4 adjacent-scan rule,
  but `last_path_hash > next.first_path_hash` is malformed;
- DirectoryHintShardEntry records are sorted as required by §15.8, with
  `last_dir_hash ≤ next.first_dir_hash` for adjacent entries; if the
  boundary hashes are equal, readers use the §15.8 adjacent-scan rule,
  but `last_dir_hash > next.first_dir_hash` is malformed;
- every ShardEntry, EnvelopeEntry, FrameEntry, and FileEntry referenced
  by another table exists;
- each IndexShard's local FrameEntry and EnvelopeEntry tables contain
  all rows needed by that shard's FileEntry ranges;
- every global frame index in
  `EnvelopeEntry.first_frame_index .. first_frame_index + frame_count`
  exists in the owning IndexShard's local FrameEntry table;
- every FrameEntry in an envelope's frame range has the same
  `envelope_index`;
- `FrameEntry.offset_in_envelope + compressed_size` is within
  `EnvelopeEntry.plaintext_size`;
- `EnvelopeEntry.encrypted_size = data_block_count × block_size`;
- every payload `EnvelopeEntry.frame_count` is at least 1 and
  `plaintext_size` is greater than 0;
- every payload envelope contains complete FrameEntry records only; no
  zero-length, padding-only, or frame-less payload envelope is valid;
- every global frame index in
  `FileEntry.first_frame_index .. first_frame_index + frame_count`
  exists in the owning IndexShard's local FrameEntry table;
- `offset_in_first_frame_plaintext` is ≤ the first frame's
  `decompressed_size`;
- `tar_member_group_size` fits within the concatenated decoded bytes
  from the FileEntry frame range after applying
  `offset_in_first_frame_plaintext`;
- frame `tar_stream_offset` values are monotonic and consistent with
  preceding frame decompressed sizes for frames in table order;
- when the same `frame_index` or `envelope_index` appears in more than
  one loaded IndexShard local table, every defined field in the
  duplicated FrameEntry or EnvelopeEntry row MUST match. Because all
  reserved fields are separately required to be zero in this format
  version, this is equivalent to byte-identical row encoding in v0.15.
  Readers MUST reject on mismatch. A full-archive `verify` operation
  MUST check this globally across all IndexShards.
- in full-archive `verify`, `IndexRoot.payload_block_count` MUST equal
  the sum of `EnvelopeEntry.data_block_count` over all distinct payload
  envelopes observed across shard-local EnvelopeEntry tables.

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
surface it through their diagnostics/error channel; library diagnostics
SHOULD be structured and include unsupported extension/profile
identifiers when available. Unsupported PAX/GNU extension records, failed
xattr/ACL application, timestamp precision loss, sparse-file fallback,
and ownership/mode application failures MUST be reported unless the user
explicitly requested best-effort quiet mode.

Recommended profile identifiers for diagnostics and conformance strings
are: `ustar-baseline`, `pax-posix-2001`, `gnu-longname`,
`pax-xattrs-acls`, and `gnu-sparse`. Implementations MAY expose more
specific local profile names, but they SHOULD map them to these baseline
identifiers when reporting unsupported metadata.

Path validation (no `..`, no leading `/`, no escape via symlinks) is
performed by the extractor at write and read time. Writers MUST NOT emit
archive paths with absolute paths, `..` components, empty components, NUL
bytes, or platform-specific escape forms. Readers MUST still validate and
reject unsafe paths because archives may be malicious or non-conforming.

---

## 17. Read Algorithm

### 17.1 Open

```
1. Read VolumeHeader at offset 0; verify CRC.
   Reject if `format_version != 1` or `volume_format_rev` is greater
   than the newest revision implemented by the reader. A reader claiming
   only v0.15 conformance rejects `volume_format_rev != 15`.
   Reject if `VolumeHeader.stripe_width = 0`.
2. Validate `crypto_header_offset` and `crypto_header_length` against
   the volume/stream bounds and reader caps; reject if they point before
   the end of VolumeHeader, exceed available bytes on seekable input, or
   require an allocation over caps. Then read CryptoHeader. Reject this
   CryptoHeader copy before KDF if `CryptoHeaderFixed.length !=
   VolumeHeader.crypto_header_length`, if `CryptoHeader.stripe_width =
   0`, or if `CryptoHeader.stripe_width != VolumeHeader.stripe_width`;
   try another volume's CryptoHeader copy if one is available.
3. Parse KdfParams; prompt for passphrase or load keyfile. If
   `kdf_algo == Argon2id`, reject if `t_cost`, `m_cost_kib`,
   `parallelism`, or `salt_length` exceed reader caps or if
   `salt_length` is outside 8..64 bytes, `parallelism = 0`, or
   `m_cost_kib < 8 × parallelism`.
4. Run KDF → master_key. Derive mac_key using the archive UUID and
   session ID from VolumeHeader (§13.2). Verify CryptoHeader HMAC,
   including the VolumeHeader UUID/session binding (§9).
   On failure: try another volume's CryptoHeader copy. If all fail under
   the same key: abort "wrong key or all CryptoHeader copies corrupt."
5. Derive enc_key, nonce_seed, index_root_key, index_shard_key,
   dictionary_key, dir_hint_key, and index_nonce_seed.
6. If the input is seekable:
     a. Determine file size of an available volume (OS stat / Content-Length).
     b. If file_size < sizeof(VolumeHeader) + sizeof(VolumeTrailer),
        reject the volume as malformed before seeking. Otherwise seek to
        file_size − 128; read VolumeTrailer.
     c. Verify trailer magic and trailer HMAC. On failure: this volume is
        tampered or truncated; try another volume. Verify that the
        authenticated trailer `archive_uuid`, `session_id`, and
        `volume_index` match the VolumeHeader; on mismatch, reject this
        volume without attempting object decryption.
     d. Range-check `manifest_footer_offset` and
        `manifest_footer_length` against the volume size and reader caps
        before seeking or allocating. `manifest_footer_length` MUST equal
        `sizeof(ManifestFooter)`. Then read ManifestFooter and verify
        HMAC. Verify that ManifestFooter `archive_uuid`,
        `session_id`, and `volume_index` match both the authenticated
        trailer and the VolumeHeader. Verify
        `ManifestFooter.total_volumes == CryptoHeader.stripe_width ==
        VolumeHeader.stripe_width` and that the value is non-zero; reject
        on mismatch.
     e. If ManifestFooter.is_authoritative = 0, this volume is not a
        random-access bootstrap source. Try another volume, use a
        trusted bootstrap sidecar, or enter sequential recovery mode.
7. If the input is non-seekable:
     a. If a trusted bootstrap sidecar is supplied, use it for
        ManifestFooter and IndexRoot bootstrap after verifying sidecar
        HMAC, ManifestFooter HMAC, and object AEAD.
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
10. Validate IndexRoot structure (§15.9); extract the shard table,
    optional directory-hint shard table, and optional dictionary object
    extent.
11. If has_dictionary = 1: read the dictionary object blocks from the
    IndexRoot dictionary extent; repair, trim, AEAD-decrypt with
    `dictionary_key` using domain `dict`, and zstd-decompress (no
    dictionary). Initialize the payload zstd decompression context with
    those bytes.
12. Compute target_hash = SHA-256(target_path)[0..8].
13. Binary search ShardEntry → candidate shard set, including adjacent
    equal-boundary shards if needed.
14. Read candidate shard data/parity blocks using each ShardEntry's
    object-local FEC counts; repair, trim to encrypted_size,
    AEAD-decrypt with index_shard_key, and zstd-decompress
    (no dictionary).
15. Validate each IndexShard structure (§15.9).
16. Binary search FileEntry by `(path_hash, normalized path bytes)`;
    resolve collisions via string compare; get (first_frame_index, frame_count,
    offset_in_first_frame_plaintext, tar_member_group_size).
17. Read the FrameEntry range from the same IndexShard's local frame
    table and collect the unique EnvelopeEntry records from that shard's
    local envelope table.
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
each encrypted envelope, verifies AEAD with the current
`next_envelope_index` counter, strips suffix padding, zstd-decompresses
each packed frame, and feeds the resulting tar bytes to a tar library.
`next_envelope_index` starts at 0 and increments exactly once after each
complete payload envelope authenticates. Payload-parity BlockRecords do
not increment this counter.
If the BlockRecord carrying an envelope-end flag fails CRC and no parity
is available to repair that object, the reader MUST abort sequential
extraction at that envelope. It MUST NOT guess the envelope boundary.

For non-seekable single-volume input, this is the required fallback when
no bootstrap sidecar is available and `has_dictionary = 0`. If
`has_dictionary = 1`, the reader needs authenticated dictionary material
before decompressing payload frames. Without a bootstrap sidecar that
provides an authenticated encrypted IndexRoot copy that locates the
dictionary object and an authenticated encrypted dictionary-object copy
that supplies the dictionary bytes, the reader MUST reject with
"dictionary bootstrap required." If the payload stream is already flowing
before the sidecar is available, the reader MUST buffer encrypted
envelope bytes until the dictionary is recovered or reject; it MUST NOT
attempt dictionary-less decompression.

For multi-volume striped archives, a non-seekable sequential reader must
receive all required volume streams in a way that allows global block
order to be reconstructed; otherwise it must reject with "global block
ordering required for striped multi-volume sequential extract."
One conforming implementation strategy is to read each supplied volume
stream sequentially, inspect each BlockRecord header, and merge records
by ascending `block_index` before envelope assembly. This is an
implementation note; the wire format requirement is only that global
payload-data block order be reconstructable. tzap does not define a
multiplexed multi-volume pipe container, concatenation delimiter, or
volume-stream wrapper; any tool that concatenates, delimits, or
multiplexes volumes is outside this archive wire format and must present
the original BlockRecord `volume_index`/`block_index` semantics to the
reader.

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
For IndexRoot, object-local repair still requires bootstrap metadata
from ManifestFooter or a bootstrap sidecar to locate the IndexRoot block
extent (§11).
For each FEC object, all data and parity BlockRecords occupy one
contiguous global `block_index` range:
`first_block_index .. first_block_index + data_block_count +
parity_block_count`. Data blocks appear first, followed by parity blocks.

Object classes:

- payload envelope: bounded by `fec_data_shards` / `fec_parity_shards`;
- index shard: bounded by `index_fec_data_shards` /
  `index_fec_parity_shards`;
- IndexRoot: bounded by `index_root_fec_data_shards` /
  `index_root_fec_parity_shards`;
- dictionary object: bounded by `index_root_fec_data_shards` /
  `index_root_fec_parity_shards`;
- directory hint shard: bounded by `index_fec_data_shards` /
  `index_fec_parity_shards`.

For `ReedSolomonGF16`, a single FEC object MUST NOT use more than
65,535 total shards (`data_block_count + parity_block_count`). Writers
MUST reject parameters or split metadata before exceeding this field
limit; readers MUST reject an object whose recorded total exceeds it.
At the default 64 KiB block size, this caps any one Reed-Solomon object
at just under 4 GiB of encoded shard payload, so large metadata must be
sharded rather than placed in IndexRoot.

`record_crc32c` on data and parity BlockRecords is an unkeyed bit-rot
detector, not a cryptographic authenticator. Undetected corruption in a
parity block can cause repair to fail or produce candidate ciphertext
that later fails AEAD verification, but readers MUST NOT release
plaintext from any repaired object until that object's AEAD tag verifies.

For each object, the writer splits encrypted bytes into
`data_block_count` data blocks, derives that object's actual
`parity_block_count` from §27 using `data_block_count`, computes parity,
and writes data followed by parity. The object's table entry records
`first_block_index`, `data_block_count`, `parity_block_count`, and
`encrypted_size`; readers use those fields to fetch exactly the blocks
required to repair and decrypt that object.

Because a contiguous range striped by `block_index mod V` is balanced
across volumes, loss of any N volumes removes at most
`N × ceil(G_total / V)` shards from that object. Writers do not need to
pad each object to a multiple of V for the volume-loss guarantee.

`*_data_shards` and `*_parity_shards` in CryptoHeader are class maxima,
not the parity count that must be written for every object. The actual
per-object `parity_block_count` MUST be ≤ the relevant class maximum.

Writers MUST size objects so `data_block_count` does not exceed the data
shard limit for that object class. The effective data-shard limit for
any class is also bounded by `floor(u32::MAX / block_size)`, because
`encrypted_size` is a u32 and must equal `data_block_count * block_size`.
There is no global 64 KiB block-size requirement: larger block sizes are
valid only when class maxima and actual object sizes are small enough
for this product to fit in `u32`. If an envelope, index shard,
IndexRoot, dictionary object, or directory hint shard would exceed its
limit, the writer must split earlier or choose larger FEC parameters
before writing. IndexRoot itself MUST NOT be used as the split target for
unbounded metadata; shard-local frame/envelope tables and directory hint
shards are the scaling mechanism. IndexRoot is not splittable in this
format version. Writers MUST keep it below the selected
`index_root_fec_data_shards` limit, the effective u32-size limit, and
the ReedSolomonGF16 total-shard limit by increasing files per shard,
reducing root-table cardinality where possible, or otherwise reject with
"IndexRoot too large."

Writers MUST also ensure `data_block_count * block_size` fits in `u32`
for every encrypted object, because `encrypted_size` is a u32 field.

Recoverability for each object: `parity_block_count ≥ N ×
ceil(G_total / V)` for N-volume tolerance, where `G_total =
data_block_count + parity_block_count` for that object.

Synthetic zero shards used internally by a Reed-Solomon implementation to
fill an encoder matrix are virtual. They MUST NOT be written as
BlockRecords, assigned block indices, or counted in `data_block_count`.
`BlockRecord.flags` bit 1 is reserved for future compatibility and MUST
be zero in v0.15 archives. Readers MUST reject blocks with reserved flag
bits set.

---

## 19. Write Algorithm

### 19.1 Default: parallel-volume forward-only write

```
1. Generate `archive_uuid` and `session_id` from a CSPRNG. Each is 16
   bytes with at least 128 bits of entropy; timestamp-derived or
   deterministic session IDs are forbidden.
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
   tar member group; split very large groups into ordered frame ranges
   whose uncompressed frame payloads target chunk_size. Record
   FrameEntry.tar_stream_offset and decompressed_size for each frame.
10. Pack complete frames into envelopes. A frame MUST NOT be split across
    envelopes. Assign envelope_index sequentially from 0 in closure
    order. When closing an envelope:
     - suffix-pad and AEAD-encrypt it;
     - split encrypted bytes into data blocks; `data_block_count` is the
       number of ciphertext blocks including the AEAD tag and suffix
       padding;
     - compute object-local parity blocks;
     - write data+parity blocks through the stripe mapper;
     - record EnvelopeEntry with data/parity counts and frame range;
     - record FrameEntry.envelope_index and offset_in_envelope in memory.
11. Build index (compute SHA-256(path) for every FileEntry, sort by hash):
     a. Partition into shards of ~10,000 files each (default)
        while applying the bounded hash-prefix run rule (§15.4).
    b. For each shard: serialize FileEntry records plus the local
        FrameEntry and EnvelopeEntry rows needed by those files,
        zstd-compress (no dict), AEAD-encrypt, object-local FEC-encode,
        write blocks (continuing block_index, kind 4/5), and record
        ShardEntry data/parity counts.
     c. If has_dictionary = 1: zstd-compress the raw dictionary bytes
        without using the dictionary itself, AEAD-encrypt with
        dictionary_key using domain `dict`, object-local FEC-encode, and
        write dictionary blocks (kind 6/7).
     d. If directory hints are required or requested: build one or more
        DirectoryHintTable objects, zstd-compress (no dict),
        AEAD-encrypt with dir_hint_key using domain `dirhint`,
        object-local FEC-encode, write blocks (kind 8/9), and record
        DirectoryHintShardEntry data/parity counts.
     e. Build Index Root: encrypted archive totals + ShardEntry table +
        dictionary object extent (if any) + DirectoryHintShardEntry table
        (if any). IndexRoot MUST NOT contain global FrameEntry or
        EnvelopeEntry tables or raw dictionary bytes.
     f. zstd-compress IndexRoot (no dictionary even if has_dictionary = 1),
        AEAD-encrypt with index_root_key, object-local FEC-encode using
        `compute_parity(D = data_block_count, V, N, bit_rot_pct)` from
        §27 bounded by `index_root_fec_data_shards` /
        `index_root_fec_parity_shards`, write blocks (kind 2/3), and
        record IndexRoot data/parity counts for the ManifestFooter.
12. Build the shared ManifestFooter bootstrap fields (authoritative).
13. For each sink, in any order (no inter-sink dependencies):
     - Build this volume's ManifestFooter copy by setting
       volume_index to the sink's zero-based volume index and computing
       manifest_hmac over that copy.
     - Write that ManifestFooter at current sink position
     - Write VolumeTrailer with:
         block_count = blocks written to this sink
         bytes_written = sink's current cursor
         manifest_footer_offset = position where footer was written above
         manifest_footer_length = sizeof(ManifestFooter)
         trailer_hmac = HMAC using the §12 domain-separated trailer
         input over the first 96 trailer bytes
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

No part of the v0.15 write path needs to revisit a closed S3 part or to
write at an arbitrary byte offset.

### 19.3 Single-stream streaming mode

Single-sink, fully non-reopenable streaming is supported only with
`stripe_width = 1` and `volume_loss_tolerance = 0`. The writer emits one
volume forward-only: VolumeHeader, CryptoHeader, payload/index blocks,
ManifestFooter, and VolumeTrailer. If the writer uses a payload zstd
dictionary (`has_dictionary = 1`), it MUST also emit a bootstrap sidecar
containing authenticated encrypted IndexRoot and dictionary-object copies
(§12.2), otherwise non-seekable sequential extraction would be
impossible.
Because the IndexRoot is finalized after payload envelopes, this mode is
not live-decompressible with a dictionary unless the reader can obtain an
already-complete sidecar or buffer encrypted payload bytes until the
sidecar is complete.
That buffer can be as large as the encrypted payload stream. A writer
MUST NOT advertise live stdout-to-stdin decompression for a
dictionary-compressed single stream unless the required bootstrap sidecar
is complete and available to the reader before payload decompression
starts.
The bootstrap sidecar may be written to a separate path, file
descriptor, or stream. It is not interleaved into the core tzap payload
stream unless an external wrapper outside this format defines such
multiplexing.

For `stripe_width > 1`, the writer must use §7.4 behavior. If only one
non-reopenable sink is available, it must reject or spool locally before
writing final volumes. There is no conforming v0.15 mode that round-robins
striped blocks into multiple non-reopenable volume streams without
either concurrent sinks or spooling.

---

## 20. Performance

### 20.1 Padding overhead (v0.15 unchanged from v0.14)

| Envelope size | Block size | Avg overhead |
|---|---|---|
| 1 MiB | 64 KiB | ~3% |
| 4 MiB | 64 KiB | ~0.8% |
| 16 MiB | 64 KiB | ~0.2% |

These are average estimates. Worst-case overhead can be higher for very
small envelopes or exact-fit envelopes, because the canonical padding
rule adds an entire `BLOCK_SIZE` when plaintext plus AEAD tag would
otherwise exactly fill the final block.

### 20.2 Dictionary

When `has_dictionary = 1`, the dictionary is loaded once per archive
(after IndexRoot decode) and reused across all payload envelope
decompressions. For small-file corpora, compression ratio improvements
of 30–50% are typical.

### 20.3 Parallelism

Same as v0.14. Envelope-level AEAD, object-local FEC encoding, zstd frame
compression, and per-sink writes are all independent.

---

## 21. Failure Modes

| Failure | Detection | Recovery |
|---|---|---|
| Bit-rot in block payload | record_crc32c | FEC repair |
| Any single volume lost (default mode) | block_index gap | FEC (if parity sized correctly) |
| CryptoHeader corrupt in 1 volume | HMAC fails | Use another volume's copy |
| ManifestFooter corrupt in 1 volume | HMAC fails | Use another volume's copy |
| All ManifestFooter copies corrupt/missing | HMAC/trailer lookup fails | Use trusted bootstrap sidecar or sequential recovery |
| VolumeTrailer corrupt | HMAC fails | Try another volume; if all corrupt, scan from end for magic |
| V=1 streaming volume lost | Volume file missing | Unrecoverable unless another copy exists |
| Mid-stream writer crash | VolumeTrailer absent or HMAC fails | Reader reports clearly |
| Adversarial volume splice | session_id mismatch | Detected; rejected |
| IndexRoot block extent known but unrecoverable | High parity usually saves it | If exhausted, recovery mode |
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
- VolumeHeader and BlockRecord CRC32C fields are corruption detectors,
  not authentication. Readers only trust archive identity and repaired
  object bytes after authenticated header/trailer/footer checks and
  AEAD/HMAC verification succeed.
- `session_id` is bound into AEAD nonce derivation and AAD, preventing
  same-key/same-archive envelope or index replay across write sessions.
- `archive_uuid` and `session_id` are also bound into HKDF subkey
  derivation and CryptoHeader HMAC input, so raw-key mode does not reuse
  the same `mac_key` or AEAD keys across write sessions.
- Padding is authenticated by AEAD; zero padding is additionally checked
  as canonical-format validation.
- Reader caps and structural validation are mandatory before allocation.
- The 64-bit path-hash prefix is an indexing compactness trade-off, not
  collision-resistant identity. A malicious archive producer or
  path-supplying adversary may force hash-prefix collision runs; readers
  bound the work with `max_hash_collision_shard_scan` and fail clearly
  rather than performing unbounded random-access scans.
- Duplicated FrameEntry/EnvelopeEntry rows across IndexShards are checked
  for consistency when multiple relevant shards are loaded and by
  full-archive `verify`. Random extraction of a single file normally
  loads only the file's owning shard, so it cannot prove that another
  shard's duplicate row agrees. Users who do not control the archive
  producer SHOULD run `verify` before trusting random-extract output.
- The registered AEADs are not specified as formally key-committing
  AEADs. tzap provides early wrong-key detection through archive-bound
  HMACs and authenticated metadata before plaintext release, but formal
  key-commitment is left to a future committed-AEAD mode or detached
  signature profile (§30).

---

## 23. Versioning

`format_version` bumps on breaking changes; `volume_format_rev` identifies
the draft-level wire revision while the format is pre-implementation. This
document uses `format_version = 1` and `volume_format_rev = 15`. Readers
MUST reject archives with `format_version != 1` or with
`volume_format_rev` greater than the newest revision they implement.
Readers claiming conformance only to this draft MUST require
`volume_format_rev = 15`; accepting earlier draft revisions requires an
explicit compatibility mode.
Unknown algorithm IDs and critical extensions are hard errors.

The v0.x documents are pre-implementation drafts. A later v0.x draft may
still refine wire details while retaining `format_version = 1`; once any
implementation claims conformance to this v0.15 draft, incompatible
changes require a `format_version` bump.

Readers MUST reject IndexRoot, IndexShard, DirectoryHintTable, and
BootstrapSidecarHeader structures whose `version` field is not `1` in
this format version.
Per-structure `version` fields are independent of `volume_format_rev`.
A future draft may change one structure's version without changing the
others; `volume_format_rev` identifies the overall draft-level wire
revision, while each structure version gates that structure's plaintext
layout.

---

## 24. Sizing Defaults

| Parameter | Default | Notes |
|---|---|---|
| `chunk_size` | 256 KiB | writer target for uncompressed zstd-frame chunks; not a parsing boundary; MUST be non-zero |
| `envelope_target_size` | 1 MiB | MUST be non-zero |
| `block_size` | 64 KiB | MUST be at least 4096 bytes |
| `fec_data_shards` | 224 | maximum payload-envelope data blocks |
| `fec_parity_shards` | derived from V and N | maximum payload-envelope parity blocks; actual count is per-object (§27) |
| `index_fec_data_shards` | 16 | maximum index-shard and directory-hint-shard data blocks |
| `index_fec_parity_shards` | derived from V and N | maximum index-shard/directory-hint-shard parity blocks; actual count is per-object (§27) |
| `index_root_fec_data_shards` | dynamic, minimum 16 | maximum IndexRoot and dictionary-object data blocks; writer MUST raise enough for serialized IndexRoot, but total data+parity shards and `data_shards * block_size` must fit §18 limits |
| `index_root_fec_parity_shards` | derived from V and N | maximum IndexRoot/dictionary parity blocks; actual count is per-object (§27) |
| Files per shard | 10_000 | |
| `max_hash_prefix_run_files` | 50_000 | shard split ceiling for identical 8-byte hash prefixes |
| `directory_hint_required_file_count` | 100_000 | directory hint shards required above this count |
| `stripe_width V` | 8 | MUST be at least 1 |
| AEAD | AES-256-GCM-SIV | |
| KDF | Argon2id t=3 m=256 MiB p=4 | |
| `volume_loss_tolerance N` | 1 | |
| `bit_rot_buffer_pct` | 5 | MUST be ≤ 100 |

The effective data-shard ceiling for every object class is
`min(class_data_shards, floor(u32::MAX / block_size))`. Writers MUST
choose class maxima and actual object sizes so `encrypted_size` remains
representable as u32. Larger `block_size` values are therefore usable
only with smaller data-shard counts.

The dynamic IndexRoot data-shard value has no unbounded escape hatch:
`index_root_fec_data_shards + index_root_fec_parity_shards` MUST still
fit the ReedSolomonGF16 65,535-total-shard limit and the u16 header
fields. If the serialized IndexRoot cannot fit after root-table
cardinality has been reduced as far as this format allows, the writer
MUST reject rather than emit a non-conforming root object. A two-level or
continuation IndexRoot is future work (§30).

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
| `TZBS` | `54 5A 42 53` | Bootstrap sidecar |

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

tzap extract [--password-stdin] [--keyfile FILE] [--bootstrap FILE]
             [--strip-components N] [-C DIR] ARCHIVE [PATH...]

tzap list    [--password-stdin] [--keyfile FILE] [--bootstrap FILE] [--long]
             [--sort path|hash] ARCHIVE        # sort=hash is faster

tzap verify  [--password-stdin] [--keyfile FILE] [--bootstrap FILE]
             [--repair-to DIR] ARCHIVE

tzap info    ARCHIVE

tzap recover [--password-stdin] [--keyfile FILE]
             [--bootstrap FILE] ARCHIVE...
```

---

## 27. Parity Auto-Scaling (Required CLI Behavior)

```
fn compute_parity(D, V, N, bit_rot_pct):
    min_parity       = 1 if (N > 0 || bit_rot_pct > 0) else 0
    G_parity         = 0

    iterate until G_parity stabilizes:
        G_total          = D + G_parity
        G_parity_volume  = N × ceil(G_total / V)
        G_parity_bitrot  = ceil(G_total × bit_rot_pct / 100)
        G_parity         = max(G_parity_volume + G_parity_bitrot, min_parity)

class maximum:
    class_parity_shards = compute_parity(D = class_data_shards, V, N, bit_rot_pct)

per object:
    parity_block_count = compute_parity(D = data_block_count, V, N, bit_rot_pct)
```

The iteration MUST stop after convergence or after 100 iterations,
whichever comes first. If it has not converged within 100 iterations, the
writer MUST reject the parameter set. Normal parameter sets converge in a
small number of iterations.

All arithmetic in `compute_parity` MUST use checked unsigned 64-bit
integer operations. Writers MUST reject the parameter set if any
intermediate addition, multiplication, or ceiling calculation overflows.
Writers MUST reject `bit_rot_pct > 100` as nonsensical even though the
field is a u8. The computed class-maximum parity value MUST be ≤ 65,535
because it is stored in u16 class fields; if it exceeds that limit, the
writer MUST reject the configuration.

A simple sufficient condition for the unrounded recurrence to converge
is `N / V + bit_rot_pct / 100 < 1`. The required `N < V` rule and the
default 5% bit-rot buffer satisfy this for normal configurations. The
100-iteration cap remains normative because integer ceilings and unsafe
override parameters still need a deterministic rejection path.

The class-maximum invocation chooses each class maximum
(`*_parity_shards`) from that class's maximum data shards
(`*_data_shards`). The per-object invocation stores the resulting
`parity_block_count` in EnvelopeEntry, ShardEntry, or ManifestFooter and
MUST NOT exceed the class maximum.

For payload defaults (D_max=224, V=8, N=1, bit_rot=5%): the class maximum
stabilizes at `G_parity = 48`. That is 272 encoded shards total, a
17.6% parity fraction of encoded blocks and ~21.4% storage overhead over
data at the maximum object size. A smaller object uses fewer parity
blocks. For example, a 17-data-block payload envelope with the same V/N
and bit-rot settings stabilizes at `parity_block_count = 5`.

The bit-rot term is deliberately conservative extra margin after
volume-loss sizing. It is not a separate guarantee independent of volume
loss; rather, the stated guarantee is recovery from the configured
volume loss plus additional scattered block corruption up to the chosen
buffer, subject to Reed-Solomon erasure/error handling and successful
identification of corrupt blocks by CRC/AEAD.

Writers MUST reject `N ≥ V`. For `V = 1`, writers MUST set `N = 0`;
bit-rot parity may still be emitted, but no amount of parity can recover
the loss of the only volume.

The CLI emits the chosen parity and the resilience guarantee in plain
English at archive creation. Power users may override with
`--unsafe-parity D:P` combined with an explicit acknowledgment flag.

---

## 28. Reference Implementation Notes

Crate selection unchanged from v0.14. Reference implementations should
model IndexRoot, IndexShard, dictionary object, and directory hint shard
as distinct encrypted metadata object types.

### 28.1 Test corpus additions for v0.15

- **Empty archive**: archive with zero files; verify `file_count = 0`,
  `shard_count = 0`, `directory_hint_shard_count = 0`, no dictionary,
  no payload envelopes, `payload_block_count = 0`, and valid IndexRoot,
  ManifestFooter, and trailer. Verify `tar_total_size = 0` and
  `content_sha256 =
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- **Empty payload envelope rejection**: mutate an archive to contain a
  payload EnvelopeEntry with `frame_count = 0` or `plaintext_size = 0`;
  verify readers reject it rather than invoking a zstd decoder on empty
  payload bytes.
- **Reserved FileEntry flags**: set one FileEntry flag bit; verify reader
  rejects before extraction.
- **Encrypted-size canonicality**: mutate `encrypted_size` to be smaller
  or larger than `data_block_count * block_size`; verify rejection.
- **Shard and collision caps**: create a shard over
  `max_files_per_index_shard` and a hash-prefix collision run over
  `max_hash_collision_shard_scan`; verify both fail clearly.
- **Header/trailer identity binding**: combine a VolumeHeader from one
  archive with an authenticated trailer/footer from another archive under
  the same key; verify the reader rejects before object decryption.
- **Volume count cross-checks**: mutate `VolumeHeader.stripe_width`,
  `CryptoHeader.stripe_width`, and `ManifestFooter.total_volumes`
  independently; verify readers reject any mismatch.
- **Volume format revision**: create archives with `volume_format_rev`
  below, equal to, and above 15; verify v0.15-only readers accept only
  15 and reject newer revisions.
- **CryptoHeader length consistency**: mutate
  `VolumeHeader.crypto_header_length` and `CryptoHeaderFixed.length`
  independently; verify readers reject mismatches before parsing trailing
  extension bytes.
- **CryptoHeader identity binding**: combine a VolumeHeader from one
  archive with a CryptoHeader from another archive under the same raw key
  and verify CryptoHeader HMAC fails because UUID/session are bound.
- **Per-volume ManifestFooter copies**: create a multi-volume archive and
  verify each footer HMAC authenticates with that volume's own
  `volume_index` while all shared IndexRoot/bootstrap fields are equal.
- **HMAC domain vectors**: fixed `mac_key`, UUID/session, and serialized
  CryptoHeader, ManifestFooter, VolumeTrailer, and BootstrapSidecarHeader
  bytes. Verify all HMACs use their `tzap-v1-*` domain strings and raw
  byte concatenation exactly.
- **Unsafe paths**: include absolute paths, `..` components, empty
  components, and NUL-containing names; verify conformant writers reject
  and readers reject non-conforming archives.
- **Parity convergence cap**: use pathological parity parameters that do
  not converge within 100 iterations; verify writer rejects. Also verify
  checked arithmetic rejects overflow, `bit_rot_pct > 100`, and class
  parity results above 65,535.
- **AEAD constants**: for every registered AEAD algorithm, verify the
  nonce length and tag length match §5 and that archives using another
  length are rejected.
- **Integrity byte ranges**: corrupt the byte immediately before and at
  each CRC/HMAC field boundary for VolumeHeader, ManifestFooter,
  VolumeTrailer, and BootstrapSidecarHeader; verify only covered bytes
  affect that checksum/MAC and authenticated structures still reject
  tampering.
- **Sequential envelope counters**: pipe a dictionary-free archive with
  multiple envelopes and parity blocks through sequential extraction.
  Verify AEAD counters start at 0, increment once per payload envelope,
  and do not increment for parity BlockRecords.
- **Reserved BlockRecord flags**: set bit 1 and a high flag bit on data
  and parity BlockRecords; verify readers reject before using payload
  bytes.
- **Parity recurrence seed**: verify class-max and per-object parity
  calculations start from `G_parity = 0` and converge to the expected
  values in §27.
- **HKDF vectors**: fixed passphrase, Argon2id salt/params, raw-key
  cases, archive UUID, and session ID with expected `enc_key`, `mac_key`,
  nonce seeds, index keys, dictionary key, and directory-hint key. Verify
  independent implementations derive identical subkeys and that changing
  UUID/session changes all subkeys. The reference corpus MUST contain
  literal input byte strings and expected hex outputs, not only
  property-style tests.
- **KDF parameter caps**: Argon2id salt lengths below 8 and above 64,
  `t_cost`, `m_cost_kib`, and `parallelism` over reader caps,
  `m_cost_kib < 8 × parallelism`, and raw mode with exactly two KdfParams
  bytes `algo_tag = 0`. Verify all invalid cases reject before expensive
  allocation or KDF execution.
- **Nonce info vectors**: verify nonce derivation uses
  `b"tzap-v1-nonce" || u16(domain_len) || domain || uuid || session ||
  counter_le64`; changing only the domain length encoding changes the
  derived nonce and old non-length-prefixed derivations fail to decrypt.
- **IndexRoot AEAD counter**: archive whose IndexRoot uses counter 0 for
  both nonce and AAD; verify decryption succeeds. Archive using the old
  mismatched AAD counter must fail authentication.
- **Chunk-size semantics**: archives with `chunk_size` smaller than,
  equal to, and larger than typical file sizes. Verify readers ignore it
  for parsing, reject `chunk_size = 0`, and use FrameEntry extents as the
  only random-access authority.
- **BlockRecord CRC and kind validation**: corrupt every byte range
  covered by `record_crc32c`, set unknown `kind` values, set reserved
  bytes, and set bit 0 on parity blocks; verify readers reject.
- **Block index ordering**: duplicate, decreasing, and missing
  `block_index` values inside required object extents and across
  multi-volume reconstruction; verify readers reject unless explicit
  recovery mode repairs the gap.
- **Striped block congruence**: for multi-volume archives, mutate one
  volume so a BlockRecord has `block_index mod stripe_width !=
  volume_index`, and mutate another so consecutive block indices differ
  by more than `stripe_width`; verify readers reject the volume even when
  other volumes are unavailable.
- **ManifestFooter bootstrap dependency**: corrupt all ManifestFooter
  copies while leaving IndexRoot blocks intact; verify random-access
  bootstrap fails unless a valid bootstrap sidecar is supplied.
- **Large-index root bound**: synthesize an archive plan with enough
  files that global FrameEntry/EnvelopeEntry tables would exceed one
  GF(2^16) FEC object. Verify IndexRoot contains only ShardEntry and
  metadata-object extent tables, while each IndexShard carries its local
  frame/envelope rows. Also synthesize a root table that still exceeds
  the IndexRoot FEC/u32 limits and verify the writer rejects "IndexRoot
  too large."
- **Directory hint sharding**: build directory hints whose entry table
  and string pool exceed 4 GiB in aggregate. Verify writers emit multiple
  DirectoryHintTable objects with 64-bit internal offsets and readers
  reject any single hint shard exceeding §18 object limits. Verify
  `DirectoryHintTable.shard_list_offset` and
  `shard_list_offset_in_array` are 4-byte aligned, and the latter is
  interpreted relative to the shard-list array.
- **Directory hint lookup**: directory paths at root and nested levels,
  hash collisions, and boundary equality across hint shards. Verify the
  §15.8 lookup algorithm returns only verified candidate IndexShard IDs.
- **Decompressed-size caps**: create metadata objects that decompress to
  more than their recorded u32 `decompressed_size` or more than
  `u32::MAX`; verify readers reject before allocation.
- **Block-size/product cap**: use a large `block_size` with class data
  shard maxima whose product would overflow u32; verify writers reject
  or reduce the effective data-shard limit and readers reject overflow.
- **GF16 object limit**: attempt to encode an object whose
  `data_block_count + parity_block_count` exceeds 65,535 under
  `ReedSolomonGF16`; verify writer and reader reject it.
- **Padding boundaries**: envelopes whose ciphertext length, including
  AEAD tag, would otherwise be exactly a multiple of BLOCK_SIZE (force
  the writer to add an extra BLOCK_SIZE of padding); verify reader
  correctly truncates.
- **Padding marker boundary**: fuzz payloads whose last compressed byte
  is 0xFF and verify the marker remains unambiguous because mandatory
  suffix padding occupies the envelope plaintext's final byte(s).
- **Wide-form padding**: envelopes where pad_len ≥ 255 (common when
  envelope is large and last frame is small); include malformed
  plaintexts with final byte 0xFF, N < 5, `pad_len < 5`, `pad_len > N`,
  and `pad_len = 0`. Verify all are rejected before subtraction or
  slicing.
- **Session-bound AEAD**: two archives with the same raw key,
  archive_uuid, and envelope counter but different session_id; verify
  envelope and index splicing fails authentication.
- **Frame-addressed random access**: files whose tar member group starts
  at frame offset 0, starts mid-frame after another file, and spans
  multiple frames/envelopes. Verify extraction decodes frame ranges and
  slices decompressed frame plaintext, never envelope plaintext.
- **Object-local FEC repair**: corrupt one data block in a payload
  envelope, an index shard, and IndexRoot. Verify each object repairs
  using only its recorded data/parity block extent. Verify actual
  per-object parity counts are smaller for small objects than the class
  maximum.
- **Parity-block corruption**: corrupt parity BlockRecord payloads and
  CRCs independently. Verify CRC-detected corruption is treated as an
  erasure and any unrepaired or incorrectly repaired ciphertext still
  fails AEAD before plaintext release.
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
  and splits the run above that ceiling. Verify readers scan adjacent
  equal-boundary shards only up to `max_hash_collision_shard_scan` and
  fail clearly when the cap is exceeded.
- **Directory hints**: archive with many directories whose files hash
  into distant shards; verify prefix extraction uses hinted shard IDs and
  still validates string-pool paths. Verify archives with more than
  `directory_hint_required_file_count` files include directory hint
  shards, and readers warn/fall back or fail clearly when required hints
  are absent or corrupt.
- **Structural validation**: malformed IndexRoot and IndexShard buffers
  with overflowing counts, invalid versions, non-zero reserved fields,
  invalid offsets, and out-of-range string-pool paths; verify rejection
  before allocation.
- **Counted zero tables**: IndexRoot with `shard_count = 0`,
  IndexShardHeader with zero local table counts, and DirectoryHintTable
  with `entry_count = 0`; verify corresponding offsets must be zero and
  are not rejected merely for pointing before the fixed header.
- **Directory hint shard ranges**: mutate DirectoryHintShardEntry ranges
  so `last_dir_hash > next.first_dir_hash`; verify lookup and verify
  reject before binary search.
- **Payload block total**: mutate `IndexRoot.payload_block_count` so it
  no longer equals the sum of distinct payload EnvelopeEntry
  `data_block_count` values; verify full-archive `verify` rejects.
- **Duplicate local table consistency**: duplicate the same global
  FrameEntry or EnvelopeEntry in multiple IndexShards with one byte
  changed; verify full archive verification and multi-shard reads reject.
- **Single-sink streaming rejection**: attempt `stripe_width > 1` with a
  fully non-reopenable sink; verify the writer rejects or requires local
  spooling instead of silently buffering unbounded data.
- **Non-seekable sequential extract**: pipe a single-volume archive into
  the reader without a sidecar; verify sequential envelope extraction
  succeeds for `has_dictionary = 0` while listing/random extract fail
  clearly. Repeat with `has_dictionary = 1` and no bootstrap sidecar;
  verify the reader rejects with "dictionary bootstrap required."
- **Bootstrap sidecar**: dictionary archive with a bootstrap sidecar;
  verify `TZBS` header CRC, sidecar HMAC, UUID/session binding,
  ManifestFooter HMAC, IndexRoot AEAD, and dictionary-object AEAD are
  checked; verify IndexRoot and dictionary objects decrypt from sidecar
  BlockRecord copies and the dictionary is available before payload
  frame decompression. Verify sparse flag combinations follow the §12.3
  cursor rule. Verify sidecars with padding, extension bytes, unclaimed
  gaps, or trailing bytes are rejected.
- **ManifestFooter pointer bounds**: mutate `manifest_footer_offset` and
  `manifest_footer_length` in VolumeTrailer to point outside the volume,
  before valid data, or to the wrong length; verify readers reject before
  seeking, allocating, or attempting ManifestFooter HMAC.
- **Volume tolerance constraints**: verify writers reject `N ≥ V` and
  force `N = 0` for fully non-reopenable `V = 1` streaming.
- **Forbidden CryptoHeader hash**: archive containing extension `0x0004`
  is rejected.
- **S3 round-trip**: write to actual S3 (or minio) via multipart upload;
  read back via Range requests; no seek-back used.
- **Dictionary**: archives created with and without dictionary; verify
  dictionary correctly bootstraps via IndexRoot's dictionary-object
  extent.
- **Trailer-from-end**: verify seekable readers locate the trailer from
  `file_size - 128`, then reject cleanly if the required VolumeHeader or
  CryptoHeader bytes are unavailable or if the volume is smaller than
  `sizeof(VolumeHeader) + sizeof(VolumeTrailer)`.
- **Metadata warnings**: unsupported PAX/GNU extension record, failed
  xattr/ACL application, timestamp precision loss, and sparse-file
  fallback all produce diagnostics unless best-effort quiet mode is
  explicitly enabled.

---

## 29. Conformance

A conformant writer:

1. Produces archives whose write sequence is strictly forward
   (no seek-back, no overwrite-in-place) and sets
   `format_version = 1` and `volume_format_rev = 15`.
2. Sorts the file table globally by
   `(SHA-256(path)[0..8], normalized path bytes)`.
3. Avoids splitting identical 8-byte path-hash prefixes below
   `max_hash_prefix_run_files`, and splits rather than creating
   unbounded shards above that ceiling.
4. Records FileEntry as a decompressed zstd frame extent, never as a tar
   offset inside envelope plaintext.
5. Keeps every zstd frame wholly inside one envelope.
6. Records object-local FEC data/parity counts for every encrypted
   object.
7. Stores the ManifestFooter pointer in the VolumeTrailer and emits a
   per-volume ManifestFooter whose authenticated `volume_index` matches
   the containing volume.
8. Caps CryptoHeader extension payloads at 256 bytes each.
9. Stores any pre-trained zstd dictionary as an encrypted dictionary
   object located by IndexRoot, not in CryptoHeader or raw IndexRoot
   plaintext.
10. Applies suffix-marker padding (§6.1).
11. Binds AEAD nonce derivation and AAD to both `archive_uuid` and
   `session_id`.
12. Uses `stripe_width = 1` for fully non-reopenable single-sink
   streaming, sets `volume_loss_tolerance = 0` in that mode, and emits a
   §12.3 bootstrap sidecar if `has_dictionary = 1`.
13. Emits PAX/GNU tar extension records when claiming metadata beyond
   ustar baseline.
14. Includes directory hint shards when
    `file_count > directory_hint_required_file_count` or when claiming
    cloud/object-store optimized directory-prefix operations (§15.8).
15. Auto-scales `G_parity` per §27 unless `--unsafe-parity` is set.
16. Rejects `volume_loss_tolerance N` values where `N ≥ V`.
    Writers MUST set `stripe_width V ≥ 1`.
17. Never emits CryptoHeader extension tag `0x0004`.
18. Derives subkeys with the §13.2 HKDF-SHA-256 schedule, including
    archive UUID and session ID in HKDF-Extract salt.
19. Uses the same AEAD counter value in nonce derivation and AAD,
    including counter 0 for IndexRoot.
20. Sets `chunk_size` to a non-zero writer target and does not rely on it
    as an on-disk parsing boundary.
    Emits KDF parameter payloads exactly as §13.1 specifies, including
    `m_cost_kib ≥ 8 × parallelism` for Argon2id.
21. Assigns payload envelope indices contiguously from 0 in write order.
22. Sets all reserved BlockRecord flag bits to zero, sets bit 0 only on
    the last data block of an encrypted object, and never sets bit 0 on
    parity blocks.
23. Keeps global FrameEntry and EnvelopeEntry tables out of IndexRoot;
    each IndexShard carries the local frame/envelope rows needed by its
    FileEntry records.
24. Splits metadata before any ReedSolomonGF16 FEC object would exceed
    65,535 total shards, and rejects if the non-splittable IndexRoot
    itself would exceed that limit.
25. Sets `FileEntry.flags = 0` and emits no unsafe archive paths
    (absolute paths, `..`, empty components, NUL bytes, or platform
    escape forms). Every FileEntry path length is at least 1 and no
    greater than `CryptoHeader.max_path_length`.
26. Ensures every encrypted object's `encrypted_size` equals
    `data_block_count * block_size` and fits in `u32`; also ensures
    every recorded u32 plaintext/decompressed size field fits in `u32`.
27. Emits valid empty archives when `file_count = 0` rather than inventing
    placeholder files or shards.
28. Never emits a payload envelope with `frame_count = 0`,
    `plaintext_size = 0`, or no complete zstd frames.
29. Sizes IndexShards so `file_count ≤ max_files_per_index_shard`
    (1,000,000 in this draft).
30. Emits only known BlockRecord kinds and zeroes every `_reserved*`
    field.
31. Generates `archive_uuid` and `session_id` from a CSPRNG with at least
    128 bits of entropy each.
32. Writes BlockRecords for each volume in strictly increasing
    `block_index` order, with each `block_index ≡ volume_index (mod
    stripe_width)` and consecutive records in that volume spaced exactly
    by `stripe_width`; never emits duplicate global block indices.
33. Emits `IndexShardHeader.version = 1` and uses domain-separated HMAC
    inputs for CryptoHeader, ManifestFooter, VolumeTrailer, and
    BootstrapSidecarHeader.
34. Sets all IndexRoot dictionary fields to zero whenever
    `has_dictionary = 0`.
35. Emits v0.15 bootstrap sidecars as packed sequences with no padding,
    extension bytes, unclaimed gaps, or trailing bytes.
36. Emits zero offsets for absent counted tables and no non-zero
    zero-count table pointers.
37. Sets `IndexRoot.payload_block_count` to the sum of distinct payload
    envelope data blocks.

A conformant reader:

1. On seekable input, locates the VolumeTrailer by seeking to
   `file_size - 128`.
2. Locates the ManifestFooter from the trailer or from a trusted
   bootstrap sidecar, not from VolumeHeader.
3. Rejects non-authoritative ManifestFooter copies for random-access
   bootstrap.
4. On non-seekable input without a sidecar, either performs sequential
   extraction (§17.3) for non-dictionary archives or rejects operations
   that require random access or dictionary bootstrap clearly.
5. Strips padding by reading the final byte (and possibly 4 more for
   wide form), not by scanning from the start.
6. Rejects wide-form padding with `N < 5`, `pad_len < 5`,
   `pad_len > N`, or `pad_len = 0` before indexing, subtracting, or
   slicing.
7. Searches the file table by `(SHA-256(path)[0..8], normalized path
   bytes)`, not by string compare on partial path bounds.
8. Handles adjacent shard-boundary hash equality defensively by scanning
   adjacent equal-boundary shards subject to
   `max_hash_collision_shard_scan`.
9. Validates IndexRoot, IndexShard, and DirectoryHintTable structural
   counts and offsets before allocation or indexing.
10. Reconstructs random-access file bytes by decoding the FileEntry
   frame range and slicing decompressed frame plaintext.
11. Uses object-local FEC counts from ManifestFooter, EnvelopeEntry, or
   ShardEntry to repair encrypted objects.
12. Loads the zstd dictionary (if `has_dictionary = 1`) from the
   dictionary object located by IndexRoot before decompressing any
   payload envelope.
13. Reports degraded metadata fidelity when the relevant tar extension
   profile is unsupported or metadata application fails.
14. Enforces all resource caps from §13.3.
15. Rejects CryptoHeader extension tag `0x0004`.
16. Validates §12.3 sidecar HMAC, UUID/session binding,
    known flag bits, ManifestFooter HMAC, IndexRoot AEAD, and
    dictionary-object AEAD when present before trusting bootstrap sidecar
    bytes. It MAY use sidecar CRC as an early corruption check.
17. Derives subkeys with the §13.2 HKDF-SHA-256 schedule and verifies
    CryptoHeader HMAC with the VolumeHeader UUID/session binding.
18. Rejects `chunk_size = 0` and treats non-zero `chunk_size` as advisory
    metadata only; FrameEntry and EnvelopeEntry remain authoritative.
19. Rejects BlockRecords with reserved flag bits set, unknown `kind`
    values, non-zero reserved bytes, or bit 0 set on parity blocks.
20. For sequential extraction, derives each payload envelope AEAD counter
    from a local contiguous counter starting at 0 and incremented only
    after a complete payload envelope authenticates.
21. Rejects any ReedSolomonGF16 object whose
    `data_block_count + parity_block_count` exceeds 65,535.
22. Uses shard-local FrameEntry and EnvelopeEntry tables for random
    extraction; IndexRoot is not expected to contain global copies.
23. Rejects non-zero `FileEntry.flags`, unsafe archive paths, and
    FileEntry paths with `path_length = 0` or length greater than
    `CryptoHeader.max_path_length`; rejects encrypted objects whose
    `encrypted_size` does not equal `data_block_count * block_size`.
24. Verifies authenticated VolumeTrailer and ManifestFooter identity
    fields match the VolumeHeader before using bootstrap data, and
    range-checks `manifest_footer_offset` / `manifest_footer_length`
    before reading the ManifestFooter.
25. Rejects empty payload envelopes and any IndexRoot, IndexShard,
    dictionary object, or DirectoryHintTable object that exceeds its FEC,
    u32 size-field, or reader resource limits.
26. Rejects any parsed structure with non-zero `_reserved*` fields unless
    a later format version explicitly assigns that field.
27. Verifies that BlockRecords within a volume are strictly increasing by
    `block_index`, that each block satisfies
    `block_index mod stripe_width = volume_index`, and that consecutive
    records in the same volume are spaced by exactly `stripe_width`.
    When reconstructing a complete global order across volumes, verifies
    that no two BlockRecords share the same `block_index` and that no
    global block index is missing. Duplicate or decreasing block indices
    are hard errors; gaps inside a declared object extent are hard errors
    unless the reader is in an explicit recovery mode that can repair the
    missing blocks.
28. Rejects unsupported `volume_format_rev`, mismatched
    `VolumeHeader.stripe_width`, `CryptoHeader.stripe_width`, or
    `ManifestFooter.total_volumes`, zero stripe/volume counts,
    `CryptoHeaderFixed.length != VolumeHeader.crypto_header_length`, and
    excessive KDF parameters before attempting expensive work.
29. Rejects `has_dictionary = 0` with non-zero IndexRoot dictionary
    fields, unrecognized IndexShard versions, invalid zero-count table
    offsets, invalid DirectoryHintShardEntry ordering, and non-matching
    duplicate FrameEntry/EnvelopeEntry rows when observed.
30. Rejects sidecars that are not packed exactly as §12.3 specifies.
31. During full-archive `verify`, checks that
    `IndexRoot.payload_block_count` equals the sum of distinct payload
    EnvelopeEntry data-block counts.

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
7. Two-level or continuation IndexRoot for archives whose root tables
   exceed the single-object FEC/u32 size limits.
8. Formally key-committing AEAD mode or a mandatory detached signature
   profile for deployments that require key-commitment properties beyond
   archive-bound HMAC wrong-key detection.
9. Optional redundant envelope-length metadata in BlockRecord or an
   envelope table for stronger sequential extraction diagnostics after
   unrecoverable bit errors.

---

## 31. Glossary

- **Block** — fixed-`BLOCK_SIZE` ciphertext/parity; FEC unit.
- **Envelope** — packed group of zstd frames; AEAD unit.
- **Frame** — one zstd frame; compression unit.
- **FEC object** — one encrypted object repaired with its own data/parity
  block extent: payload envelope, index shard, or IndexRoot. IndexRoot
  still needs ManifestFooter or bootstrap sidecar metadata to locate that
  extent.
- **Group** — `G_total = data_block_count + parity_block_count` blocks;
  FEC math unit for one object.
- **Shard** — independent encrypted/FEC-protected segment of the file table.
- **Index Root** — small encrypted root object with archive totals,
  ShardEntry records, and optional metadata-object extents; it does not
  contain global frame/envelope tables or raw dictionary bytes.
- **Tar member group** — all tar records needed to restore one logical
  archive path, including path-specific metadata records and main entry.
- **Stripe width V** — number of volumes; `volume = block_index mod V`.
- **session_id** — CSPRNG-generated 16-byte per-write-invocation value;
  distinguishes archives even when archive_uuid coincides.
- **Suffix-marker padding** — padding scheme where the last byte of the
  envelope plaintext encodes the padding length (extending to a 5-byte
  wide form for pad_len ≥ 255).

---

## Appendix A: All changes from v0.14 → v0.15

| Section | Change |
|---|---|
| §4 / §14.1 | Packed unaligned field handling documented; nonce domain is length-prefixed |
| §8 / §17.1 / §23 | `volume_format_rev = 15`; zero stripe widths rejected |
| §9 / §17.1 | CryptoHeader internal length must match VolumeHeader length |
| §10 / §29 | Per-volume BlockRecord congruence and stride checks added |
| §12.3 | Sparse sidecar flag combinations defined by cursor-based packed layout |
| §13 / §17.1 | KDFParams wire layout clarified; Argon2id `m_cost_kib ≥ 8 × parallelism` enforced |
| §15.2 / §15.9 | Counted zero-table offsets and `payload_block_count` invariant documented |
| §15.6 / §15.9 | FileEntry path length lower/upper bounds enforced |
| §15.8 / §15.9 | DirectoryHintShardEntry range monotonicity validated |
| §17.1 | ManifestFooter pointer range checks added before read/allocation |
| §28.1 / §29 | v0.15 tests and conformance checklist expanded |

---

*End of v0.15 specification.*
