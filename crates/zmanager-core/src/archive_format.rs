//! Canonical archive-format detection by path (CR-114).
//!
//! Historically every consumer (the CLI's format helpers, the archive
//! browser, and the extraction/list/test dispatch chains) carried its own
//! extension predicates, and they drifted. This is the single detector;
//! callers dispatch on [`ArchiveFormatKind`].
//!
//! This module also owns the compile-time format capability registry: one
//! row per format with its extension list and backend availability. Adding a
//! new format is one row in [`FORMAT_CAPABILITIES`]; platform-gated backends
//! declare their status there instead of sprinkling `cfg` across consumers.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

/// Canonical extension lists for path-based format detection.
pub const ZIP_FAMILY_EXTENSIONS: &[&str] = &[".zip", ".zipx", ".jar", ".war", ".ipa", ".apk", ".appx", ".xpi", ".cbz", ".epub"];
pub const SEVEN_Z_EXTENSIONS: &[&str] = &[".7z", ".cb7", ".sevenz"];
pub const RAR_EXTENSIONS: &[&str] = &[".rar", ".cbr"];
pub const TAR_EXTENSIONS: &[&str] = &[".tar", ".cbt", ".pax", ".ustar"];
pub const TAR_BZ2_EXTENSIONS: &[&str] = &[".tar.bz2", ".tbz2", ".tbz"];
pub const TAR_XZ_EXTENSIONS: &[&str] = &[".tar.xz", ".txz"];
pub const TAR_LZMA_EXTENSIONS: &[&str] = &[".tar.lzma", ".tlzma"];
pub const TAR_LZ_EXTENSIONS: &[&str] = &[".tar.lz"];
pub const TAR_LZO_EXTENSIONS: &[&str] = &[".tar.lzo"];
pub const TAR_COMPRESS_EXTENSIONS: &[&str] = &[".tar.z", ".taz"];
pub const TAR_LZ4_EXTENSIONS: &[&str] = &[".tar.lz4"];
pub const TAR_UU_EXTENSIONS: &[&str] = &[".tar.uu", ".tar.b64"];
pub const ISO_EXTENSIONS: &[&str] = &[".iso"];
pub const CAB_EXTENSIONS: &[&str] = &[".cab"];
pub const CPIO_EXTENSIONS: &[&str] = &[".cpio", ".cpio.gz", ".cpgz", ".cpio.bz2", ".cpio.xz", ".cpio.lzma", ".cpio.zst"];
pub const RPM_EXTENSIONS: &[&str] = &[".rpm"];
pub const XAR_EXTENSIONS: &[&str] = &[".xar"];
pub const PKG_EXTENSIONS: &[&str] = &[".pkg"];
pub const DMG_EXTENSIONS: &[&str] = &[".dmg"];
pub const LHA_EXTENSIONS: &[&str] = &[".lha", ".lzh"];
pub const AR_EXTENSIONS: &[&str] = &[".a", ".ar", ".lib"];
pub const WARC_EXTENSIONS: &[&str] = &[".warc"];
pub const MTREE_EXTENSIONS: &[&str] = &[".mtree"];
pub const TAR_ZST_EXTENSIONS: &[&str] = &[".tar.zst", ".tzst"];
pub const TGZ_EXTENSIONS: &[&str] = &[".tgz", ".tar.gz"];
pub const TZAP_EXTENSIONS: &[&str] = &[".tzap"];
pub const APPLE_ARCHIVE_EXTENSIONS: &[&str] = &[".aar", ".aea"];
pub const DEB_EXTENSIONS: &[&str] = &[".deb"];
pub const MSI_EXTENSIONS: &[&str] = &[".msi"];
pub const VHD_EXTENSIONS: &[&str] = &[".vhd"];
pub const VMDK_EXTENSIONS: &[&str] = &[".vmdk"];
pub const UDF_EXTENSIONS: &[&str] = &[".udf"];
pub const SQUASHFS_EXTENSIONS: &[&str] = &[".squashfs", ".sqfs"];
pub const APPIMAGE_EXTENSIONS: &[&str] = &[".appimage"];
// `.esd` is intentionally absent: distribution ESDs are LZMS-compressed solid
// images, which the WIM backend does not decode. Content detection still maps
// the `MSWIM` magic to `Wim`, so an ESD passed by name fails with the precise
// "LZMS is not supported" message instead of "unknown format".
pub const WIM_EXTENSIONS: &[&str] = &[".wim", ".swm"];
pub const VDI_EXTENSIONS: &[&str] = &[".vdi"];
pub const NRG_EXTENSIONS: &[&str] = &[".nrg"];
pub const MDF_EXTENSIONS: &[&str] = &[".mdf", ".mds"];
pub const CDI_EXTENSIONS: &[&str] = &[".cdi"];
pub const ISZ_EXTENSIONS: &[&str] = &[".isz"];
// `.img` is intentionally absent here: it is a generic raw-image extension used
// by SD-card, floppy, and disk dumps, and claiming it as CloneCD mislabels every
// one of them. A CloneCD set is entered through its `.ccd` control file, which
// resolves the sibling `.img` itself. `.img` is claimed by `RAW_DISK_EXTENSIONS`
// instead, which is what those dumps actually are.
pub const CCD_EXTENSIONS: &[&str] = &[".ccd"];
pub const CUE_EXTENSIONS: &[&str] = &[".cue"];
pub const VHDX_EXTENSIONS: &[&str] = &[".vhdx"];
pub const QCOW2_EXTENSIONS: &[&str] = &[".qcow2", ".qcow"];
// Only the physical EnCase images the EWF reader opens. `.s01` (SMART), `.l01`
// and `.lx01` (EnCase *logical* evidence) are deliberately absent: the reader
// resolves an EWF segment set by the `.e01`/`.ex01` extension alone, so claiming
// the others advertises a backend that cannot open them. They are also logical
// containers, so they would need the logical-container route, not the disk route.
pub const EWF_EXTENSIONS: &[&str] = &[".e01", ".ex01"];
pub const AD1_EXTENSIONS: &[&str] = &[".ad1"];
// Every DAR slice (`basename.N.dar`) ends in `.dar`, so the one suffix covers the set.
pub const DAR_EXTENSIONS: &[&str] = &[".dar"];
pub const AFF4_EXTENSIONS: &[&str] = &[".aff4"];
pub const RAW_DISK_EXTENSIONS: &[&str] = &[".raw", ".dd", ".dsk", ".img"];

/// Compile-time availability of a format's backend on this target.
///
/// Recognition of a format is platform-independent; execution is not. The
/// capability table answers "can this build actually handle this format?",
/// and consumers (CLI listings, dispatch, FFI capability queries) use it
/// instead of carrying their own platform predicates.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BackendStatus {
    /// The backend is compiled in and available.
    Available,
    /// The backend cannot run on this platform (for example Apple Archive off-Apple).
    UnsupportedPlatform,
    /// The backend exists but is currently unavailable at runtime.
    Unavailable { reason: &'static str },
}

/// Archive format kind detected from a path.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ArchiveFormatKind {
    /// Single-file ZIP family (zip/zipx/jar/…).
    Zip,
    /// Split ZIP volume set (`.z01`, `.z02`, …, `.zip`).
    SplitZip,
    /// 7z, including numbered `.7z.001` volumes.
    SevenZ,
    /// `.tar.zst` / `.tzst`.
    TarZst,
    /// `.tgz` / `.tar.gz` — handled by the native Rust TAR.GZ backend.
    TarGz,
    /// Uncompressed `.tar`.
    Tar,
    /// `.tar.bz2` / `.tbz2` / `.tbz`.
    TarBz2,
    /// `.tar.xz` / `.txz`.
    TarXz,
    /// `.tar.lzma` / `.tlzma`.
    TarLzma,
    /// `.tar.lz` / Lzip-compressed TAR.
    TarLz,
    /// `.tar.lzo` / LZO-compressed TAR.
    TarLzo,
    /// `.tar.Z` / compress-compressed TAR.
    TarCompress,
    /// `.tar.lz4` / LZ4-compressed TAR.
    TarLz4,
    /// `.tar.uu` / `.tar.b64` / uuencode- or base64-encoded TAR.
    TarUu,
    /// ISO disk image (`.iso`).
    Iso,
    /// Windows Cabinet (`.cab`).
    Cab,
    /// CPIO archive (`.cpio`).
    Cpio,
    /// RPM package (`.rpm`).
    Rpm,
    /// XAR archive (`.xar`).
    Xar,
    /// Apple Installer Package (`.pkg`).
    Pkg,
    /// Apple Disk Image (`.dmg`).
    Dmg,
    /// LHA/LZH archive.
    Lha,
    /// AR archive (`.a`, `.ar`, `.lib`).
    Ar,
    /// WARC archive (`.warc`).
    Warc,
    /// Mtree hierarchy (`.mtree`).
    Mtree,
    /// TZAP, including numbered volumes.
    Tzap,
    /// RAR (`.rar`, `.cbr`).
    Rar,
    /// Apple Archive (`.aar`, `.aea`).
    AppleArchive,
    /// `.deb` package.
    Deb,
    /// Windows Installer package (`.msi`).
    Msi,
    /// Microsoft Virtual PC / Hyper-V disk image (`.vhd`).
    Vhd,
    /// VMware virtual disk (`.vmdk`).
    #[allow(clippy::doc_markdown)]
    Vmdk,
    /// Universal Disk Format optical image (`.udf`).
    Udf,
    /// `SquashFS` compressed filesystem (`.squashfs`, `.sqfs`).
    Squashfs,
    /// Linux `AppImage` executable package (`.appimage`).
    AppImage,
    /// Microsoft Windows Imaging package (`.wim`, `.swm`, `.esd`).
    Wim,
    /// Oracle `VirtualBox` disk image (`.vdi`).
    Vdi,
    /// Nero Burning ROM image (`.nrg`).
    Nrg,
    /// Alcohol 120% image (`.mdf`, `.mds`).
    Mdf,
    /// `DiscJuggler` image (`.cdi`).
    Cdi,
    /// Compressed ISO image (`.isz`).
    Isz,
    /// `CloneCD` image (`.ccd`, `.img`).
    Ccd,
    /// `CUE/BIN` optical disc sheet (`.cue`).
    Cue,
    /// Microsoft Hyper-V Virtual Hard Disk v2 (`.vhdx`).
    Vhdx,
    /// QEMU Copy-On-Write disk image (`.qcow2`, `.qcow`).
    Qcow2,
    /// Expert Witness Format / `EnCase` physical forensic image (`.e01`, `.ex01`).
    Ewf,
    /// `AccessData` / FTK Imager Logical Image (`.ad1`).
    Ad1,
    /// Disk `ARchiver` backup package (`.dar`).
    Dar,
    /// Advanced Forensic Format 4 container (`.aff4`).
    Aff4,
    /// Raw sector disk or partition dump (`.raw`, `.dd`, `.dsk`, `.img`).
    RawDisk,
    /// Raw single-file compression stream.
    RawStream,
    /// Not recognized as any archive format.
    Unknown,
}

/// One row of the compile-time format capability table.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FormatCapability {
    /// The detected format kind.
    pub kind: ArchiveFormatKind,
    /// Extension suffixes this format is recognized by. Formats detected by
    /// predicate functions (raw stream, split ZIP, 7z volumes, TZAP) carry
    /// the empty slice here; those predicates stay in [`detect_archive_format`].
    pub extensions: &'static [&'static str],
    /// Backend availability on this target.
    pub status: BackendStatus,
}

/// The capability table, ordered by detection priority so that
/// [`detect_archive_format`] can iterate it directly. Adding a format means
/// adding one row here (and a variant above); platform-gated backends express
/// availability through [`apple_archive_status`]-style rows.
pub const FORMAT_CAPABILITIES: &[FormatCapability] = &[
    FormatCapability { kind: ArchiveFormatKind::RawStream, extensions: crate::raw_stream_backend::RAW_STREAM_SUFFIXES, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Zip, extensions: ZIP_FAMILY_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::SplitZip, extensions: &[], status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::SevenZ, extensions: SEVEN_Z_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Rar, extensions: RAR_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::TarZst, extensions: TAR_ZST_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::TarGz, extensions: TGZ_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Tar, extensions: TAR_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::TarBz2, extensions: TAR_BZ2_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::TarXz, extensions: TAR_XZ_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::TarLzma, extensions: TAR_LZMA_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::TarLz, extensions: TAR_LZ_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::TarLzo, extensions: TAR_LZO_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::TarCompress, extensions: TAR_COMPRESS_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::TarLz4, extensions: TAR_LZ4_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::TarUu, extensions: TAR_UU_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Iso, extensions: ISO_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Cab, extensions: CAB_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Cpio, extensions: CPIO_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Rpm, extensions: RPM_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Xar, extensions: XAR_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Pkg, extensions: PKG_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Dmg, extensions: DMG_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Lha, extensions: LHA_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Ar, extensions: AR_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Warc, extensions: WARC_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Mtree, extensions: MTREE_EXTENSIONS, status: mtree_status() },
    FormatCapability { kind: ArchiveFormatKind::Tzap, extensions: &[], status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::AppleArchive, extensions: APPLE_ARCHIVE_EXTENSIONS, status: apple_archive_status() },
    FormatCapability { kind: ArchiveFormatKind::Deb, extensions: DEB_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Msi, extensions: MSI_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Vhd, extensions: VHD_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Vmdk, extensions: VMDK_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Udf, extensions: UDF_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Squashfs, extensions: SQUASHFS_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::AppImage, extensions: APPIMAGE_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Wim, extensions: WIM_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Vdi, extensions: VDI_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Nrg, extensions: NRG_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Mdf, extensions: MDF_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Cdi, extensions: CDI_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Isz, extensions: ISZ_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Ccd, extensions: CCD_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Cue, extensions: CUE_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Vhdx, extensions: VHDX_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Qcow2, extensions: QCOW2_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Ewf, extensions: EWF_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Ad1, extensions: AD1_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Dar, extensions: DAR_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::Aff4, extensions: AFF4_EXTENSIONS, status: BackendStatus::Available },
    FormatCapability { kind: ArchiveFormatKind::RawDisk, extensions: RAW_DISK_EXTENSIONS, status: BackendStatus::Available },
];

/// Availability of the native Apple Archive backend on this target.
const fn apple_archive_status() -> BackendStatus {
    if cfg!(any(target_os = "macos", target_os = "ios")) { BackendStatus::Available } else { BackendStatus::UnsupportedPlatform }
}

/// Availability of the native MTREE backend on this target.
///
/// The reader is pure Rust and platform-independent: MTREE is a text manifest,
/// and nothing in the parser needs a Unix-only API. Extraction of a `type=link`
/// record still fails on platforms without symlink support, which the shared
/// `extract_materialize::write_symlink` stub reports.
const fn mtree_status() -> BackendStatus {
    BackendStatus::Available
}

/// Returns whether the backend for `kind` is available on this platform.
///
/// Formats without a table row are not registered engine formats. Unknown
/// input is intentionally handled as an invalid format at engine open.
#[must_use]
pub fn format_status(kind: ArchiveFormatKind) -> BackendStatus {
    FORMAT_CAPABILITIES
        .iter()
        .find(|capability| capability.kind == kind)
        .map_or(BackendStatus::Unavailable { reason: "format is not registered" }, |capability| capability.status)
}

/// Detects the archive format from a path.
///
/// Raw-stream detection runs first because it deliberately excludes container
/// spellings such as `.tar.gz`; the remaining extension sets are disjoint.
/// The ordered extension checks come from [`FORMAT_CAPABILITIES`].
#[must_use]
pub fn detect_archive_format(path: impl AsRef<Path>) -> ArchiveFormatKind {
    let path = path.as_ref();
    if crate::engine::source::is_split_zip_archive_path(path) {
        return ArchiveFormatKind::SplitZip;
    }
    if crate::raw_stream_backend::detect_raw_stream_format(path).is_some() {
        return ArchiveFormatKind::RawStream;
    }
    if ends_with_any(path, ZIP_FAMILY_EXTENSIONS) {
        return if crate::engine::source::is_split_zip_archive_path(path) { ArchiveFormatKind::SplitZip } else { ArchiveFormatKind::Zip };
    }
    if ends_with_any(path, SEVEN_Z_EXTENSIONS) || crate::sevenz_backend::is_7z_volume_path(path) {
        return ArchiveFormatKind::SevenZ;
    }
    for capability in FORMAT_CAPABILITIES {
        match capability.kind {
            ArchiveFormatKind::RawStream | ArchiveFormatKind::SplitZip | ArchiveFormatKind::SevenZ | ArchiveFormatKind::Unknown => continue,
            ArchiveFormatKind::Tzap if crate::tzap::is_tzap_archive_path(path) => return ArchiveFormatKind::Tzap,
            _ => {}
        }
        if ends_with_any(path, capability.extensions) {
            return capability.kind;
        }
    }
    detect_content_format(path).unwrap_or(ArchiveFormatKind::Unknown)
}

/// Detects the two compatibility inputs that intentionally have no useful
/// filename extension: ZIP self-extracting executables and gzip-wrapped CPIO.
/// This keeps `UNKNOWN` out of the engine registry while preserving the
/// compatibility fixtures covered by the explicit content-detection allow-list.
fn detect_content_format(path: &Path) -> Option<ArchiveFormatKind> {
    let mut file = File::open(path).ok()?;
    let mut prefix = Vec::new();
    file.by_ref().take(1024 * 1024).read_to_end(&mut prefix).ok()?;
    let mut search_slice = &prefix[..];
    while let Some(pos) = memchr::memchr(b'P', search_slice) {
        if search_slice.len() < pos + 4 {
            break;
        }
        let magic = &search_slice[pos..pos + 4];
        if magic == b"PK\x03\x04" || magic == b"PK\x05\x06" || magic == b"PK\x07\x08" {
            return Some(ArchiveFormatKind::Zip);
        }
        search_slice = &search_slice[pos + 1..];
    }
    if prefix.len() >= 265 && (&prefix[257..263] == b"ustar\0" || &prefix[257..263] == b"ustar ") {
        return Some(ArchiveFormatKind::Tar);
    }
    if prefix.starts_with(&[0x1f, 0x8b]) {
        let file = File::open(path).ok()?;
        let mut decoder = flate2::read::GzDecoder::new(file).take(6);
        let mut cpio_magic = [0_u8; 6];
        decoder.read_exact(&mut cpio_magic).ok()?;
        if matches!(&cpio_magic, b"070701" | b"070702" | b"070707") {
            return Some(ArchiveFormatKind::Cpio);
        }
    }
    if prefix.starts_with(b"MSWIM\0\0\0") {
        return Some(ArchiveFormatKind::Wim);
    }
    if prefix.starts_with(b"hsqs") {
        return Some(ArchiveFormatKind::Squashfs);
    }
    if prefix.starts_with(b"\x7fELF") && prefix.len() >= 11 && prefix[8..11] == [0x41, 0x49, 0x02] {
        return Some(ArchiveFormatKind::AppImage);
    }
    // VirtualBox's VDI_IMAGE_SIGNATURE (0xbeda107f) stored little-endian at
    // offset 64.
    if prefix.len() >= 68 && prefix[64..68] == [0x7f, 0x10, 0xda, 0xbe] {
        return Some(ArchiveFormatKind::Vdi);
    }
    if prefix.starts_with(b"IsZ!") {
        return Some(ArchiveFormatKind::Isz);
    }
    // VHDX carries exactly one file identifier, `vhdxfile`, at offset 0.
    if prefix.starts_with(b"vhdxfile") {
        return Some(ArchiveFormatKind::Vhdx);
    }
    if prefix.starts_with(&[0x51, 0x46, 0x49, 0xfb]) {
        return Some(ArchiveFormatKind::Qcow2);
    }
    // EWF v1 (`EVF`) and v2 (`EVF2`) *physical* images. The logical siblings
    // (`LVF`, `LEF2`) are not detected: the EWF reader cannot open them, so
    // claiming the magic would route an unopenable file into the disk backend.
    if prefix.starts_with(b"EVF\x09\x0d\x0a\xff\x00") || prefix.starts_with(b"EVF2\x0d\x0a\x81\x00") {
        return Some(ArchiveFormatKind::Ewf);
    }
    if prefix.starts_with(b"ADSEGMENTEDFILE\0") {
        return Some(ArchiveFormatKind::Ad1);
    }
    None
}

fn ends_with_any(path: &Path, suffixes: &[&str]) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else { return false };
    suffixes.iter().any(|suffix| crate::strings::ends_with_ignore_ascii_case(name, suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;
    use std::fs;

    fn detect(name: &str) -> ArchiveFormatKind {
        detect_archive_format(Path::new(name))
    }

    #[test]
    fn capability_table_covers_every_format_kind() {
        let table_kinds: Vec<ArchiveFormatKind> = FORMAT_CAPABILITIES.iter().map(|capability| capability.kind).collect();
        for kind in [
            ArchiveFormatKind::Zip,
            ArchiveFormatKind::SplitZip,
            ArchiveFormatKind::SevenZ,
            ArchiveFormatKind::TarZst,
            ArchiveFormatKind::TarGz,
            ArchiveFormatKind::Tar,
            ArchiveFormatKind::TarBz2,
            ArchiveFormatKind::TarXz,
            ArchiveFormatKind::TarLzma,
            ArchiveFormatKind::TarLz,
            ArchiveFormatKind::TarLzo,
            ArchiveFormatKind::TarCompress,
            ArchiveFormatKind::TarLz4,
            ArchiveFormatKind::TarUu,
            ArchiveFormatKind::Iso,
            ArchiveFormatKind::Cab,
            ArchiveFormatKind::Cpio,
            ArchiveFormatKind::Rpm,
            ArchiveFormatKind::Xar,
            ArchiveFormatKind::Pkg,
            ArchiveFormatKind::Dmg,
            ArchiveFormatKind::Lha,
            ArchiveFormatKind::Ar,
            ArchiveFormatKind::Warc,
            ArchiveFormatKind::Mtree,
            ArchiveFormatKind::Tzap,
            ArchiveFormatKind::Rar,
            ArchiveFormatKind::AppleArchive,
            ArchiveFormatKind::Deb,
            ArchiveFormatKind::Msi,
            ArchiveFormatKind::Vhd,
            ArchiveFormatKind::Vmdk,
            ArchiveFormatKind::Udf,
            ArchiveFormatKind::Squashfs,
            ArchiveFormatKind::AppImage,
            ArchiveFormatKind::Wim,
            ArchiveFormatKind::Vdi,
            ArchiveFormatKind::Nrg,
            ArchiveFormatKind::Mdf,
            ArchiveFormatKind::Cdi,
            ArchiveFormatKind::Isz,
            ArchiveFormatKind::Ccd,
            ArchiveFormatKind::Cue,
            ArchiveFormatKind::Vhdx,
            ArchiveFormatKind::Qcow2,
            ArchiveFormatKind::Ewf,
            ArchiveFormatKind::Ad1,
            ArchiveFormatKind::Dar,
            ArchiveFormatKind::Aff4,
            ArchiveFormatKind::RawDisk,
            ArchiveFormatKind::RawStream,
        ] {
            assert!(table_kinds.contains(&kind), "capability table is missing a row for {kind:?}");
        }
    }

    #[test]
    fn apple_archive_status_matches_platform() {
        let expected = if cfg!(any(target_os = "macos", target_os = "ios")) { BackendStatus::Available } else { BackendStatus::UnsupportedPlatform };
        assert_eq!(format_status(ArchiveFormatKind::AppleArchive), expected);
    }

    #[test]
    fn mtree_status_is_available_on_every_target() {
        assert_eq!(format_status(ArchiveFormatKind::Mtree), BackendStatus::Available);
    }

    #[test]
    fn common_formats_report_available() {
        assert_eq!(format_status(ArchiveFormatKind::Zip), BackendStatus::Available);
        assert_eq!(format_status(ArchiveFormatKind::TarZst), BackendStatus::Available);
        assert_eq!(format_status(ArchiveFormatKind::SevenZ), BackendStatus::Available);
        assert_eq!(format_status(ArchiveFormatKind::Deb), BackendStatus::Available);
        assert_eq!(format_status(ArchiveFormatKind::Vhdx), BackendStatus::Available);
        assert_eq!(format_status(ArchiveFormatKind::Qcow2), BackendStatus::Available);
        assert_eq!(format_status(ArchiveFormatKind::Ewf), BackendStatus::Available);
        assert_eq!(format_status(ArchiveFormatKind::Ad1), BackendStatus::Available);
        assert_eq!(format_status(ArchiveFormatKind::Dar), BackendStatus::Available);
        assert_eq!(format_status(ArchiveFormatKind::Aff4), BackendStatus::Available);
        assert_eq!(format_status(ArchiveFormatKind::RawDisk), BackendStatus::Available);
    }

    #[test]
    fn detection_order_is_preserved() {
        // Raw-stream family (non-container spellings) is detected first.
        assert_eq!(detect("stream.zst"), ArchiveFormatKind::RawStream);
        // Container spellings still win over raw-stream detection.
        assert_eq!(detect("archive.tar.zst"), ArchiveFormatKind::TarZst);
        assert_eq!(detect("archive.tgz"), ArchiveFormatKind::TarGz);
        assert_eq!(detect("archive.tar.gz"), ArchiveFormatKind::TarGz);
        assert_eq!(detect("archive.tar"), ArchiveFormatKind::Tar);
        assert_eq!(detect("archive.tar.bz2"), ArchiveFormatKind::TarBz2);
        assert_eq!(detect("archive.tar.xz"), ArchiveFormatKind::TarXz);
        assert_eq!(detect("archive.tar.lzma"), ArchiveFormatKind::TarLzma);
        assert_eq!(detect("archive.tar.lz"), ArchiveFormatKind::TarLz);
        assert_eq!(detect("archive.tar.lzo"), ArchiveFormatKind::TarLzo);
        assert_eq!(detect("archive.tar.Z"), ArchiveFormatKind::TarCompress);
        assert_eq!(detect("archive.tar.lz4"), ArchiveFormatKind::TarLz4);
        assert_eq!(detect("archive.tar.lrz"), ArchiveFormatKind::Unknown);
        assert_eq!(detect("archive.pax"), ArchiveFormatKind::Tar);
        assert_eq!(detect("archive.ustar"), ArchiveFormatKind::Tar);
        assert_eq!(detect("archive.zip"), ArchiveFormatKind::Zip);
        assert_eq!(detect("archive.7z"), ArchiveFormatKind::SevenZ);
        assert_eq!(detect("archive.7z.001"), ArchiveFormatKind::SevenZ);
        assert_eq!(detect("archive.rar"), ArchiveFormatKind::Rar);
        assert_eq!(detect("archive.iso"), ArchiveFormatKind::Iso);
        assert_eq!(detect("archive.cab"), ArchiveFormatKind::Cab);
        assert_eq!(detect("archive.cpio"), ArchiveFormatKind::Cpio);
        assert_eq!(detect("archive.rpm"), ArchiveFormatKind::Rpm);
        assert_eq!(detect("archive.xar"), ArchiveFormatKind::Xar);
        assert_eq!(detect("archive.pkg"), ArchiveFormatKind::Pkg);
        assert_eq!(detect("archive.dmg"), ArchiveFormatKind::Dmg);
        assert_eq!(detect("archive.lha"), ArchiveFormatKind::Lha);
        assert_eq!(detect("archive.ar"), ArchiveFormatKind::Ar);
        assert_eq!(detect("archive.warc"), ArchiveFormatKind::Warc);
        assert_eq!(detect("archive.mtree"), ArchiveFormatKind::Mtree);
        assert_eq!(detect("archive.tzap"), ArchiveFormatKind::Tzap);
        assert_eq!(detect("archive.aar"), ArchiveFormatKind::AppleArchive);
        assert_eq!(detect("archive.AEA"), ArchiveFormatKind::AppleArchive);
        assert_eq!(detect("archive.deb"), ArchiveFormatKind::Deb);
        assert_eq!(detect("archive.msi"), ArchiveFormatKind::Msi);
        assert_eq!(detect("archive.MSI"), ArchiveFormatKind::Msi);
        assert_eq!(detect("archive.vhd"), ArchiveFormatKind::Vhd);
        assert_eq!(detect("archive.VMDK"), ArchiveFormatKind::Vmdk);
        assert_eq!(detect("archive.udf"), ArchiveFormatKind::Udf);
        assert_eq!(detect("archive.vhdx"), ArchiveFormatKind::Vhdx);
        assert_eq!(detect("archive.qcow2"), ArchiveFormatKind::Qcow2);
        assert_eq!(detect("archive.qcow"), ArchiveFormatKind::Qcow2);
        assert_eq!(detect("archive.e01"), ArchiveFormatKind::Ewf);
        assert_eq!(detect("archive.ex01"), ArchiveFormatKind::Ewf);
        assert_eq!(detect("archive.ad1"), ArchiveFormatKind::Ad1);
        assert_eq!(detect("archive.dar"), ArchiveFormatKind::Dar);
        // Every DAR slice ends in `.dar`, so the multi-slice names resolve too.
        assert_eq!(detect("archive.1.dar"), ArchiveFormatKind::Dar);
        assert_eq!(detect("archive.17.dar"), ArchiveFormatKind::Dar);
        assert_eq!(detect("archive.aff4"), ArchiveFormatKind::Aff4);
        assert_eq!(detect("archive.raw"), ArchiveFormatKind::RawDisk);
        assert_eq!(detect("archive.dd"), ArchiveFormatKind::RawDisk);
        assert_eq!(detect("archive.dsk"), ArchiveFormatKind::RawDisk);
        assert_eq!(detect("archive.img"), ArchiveFormatKind::RawDisk);
        assert_eq!(detect("archive.unknown"), ArchiveFormatKind::Unknown);
    }

    #[test]
    fn split_zip_volume_set_detects_split_zip() {
        let dir = TestDir::new("detect-split-zip");
        fs::write(dir.path("multi.z01"), b"sidecar").unwrap();
        fs::write(dir.path("multi.zip"), b"final").unwrap();
        assert_eq!(detect_archive_format(dir.path("multi.zip")), ArchiveFormatKind::SplitZip);
        assert_eq!(detect_archive_format(dir.path("multi.z01")), ArchiveFormatKind::SplitZip);
    }

    #[test]
    fn content_detection_recognizes_zip_self_extracting_input() {
        let dir = TestDir::new("detect-zip-sfx");
        let mut input = vec![0_u8; 37];
        input.extend_from_slice(b"PK\x03\x04synthetic zip payload");
        fs::write(dir.path("installer.bin"), input).unwrap();
        assert_eq!(detect_archive_format(dir.path("installer.bin")), ArchiveFormatKind::Zip);
    }

    #[test]
    fn content_detection_recognizes_extensionless_tar_input() {
        let dir = TestDir::new("detect-tar-content");
        let mut input = vec![0_u8; 265];
        input[257..263].copy_from_slice(b"ustar\0");
        fs::write(dir.path("payload.data"), input).unwrap();
        assert_eq!(detect_archive_format(dir.path("payload.data")), ArchiveFormatKind::Tar);
    }

    #[test]
    fn new_disk_and_filesystem_formats_detect_by_extension() {
        assert_eq!(detect("image.squashfs"), ArchiveFormatKind::Squashfs);
        assert_eq!(detect("image.sqfs"), ArchiveFormatKind::Squashfs);
        assert_eq!(detect("Tool-x86_64.AppImage"), ArchiveFormatKind::AppImage);
        assert_eq!(detect("install.wim"), ArchiveFormatKind::Wim);
        assert_eq!(detect("install.swm"), ArchiveFormatKind::Wim);
        assert_eq!(detect("disk.vdi"), ArchiveFormatKind::Vdi);
        assert_eq!(detect("disc.nrg"), ArchiveFormatKind::Nrg);
        assert_eq!(detect("disc.mdf"), ArchiveFormatKind::Mdf);
        assert_eq!(detect("disc.mds"), ArchiveFormatKind::Mdf);
        assert_eq!(detect("disc.cdi"), ArchiveFormatKind::Cdi);
        assert_eq!(detect("disc.isz"), ArchiveFormatKind::Isz);
        assert_eq!(detect("disc.ccd"), ArchiveFormatKind::Ccd);
        assert_eq!(detect("disc.cue"), ArchiveFormatKind::Cue);
        assert_eq!(detect("disk.vhdx"), ArchiveFormatKind::Vhdx);
        assert_eq!(detect("disk.qcow2"), ArchiveFormatKind::Qcow2);
        assert_eq!(detect("disk.qcow"), ArchiveFormatKind::Qcow2);
        assert_eq!(detect("evidence.e01"), ArchiveFormatKind::Ewf);
        assert_eq!(detect("evidence.ex01"), ArchiveFormatKind::Ewf);
        assert_eq!(detect("evidence.ad1"), ArchiveFormatKind::Ad1);
        assert_eq!(detect("backup.dar"), ArchiveFormatKind::Dar);
        assert_eq!(detect("backup.1.dar"), ArchiveFormatKind::Dar);
        assert_eq!(detect("container.aff4"), ArchiveFormatKind::Aff4);
        assert_eq!(detect("disk.raw"), ArchiveFormatKind::RawDisk);
        assert_eq!(detect("disk.dd"), ArchiveFormatKind::RawDisk);
        assert_eq!(detect("disk.dsk"), ArchiveFormatKind::RawDisk);
        assert_eq!(detect("disk.img"), ArchiveFormatKind::RawDisk);
    }

    #[test]
    fn no_two_formats_claim_the_same_extension() {
        // `detect_archive_format` returns the first capability row whose suffix
        // matches, so an exact duplicate would silently hand one format's files
        // to whichever row is registered first.
        let mut seen: Vec<(String, ArchiveFormatKind)> = Vec::new();
        for capability in FORMAT_CAPABILITIES {
            for extension in capability.extensions {
                let lowered = extension.to_ascii_lowercase();
                assert!(
                    !seen.iter().any(|(seen_extension, _)| *seen_extension == lowered),
                    "{extension} is claimed by both {:?} and {:?}",
                    capability.kind,
                    seen.iter().find(|(seen_extension, _)| *seen_extension == lowered).map(|(_, kind)| *kind),
                );
                seen.push((lowered, capability.kind));
            }
        }
        assert!(seen.len() > 100, "expected the capability table to cover a large extension set, saw {}", seen.len());
    }

    #[test]
    fn nested_extensions_are_registered_before_the_suffix_they_contain() {
        // Compound suffixes legitimately nest (`.tar.zst` inside `.zst`,
        // `.cpio.gz` inside `.gz`). `detect_archive_format` takes the first
        // match, so the *more specific* row must come first or the compound
        // format is unreachable. RawStream is exempt: it is resolved by
        // `detect_raw_stream_format` ahead of the table walk.
        let rows: Vec<(&str, ArchiveFormatKind, usize)> = FORMAT_CAPABILITIES
            .iter()
            .enumerate()
            .filter(|(_, capability)| capability.kind != ArchiveFormatKind::RawStream)
            .flat_map(|(index, capability)| capability.extensions.iter().map(move |extension| (*extension, capability.kind, index)))
            .collect();
        for (specific, specific_kind, specific_index) in &rows {
            for (general, general_kind, general_index) in &rows {
                if specific_kind == general_kind || specific == general || !specific.ends_with(general) {
                    continue;
                }
                assert!(
                    specific_index < general_index,
                    "{specific} ({specific_kind:?}) is shadowed by {general} ({general_kind:?}): register the specific suffix first"
                );
            }
        }
    }

    #[test]
    fn generic_and_unimplemented_extensions_are_not_claimed() {
        // `.img` is used by SD-card, floppy, and raw disk dumps: it resolves to
        // `RawDisk`, never to CloneCD. A CloneCD set is entered through its
        // `.ccd` control file, which resolves the sibling `.img` itself.
        assert_eq!(detect("raspios.img"), ArchiveFormatKind::RawDisk);

        // EnCase *logical* evidence (`.l01`/`.lx01`) and SMART (`.s01`) are not
        // claimed: the EWF reader resolves a segment set by the `.e01`/`.ex01`
        // extension alone and cannot open these, so advertising them would
        // promise a backend that always fails. See `EWF_EXTENSIONS`.
        for unsupported in ["evidence.s01", "evidence.l01", "evidence.lx01"] {
            assert_eq!(detect(unsupported), ArchiveFormatKind::Unknown, "{unsupported}");
        }
        for absent in [".s01", ".l01", ".lx01"] {
            assert!(!EWF_EXTENSIONS.contains(&absent), "{absent} must not be advertised as EWF");
        }

        // `.esd` images are LZMS-compressed solid WIMs, which the WIM backend
        // does not decode, so the extension is not advertised.
        assert!(!WIM_EXTENSIONS.contains(&".esd"));
        assert!(!CCD_EXTENSIONS.contains(&".img"));
        assert!(RAW_DISK_EXTENSIONS.contains(&".img"));
    }

    #[test]
    fn content_detection_recognizes_the_new_image_magics() {
        let dir = TestDir::new("detect-image-content");

        let mut squashfs = vec![0_u8; 128];
        squashfs[0..4].copy_from_slice(b"hsqs");
        fs::write(dir.path("payload.bin"), &squashfs).unwrap();
        assert_eq!(detect_archive_format(dir.path("payload.bin")), ArchiveFormatKind::Squashfs);

        let mut wim = vec![0_u8; 256];
        wim[0..8].copy_from_slice(b"MSWIM\0\0\0");
        fs::write(dir.path("image.data"), &wim).unwrap();
        assert_eq!(detect_archive_format(dir.path("image.data")), ArchiveFormatKind::Wim);

        // An `.esd` reaches the WIM backend through content detection even
        // though the extension is not advertised, so the failure names LZMS
        // rather than "unknown format".
        fs::write(dir.path("install.esd"), &wim).unwrap();
        assert_eq!(detect_archive_format(dir.path("install.esd")), ArchiveFormatKind::Wim);

        // VirtualBox's signature is 0xbeda107f, little-endian at offset 64.
        let mut vdi = vec![0_u8; 512];
        vdi[64..68].copy_from_slice(&0xbeda_107f_u32.to_le_bytes());
        fs::write(dir.path("disk.data"), &vdi).unwrap();
        assert_eq!(detect_archive_format(dir.path("disk.data")), ArchiveFormatKind::Vdi);

        let mut appimage = vec![0_u8; 128];
        appimage[0..4].copy_from_slice(b"\x7fELF");
        appimage[8..11].copy_from_slice(&[0x41, 0x49, 0x02]);
        fs::write(dir.path("tool.run"), &appimage).unwrap();
        assert_eq!(detect_archive_format(dir.path("tool.run")), ArchiveFormatKind::AppImage);

        let mut isz = vec![0_u8; 64];
        isz[0..4].copy_from_slice(b"IsZ!");
        fs::write(dir.path("compressed.data"), &isz).unwrap();
        assert_eq!(detect_archive_format(dir.path("compressed.data")), ArchiveFormatKind::Isz);

        let mut vhdx = vec![0_u8; 64];
        vhdx[0..8].copy_from_slice(b"vhdxfile");
        fs::write(dir.path("hyperv.data"), &vhdx).unwrap();
        assert_eq!(detect_archive_format(dir.path("hyperv.data")), ArchiveFormatKind::Vhdx);

        let mut qcow2 = vec![0_u8; 64];
        qcow2[0..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xfb]);
        fs::write(dir.path("qemu.data"), &qcow2).unwrap();
        assert_eq!(detect_archive_format(dir.path("qemu.data")), ArchiveFormatKind::Qcow2);

        let mut ewf = vec![0_u8; 64];
        ewf[0..8].copy_from_slice(b"EVF\x09\x0d\x0a\xff\x00");
        fs::write(dir.path("encase.data"), &ewf).unwrap();
        assert_eq!(detect_archive_format(dir.path("encase.data")), ArchiveFormatKind::Ewf);

        let mut ewf2 = vec![0_u8; 64];
        ewf2[0..8].copy_from_slice(b"EVF2\x0d\x0a\x81\x00");
        fs::write(dir.path("encase2.data"), &ewf2).unwrap();
        assert_eq!(detect_archive_format(dir.path("encase2.data")), ArchiveFormatKind::Ewf);

        // The *logical* EWF signatures stay unclaimed: the reader cannot open
        // them, so detecting them would route an unopenable file at the disk
        // backend instead of reporting an honest "unknown format".
        for logical_magic in [&b"LVF\x09\x0d\x0a\xff\x00"[..], &b"LEF2\x0d\x0a\x81\x00"[..]] {
            let mut logical = vec![0_u8; 64];
            logical[0..8].copy_from_slice(logical_magic);
            fs::write(dir.path("logical.data"), &logical).unwrap();
            assert_eq!(detect_archive_format(dir.path("logical.data")), ArchiveFormatKind::Unknown, "{logical_magic:?}");
        }

        let mut ad1 = vec![0_u8; 64];
        ad1[0..16].copy_from_slice(b"ADSEGMENTEDFILE\0");
        fs::write(dir.path("ftk.data"), &ad1).unwrap();
        assert_eq!(detect_archive_format(dir.path("ftk.data")), ArchiveFormatKind::Ad1);
    }

    #[test]
    fn content_detection_recognizes_gzip_cpio_input() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write as _;

        let dir = TestDir::new("detect-cpio-content");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"070701").unwrap();
        fs::write(dir.path("package.data"), encoder.finish().unwrap()).unwrap();
        assert_eq!(detect_archive_format(dir.path("package.data")), ArchiveFormatKind::Cpio);
    }
}
