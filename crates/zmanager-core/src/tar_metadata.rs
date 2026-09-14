use std::io;
use std::time::SystemTime;

use tzap_core::ArchiveTimestamp;

const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;

/// The tar backends use the same timespec `tzap-core` defines, so the host-time
/// conversion has one owner across both projects.
///
/// What stays here is only what tar genuinely does differently from TZAP: see
/// [`timestamp_to_pax_value`] and [`parse_pax_mtime`].
pub(crate) type TarTimestamp = ArchiveTimestamp;

/// Converts a modification time to Unix seconds, when it is at or after the
/// epoch. Shared by the tar-family backends.
#[must_use]
pub(crate) fn system_time_to_unix_seconds(time: std::time::SystemTime) -> Option<u64> {
    time.duration_since(std::time::UNIX_EPOCH).ok().map(|duration| duration.as_secs())
}

pub(crate) fn append_pax_mtime<W: io::Write>(builder: &mut tar::Builder<W>, modified: Option<SystemTime>) -> io::Result<()> {
    let Some(modified) = modified else {
        return Ok(());
    };
    let timestamp = system_time_to_timestamp(modified)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "modification time is outside the supported tar timestamp range"))?;
    if timestamp.seconds >= 0 && timestamp.nanoseconds == 0 {
        return Ok(());
    }

    let encoded = timestamp_to_pax_value(timestamp);
    builder.append_pax_extensions([("mtime", encoded.as_bytes())])
}

/// Parse a **tar** PAX `mtime`, which is laxer than `entry_metadata::parse_timestamp`.
///
/// Tar in the wild carries a leading `+`, trailing zeros in the fraction, and
/// more than nine fractional digits; the TZAP parser rejects all three as
/// non-canonical. The timespec the two produce is the same.
pub(crate) fn parse_pax_mtime(value: &[u8]) -> Option<TarTimestamp> {
    let value = std::str::from_utf8(value).ok()?;
    let (negative, unsigned) = value.strip_prefix('-').map_or((false, value), |value| (true, value));
    let unsigned = if negative { unsigned } else { unsigned.strip_prefix('+').unwrap_or(unsigned) };
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let whole = i64::try_from(whole.parse::<u64>().ok()?).ok()?;
    let mut nanoseconds = 0_u32;
    let mut digits = 0_u32;
    for byte in fraction.bytes().take(9) {
        nanoseconds = nanoseconds.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
        digits += 1;
    }
    nanoseconds = nanoseconds.checked_mul(10_u32.pow(9 - digits))?;

    if !negative {
        return Some(TarTimestamp::new(whole, nanoseconds));
    }
    if nanoseconds == 0 {
        return Some(TarTimestamp::new(whole.checked_neg()?, 0));
    }
    Some(TarTimestamp::new(whole.checked_neg()?.checked_sub(1)?, NANOSECONDS_PER_SECOND - nanoseconds))
}

fn system_time_to_timestamp(time: SystemTime) -> Option<TarTimestamp> {
    tzap_core::entry_metadata::archive_timestamp_from_system_time(time)
}

/// Encode for a **tar** PAX header, which is not the TZAP encoding.
///
/// `ArchiveTimestamp::canonical_pax_value` is deliberately not used here.
/// §16.7.2 trims trailing zeros and forbids an integer part of `-0`, so it
/// refuses the last second before the epoch outright; tar has no such rule, and
/// GNU tar and libarchive both read `-0.5`. Refusing it would lose a time that
/// a tar archive can legitimately carry.
fn timestamp_to_pax_value(timestamp: TarTimestamp) -> String {
    if timestamp.seconds >= 0 {
        return format!("{}.{:09}", timestamp.seconds, timestamp.nanoseconds);
    }
    if timestamp.nanoseconds == 0 {
        return timestamp.seconds.to_string();
    }

    let whole = timestamp.seconds.unsigned_abs() - 1;
    let fraction = NANOSECONDS_PER_SECOND - timestamp.nanoseconds;
    format!("-{whole}.{fraction:09}")
}

#[cfg(test)]
mod tests {
    use super::{TarTimestamp, parse_pax_mtime, timestamp_to_pax_value};

    #[test]
    fn pax_timestamp_parser_handles_positive_and_negative_fractions() {
        for timestamp in [TarTimestamp::new(1, 250_000_000), TarTimestamp::new(-2, 750_000_000), TarTimestamp::new(-1, 500_000_000)] {
            let encoded = timestamp_to_pax_value(timestamp);
            assert_eq!(parse_pax_mtime(encoded.as_bytes()), Some(timestamp));
        }
        assert_eq!(parse_pax_mtime(b"-+1.0"), None);
    }
    #[test]
    fn system_time_to_timestamp_handles_edge_cases() {
        use super::system_time_to_timestamp;
        use std::time::{Duration, UNIX_EPOCH};

        // Post-epoch
        assert_eq!(system_time_to_timestamp(UNIX_EPOCH + Duration::new(1, 250_000_000)), Some(TarTimestamp::new(1, 250_000_000)));

        // Pre-epoch
        assert_eq!(system_time_to_timestamp(UNIX_EPOCH - Duration::new(1, 250_000_000)), Some(TarTimestamp::new(-2, 750_000_000)));

        // Exactly epoch
        assert_eq!(system_time_to_timestamp(UNIX_EPOCH), Some(TarTimestamp::new(0, 0)));
    }
}

/// Produces exactly `declared` bytes from `inner`, whatever the file does.
///
/// A tar header states the member's length before its bytes are written, so the
/// promise is already made by the time the file is read. Anything else leaves
/// the next header at the wrong offset and truncates the archive at that member.
pub(crate) struct ExactLengthReader<R> {
    inner: R,
    remaining: u64,
    padded: u64,
}

impl<R: io::Read> ExactLengthReader<R> {
    pub(crate) fn new(inner: R, declared: u64) -> Self {
        Self { inner, remaining: declared, padded: 0 }
    }

    /// Bytes the file was short by, zero-filled to honour the header.
    pub(crate) fn padded(&self) -> u64 {
        self.padded
    }

    /// Whether the file still had data past the declared length.
    pub(crate) fn grew(&mut self) -> bool {
        let mut probe = [0u8; 1];
        matches!(self.inner.read(&mut probe), Ok(1))
    }
}

impl<R: io::Read> io::Read for ExactLengthReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || out.is_empty() {
            return Ok(0);
        }
        let cap = usize::try_from(self.remaining).unwrap_or(usize::MAX).min(out.len());
        let read = self.inner.read(&mut out[..cap])?;
        if read == 0 {
            // The file ended early. Zero-fill the rest rather than emit a short
            // member: GNU tar reports "File shrank by N bytes; padding with
            // zeros" and libarchive pads the same way.
            out[..cap].fill(0);
            self.remaining -= cap as u64;
            self.padded += cap as u64;
            return Ok(cap);
        }
        self.remaining -= read as u64;
        Ok(read)
    }
}

/// Plain-language note for a file whose length moved while it was being read.
///
/// This is ordinary on a live system -- a log being appended to, a database
/// checkpointing, a build still running -- so it is reported as something that
/// happened, not as an error the person has to act on. The archive is complete
/// and readable either way; only this member's contents are as of the moment
/// archiving started.
pub(crate) fn changed_during_read_note(archive_path: &str, declared: u64, padded: u64, grew: bool) -> Option<String> {
    if padded > 0 {
        let kept = declared.saturating_sub(padded);
        Some(format!(
            "{archive_path} was shortened while being archived; kept the {} that was still there and filled the remaining {} with zeros",
            tzap_core::entry_metadata::human_bytes(kept),
            tzap_core::entry_metadata::human_bytes(padded)
        ))
    } else if grew {
        Some(format!("{archive_path} was still being written while being archived; stored the first {}", tzap_core::entry_metadata::human_bytes(declared)))
    } else {
        None
    }
}

#[cfg(test)]
mod exact_length_tests {
    use super::{ExactLengthReader, changed_during_read_note};
    use std::io::{Cursor, Read as _};

    /// A member must be exactly as long as its header promised, whichever way
    /// the file moved. Anything else leaves the next header at the wrong offset
    /// and silently truncates the archive from that member onward -- which is
    /// what `tar::Builder::append_file` does, because it pads from the number of
    /// bytes it actually copied rather than from the declared size.
    #[test]
    fn a_member_is_always_exactly_its_declared_length() {
        // Shrank: 1000 promised, 400 left on disk.
        let mut short = ExactLengthReader::new(Cursor::new(vec![b'x'; 400]), 1000);
        let mut out = Vec::new();
        short.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 1000, "a shrinking file must still fill its declared length");
        assert_eq!(&out[..400], &[b'x'; 400], "the bytes that were there must be kept");
        assert!(out[400..].iter().all(|byte| *byte == 0), "the missing tail must be zeros");
        assert_eq!(short.padded(), 600);

        // Grew: 1000 promised, 4000 now on disk.
        let mut long = ExactLengthReader::new(Cursor::new(vec![b'y'; 4000]), 1000);
        let mut out = Vec::new();
        long.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 1000, "a growing file must not overrun its declared length");
        assert_eq!(long.padded(), 0);
        assert!(long.grew(), "the growth must be detectable so it can be reported");

        // Unchanged: no note, nothing padded.
        let mut exact = ExactLengthReader::new(Cursor::new(vec![b'z'; 1000]), 1000);
        let mut out = Vec::new();
        exact.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 1000);
        assert_eq!(exact.padded(), 0);
        assert!(!exact.grew());
    }

    /// The person reading this is backing something up, not debugging tar.
    #[test]
    fn the_note_explains_what_happened_without_jargon() {
        let shrank = changed_during_read_note("var/log/app.log", 4 * 1024 * 1024, 3 * 1024 * 1024, false).unwrap();
        assert!(shrank.contains("var/log/app.log"), "{shrank}");
        assert!(shrank.contains("1.0 MB") && shrank.contains("3.0 MB"), "kept and zero-filled amounts must both be stated: {shrank}");

        let grew = changed_during_read_note("var/log/app.log", 4 * 1024 * 1024, 0, true).unwrap();
        assert!(grew.contains("still being written") && grew.contains("4.0 MB"), "{grew}");

        assert!(changed_during_read_note("steady.bin", 10, 0, false).is_none(), "an unchanged file needs no note");
    }
}

#[cfg(all(test, unix))]
mod skip_unreadable_tests {
    use crate::manifest::{PlanOptions, plan_archive};
    use crate::test_support::TestDir;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    /// One unreadable file must not cost the whole archive, in any backend.
    ///
    /// GNU tar warns and exits 2, bsdtar warns and exits 1, 7-Zip warns and
    /// exits 1 -- all three still write an archive holding everything they could
    /// read. A combined tool is held to the same standard: refusing outright
    /// means a backup of a live tree produces nothing because one file had the
    /// wrong permissions.
    #[test]
    fn every_create_backend_skips_an_unreadable_file_and_still_writes_the_archive() {
        let temp = TestDir::new("skip-unreadable");
        let source = temp.path("tree");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("readable.txt"), b"kept\n").unwrap();
        fs::write(source.join("locked.txt"), b"secret\n").unwrap();
        fs::set_permissions(source.join("locked.txt"), fs::Permissions::from_mode(0o000)).unwrap();
        // Running as root defeats the fixture: nothing would be skipped.
        if fs::File::open(source.join("locked.txt")).is_ok() {
            return;
        }

        let manifest = plan_archive(&source, &PlanOptions::default()).expect("plan");

        let named = |warnings: &[String]| warnings.iter().any(|warning| warning.contains("locked.txt"));

        let zst =
            crate::tar_zst_backend::create_tar_zst_from_manifest(&manifest, temp.path("out.tar.zst"), &crate::tar_zst_backend::TarZstdCreateOptions::default())
                .expect("tar.zst must still produce an archive");
        assert!(named(&zst.warnings), "tar.zst must name the skipped file: {:?}", zst.warnings);
        assert!(zst.written_entries >= 1, "tar.zst must archive the readable member");

        let gz = crate::tar_gz_backend::create_tar_gz_from_manifest(&manifest, temp.path("out.tar.gz"), &crate::tar_gz_backend::TarGzCreateOptions::default())
            .expect("tar.gz must still produce an archive");
        assert!(named(&gz.warnings), "tar.gz must name the skipped file: {:?}", gz.warnings);

        let zip = crate::zip_backend::create_zip_from_manifest(&manifest, temp.path("out.zip"), &crate::zip_backend::ZipCreateOptions::default())
            .expect("zip must still produce an archive");
        assert!(named(&zip.warnings), "zip must name the skipped file: {:?}", zip.warnings);
        assert!(zip.written_entries >= 1, "zip must archive the readable member");
    }
}

#[cfg(all(test, unix))]
mod pax_extension_ordering_tests {
    use crate::manifest::{PlanOptions, plan_archive};
    use crate::test_support::TestDir;
    use filetime::FileTime;
    use std::fs;
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;

    const SKIPPED_MTIME: i64 = 1_700_000_000;
    const KEPT_MTIME: i64 = 1_767_229_200;

    fn octal(field: &[u8]) -> u64 {
        let text = String::from_utf8_lossy(field);
        u64::from_str_radix(text.trim_matches(['\0', ' ']), 8).unwrap_or(0)
    }

    fn pax_mtime_seconds(body: &str) -> Option<i64> {
        body.split('\n').find_map(|record| record.split_once("mtime=")).and_then(|(_, value)| value.split('.').next()?.parse::<i64>().ok())
    }

    /// Resolve each member's mtime the way POSIX requires a reader to: a PAX
    /// extension header applies to the member that *follows* it.
    ///
    /// The `tar` crate's `header().mtime()` reads the ustar field and ignores
    /// the override, so it cannot see this bug at all -- but GNU tar, bsdtar and
    /// 7-Zip all apply the record, which is what the archive actually means.
    fn effective_mtimes(bytes: &[u8]) -> Vec<(String, i64)> {
        let mut members = Vec::new();
        let mut pending: Option<i64> = None;
        let mut offset = 0usize;
        while offset + 512 <= bytes.len() {
            let header = &bytes[offset..offset + 512];
            if header.iter().all(|byte| *byte == 0) {
                break;
            }
            let size = usize::try_from(octal(&header[124..136])).unwrap_or(0);
            let body = &bytes[offset + 512..(offset + 512 + size).min(bytes.len())];
            if header[156] == b'x' {
                pending = pax_mtime_seconds(&String::from_utf8_lossy(body));
            } else {
                let name = String::from_utf8_lossy(&header[0..100]).trim_end_matches('\0').to_string();
                let stated = i64::try_from(octal(&header[136..148])).unwrap_or(0);
                members.push((name, pending.take().unwrap_or(stated)));
            }
            offset += 512 + size.div_ceil(512) * 512;
        }
        assert!(pending.is_none(), "a PAX record was left with no member of its own to describe");
        members
    }

    /// A skipped member must not retime the member that follows it.
    ///
    /// A PAX `mtime` record binds to the next member in the stream. Writing one
    /// before deciding whether the member can be produced meant an unreadable
    /// file handed its timestamp to whichever file came next -- silently, since
    /// the archive stays structurally valid and only the date is wrong.
    #[test]
    fn a_skipped_member_does_not_retime_the_next_one() {
        let temp = TestDir::new("pax-ordering");
        let source = temp.path("tree");
        fs::create_dir_all(&source).unwrap();
        let skipped = source.join("a_locked.txt");
        let kept = source.join("b_readable.txt");
        fs::write(&skipped, b"secret\n").unwrap();
        fs::write(&kept, b"kept\n").unwrap();

        // The skipped file carries a sub-second mtime, so it emits a PAX record;
        // the survivor's is a whole second, so it emits none of its own and
        // would silently inherit the record left dangling before it.
        filetime::set_file_mtime(&skipped, FileTime::from_unix_time(SKIPPED_MTIME, 123_456_789)).unwrap();
        filetime::set_file_mtime(&kept, FileTime::from_unix_time(KEPT_MTIME, 0)).unwrap();
        fs::set_permissions(&skipped, fs::Permissions::from_mode(0o000)).unwrap();
        // Running as root defeats the fixture: nothing would be skipped.
        if fs::File::open(&skipped).is_ok() {
            return;
        }

        let manifest = plan_archive(&source, &PlanOptions::default()).expect("plan");

        let zst_path = temp.path("out.tar.zst");
        let zst = crate::tar_zst_backend::create_tar_zst_from_manifest(&manifest, &zst_path, &crate::tar_zst_backend::TarZstdCreateOptions::default())
            .expect("tar.zst must still produce an archive");
        assert!(zst.warnings.iter().any(|warning| warning.contains("a_locked.txt")), "the skipped file must be named: {:?}", zst.warnings);
        let zst_bytes = zstd::decode_all(fs::File::open(&zst_path).unwrap()).unwrap();

        let gz_path = temp.path("out.tar.gz");
        let gz = crate::tar_gz_backend::create_tar_gz_from_manifest(&manifest, &gz_path, &crate::tar_gz_backend::TarGzCreateOptions::default())
            .expect("tar.gz must still produce an archive");
        assert!(gz.warnings.iter().any(|warning| warning.contains("a_locked.txt")), "the skipped file must be named: {:?}", gz.warnings);
        let mut gz_bytes = Vec::new();
        flate2::read::GzDecoder::new(fs::File::open(&gz_path).unwrap()).read_to_end(&mut gz_bytes).unwrap();

        for (format, bytes) in [("tar.zst", zst_bytes), ("tar.gz", gz_bytes)] {
            let members = effective_mtimes(&bytes);
            assert!(!members.iter().any(|(name, _)| name.contains("a_locked.txt")), "{format}: the unreadable file must not be in the archive: {members:?}");
            let (_, mtime) =
                members.iter().find(|(name, _)| name.contains("b_readable.txt")).unwrap_or_else(|| panic!("{format}: the readable file must be archived"));
            assert_ne!(*mtime, SKIPPED_MTIME, "{format}: the surviving file inherited the skipped file's timestamp");
            assert_eq!(*mtime, KEPT_MTIME, "{format}: the surviving file must keep its own timestamp");
        }
    }
}
