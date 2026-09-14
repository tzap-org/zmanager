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

/// Returns the number of available CPU threads when there is more than one,
/// used to enable parallel compression. Shared by the zstd and 7z backends.
#[must_use]
pub(crate) fn available_parallelism_at_least_two() -> Option<u32> {
    static PARALLELISM: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    *PARALLELISM.get_or_init(|| {
        let threads = std::thread::available_parallelism().ok()?.get();
        u32::try_from(threads).ok().filter(|threads| *threads > 1)
    })
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
