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
