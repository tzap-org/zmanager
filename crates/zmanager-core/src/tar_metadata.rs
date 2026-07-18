use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TarTimestamp {
    pub(crate) seconds: i64,
    pub(crate) nanoseconds: u32,
}

pub(crate) fn append_pax_mtime<W: io::Write>(
    builder: &mut tar::Builder<W>,
    modified: Option<SystemTime>,
) -> io::Result<()> {
    let Some(modified) = modified else {
        return Ok(());
    };
    let timestamp = system_time_to_timestamp(modified).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "modification time is outside the supported tar timestamp range",
        )
    })?;
    if timestamp.seconds >= 0 && timestamp.nanoseconds == 0 {
        return Ok(());
    }

    let encoded = timestamp_to_pax_value(timestamp);
    builder.append_pax_extensions([("mtime", encoded.as_bytes())])
}

pub(crate) fn parse_pax_mtime(value: &[u8]) -> Option<TarTimestamp> {
    let value = std::str::from_utf8(value).ok()?;
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    let unsigned = if negative {
        unsigned
    } else {
        unsigned.strip_prefix('+').unwrap_or(unsigned)
    };
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let whole = i64::try_from(whole.parse::<u64>().ok()?).ok()?;
    let mut nanoseconds = 0_u32;
    let mut digits = 0_u32;
    for byte in fraction.bytes().take(9) {
        nanoseconds = nanoseconds
            .checked_mul(10)?
            .checked_add(u32::from(byte - b'0'))?;
        digits += 1;
    }
    nanoseconds = nanoseconds.checked_mul(10_u32.pow(9 - digits))?;

    if !negative {
        return Some(TarTimestamp {
            seconds: whole,
            nanoseconds,
        });
    }
    if nanoseconds == 0 {
        return Some(TarTimestamp {
            seconds: whole.checked_neg()?,
            nanoseconds: 0,
        });
    }
    Some(TarTimestamp {
        seconds: whole.checked_neg()?.checked_sub(1)?,
        nanoseconds: NANOSECONDS_PER_SECOND - nanoseconds,
    })
}

fn system_time_to_timestamp(time: SystemTime) -> Option<TarTimestamp> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Some(TarTimestamp {
            seconds: i64::try_from(duration.as_secs()).ok()?,
            nanoseconds: duration.subsec_nanos(),
        }),
        Err(error) => {
            let duration = error.duration();
            let seconds = i64::try_from(duration.as_secs()).ok()?;
            if duration.subsec_nanos() == 0 {
                Some(TarTimestamp {
                    seconds: seconds.checked_neg()?,
                    nanoseconds: 0,
                })
            } else {
                Some(TarTimestamp {
                    seconds: seconds.checked_neg()?.checked_sub(1)?,
                    nanoseconds: NANOSECONDS_PER_SECOND - duration.subsec_nanos(),
                })
            }
        }
    }
}

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
        for timestamp in [
            TarTimestamp {
                seconds: 1,
                nanoseconds: 250_000_000,
            },
            TarTimestamp {
                seconds: -2,
                nanoseconds: 750_000_000,
            },
            TarTimestamp {
                seconds: -1,
                nanoseconds: 500_000_000,
            },
        ] {
            let encoded = timestamp_to_pax_value(timestamp);
            assert_eq!(parse_pax_mtime(encoded.as_bytes()), Some(timestamp));
        }
        assert_eq!(parse_pax_mtime(b"-+1.0"), None);
    }
}
