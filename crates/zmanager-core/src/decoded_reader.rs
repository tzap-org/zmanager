//! Bounds temporary decoded intermediates before archive metadata is trusted.

use crate::jobs::{CancellationToken, JobCancelled};
use std::fmt;
use std::io::{self, Read};

#[derive(Debug)]
pub(crate) struct DecodedSizeLimitExceeded;

impl fmt::Display for DecodedSizeLimitExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("decoded archive exceeds the configured temporary-intermediate byte limit")
    }
}

impl std::error::Error for DecodedSizeLimitExceeded {}

pub(crate) fn is_size_limit(error: &io::Error) -> bool {
    error.get_ref().is_some_and(<dyn std::error::Error + Send + Sync>::is::<DecodedSizeLimitExceeded>)
}

pub(crate) struct BoundedDecoder<R> {
    inner: R,
    remaining: Option<u64>,
    cancellation: Option<CancellationToken>,
}

impl<R> BoundedDecoder<R> {
    pub(crate) fn new(inner: R, limit: Option<u64>, cancellation: Option<CancellationToken>) -> Self {
        Self { inner, remaining: limit, cancellation }
    }
}

impl<R: Read> Read for BoundedDecoder<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.cancellation.as_ref().is_some_and(CancellationToken::is_cancelled) {
            return Err(io::Error::other(JobCancelled));
        }
        let Some(remaining) = self.remaining else {
            return self.inner.read(buffer);
        };
        if remaining == 0 {
            // EOF at exactly the limit is valid. The probe never reaches the
            // output file, so even the first excess byte is not materialized.
            return match self.inner.read(&mut [0_u8; 1])? {
                0 => Ok(0),
                _ => Err(io::Error::other(DecodedSizeLimitExceeded)),
            };
        }
        let length = usize::try_from(remaining).unwrap_or(usize::MAX).min(buffer.len());
        let read = self.inner.read(&mut buffer[..length])?;
        self.remaining = Some(remaining - read as u64);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoded_limit_caps_output_and_accepts_exact_eof() {
        for input in [b"abc".as_slice(), b"abcd".as_slice()] {
            let mut reader = BoundedDecoder::new(input, Some(3), None);
            let mut output = Vec::new();
            let result = io::copy(&mut reader, &mut output);
            assert_eq!(output, b"abc");
            if input.len() == 3 {
                assert_eq!(result.unwrap(), 3);
            } else {
                assert!(is_size_limit(&result.unwrap_err()));
            }
        }
        let mut output = Vec::new();
        io::copy(&mut BoundedDecoder::new(b"abcd".as_slice(), None, None), &mut output).unwrap();
        assert_eq!(output, b"abcd");
    }

    #[test]
    fn cancellation_stops_a_decoder_between_reads() {
        let cancellation = CancellationToken::new();
        let mut reader = BoundedDecoder::new(b"abcd".as_slice(), Some(4), Some(cancellation.clone()));
        assert_eq!(reader.read(&mut [0_u8; 1]).unwrap(), 1);
        cancellation.cancel();
        let error = reader.read(&mut [0_u8; 1]).unwrap_err();
        assert!(crate::extract_loop::is_job_cancelled(&error));
    }
}
