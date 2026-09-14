//! Shared CPU-count policy for the backends that compress in parallel.
//!
//! Lives on its own rather than inside a format module: the zstd, 7z and ZIP
//! backends all ask the same question, and none of them is the owner of it.

/// Returns the number of available CPU threads when there is more than one.
///
/// `None` means "do not ask for parallel work" -- either the host reports a
/// single CPU, or it will not say. Memoised because `available_parallelism`
/// queries the OS and every create call would otherwise repeat it.
#[must_use]
pub(crate) fn available_parallelism_at_least_two() -> Option<u32> {
    static PARALLELISM: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    *PARALLELISM.get_or_init(|| {
        let threads = std::thread::available_parallelism().ok()?.get();
        u32::try_from(threads).ok().filter(|threads| *threads > 1)
    })
}
