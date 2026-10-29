//! Default wall clock for auth and certificate operations. Clients inject a
//! clock for deterministic protocol tests; network completion reads it again.

pub(crate) fn unix_seconds() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}
