//! Random bytes from the operating system.

/// Fills `out` from the operating system's cryptographic random source. Fails when
/// that source is unavailable; it never substitutes a deterministic generator.
pub fn fill_random(out: &mut [u8]) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(out)
    }
    #[cfg(windows)]
    {
        use rand_core::TryRngCore;
        rand_core::OsRng.try_fill_bytes(out).map_err(|e| std::io::Error::other(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
