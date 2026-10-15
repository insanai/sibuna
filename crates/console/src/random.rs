//! Random bytes from the operating system: session tokens, CSRF secrets, recovery codes,
//! nonces and operation ids.
//!
//! The console reads `/dev/urandom`, as the daemon does, because `sibuna-crypto` has no
//! operating-system random source and the standard library exposes none. Every call opens
//! the device, reads exactly the bytes asked for and closes it; the console asks rarely
//! (sign-ins, enrollments, commands), never on the data plane.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};

/// The device read for random bytes.
pub const DEVICE: &str = "/dev/urandom";

/// Why random bytes could not be produced.
#[derive(Debug)]
pub struct RandomError(io::Error);

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot read random bytes from {DEVICE}: {}", self.0)
    }
}

impl std::error::Error for RandomError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Fills `out` with random bytes.
///
/// Fails with [`RandomError`] when the device cannot be opened or read in full; `out` may
/// then hold partial output and must not be used.
pub fn fill(out: &mut [u8]) -> Result<(), RandomError> {
    let mut device = File::open(DEVICE).map_err(RandomError)?;
    device.read_exact(out).map_err(RandomError)
}

/// Returns `N` random bytes.
///
/// Fails like [`fill`].
pub fn array<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ_and_fill_the_whole_buffer() {
        let first: [u8; 32] = array().unwrap();
        let second: [u8; 32] = array().unwrap();
        assert_ne!(first, second);
        let mut big = vec![0u8; 4096];
        fill(&mut big).unwrap();
        // 4,096 zero bytes from a working device has probability 2^-32768.
        assert!(big.iter().any(|&byte| byte != 0));
    }
}
