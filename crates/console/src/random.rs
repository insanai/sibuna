//! Random bytes from the operating system: session tokens, CSRF secrets, recovery codes,
//! nonces and operation ids.
//!
//! The console reads `/dev/urandom` on Unix, as the daemon does, because `sibuna-crypto` has
//! no operating-system random source and the standard library exposes none. Every call
//! opens the device, reads exactly the bytes asked for and closes it; the console asks
//! rarely (sign-ins, enrollments, commands), never on the data plane. On Windows it calls
//! `BCryptGenRandom` with the system-preferred generator instead.

// Windows only: one call into `bcrypt`, which `std` does not wrap.
#![cfg_attr(windows, allow(unsafe_code))]

use std::fmt;
use std::io;

/// The source of random bytes, as error messages name it.
#[cfg(not(windows))]
pub const SOURCE: &str = "/dev/urandom";
/// The source of random bytes, as error messages name it.
#[cfg(windows)]
pub const SOURCE: &str = "BCryptGenRandom";

/// Why random bytes could not be produced.
#[derive(Debug)]
pub struct RandomError(io::Error);

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot read random bytes from {SOURCE}: {}", self.0)
    }
}

impl std::error::Error for RandomError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Fills `out` with random bytes.
///
/// Fails with [`RandomError`] when the source cannot be opened or read in full; `out` may
/// then hold partial output and must not be used.
pub fn fill(out: &mut [u8]) -> Result<(), RandomError> {
    fill_from_system(out).map_err(RandomError)
}

/// Returns `N` random bytes.
///
/// Fails like [`fill`].
pub fn array<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(not(windows))]
fn fill_from_system(out: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    std::fs::File::open(SOURCE)?.read_exact(out)
}

#[cfg(windows)]
fn fill_from_system(out: &mut [u8]) -> io::Result<()> {
    use std::ffi::c_void;

    /// Use the system-preferred generator; no algorithm handle is passed.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }

    // The length is a `ULONG`; larger buffers are filled in pieces.
    for chunk in out.chunks_mut(u32::MAX as usize) {
        let length = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
        // SAFETY: `chunk` is a valid, writable buffer of exactly `length` bytes; a null
        // algorithm handle is what BCRYPT_USE_SYSTEM_PREFERRED_RNG requires.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                chunk.as_mut_ptr(),
                length,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(io::Error::other(format!("BCryptGenRandom failed ({status:#010x})")));
        }
    }
    Ok(())
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
