//! Random bytes from the operating system, for the master seed when no `--secret-file` or
//! `SIBUNA_SECRET` names one.
//!
//! The standard library exposes no random source. On Unix the daemon reads
//! `/dev/urandom`, which Linux, macOS, FreeBSD and OpenBSD all provide; on Windows it calls
//! `BCryptGenRandom` with the system-preferred generator, the source `std` itself uses for
//! its hash keys. The console's `sibuna_console::random` does the same for its tokens.

// Windows only: one call into `bcrypt`, which `std` does not wrap.
#![cfg_attr(windows, allow(unsafe_code))]

use std::io;

/// Fills `out` with random bytes from the operating system.
///
/// Fails with the I/O error of opening or reading `/dev/urandom` (Unix), or with an error
/// carrying the `NTSTATUS` of `BCryptGenRandom` (Windows); `out` may then hold partial
/// output and must not be used.
#[cfg(not(windows))]
pub fn fill(out: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(out)
}

/// Fills `out` with random bytes from the operating system.
///
/// Fails with the I/O error of opening or reading `/dev/urandom` (Unix), or with an error
/// carrying the `NTSTATUS` of `BCryptGenRandom` (Windows); `out` may then hold partial
/// output and must not be used.
#[cfg(windows)]
pub fn fill(out: &mut [u8]) -> io::Result<()> {
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
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        fill(&mut first).unwrap();
        fill(&mut second).unwrap();
        assert_ne!(first, second);
        let mut big = vec![0u8; 4096];
        fill(&mut big).unwrap();
        // 4,096 zero bytes from a working source has probability 2^-32768.
        assert!(big.iter().any(|&byte| byte != 0));
    }
}
