//! Thread stack sizes for service threads.
//!
//! Every service thread has a documented usable stack of 256 KiB in an optimised build.
//! Unoptimised builds keep temporaries in separate stack slots and need several times the
//! optimised frame depth, so [`bytes`] scales the request by [`DEBUG_SCALE`] there, and test
//! binaries exercise the same paths without overflowing.
//!
//! The Zig version also added the 256 KiB signal stack that Zig keeps in thread-local
//! storage, because glibc carves static TLS out of the requested stack. Rust's standard
//! library maps its signal stack separately and never requests less than glibc's minimum
//! stack, which accounts for static TLS, so that term is gone.

/// The usable stack of every service thread in an optimised build.
pub const USABLE: usize = 256 * 1024;

/// How much more stack an unoptimised build reserves.
pub const DEBUG_SCALE: usize = if cfg!(debug_assertions) { 4 } else { 1 };

/// The stack to request for a thread that needs `usable` bytes in an optimised build.
/// Saturates instead of overflowing.
pub const fn bytes(usable: usize) -> usize {
    usable.saturating_mul(DEBUG_SCALE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_usable_stack_request_is_never_reduced() {
        assert!(bytes(USABLE) >= USABLE);
        // Zig added its thread-local signal stack here; Rust has none to add.
        assert_eq!(bytes(0), 0);
        assert_eq!(bytes(usize::MAX), usize::MAX);
    }
}
