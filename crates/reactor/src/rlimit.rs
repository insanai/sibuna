//! The limit on open file descriptors of this process.
//!
//! A worker that serves many sockets needs as many descriptors. The limit has a soft
//! value, which applies, and a hard value, up to which a process may raise the soft one
//! without a privilege. Linux and macOS on 64-bit processors are supported. Elsewhere the
//! functions report [`io::ErrorKind::Unsupported`].

#![allow(unsafe_code)]

use std::io;

/// The soft and the hard limit on open file descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorLimit {
    /// The limit that applies now.
    pub soft: u64,
    /// The most the soft limit may be raised to. `u64::MAX` when unlimited.
    pub hard: u64,
}

/// Reads the descriptor limit of the process.
///
/// # Errors
///
/// The error of the system call, or `Unsupported` on a platform without one here.
pub fn descriptor_limit() -> io::Result<DescriptorLimit> {
    sys::read()
}

/// Sets the soft descriptor limit to `soft`, which must not exceed the hard limit. The
/// hard limit is unchanged. A lowered limit does not close descriptors that are open.
///
/// # Errors
///
/// The error of the system call, or `Unsupported` on a platform without one here.
pub fn set_descriptor_limit(soft: u64) -> io::Result<()> {
    let hard = sys::read()?.hard;
    sys::write(DescriptorLimit { soft: soft.min(hard), hard })
}

#[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
mod sys {
    use std::ffi::c_int;
    use std::io;

    use super::DescriptorLimit;

    /// `RLIMIT_NOFILE` of `<sys/resource.h>`.
    #[cfg(target_os = "linux")]
    const RLIMIT_NOFILE: c_int = 7;
    #[cfg(target_os = "macos")]
    const RLIMIT_NOFILE: c_int = 8;

    /// `struct rlimit`: two `rlim_t`, which is 64 bits wide on these platforms.
    #[repr(C)]
    struct RLimit {
        current: u64,
        maximum: u64,
    }

    unsafe extern "C" {
        fn getrlimit(resource: c_int, limit: *mut RLimit) -> c_int;
        fn setrlimit(resource: c_int, limit: *const RLimit) -> c_int;
    }

    pub fn read() -> io::Result<DescriptorLimit> {
        let mut limit = RLimit { current: 0, maximum: 0 };
        // SAFETY: `limit` is a live `struct rlimit` that the call fills and does not keep.
        if unsafe { getrlimit(RLIMIT_NOFILE, &raw mut limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(DescriptorLimit { soft: limit.current, hard: limit.maximum })
    }

    pub fn write(limit: DescriptorLimit) -> io::Result<()> {
        let limit = RLimit { current: limit.soft, maximum: limit.hard };
        // SAFETY: `limit` is a live, initialized `struct rlimit` that the call only reads.
        if unsafe { setrlimit(RLIMIT_NOFILE, &raw const limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")))]
mod sys {
    use std::io;

    use super::DescriptorLimit;

    pub fn read() -> io::Result<DescriptorLimit> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no descriptor limit on this platform"))
    }

    pub fn write(_limit: DescriptorLimit) -> io::Result<()> {
        read().map(|_| ())
    }
}

#[cfg(test)]
#[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
mod tests {
    use super::*;

    #[test]
    fn the_soft_limit_can_be_set_within_the_hard_limit() {
        let before = descriptor_limit().expect("the limit is readable");
        assert!(before.soft <= before.hard);
        assert!(before.soft > 0);
        // Setting the current value changes nothing and must succeed.
        set_descriptor_limit(before.soft).expect("the same limit is accepted");
        assert_eq!(descriptor_limit().expect("readable"), before);
        // A request above the hard limit is cut to it and leaves the hard limit alone.
        if before.hard != u64::MAX {
            set_descriptor_limit(u64::MAX).expect("cut to the hard limit");
            let raised = descriptor_limit().expect("readable");
            assert_eq!((raised.soft, raised.hard), (before.hard, before.hard));
            set_descriptor_limit(before.soft).expect("restored");
        }
    }
}
