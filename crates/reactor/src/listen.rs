//! Kernel admission for a TCP listener: options that make the kernel hold or queue
//! connections before the process sees them.
//!
//! Both options need no privilege. They are set on a listener that is already bound,
//! so a caller can apply them after a start and again after a reload.
//!
//! - [`set_defer_accept`] makes Linux give a connection to `accept` only when its first
//!   data arrived, or after a time without data. A connection that never sends a byte
//!   costs the process nothing until then.
//! - [`set_backlog`] sets the length of the queue of connections that wait for `accept`.
//!
//! On a platform without the option the call returns [`io::ErrorKind::Unsupported`]. A
//! caller that treats the options as an optimisation serves on.

#![allow(unsafe_code)]

use std::io;
use std::net::TcpListener;
use std::time::Duration;

/// True when [`set_defer_accept`] works on this platform.
pub const CAN_DEFER_ACCEPT: bool = cfg!(any(target_os = "linux", target_os = "android"));

/// True when [`set_backlog`] works on this platform.
pub const CAN_SET_BACKLOG: bool = cfg!(unix);

/// Makes the kernel hold each new connection of `listener` until the client sends
/// data, for at most about `wait`. `Duration::ZERO` turns the option off. The time is
/// rounded up to whole seconds, and the kernel rounds it again to its retransmission
/// schedule.
///
/// # Errors
///
/// The operating system's error when it refuses the option, and
/// [`io::ErrorKind::Unsupported`] on a platform without it. The listener is unchanged
/// then and keeps serving.
pub fn set_defer_accept(listener: &TcpListener, wait: Duration) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    return linux::set_defer_accept(listener, wait);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (listener, wait);
        Err(io::Error::new(io::ErrorKind::Unsupported, "no deferred accept on this platform"))
    }
}

/// The time, in seconds, that `listener` holds a connection without data, as the kernel
/// reports it. Zero means the option is off.
///
/// # Errors
///
/// As [`set_defer_accept`].
pub fn defer_accept(listener: &TcpListener) -> io::Result<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    return linux::defer_accept(listener);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = listener;
        Err(io::Error::new(io::ErrorKind::Unsupported, "no deferred accept on this platform"))
    }
}

/// Sets the length of the accept queue of `listener`, which is already listening. The
/// kernel lowers a length above its own limit (`net.core.somaxconn` on Linux) without
/// an error.
///
/// # Errors
///
/// The operating system's error, and [`io::ErrorKind::Unsupported`] on a platform
/// where a second `listen` is not known to resize the queue.
pub fn set_backlog(listener: &TcpListener, length: u32) -> io::Result<()> {
    #[cfg(unix)]
    return unix::set_backlog(listener, length);
    #[cfg(not(unix))]
    {
        let _ = (listener, length);
        Err(io::Error::new(io::ErrorKind::Unsupported, "no backlog change on this platform"))
    }
}

#[cfg(unix)]
mod unix {
    use std::io;
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn listen(fd: i32, backlog: i32) -> i32;
    }

    pub(super) fn set_backlog(listener: &TcpListener, length: u32) -> io::Result<()> {
        let length = i32::try_from(length).unwrap_or(i32::MAX);
        // SAFETY: `listen` takes a descriptor and an integer. The descriptor is open
        // for as long as `listener` is borrowed.
        if unsafe { listen(listener.as_raw_fd(), length) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::io;
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    const IPPROTO_TCP: i32 = 6;
    const TCP_DEFER_ACCEPT: i32 = 9;

    unsafe extern "C" {
        fn setsockopt(fd: i32, level: i32, name: i32, value: *const u8, length: u32) -> i32;
        fn getsockopt(fd: i32, level: i32, name: i32, value: *mut u8, length: *mut u32) -> i32;
    }

    pub(super) fn set_defer_accept(listener: &TcpListener, wait: Duration) -> io::Result<()> {
        let whole = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
        let seconds = i32::try_from(whole).unwrap_or(i32::MAX).to_ne_bytes();
        let fd = listener.as_raw_fd();
        // SAFETY: `seconds` is four live bytes, the length passed, and the kernel copies
        // them before the call returns. The descriptor is open while `listener` is
        // borrowed.
        let result = unsafe { setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, seconds.as_ptr(), 4) };
        if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }

    pub(super) fn defer_accept(listener: &TcpListener) -> io::Result<u32> {
        let mut seconds = [0u8; 4];
        let mut length = 4u32;
        let fd = listener.as_raw_fd();
        // SAFETY: `seconds` has room for the four bytes that `length` announces, both
        // live for the call, and the kernel writes at most `length` bytes.
        let result = unsafe {
            getsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, seconds.as_mut_ptr(), &raw mut length)
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(u32::try_from(i32::from_ne_bytes(seconds)).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpStream;
    use std::time::Instant;

    fn listener() -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        listener
    }

    /// Whether `listener` hands out a connection within `wait`.
    fn accepts_within(listener: &TcpListener, wait: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < wait {
            if listener.accept().is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    #[test]
    fn the_backlog_of_a_listening_socket_can_be_set_again() {
        let listener = listener();
        if !CAN_SET_BACKLOG {
            assert_eq!(set_backlog(&listener, 16).unwrap_err().kind(), io::ErrorKind::Unsupported);
            return;
        }
        set_backlog(&listener, 16).expect("smaller backlog");
        set_backlog(&listener, u32::MAX).expect("the kernel clamps a huge backlog");
        let address = listener.local_addr().expect("address");
        let _client = TcpStream::connect(address).expect("connect");
        assert!(accepts_within(&listener, Duration::from_secs(2)), "the listener still serves");
    }

    #[test]
    fn a_deferred_listener_holds_a_silent_connection_until_data_arrives() {
        let listener = listener();
        if !CAN_DEFER_ACCEPT {
            let error = set_defer_accept(&listener, Duration::from_secs(5)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            return;
        }
        set_defer_accept(&listener, Duration::from_secs(5)).expect("defer");
        assert!(defer_accept(&listener).expect("read back") >= 5);
        let address = listener.local_addr().expect("address");
        let mut silent = TcpStream::connect(address).expect("connect");
        assert!(!accepts_within(&listener, Duration::from_millis(300)), "held by the kernel");
        silent.write_all(b"x").expect("first byte");
        assert!(accepts_within(&listener, Duration::from_secs(2)), "released by data");
    }

    #[test]
    fn zero_turns_deferral_off_and_a_part_of_a_second_rounds_up() {
        let listener = listener();
        if !CAN_DEFER_ACCEPT {
            return;
        }
        set_defer_accept(&listener, Duration::from_millis(1500)).expect("defer");
        assert!(defer_accept(&listener).expect("read back") >= 2);
        set_defer_accept(&listener, Duration::ZERO).expect("off");
        assert_eq!(defer_accept(&listener).expect("read back"), 0);
        let address = listener.local_addr().expect("address");
        let _silent = TcpStream::connect(address).expect("connect");
        assert!(accepts_within(&listener, Duration::from_secs(2)), "given at once");
    }
}
