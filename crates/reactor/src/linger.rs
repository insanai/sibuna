//! Ending a connection with a reset instead of an orderly close (SID 0034).
//!
//! A socket with `SO_LINGER` on and a zero time sends a reset when it is closed, and the
//! kernel keeps no `TIME_WAIT` state for it. A refused connection then costs one segment
//! instead of a FIN exchange.

#![allow(unsafe_code)]

use std::net::TcpStream;

/// True when [`reset`] sends a reset on this platform. Elsewhere it closes in order.
pub const CAN_RESET: bool = cfg!(any(unix, windows));

/// Closes `stream` with a reset. When the platform refuses the option the stream closes
/// in order, which is never worse than not asking.
pub fn reset(stream: TcpStream) {
    #[cfg(unix)]
    unix::zero_linger(&stream);
    #[cfg(windows)]
    windows::zero_linger(&stream);
    drop(stream);
}

#[cfg(unix)]
mod unix {
    use std::net::TcpStream;
    use std::os::fd::AsRawFd;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const SOL_SOCKET: i32 = 1;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const SO_LINGER: i32 = 13;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const SOL_SOCKET: i32 = 0xffff;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const SO_LINGER: i32 = 0x0080;

    unsafe extern "C" {
        fn setsockopt(fd: i32, level: i32, name: i32, value: *const u8, length: u32) -> i32;
    }

    pub(super) fn zero_linger(stream: &TcpStream) {
        // struct linger { int l_onoff; int l_linger; }: on, zero seconds.
        let mut linger = [0u8; 8];
        linger[..4].copy_from_slice(&1i32.to_ne_bytes());
        // SAFETY: `linger` is eight live bytes, the length passed, and the kernel copies
        // them before the call returns. The descriptor is open while `stream` is borrowed.
        let _ =
            unsafe { setsockopt(stream.as_raw_fd(), SOL_SOCKET, SO_LINGER, linger.as_ptr(), 8) };
    }
}

#[cfg(windows)]
mod windows {
    use std::net::TcpStream;
    use std::os::windows::io::AsRawSocket;

    const SOL_SOCKET: i32 = 0xffff;
    const SO_LINGER: i32 = 0x0080;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(socket: usize, level: i32, name: i32, value: *const u8, length: i32) -> i32;
    }

    pub(super) fn zero_linger(stream: &TcpStream) {
        // struct linger { u_short l_onoff; u_short l_linger; }: on, zero seconds.
        let linger = [1u8, 0, 0, 0];
        let socket = stream.as_raw_socket() as usize;
        // SAFETY: `linger` is four live bytes, the length passed, and Winsock copies them
        // before the call returns. The socket is open while `stream` is borrowed.
        let _ = unsafe { setsockopt(socket, SOL_SOCKET, SO_LINGER, linger.as_ptr(), 4) };
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn a_reset_reaches_the_peer_as_a_reset() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        reset(accepted);
        let mut byte = [0u8; 1];
        let result = client.read(&mut byte);
        if CAN_RESET && cfg!(any(target_os = "linux", target_os = "android")) {
            let error = result.expect_err("a reset, not an end of stream");
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        }
    }
}
