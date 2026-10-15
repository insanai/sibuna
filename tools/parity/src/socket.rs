//! Client sockets bound to a chosen loopback source address before they connect, so every
//! scenario reaches the daemons from an address of its own even when forwarded headers
//! are not trusted.
//!
//! The standard library cannot bind a TCP client socket before `connect`, so on Linux we
//! call `socket`, `bind` and `connect` from the C library directly. Elsewhere the socket
//! connects from the default address and scenarios share it, which only matters for the
//! configurations that do not trust forwarded headers.

// FFI: three libc calls the standard library does not expose for client sockets.
#![allow(unsafe_code)]

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};

/// Connects to `remote` from `source` (port chosen by the kernel).
///
/// # Errors
///
/// Returns the operating system's error for a failed `socket`, `bind` or `connect`.
#[cfg(target_os = "linux")]
pub fn connect_from(source: Ipv4Addr, remote: SocketAddrV4) -> io::Result<TcpStream> {
    use std::os::fd::{FromRawFd, OwnedFd};

    const AF_INET: i32 = 2;
    const SOCK_STREAM: i32 = 1;
    const SOCK_CLOEXEC: i32 = 0o2_000_000;

    /// `struct sockaddr_in` of Linux: family, port and address in network byte order.
    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        address: [u8; 4],
        zero: [u8; 8],
    }

    unsafe extern "C" {
        fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
        fn bind(fd: i32, address: *const SockaddrIn, length: u32) -> i32;
        fn connect(fd: i32, address: *const SockaddrIn, length: u32) -> i32;
    }

    let to_sockaddr = |address: Ipv4Addr, port: u16| SockaddrIn {
        family: AF_INET as u16,
        port: port.to_be(),
        address: address.octets(),
        zero: [0; 8],
    };
    let local = to_sockaddr(source, 0);
    let peer = to_sockaddr(*remote.ip(), remote.port());
    let length = size_of::<SockaddrIn>() as u32;
    // SAFETY: `socket` takes no pointers; it returns a new descriptor or -1.
    let fd = unsafe { socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a descriptor we just created and own; `OwnedFd` closes it on every
    // path below, including the error returns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: `local` is a valid `sockaddr_in` that lives across the call, and `length` is
    // its size.
    if unsafe { bind(fd, &local, length) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as for `bind`, with `peer`.
    if unsafe { connect(fd, &peer, length) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpStream::from(owned))
}

/// Connects to `remote` from the default address: `source` is ignored off Linux.
///
/// # Errors
///
/// Returns the error of [`TcpStream::connect`].
#[cfg(not(target_os = "linux"))]
pub fn connect_from(_source: Ipv4Addr, remote: SocketAddrV4) -> io::Result<TcpStream> {
    TcpStream::connect(remote)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn the_peer_sees_the_bound_source() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!("IPv4 listener")
        };
        let source = Ipv4Addr::new(127, 9, 8, 7);
        let _stream = connect_from(source, address).unwrap();
        let (_, peer) = listener.accept().unwrap();
        assert_eq!(peer.ip(), std::net::IpAddr::V4(source));
    }

    #[test]
    fn a_refused_connection_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!("IPv4 listener")
        };
        drop(listener);
        assert!(connect_from(Ipv4Addr::new(127, 0, 0, 1), address).is_err());
    }
}
