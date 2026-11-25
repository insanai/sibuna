//! A TCP connection that leaves from a chosen local address.
//!
//! The standard library connects from the address that the routing table selects. A
//! node that its peers know by one address must connect from that address, on a host
//! with several. On Linux we bind the socket before the connect.

#![allow(unsafe_code)]

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};

/// Starts a TCP connection to `address` from the local address `local`, without
/// waiting for it. The returned socket is non-blocking. It becomes writable when the
/// connection completes or fails, and [`TcpStream::take_error`] then tells which.
///
/// # Errors
///
/// The operating system's error when the socket cannot be created or bound, or the
/// connection is refused at once, and [`io::ErrorKind::Unsupported`] on a platform
/// without this call: see [`CAN_CONNECT_FROM`].
pub fn start_connect_from(local: IpAddr, address: SocketAddr) -> io::Result<TcpStream> {
    start::from(local, address)
}

/// True when [`start_connect_from`] works on this platform.
pub const CAN_CONNECT_FROM: bool = cfg!(any(target_os = "linux", target_os = "android"));

#[cfg(any(target_os = "linux", target_os = "android"))]
mod start {
    use std::io;
    use std::net::{IpAddr, SocketAddr, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    const SOCK_STREAM: i32 = 1;
    const SOCK_NONBLOCK: i32 = 0x800;
    const SOCK_CLOEXEC: i32 = 0x80000;
    const IPPROTO_IP: i32 = 0;
    const IP_BIND_ADDRESS_NO_PORT: i32 = 24;
    const EINPROGRESS: i32 = 115;

    unsafe extern "C" {
        fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
        fn setsockopt(fd: i32, level: i32, name: i32, value: *const u8, length: u32) -> i32;
        #[link_name = "bind"]
        fn bind_socket(fd: i32, address: *const u8, length: u32) -> i32;
        fn connect(fd: i32, address: *const u8, length: u32) -> i32;
    }

    /// The bytes of a `sockaddr_in` or `sockaddr_in6` and their count.
    fn raw(address: SocketAddr) -> ([u8; 28], u32) {
        let mut bytes = [0u8; 28];
        match address {
            SocketAddr::V4(v4) => {
                bytes[..2].copy_from_slice(&AF_INET.to_ne_bytes());
                bytes[2..4].copy_from_slice(&v4.port().to_be_bytes());
                bytes[4..8].copy_from_slice(&v4.ip().octets());
                (bytes, 16)
            }
            SocketAddr::V6(v6) => {
                bytes[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
                bytes[2..4].copy_from_slice(&v6.port().to_be_bytes());
                bytes[4..8].copy_from_slice(&v6.flowinfo().to_be_bytes());
                bytes[8..24].copy_from_slice(&v6.ip().octets());
                bytes[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
                (bytes, 28)
            }
        }
    }

    pub(super) fn from(local: IpAddr, address: SocketAddr) -> io::Result<TcpStream> {
        if local.is_ipv4() != address.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{local} and {address} are of different address families"),
            ));
        }
        let domain = i32::from(if address.is_ipv4() { AF_INET } else { AF_INET6 });
        // SAFETY: `socket` takes three integers and returns a descriptor or -1.
        let fd = unsafe { socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a descriptor the call above just returned, owned by nobody else.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // The port is chosen at the connect, so that the ports of one local address
        // serve many destinations. An older kernel refuses the option and binds a port
        // now, which is correct too.
        let on = 1i32.to_ne_bytes();
        // SAFETY: `on` is four live bytes, the length passed, and the kernel copies
        // them before the call returns.
        let _ = unsafe {
            setsockopt(owned.as_raw_fd(), IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, on.as_ptr(), 4)
        };
        let (bytes, length) = raw(SocketAddr::new(local, 0));
        // SAFETY: `bytes` holds a live socket address of `length` bytes, and the kernel
        // copies it before the call returns.
        if unsafe { bind_socket(owned.as_raw_fd(), bytes.as_ptr(), length) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (bytes, length) = raw(address);
        // SAFETY: as for the bind above.
        if unsafe { connect(owned.as_raw_fd(), bytes.as_ptr(), length) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(EINPROGRESS) {
                return Err(error);
            }
        }
        Ok(TcpStream::from(owned))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod start {
    use std::io;
    use std::net::{IpAddr, SocketAddr, TcpStream};

    pub(super) fn from(_local: IpAddr, _address: SocketAddr) -> io::Result<TcpStream> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::net::TcpListener;

    use super::*;
    use crate::{Poller, WRITE, handle};

    #[test]
    fn a_connection_leaves_from_the_chosen_local_address() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let local: IpAddr = "127.0.0.9".parse().expect("address");
        let stream = start_connect_from(local, address).expect("start");
        let mut poller = Poller::new().expect("poller");
        poller.set(handle(&stream), WRITE, 1u8).expect("register");
        let mut ready = Vec::new();
        poller.wait(2_000, &mut ready).expect("wait");
        assert_eq!(ready, [1]);
        assert!(stream.take_error().expect("status").is_none());
        let (_, source) = listener.accept().expect("accept");
        assert_eq!(source.ip(), local);
        assert_eq!(stream.local_addr().expect("local"), source);
    }

    #[test]
    fn mixed_address_families_are_refused_before_any_socket() {
        let local: IpAddr = "::1".parse().expect("address");
        let refused = start_connect_from(local, "127.0.0.1:9".parse().expect("address"));
        assert_eq!(refused.expect_err("refused").kind(), io::ErrorKind::InvalidInput);
    }
}
