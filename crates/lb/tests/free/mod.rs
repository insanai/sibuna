//! Listener addresses for tests that no other test takes.
//!
//! A test needs the address of a listener before the edge binds it. A port that was
//! bound and released on `127.0.0.1` is not safe: a test beside this one may be given
//! the same port for a client socket or a listener of its own before the edge binds it,
//! and the edge then fails with "address in use". We therefore give each call a
//! loopback address of its own. Ports on different addresses do not collide.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};

/// A loopback address that this process hands out once: the process number and a
/// serial fill the three free bytes of `127.0.0.0/8`.
fn host() -> IpAddr {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let [_, _, high, low] = std::process::id().to_be_bytes();
    // The second byte stays in 64..128, away from `127.0.0.1` and from the addresses
    // that other helpers of the repository use.
    IpAddr::V4(Ipv4Addr::new(127, 64 | (high & 63), low, serial as u8))
}

/// The address of a TCP listener that is free now and stays free of other tests.
pub fn tcp() -> SocketAddr {
    let bound = TcpListener::bind((host(), 0)).and_then(|listener| listener.local_addr());
    // A system whose loopback is the single address 127.0.0.1 gets the old behaviour.
    bound.unwrap_or_else(|_| TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap())
}

/// The address of a UDP listener that is free now and stays free of other tests.
pub fn udp() -> SocketAddr {
    let bound = UdpSocket::bind((host(), 0)).and_then(|socket| socket.local_addr());
    bound.unwrap_or_else(|_| UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap())
}
