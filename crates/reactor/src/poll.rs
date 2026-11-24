//! Level-triggered socket readiness with persistent registrations.
//!
//! A worker registers a socket once and changes its interest only when the interest
//! changes. Linux uses epoll, so a wait costs time proportional to the ready sockets.
//! Other platforms keep the registrations in a table and pass it to `poll`.
//!
//! The owner removes a socket before closing it. A registration that outlives its socket
//! is harmless: the kernel reports no event for it, and [`Poller::set`] replaces it when
//! the descriptor number is used again.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
pub use std::os::fd::RawFd as Handle;
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

/// The platform's socket handle.
#[cfg(windows)]
pub type Handle = usize;

/// The handle a socket is registered by.
#[cfg(unix)]
pub fn handle(socket: &impl AsRawFd) -> Handle {
    socket.as_raw_fd()
}

/// The handle a socket is registered by.
#[cfg(windows)]
pub fn handle(socket: &impl AsRawSocket) -> Handle {
    let socket: RawSocket = socket.as_raw_socket();
    socket as usize
}

/// Interest in readable data, a hang-up or an error.
#[cfg(unix)]
pub const READ: i16 = 1;
/// Interest in room to write.
#[cfg(unix)]
pub const WRITE: i16 = 4;
/// Interest in readable data, a hang-up or an error.
#[cfg(windows)]
pub const READ: i16 = 0x0100;
/// Interest in room to write.
#[cfg(windows)]
pub const WRITE: i16 = 0x0010;

/// The registered sockets of one worker and the key reported for each.
pub struct Poller<K> {
    entries: HashMap<Handle, (i16, K)>,
    backend: backend::Backend,
}

impl<K: Copy> Poller<K> {
    /// Creates an empty poller. Fails when the platform refuses a readiness handle.
    pub fn new() -> io::Result<Self> {
        Ok(Self { entries: HashMap::new(), backend: backend::Backend::new()? })
    }

    /// Registers `handle` for `events`, or changes its events and key. No events removes
    /// it, so a socket that has nothing to wait for cannot report a hang-up in a loop.
    pub fn set(&mut self, handle: Handle, events: i16, key: K) -> io::Result<()> {
        if events == 0 {
            self.remove(handle);
            return Ok(());
        }
        let known = match self.entries.insert(handle, (events, key)) {
            Some((previous, _)) if previous == events => return Ok(()),
            Some(_) => true,
            None => false,
        };
        self.backend.set(handle, events, known)
    }

    /// Forgets `handle`. Call this before closing the socket.
    pub fn remove(&mut self, handle: Handle) {
        if self.entries.remove(&handle).is_some() {
            self.backend.remove(handle);
        }
    }

    /// Waits up to `timeout_ms` and appends the key of each ready socket to `ready`.
    pub fn wait(&mut self, timeout_ms: i32, ready: &mut Vec<K>) -> io::Result<()> {
        let entries = &self.entries;
        self.backend.wait(timeout_ms, entries.keys().map(|&h| (h, entries[&h].0)), |handle| {
            if let Some((_, key)) = entries.get(&handle) {
                ready.push(*key);
            }
        })
    }
}

fn interrupted_is_ready(error: io::Error) -> io::Result<()> {
    if error.kind() == io::ErrorKind::Interrupted { Ok(()) } else { Err(error) }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod backend {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::Handle;

    const EPOLL_CLOEXEC: i32 = 0x80000;
    const CTL_ADD: i32 = 1;
    const CTL_DEL: i32 = 2;
    const CTL_MOD: i32 = 3;
    const BATCH: usize = 256;

    // The kernel packs this structure on x86-64 and aligns it naturally elsewhere.
    #[cfg_attr(target_arch = "x86_64", repr(C, packed))]
    #[cfg_attr(not(target_arch = "x86_64"), repr(C))]
    #[derive(Clone, Copy)]
    struct Event {
        events: u32,
        data: u64,
    }

    unsafe extern "C" {
        fn epoll_create1(flags: i32) -> i32;
        fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut Event) -> i32;
        fn epoll_wait(epfd: i32, events: *mut Event, max: i32, timeout_ms: i32) -> i32;
    }

    pub(super) struct Backend {
        epoll: OwnedFd,
        events: Box<[Event]>,
    }

    impl Backend {
        pub fn new() -> io::Result<Self> {
            // SAFETY: epoll_create1 takes no pointers. A non-negative result is a new
            // descriptor that nothing else owns.
            let fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd was just returned by the kernel and is owned only here.
            let epoll = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(Self { epoll, events: vec![Event { events: 0, data: 0 }; BATCH].into() })
        }

        fn control(&self, op: i32, handle: Handle, events: i16) -> io::Result<()> {
            // poll's POLLIN and POLLOUT have the same values as EPOLLIN and EPOLLOUT.
            let mut event = Event { events: events as u16 as u32, data: handle as u64 };
            // SAFETY: event is a valid, initialized structure for the duration of the call.
            if unsafe { epoll_ctl(self.epoll.as_raw_fd(), op, handle, &mut event) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        pub fn set(&mut self, handle: Handle, events: i16, known: bool) -> io::Result<()> {
            let (first, second) = if known { (CTL_MOD, CTL_ADD) } else { (CTL_ADD, CTL_MOD) };
            match self.control(first, handle, events) {
                // The table and the kernel disagree after a descriptor number was reused.
                Err(error) if matches!(error.raw_os_error(), Some(2 | 17)) => {
                    self.control(second, handle, events)
                }
                result => result,
            }
        }

        pub fn remove(&mut self, handle: Handle) {
            let _ = self.control(CTL_DEL, handle, 0);
        }

        pub fn wait(
            &mut self,
            timeout_ms: i32,
            _entries: impl Iterator<Item = (Handle, i16)>,
            mut ready: impl FnMut(Handle),
        ) -> io::Result<()> {
            // SAFETY: the buffer holds BATCH initialized events and is exclusively
            // borrowed for the call. The kernel writes at most BATCH entries.
            let count = unsafe {
                epoll_wait(
                    self.epoll.as_raw_fd(),
                    self.events.as_mut_ptr(),
                    BATCH as i32,
                    timeout_ms,
                )
            };
            if count < 0 {
                return super::interrupted_is_ready(io::Error::last_os_error());
            }
            for event in &self.events[..count as usize] {
                // Errors and hang-ups surface through the next read or write.
                let Event { data, .. } = *event;
                ready(data as Handle);
            }
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod backend {
    use std::io;

    use super::Handle;

    #[repr(C)]
    struct PollFd {
        handle: Handle,
        events: i16,
        returned: i16,
    }

    // nfds_t is unsigned int on the supported BSDs, macOS and Windows.
    type Count = u32;

    #[cfg(unix)]
    unsafe extern "C" {
        fn poll(fds: *mut PollFd, count: Count, timeout_ms: i32) -> i32;
    }
    #[cfg(windows)]
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        #[link_name = "WSAPoll"]
        fn poll(fds: *mut PollFd, count: Count, timeout_ms: i32) -> i32;
        fn WSAGetLastError() -> i32;
    }

    pub(super) struct Backend {
        sockets: Vec<PollFd>,
        dirty: bool,
    }

    impl Backend {
        pub fn new() -> io::Result<Self> {
            Ok(Self { sockets: Vec::new(), dirty: true })
        }

        pub fn set(&mut self, _handle: Handle, _events: i16, _known: bool) -> io::Result<()> {
            self.dirty = true;
            Ok(())
        }

        pub fn remove(&mut self, _handle: Handle) {
            self.dirty = true;
        }

        pub fn wait(
            &mut self,
            timeout_ms: i32,
            entries: impl Iterator<Item = (Handle, i16)>,
            mut ready: impl FnMut(Handle),
        ) -> io::Result<()> {
            if self.dirty {
                self.sockets.clear();
                self.sockets.extend(entries.map(|(handle, events)| PollFd {
                    handle,
                    events,
                    returned: 0,
                }));
                self.dirty = false;
            }
            if self.sockets.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(timeout_ms.max(0) as u64));
                return Ok(());
            }
            let count = self.sockets.len() as Count;
            // SAFETY: the C-compatible array has count initialized entries and is
            // exclusively borrowed for the duration of poll.
            if unsafe { poll(self.sockets.as_mut_ptr(), count, timeout_ms) } < 0 {
                #[cfg(unix)]
                let error = io::Error::last_os_error();
                #[cfg(windows)]
                // SAFETY: thread-local Winsock error retrieval takes no arguments.
                let error = io::Error::from_raw_os_error(unsafe { WSAGetLastError() });
                return super::interrupted_is_ready(error);
            }
            for socket in self.sockets.iter().filter(|socket| socket.returned != 0) {
                ready(socket.handle);
            }
            Ok(())
        }
    }
}

/// Wakes a worker that is waiting in its poller. Any thread may hold a [`Wake`].
pub struct Waker {
    receiver: std::net::UdpSocket,
}

/// The sending half of a [`Waker`].
#[derive(Clone)]
pub struct Wake(std::sync::Arc<std::net::UdpSocket>);

impl Waker {
    /// Creates a connected loopback datagram pair. Only the paired sender can deliver.
    pub fn new() -> io::Result<(Self, Wake)> {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
        sender.connect(receiver.local_addr()?)?;
        receiver.connect(sender.local_addr()?)?;
        receiver.set_nonblocking(true)?;
        sender.set_nonblocking(true)?;
        Ok((Self { receiver }, Wake(std::sync::Arc::new(sender))))
    }

    /// The socket to register for reading.
    pub fn socket(&self) -> &std::net::UdpSocket {
        &self.receiver
    }

    /// Discards the pending wake-ups.
    pub fn drain(&self) {
        let mut byte = [0; 8];
        while self.receiver.recv(&mut byte).is_ok() {}
    }
}

impl Wake {
    /// Requests a wake-up. A full socket buffer already holds one, so a failure is ignored.
    pub fn wake(&self) {
        let _ = self.0.send(&[1]);
    }
}

/// Starts a TCP connection without waiting for it. The returned socket is non-blocking.
/// It becomes writable when the connection completes or fails, and
/// [`std::net::TcpStream::take_error`] then tells which.
///
/// # Errors
///
/// The operating system's error when the socket cannot be created or the connection is
/// refused at once, and [`io::ErrorKind::Unsupported`] on a platform without this call.
pub fn start_connect(address: std::net::SocketAddr) -> io::Result<std::net::TcpStream> {
    connecting::start(address)
}

/// True when [`start_connect`] works on this platform.
pub const CAN_START_CONNECT: bool = cfg!(any(target_os = "linux", target_os = "android"));

#[cfg(any(target_os = "linux", target_os = "android"))]
mod connecting {
    use std::io;
    use std::net::{SocketAddr, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const AF_INET: i32 = 2;
    const AF_INET6: i32 = 10;
    const SOCK_STREAM: i32 = 1;
    const SOCK_NONBLOCK: i32 = 0x800;
    const SOCK_CLOEXEC: i32 = 0x80000;
    const EINPROGRESS: i32 = 115;

    #[repr(C)]
    struct V4 {
        family: u16,
        port: [u8; 2],
        address: [u8; 4],
        zero: [u8; 8],
    }

    #[repr(C)]
    struct V6 {
        family: u16,
        port: [u8; 2],
        flow: u32,
        address: [u8; 16],
        scope: u32,
    }

    unsafe extern "C" {
        fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
        fn connect(fd: i32, address: *const u8, length: u32) -> i32;
    }

    pub(super) fn start(address: SocketAddr) -> io::Result<TcpStream> {
        let domain = if address.is_ipv4() { AF_INET } else { AF_INET6 };
        // SAFETY: `socket` takes three integers and returns a descriptor or -1.
        let fd = unsafe { socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a descriptor the call above just returned, owned by nobody else.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let result = match address {
            SocketAddr::V4(v4) => {
                let raw = V4 {
                    family: AF_INET as u16,
                    port: v4.port().to_be_bytes(),
                    address: v4.ip().octets(),
                    zero: [0; 8],
                };
                // SAFETY: `raw` is a live `sockaddr_in` of the length passed, and the
                // kernel copies it before the call returns.
                unsafe { connect(owned.as_raw_fd(), (&raw const raw).cast(), 16) }
            }
            SocketAddr::V6(v6) => {
                let raw = V6 {
                    family: AF_INET6 as u16,
                    port: v6.port().to_be_bytes(),
                    flow: v6.flowinfo().to_be(),
                    address: v6.ip().octets(),
                    scope: v6.scope_id(),
                };
                // SAFETY: `raw` is a live `sockaddr_in6` of the length passed, and the
                // kernel copies it before the call returns.
                unsafe { connect(owned.as_raw_fd(), (&raw const raw).cast(), 28) }
            }
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(EINPROGRESS) {
                return Err(error);
            }
        }
        Ok(TcpStream::from(owned))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod connecting {
    use std::io;
    use std::net::{SocketAddr, TcpStream};

    pub(super) fn start(_address: SocketAddr) -> io::Result<TcpStream> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn a_started_connect_completes_and_a_refused_one_reports_its_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let mut stream = start_connect(address).expect("start");
        let mut poller = Poller::new().expect("poller");
        poller.set(handle(&stream), WRITE, 1u8).expect("register");
        let mut ready = Vec::new();
        poller.wait(2_000, &mut ready).expect("wait");
        assert_eq!(ready, [1]);
        assert!(stream.take_error().expect("status").is_none());
        let (mut accepted, _) = listener.accept().expect("accept");
        stream.write_all(b"ping").expect("write");
        let mut bytes = [0; 4];
        accepted.read_exact(&mut bytes).expect("read");
        assert_eq!(&bytes, b"ping");

        drop(listener);
        drop(accepted);
        let refused = match start_connect(address) {
            Err(_) => return,
            Ok(stream) => stream,
        };
        let mut poller = Poller::new().expect("poller");
        poller.set(handle(&refused), WRITE, 2u8).expect("register");
        ready.clear();
        poller.wait(2_000, &mut ready).expect("wait");
        assert!(refused.take_error().expect("status").is_some() || refused.peer_addr().is_err());
    }
}

/// Binds a TCP listener that shares its address with other listeners of the same user
/// (`SO_REUSEPORT`). A new process can then bind the address while the old one still
/// serves, which is how a binary is replaced without closing the port.
///
/// # Errors
///
/// The operating system's error when the socket cannot be created, bound or listened
/// on, and [`io::ErrorKind::Unsupported`] on a platform without this call.
pub fn listen_shared(address: std::net::SocketAddr) -> io::Result<std::net::TcpListener> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    return sharing::bind(address, sharing::SOCK_STREAM).map(std::net::TcpListener::from);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    Err(io::Error::new(io::ErrorKind::Unsupported, format!("{address}: no shared listeners")))
}

/// Binds a UDP socket that shares its address, as [`listen_shared`] does for TCP.
///
/// # Errors
///
/// As [`listen_shared`].
pub fn bind_shared(address: std::net::SocketAddr) -> io::Result<std::net::UdpSocket> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    return sharing::bind(address, sharing::SOCK_DGRAM).map(std::net::UdpSocket::from);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    Err(io::Error::new(io::ErrorKind::Unsupported, format!("{address}: no shared listeners")))
}

/// True when [`listen_shared`] and [`bind_shared`] work on this platform.
pub const CAN_SHARE_ADDRESS: bool = cfg!(any(target_os = "linux", target_os = "android"));

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sharing {
    use std::io;
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    pub(super) const SOCK_STREAM: i32 = 1;
    pub(super) const SOCK_DGRAM: i32 = 2;
    const SOCK_CLOEXEC: i32 = 0x80000;
    const SOL_SOCKET: i32 = 1;
    const SO_REUSEADDR: i32 = 2;
    const SO_REUSEPORT: i32 = 15;
    /// The kernel lowers this to its own limit (`net.core.somaxconn`).
    const BACKLOG: i32 = 4096;

    unsafe extern "C" {
        fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
        fn setsockopt(fd: i32, level: i32, name: i32, value: *const u8, length: u32) -> i32;
        #[link_name = "bind"]
        fn bind_socket(fd: i32, address: *const u8, length: u32) -> i32;
        fn listen(fd: i32, backlog: i32) -> i32;
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

    fn checked(result: i32) -> io::Result<()> {
        if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }

    pub(super) fn bind(address: SocketAddr, kind: i32) -> io::Result<OwnedFd> {
        let domain = i32::from(if address.is_ipv4() { AF_INET } else { AF_INET6 });
        // SAFETY: `socket` takes three integers and returns a descriptor or -1.
        let fd = unsafe { socket(domain, kind | SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a descriptor the call above just returned, owned by nobody else.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let on = 1i32.to_ne_bytes();
        for option in [SO_REUSEADDR, SO_REUSEPORT] {
            // SAFETY: `on` is four live bytes, the length passed, and the kernel copies
            // them before the call returns.
            checked(unsafe { setsockopt(owned.as_raw_fd(), SOL_SOCKET, option, on.as_ptr(), 4) })?;
        }
        let (bytes, length) = raw(address);
        // SAFETY: `bytes` holds a socket address of `length` bytes, and the kernel
        // copies it before the call returns.
        checked(unsafe { bind_socket(owned.as_raw_fd(), bytes.as_ptr(), length) })?;
        if kind == SOCK_STREAM {
            // SAFETY: `listen` takes a descriptor and an integer.
            checked(unsafe { listen(owned.as_raw_fd(), BACKLOG) })?;
        }
        Ok(owned)
    }
}
