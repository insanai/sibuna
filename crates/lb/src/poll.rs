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
use std::os::fd::{AsRawFd, RawFd as Handle};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

#[cfg(windows)]
pub(crate) type Handle = usize;

#[cfg(unix)]
pub(crate) fn handle(socket: &impl AsRawFd) -> Handle {
    socket.as_raw_fd()
}

#[cfg(windows)]
pub(crate) fn handle(socket: &impl AsRawSocket) -> Handle {
    let socket: RawSocket = socket.as_raw_socket();
    socket as usize
}

#[cfg(unix)]
pub(crate) const READ: i16 = 1;
#[cfg(unix)]
pub(crate) const WRITE: i16 = 4;
#[cfg(windows)]
pub(crate) const READ: i16 = 0x0100;
#[cfg(windows)]
pub(crate) const WRITE: i16 = 0x0010;

/// The registered sockets of one worker and the key reported for each.
pub(crate) struct Poller<K> {
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
                epoll_wait(self.epoll.as_raw_fd(), self.events.as_mut_ptr(), BATCH as i32, timeout_ms)
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
                self.sockets.extend(
                    entries.map(|(handle, events)| PollFd { handle, events, returned: 0 }),
                );
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
pub(crate) struct Waker {
    receiver: std::net::UdpSocket,
}

/// The sending half of a [`Waker`].
#[derive(Clone)]
pub(crate) struct Wake(std::sync::Arc<std::net::UdpSocket>);

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
