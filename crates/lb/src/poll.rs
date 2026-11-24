//! Level-triggered socket readiness. The worker keeps every registered socket alive through
//! the wait. The table is rebuilt each turn so a stale descriptor cannot survive removal.

#![allow(unsafe_code)]

use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd as Handle};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

#[cfg(windows)]
type Handle = usize;

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

#[repr(C)]
struct PollFd {
    handle: Handle,
    events: i16,
    returned: i16,
}

// nfds_t is unsigned long on Linux and unsigned int on the supported BSDs and macOS.
#[cfg(any(target_os = "linux", target_os = "android"))]
type Count = std::ffi::c_ulong;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
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

#[derive(Default)]
pub(crate) struct Poller<K> {
    sockets: Vec<PollFd>,
    keys: Vec<K>,
}

impl<K: Copy> Poller<K> {
    pub fn new() -> Self {
        Self { sockets: Vec::new(), keys: Vec::new() }
    }

    pub fn clear(&mut self) {
        self.sockets.clear();
        self.keys.clear();
    }

    pub fn add(&mut self, handle: Handle, events: i16, key: K) {
        if events != 0 {
            self.sockets.push(PollFd { handle, events, returned: 0 });
            self.keys.push(key);
        }
    }

    pub fn wait(&mut self, timeout_ms: i32) -> io::Result<()> {
        if self.sockets.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(timeout_ms as u64));
            return Ok(());
        }
        let count = self.sockets.len() as Count;
        // SAFETY: the C-compatible array has count initialized entries, fits Count by the
        // flow limit, and is exclusively borrowed for the duration of poll.
        if unsafe { poll(self.sockets.as_mut_ptr(), count, timeout_ms) } >= 0 {
            return Ok(());
        }
        #[cfg(unix)]
        let error = io::Error::last_os_error();
        #[cfg(windows)]
        // SAFETY: thread-local Winsock error retrieval takes no arguments.
        let error = io::Error::from_raw_os_error(unsafe { WSAGetLastError() });
        if error.kind() == io::ErrorKind::Interrupted { Ok(()) } else { Err(error) }
    }

    pub fn ready(&self) -> impl Iterator<Item = K> + '_ {
        self.sockets
            .iter()
            .zip(&self.keys)
            .filter_map(|(fd, key)| (fd.returned != 0).then_some(*key))
    }
}
